import os
from pathlib import Path
import re
import tarfile
import time
import unittest

import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.update
import requests

from app.dns_manager import BACKUPS_DIR, BIND_DIR, USER_ZONES_DIR, ZoneManager

HOST = "127.0.0.1"
HTTP_PORT = 80
DNS_PORT = 53
BASE_URL = f"http://{HOST}:{HTTP_PORT}"
APP_PREFIX = "/app"
APP_URL = f"{BASE_URL}{APP_PREFIX}"

# Timeouts to wait for requests. Modify if your machine is really slow.
REQUEST_TIMEOUT = 30
DNS_TIMEOUT = 5.0

TEST_USER = "user"
ROOT_DOMAIN = os.getenv("ROOT_DOMAIN", "example.com.")
if not ROOT_DOMAIN.endswith("."):
    ROOT_DOMAIN += "."
USER_ORIGIN = f"{TEST_USER}.{ROOT_DOMAIN}"


class TestDNSPlatformIntegration(unittest.TestCase):
    """
    End-to-end integration tests for the DNS platform (run inside the container).
    Interacts with the web API on port 80 and verifies records via DNS queries on port 53.
    """

    @classmethod
    def setUpClass(cls):
        cls.headers = {"Remote-User": TEST_USER}
        cls.resolver = dns.resolver.Resolver(configure=False)
        cls.resolver.nameservers = [HOST]
        cls.resolver.port = DNS_PORT
        cls.resolver.timeout = DNS_TIMEOUT
        cls.resolver.lifetime = DNS_TIMEOUT

        # Snapshot existing user-zones and backups so running inside a live dev container
        # does not clobber developer state or leave temporary test users behind.
        zones_dir = Path(USER_ZONES_DIR)
        cls._initial_user_zones = {}
        if zones_dir.exists():
            for p in zones_dir.iterdir():
                if p.is_file():
                    cls._initial_user_zones[p.name] = p.read_text()

        backups_dir = Path(BACKUPS_DIR)
        cls._initial_backups = (
            {p.name for p in backups_dir.iterdir() if p.is_file()}
            if backups_dir.exists()
            else set()
        )

        # Ensure the user zone is initialized by hitting '/'
        resp = requests.get(f"{APP_URL}", headers=cls.headers, timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            raise RuntimeError(
                f"Failed to reach web app at {APP_URL} (status {resp.status_code})"
            )

        # If 'user' had a custom origin in a running dev container (e.g. user@santi),
        # switch 'user' back to default 'user.example.com.' for the test run.
        if f'content="{USER_ORIGIN}"' not in resp.text:
            requests.post(
                f"{APP_URL}/origin",
                json={"subdomain": TEST_USER, "acknowledge": True},
                headers=cls.headers,
                timeout=REQUEST_TIMEOUT,
            )

        # Extract the user's API token from the rendered HTML page for DynDNS tests
        match = re.search(r'value="([0-9a-f]{4}(?:-[0-9a-f]{4})+)"', resp.text)
        cls.api_token = match.group(1) if match else None

    def setUp(self):
        # Start each test with a clean default zone for 'user'
        resp = requests.post(
            f"{APP_URL}/reset_zonefile", headers=self.headers, timeout=REQUEST_TIMEOUT
        )
        self.assertEqual(resp.status_code, 200, f"Reset failed: {resp.text}")

    @classmethod
    def tearDownClass(cls):
        # Restore exact initial user-zones and backups state
        zones_dir = Path(USER_ZONES_DIR)
        if zones_dir.exists():
            for p in list(zones_dir.iterdir()):
                if p.is_file() and p.name not in cls._initial_user_zones:
                    p.unlink(missing_ok=True)
            for name, content in cls._initial_user_zones.items():
                (zones_dir / name).write_text(content)
            try:
                zm = ZoneManager(ROOT_DOMAIN)
                zm.reset_main_zone()
                zm.reset_named_conf_local()
            except Exception:
                requests.post(f"{APP_URL}/reset_zonefile", headers=cls.headers, timeout=REQUEST_TIMEOUT)
        else:
            requests.post(f"{APP_URL}/reset_zonefile", headers=cls.headers, timeout=REQUEST_TIMEOUT)

        backups_dir = Path(BACKUPS_DIR)
        if backups_dir.exists():
            for p in list(backups_dir.iterdir()):
                if p.is_file() and p.name not in cls._initial_backups:
                    p.unlink(missing_ok=True)

    def query_dns(self, qname: str, rdtype: str, origin: str = USER_ORIGIN):
        """Helper to query the BIND server for a record inside a given zone origin."""
        if qname == "@":
            fqdn = origin
        elif qname.endswith("."):
            fqdn = qname
        else:
            fqdn = f"{qname}.{origin}"
        return self.resolver.resolve(fqdn, rdtype)

    def get_zonefile(self, headers=None) -> str:
        resp = requests.get(
            f"{APP_URL}/zonefile", headers=headers or self.headers, timeout=REQUEST_TIMEOUT
        )
        self.assertEqual(resp.status_code, 200)
        return resp.text

    def put_zonefile(self, content: str, headers=None) -> requests.Response:
        req_headers = {**(headers or self.headers), "Content-Type": "text/plain"}
        return requests.put(
            f"{APP_URL}/zonefile",
            data=content.encode("utf-8"),
            headers=req_headers,
            timeout=REQUEST_TIMEOUT,
        )

    def test_01_default_zone_soa_and_ns(self):
        """Verify that a freshly reset user zone serves SOA, NS, and ns A records."""
        soa_ans = self.query_dns("@", "SOA")
        self.assertEqual(len(soa_ans), 1)
        self.assertEqual(str(soa_ans[0].mname), f"ns.{USER_ORIGIN}")

        ns_ans = self.query_dns("@", "NS")
        ns_targets = [str(r.target) for r in ns_ans]
        self.assertIn(f"ns.{USER_ORIGIN}", ns_targets)

        a_ans = self.query_dns("ns", "A")
        self.assertEqual(len(a_ans), 1)

    def test_02_create_and_query_all_record_types(self):
        """Add A, AAAA, CNAME, MX, TXT, and sub-NS records to the zonefile and resolve them via DNS."""
        base_zone = self.get_zonefile()
        extra_records = "\n".join(
            [
                "web\t300\tIN\tA\t192.0.2.10",
                "ipv6host\t300\tIN\tAAAA\t2001:db8::1234",
                "www\t300\tIN\tCNAME\tweb",
                "@\t300\tIN\tMX\t10\tmail",
                "mail\t300\tIN\tA\t192.0.2.20",
                '@\t300\tIN\tTXT\t"v=spf1 mx -all"',
                "sub\t300\tIN\tNS\tns1.external.example.",
                "",
            ]
        )
        resp = self.put_zonefile(base_zone + "\n" + extra_records)
        self.assertEqual(resp.status_code, 200, f"Zone update failed: {resp.text}")

        # Verify A record
        a_ans = self.query_dns("web", "A")
        self.assertEqual([r.address for r in a_ans], ["192.0.2.10"])
        self.assertEqual(a_ans.rrset.ttl, 300)

        # Verify AAAA record
        aaaa_ans = self.query_dns("ipv6host", "AAAA")
        self.assertEqual([r.address for r in aaaa_ans], ["2001:db8::1234"])

        # Verify CNAME record
        cname_ans = self.query_dns("www", "CNAME")
        self.assertEqual(str(cname_ans[0].target), f"web.{USER_ORIGIN}")

        # Verify MX record
        mx_ans = self.query_dns("@", "MX")
        self.assertEqual(len(mx_ans), 1)
        self.assertEqual(mx_ans[0].preference, 10)
        self.assertEqual(str(mx_ans[0].exchange), f"mail.{USER_ORIGIN}")

        # Verify TXT record
        txt_ans = self.query_dns("@", "TXT")
        txt_strings = [b"".join(r.strings).decode("utf-8") for r in txt_ans]
        self.assertIn("v=spf1 mx -all", txt_strings)

    def test_03_invalid_zonefile_is_rejected_and_preserves_previous_zone(self):
        """Uploading a malformed zonefile returns HTTP 400 and does not break the active zone."""
        base_zone = self.get_zonefile()
        valid_zone = base_zone + "\ngoodhost\tIN\tA\t192.0.2.55\n"
        self.assertEqual(self.put_zonefile(valid_zone).status_code, 200)

        # Try uploading an invalid record (invalid IPv4 address)
        bad_zone = valid_zone + "\nbadhost\tIN\tA\t999.999.999.999\n"
        bad_resp = self.put_zonefile(bad_zone)
        self.assertEqual(bad_resp.status_code, 400)

        # Verify the previous 'goodhost' record still resolves properly
        a_ans = self.query_dns("goodhost", "A")
        self.assertEqual([r.address for r in a_ans], ["192.0.2.55"])

    def test_04_dyndns_creates_and_updates_a_record(self):
        """Test the DynDNS /update/{hostname} endpoint for both creating and updating an A record."""
        self.assertIsNotNone(
            self.api_token, "Could not find user API token on user page"
        )

        # 1. Create a new record 'home' via DynDNS using query param api_key
        resp1 = requests.post(
            f"{BASE_URL}/update/home",
            params={"api_key": self.api_token, "ip": "198.51.100.10"},
            timeout=REQUEST_TIMEOUT,
        )
        self.assertEqual(resp1.status_code, 200, f"DynDNS create failed: {resp1.text}")
        self.assertEqual(resp1.json()["ip"], "198.51.100.10")

        ans1 = self.query_dns("home", "A")
        self.assertEqual([r.address for r in ans1], ["198.51.100.10"])

        # 2. Update the existing 'home' record via DynDNS using X-API-Key header
        resp2 = requests.post(
            f"{BASE_URL}/update/home",
            params={"ip": "198.51.100.99"},
            headers={"X-API-Key": self.api_token},
            timeout=REQUEST_TIMEOUT,
        )
        self.assertEqual(resp2.status_code, 200, f"DynDNS update failed: {resp2.text}")
        self.assertEqual(resp2.json()["ip"], "198.51.100.99")

        ans2 = self.query_dns("home", "A")
        self.assertEqual([r.address for r in ans2], ["198.51.100.99"])

    def test_05_reset_zonefile_wipes_custom_records(self):
        """Verify that POST /reset_zonefile removes custom records from DNS resolution."""
        base_zone = self.get_zonefile()
        self.assertEqual(
            self.put_zonefile(base_zone + "\ntemp\tIN\tA\t192.0.2.77\n").status_code,
            200,
        )
        self.assertEqual(
            [r.address for r in self.query_dns("temp", "A")], ["192.0.2.77"]
        )

        # Reset the zone
        reset_resp = requests.post(
            f"{APP_URL}/reset_zonefile", headers=self.headers, timeout=REQUEST_TIMEOUT
        )
        self.assertEqual(reset_resp.status_code, 200)

        # Querying 'temp' should now return NXDOMAIN
        with self.assertRaises(dns.resolver.NXDOMAIN):
            self.query_dns("temp", "A")

    def test_06_new_user_creation(self):
        """Verify that requesting with a new Remote-User 'test-<epoch>' creates and serves the new zone."""
        new_user = f"test-{int(time.time())}"
        new_origin = f"{new_user}.{ROOT_DOMAIN}"
        new_headers = {"Remote-User": new_user}

        # Access '/' as the new user to trigger zone creation and BIND config reload
        resp = requests.get(f"{APP_URL}", headers=new_headers, timeout=REQUEST_TIMEOUT)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(new_origin, resp.text)

        # Verify default SOA and NS records resolve via DNS for the new user's zone
        soa_ans = self.query_dns("@", "SOA", origin=new_origin)
        self.assertEqual(len(soa_ans), 1)
        self.assertEqual(str(soa_ans[0].mname), f"ns.{new_origin}")

        ns_ans = self.query_dns("@", "NS", origin=new_origin)
        ns_targets = [str(r.target) for r in ns_ans]
        self.assertIn(f"ns.{new_origin}", ns_targets)

        # Add a custom A record to the new user's zone and verify it resolves
        zone_data = self.get_zonefile(headers=new_headers)
        put_resp = self.put_zonefile(
            zone_data + "\napp\tIN\tA\t203.0.113.42\n", headers=new_headers
        )
        self.assertEqual(put_resp.status_code, 200)

        a_ans = self.query_dns("app", "A", origin=new_origin)
        self.assertEqual([r.address for r in a_ans], ["203.0.113.42"])

    def test_07_backup_contains_all_bind_files(self):
        """Verify that backup() creates a tar.gz in BACKUPS_DIR containing all files in BIND_DIR."""
        zonemgr = ZoneManager.__new__(ZoneManager)
        backup_filename = zonemgr.backup()
        self.assertIsNotNone(backup_filename)
        self.assertTrue(
            backup_filename.startswith("bind-") and backup_filename.endswith(".tar.gz"),
            f"Unexpected backup filename: {backup_filename}",
        )

        backup_path = Path(BACKUPS_DIR) / backup_filename
        self.assertTrue(backup_path.is_file(), f"Backup file not found at {backup_path}")

        bind_path = Path(BIND_DIR)
        expected_files = [
            os.path.relpath(os.path.join(root, filename), bind_path)
            for root, _, files in os.walk(bind_path)
            for filename in files
        ]
        self.assertGreater(len(expected_files), 0, "Expected files in BIND_DIR")

        with tarfile.open(backup_path, "r:gz") as tar:
            tar_members = set(tar.getnames())

        for rel_file in expected_files:
            self.assertIn(
                rel_file,
                tar_members,
                f"File '{rel_file}' from {BIND_DIR} is missing in backup {backup_filename}",
            )

    def test_08_security_recursion_and_external_domains_refused(self):
        """Verify recursion is disabled (RA=0) and queries for external domains return REFUSED."""
        for external_domain in ("google.com.", "example.org."):
            query = dns.message.make_query(external_domain, dns.rdatatype.A)
            query.flags |= dns.flags.RD
            resp = dns.query.udp(query, HOST, port=DNS_PORT, timeout=DNS_TIMEOUT)
            self.assertEqual(
                resp.rcode(),
                dns.rcode.REFUSED,
                f"Expected REFUSED for external domain {external_domain}, got {dns.rcode.to_text(resp.rcode())}",
            )
            self.assertFalse(
                bool(resp.flags & dns.flags.RA),
                f"Expected RA (Recursion Available) flag to be 0 for {external_domain}",
            )

        # Also check that authoritative responses have RA=0
        auth_query = dns.message.make_query(USER_ORIGIN, dns.rdatatype.SOA)
        auth_query.flags |= dns.flags.RD
        auth_resp = dns.query.udp(auth_query, HOST, port=DNS_PORT, timeout=DNS_TIMEOUT)
        self.assertEqual(auth_resp.rcode(), dns.rcode.NOERROR)
        self.assertFalse(
            bool(auth_resp.flags & dns.flags.RA),
            "Expected RA (Recursion Available) flag to be 0 on authoritative responses",
        )

    def test_09_security_axfr_zone_transfer_refused(self):
        """Verify that unauthorized AXFR zone transfers are refused for both root and user zones."""
        for zone_origin in (ROOT_DOMAIN, USER_ORIGIN):
            axfr_query = dns.message.make_query(zone_origin, dns.rdatatype.AXFR)
            axfr_resp = dns.query.tcp(axfr_query, HOST, port=DNS_PORT, timeout=DNS_TIMEOUT)
            self.assertEqual(
                axfr_resp.rcode(),
                dns.rcode.REFUSED,
                f"Expected AXFR for {zone_origin} to be REFUSED, got {dns.rcode.to_text(axfr_resp.rcode())}",
            )
            self.assertEqual(len(axfr_resp.answer), 0)

    def test_10_security_rfc2136_dynamic_update_refused(self):
        """Verify that direct RFC 2136 DNS UPDATE packets are refused and cannot modify zones."""
        update_msg = dns.update.UpdateMessage(USER_ORIGIN)
        update_msg.add("injected", 300, "A", "198.51.100.250")
        resp = dns.query.udp(update_msg, HOST, port=DNS_PORT, timeout=DNS_TIMEOUT)
        self.assertEqual(
            resp.rcode(),
            dns.rcode.REFUSED,
            f"Expected RFC 2136 dynamic update to be REFUSED, got {dns.rcode.to_text(resp.rcode())}",
        )
        with self.assertRaises(dns.resolver.NXDOMAIN):
            self.query_dns("injected", "A")

    def test_11_security_chaos_version_and_identity_hidden(self):
        """Verify CHAOS queries (version.bind, hostname.bind, id.server) do not leak server metadata."""
        for qname in ("version.bind.", "hostname.bind.", "id.server."):
            query = dns.message.make_query(
                qname, dns.rdatatype.TXT, dns.rdataclass.CH
            )
            resp = dns.query.udp(query, HOST, port=DNS_PORT, timeout=DNS_TIMEOUT)
            self.assertEqual(
                len(resp.answer),
                0,
                f"Expected empty answer for CHAOS query {qname}, got {resp.answer}",
            )

    def test_12_change_origin_resets_zone_and_updates_dns(self):
        """Verify POST /origin changes a user's zone origin, resets records, and updates BIND."""
        ts = int(time.time())
        u_name = f"origuser-{ts}"
        custom_sub = f"custom-{ts}"
        initial_origin = f"{u_name}.{ROOT_DOMAIN}"
        custom_origin = f"{custom_sub}.{ROOT_DOMAIN}"
        u_headers = {"Remote-User": u_name}

        # 1. Initialize user and add a custom A record
        r_init = requests.get(f"{APP_URL}", headers=u_headers, timeout=REQUEST_TIMEOUT)
        self.assertEqual(r_init.status_code, 200)
        z_data = self.get_zonefile(headers=u_headers)
        self.assertEqual(
            self.put_zonefile(
                z_data + "\noldrec\tIN\tA\t192.0.2.111\n", headers=u_headers
            ).status_code,
            200,
        )
        self.assertEqual(
            [r.address for r in self.query_dns("oldrec", "A", origin=initial_origin)],
            ["192.0.2.111"],
        )

        # 2. Unacknowledged origin change must be rejected with 400
        no_ack = requests.post(
            f"{APP_URL}/origin",
            json={"subdomain": custom_sub, "acknowledge": False},
            headers=u_headers,
            timeout=REQUEST_TIMEOUT,
        )
        self.assertEqual(no_ack.status_code, 400)

        # 3. Change origin with acknowledge=True
        change_resp = requests.post(
            f"{APP_URL}/origin",
            json={"subdomain": custom_sub, "acknowledge": True},
            headers=u_headers,
            timeout=REQUEST_TIMEOUT,
        )
        self.assertEqual(change_resp.status_code, 200, f"Origin change failed: {change_resp.text}")
        self.assertEqual(change_resp.json()["origin"], custom_origin)

        # 4. Old origin is no longer served (NXDOMAIN) and new origin serves SOA & NS
        with self.assertRaises(dns.resolver.NXDOMAIN):
            self.query_dns("@", "SOA", origin=initial_origin)

        soa_ans = self.query_dns("@", "SOA", origin=custom_origin)
        self.assertEqual(str(soa_ans[0].mname), f"ns.{custom_origin}")

        # 5. Rejects reserved 'ns' and already-taken subdomain with 409
        res_ns = requests.post(
            f"{APP_URL}/origin",
            json={"subdomain": "ns", "acknowledge": True},
            headers=u_headers,
            timeout=REQUEST_TIMEOUT,
        )
        self.assertEqual(res_ns.status_code, 409)

        # 6. User B tries to change origin to User A's new custom_sub -> 409 Conflict,
        #    and User B's existing zone & records remain intact in DNS
        user_b = f"seconduser-{ts}"
        user_b_origin = f"{user_b}.{ROOT_DOMAIN}"
        b_headers = {"Remote-User": user_b}
        requests.get(f"{APP_URL}", headers=b_headers, timeout=REQUEST_TIMEOUT)
        b_zone = self.get_zonefile(headers=b_headers)
        self.assertEqual(
            self.put_zonefile(
                b_zone + "\nbhost\tIN\tA\t192.0.2.222\n", headers=b_headers
            ).status_code,
            200,
        )
        b_conflict = requests.post(
            f"{APP_URL}/origin",
            json={"subdomain": custom_sub.upper(), "acknowledge": True},
            headers=b_headers,
            timeout=REQUEST_TIMEOUT,
        )
        self.assertEqual(b_conflict.status_code, 409)
        self.assertEqual(
            [r.address for r in self.query_dns("bhost", "A", origin=user_b_origin)],
            ["192.0.2.222"],
        )

        # 7. User A changes to a third name, freeing custom_sub -> User B can now claim custom_sub!
        third_sub = f"third-{ts}"
        a_move = requests.post(
            f"{APP_URL}/origin",
            json={"subdomain": third_sub, "acknowledge": True},
            headers=u_headers,
            timeout=REQUEST_TIMEOUT,
        )
        self.assertEqual(a_move.status_code, 200)

        b_claim = requests.post(
            f"{APP_URL}/origin",
            json={"subdomain": custom_sub, "acknowledge": True},
            headers=b_headers,
            timeout=REQUEST_TIMEOUT,
        )
        self.assertEqual(b_claim.status_code, 200)
        self.assertEqual(b_claim.json()["origin"], custom_origin)
        with self.assertRaises(dns.resolver.NXDOMAIN):
            self.query_dns("bhost", "A", origin=user_b_origin)
        soa_b_new = self.query_dns("@", "SOA", origin=custom_origin)
        self.assertEqual(str(soa_b_new[0].mname), f"ns.{custom_origin}")

    def test_13_new_user_with_taken_default_subdomain_gets_numeric_suffix(self):
        """
        Multi-user pre-claim and numeric suffix scenarios:
        - User A claims 'userc-<ts>' before 'userc-<ts>' exists -> 'userc-<ts>' logs in and gets 'userc-<ts>-1'.
        - If 'userd-<ts>' AND 'userd-<ts>-1' are both claimed before 'userd-<ts>' logs in -> 'userd-<ts>' gets 'userd-<ts>-2'.
        - When User A later vacates 'userc-<ts>', 'userc-<ts>' can reclaim their own default name 'userc-<ts>'.
        """
        ts = int(time.time()) + 1
        user_a = f"usera-{ts}"
        user_b = f"userb-{ts}"
        user_c = f"userc-{ts}"
        user_d = f"userd-{ts}"
        a_headers = {"Remote-User": user_a}
        b_headers = {"Remote-User": user_b}
        c_headers = {"Remote-User": user_c}
        d_headers = {"Remote-User": user_d}

        # 1. User A initializes and changes origin to user_c before user_c ever logs in
        requests.get(f"{APP_URL}", headers=a_headers, timeout=REQUEST_TIMEOUT)
        c_resp = requests.post(
            f"{APP_URL}/origin",
            json={"subdomain": user_c, "acknowledge": True},
            headers=a_headers,
            timeout=REQUEST_TIMEOUT,
        )
        self.assertEqual(c_resp.status_code, 200)

        # 2. Now user_c logs in for the first time -> lands on userc-<ts>-1
        t_resp = requests.get(f"{APP_URL}", headers=c_headers, timeout=REQUEST_TIMEOUT)
        self.assertEqual(t_resp.status_code, 200)
        expected_c_fallback = f"{user_c}-1.{ROOT_DOMAIN}"
        self.assertIn(expected_c_fallback, t_resp.text)

        # 3. Both userc-<ts> (User A) and userc-<ts>-1 (User C) resolve via DNS
        soa_claimed = self.query_dns("@", "SOA", origin=f"{user_c}.{ROOT_DOMAIN}")
        self.assertEqual(str(soa_claimed[0].mname), f"ns.{user_c}.{ROOT_DOMAIN}")

        soa_fallback = self.query_dns("@", "SOA", origin=expected_c_fallback)
        self.assertEqual(str(soa_fallback[0].mname), f"ns.{expected_c_fallback}")

        # 4. User A claims user_d AND User B claims user_d-1 before user_d logs in -> user_d gets user_d-2
        requests.get(f"{APP_URL}", headers=b_headers, timeout=REQUEST_TIMEOUT)
        self.assertEqual(
            requests.post(
                f"{APP_URL}/origin",
                json={"subdomain": user_d, "acknowledge": True},
                headers=a_headers,
                timeout=REQUEST_TIMEOUT,
            ).status_code,
            200,
        )
        self.assertEqual(
            requests.post(
                f"{APP_URL}/origin",
                json={"subdomain": f"{user_d}-1", "acknowledge": True},
                headers=b_headers,
                timeout=REQUEST_TIMEOUT,
            ).status_code,
            200,
        )
        d_resp = requests.get(f"{APP_URL}", headers=d_headers, timeout=REQUEST_TIMEOUT)
        self.assertEqual(d_resp.status_code, 200)
        expected_d_fallback = f"{user_d}-2.{ROOT_DOMAIN}"
        self.assertIn(expected_d_fallback, d_resp.text)
        soa_d = self.query_dns("@", "SOA", origin=expected_d_fallback)
        self.assertEqual(str(soa_d[0].mname), f"ns.{expected_d_fallback}")

        # 5. Since User A moved from user_c to user_d, user_c can now reclaim their own name 'user_c'!
        reclaim_resp = requests.post(
            f"{APP_URL}/origin",
            json={"subdomain": user_c, "acknowledge": True},
            headers=c_headers,
            timeout=REQUEST_TIMEOUT,
        )
        self.assertEqual(reclaim_resp.status_code, 200)
        self.assertEqual(reclaim_resp.json()["origin"], f"{user_c}.{ROOT_DOMAIN}")
        with self.assertRaises(dns.resolver.NXDOMAIN):
            self.query_dns("@", "SOA", origin=expected_c_fallback)
        soa_c_reclaimed = self.query_dns("@", "SOA", origin=f"{user_c}.{ROOT_DOMAIN}")
        self.assertEqual(str(soa_c_reclaimed[0].mname), f"ns.{user_c}.{ROOT_DOMAIN}")

    def test_14_mail_server_spf_dmarc_and_dkim_key_lengths(self):
        """
        Verify complete mail server DNS configuration (MX, SPF, DMARC, and DKIM):
        - Standard & >255-byte multi-chunk SPF TXT records (plus coexisting apex TXT records).
        - DKIM keys across varying algorithms and key sizes:
          * Ed25519 (~74 chars, 1 <character-string>)
          * RSA-1024 (~234 chars, 1 <character-string>)
          * RSA-1024 with extra tags (>255 chars, 2 <character-string> chunks)
          * RSA-2048 (~410 chars, 2 <character-string> chunks in 1 TXT RR)
          * RSA-4096 (~754 chars, 3 <character-string> chunks in 1 TXT RR, resolved over UDP/EDNS0 and TCP)
          * opendkim-genkey multiline parenthesized TXT ( "..." "..." ) format
        - Two-record CNAME-delegated DKIM rotation (selector1._domainkey & selector2._domainkey).
        - Rejection of an unsplit >255-byte single <character-string> by named-checkzone (HTTP 400).
        """
        base_zone = self.get_zonefile()

        ed25519_dkim = "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
        rsa1024_b64 = (
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC5N3lnvvrYgPCRSoqn+awTpE+i"
            "GYcKBPpo8HHbcFfCIIV10Hwo4PhCoGZSaKVHOjDm4yefKXhQjM7iKzEPuBatE7O4"
            "7hAx1CJpNuIdLxhILSbEmbMxJrJAG0HZVn8z6EAoOHZNaPHmK2h4UUrjOG8zA5BH"
            "fzJf7tGwI+K619fFUwIDAQAB"
        )
        rsa1024_dkim = f"v=DKIM1; k=rsa; p={rsa1024_b64}"
        rsa1024_tagged_dkim = f"v=DKIM1; h=sha256; k=rsa; s=email; t=y:s; p={rsa1024_b64}"
        rsa2048_dkim = (
            "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"
            + ("A" * 340)
            + "IDAQAB"
        )
        rsa4096_dkim = (
            "v=DKIM1; k=rsa; p=MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA"
            + ("B" * 684)
            + "IDAQAB"
        )
        opendkim_p1 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA" + ("C" * 180)
        opendkim_p2 = ("D" * 160) + "IDAQAB"
        opendkim_expected = f"v=DKIM1; h=sha256; k=rsa; p={opendkim_p1}{opendkim_p2}"

        short_spf = "v=spf1 mx a ip4:192.0.2.25 -all"
        site_verify = "google-site-verification=mail-domain-verify-12345"
        long_spf = (
            "v=spf1 mx a ip4:192.0.2.0/24 ip4:198.51.100.0/24 ip4:203.0.113.0/24 ip6:2001:db8::/32 "
            "include:_spf.google.com include:spf.protection.outlook.com "
            "include:amazonses.com include:mailgun.org include:sendgrid.net "
            "include:spf.messagingengine.com include:_spf.protonmail.ch include:servers.mcsv.net ~all"
        )
        dmarc_val = f"v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@{USER_ORIGIN.rstrip('.')}"

        def chunk_quotes(s: str, size: int = 255) -> str:
            return " ".join(f'"{s[i:i + size]}"' for i in range(0, len(s), size))

        mail_records = "\n".join(
            [
                "@\t300\tIN\tMX\t10\tmail",
                "mail\t300\tIN\tA\t192.0.2.25",
                f'@\t300\tIN\tTXT\t"{short_spf}"',
                f'@\t300\tIN\tTXT\t"{site_verify}"',
                f"bulk\t300\tIN\tTXT\t{chunk_quotes(long_spf)}",
                f'_dmarc\t300\tIN\tTXT\t"{dmarc_val}"',
                f"ed._domainkey\t300\tIN\tTXT\t{chunk_quotes(ed25519_dkim)}",
                f"rsa1024._domainkey\t300\tIN\tTXT\t{chunk_quotes(rsa1024_dkim)}",
                f"rsa1024tag._domainkey\t300\tIN\tTXT\t{chunk_quotes(rsa1024_tagged_dkim)}",
                f"rsa2048._domainkey\t300\tIN\tTXT\t{chunk_quotes(rsa2048_dkim)}",
                f"rsa4096._domainkey\t300\tIN\tTXT\t{chunk_quotes(rsa4096_dkim)}",
                (
                    'opendkim._domainkey\t300\tIN\tTXT\t( "v=DKIM1; h=sha256; k=rsa; "\n'
                    f'\t  "p={opendkim_p1}"\n'
                    f'\t  "{opendkim_p2}" ) ; ----- DKIM key opendkim for {USER_ORIGIN}'
                ),
                "selector1._domainkey\t300\tIN\tCNAME\tselector1-user._domainkey.mailprovider.example.",
                "selector2._domainkey\t300\tIN\tCNAME\tselector2-user._domainkey.mailprovider.example.",
                "",
            ]
        )

        resp = self.put_zonefile(base_zone + "\n" + mail_records)
        self.assertEqual(resp.status_code, 200, f"Mail zone update failed: {resp.text}")

        # 1. Verify MX & mail A record
        mx_ans = self.query_dns("@", "MX")
        self.assertEqual(mx_ans[0].preference, 10)
        self.assertEqual(str(mx_ans[0].exchange), f"mail.{USER_ORIGIN}")

        # 2. Verify coexisting apex TXT records (SPF + domain verification)
        apex_txt_ans = self.query_dns("@", "TXT")
        apex_txt_values = {b"".join(r.strings).decode("utf-8") for r in apex_txt_ans}
        self.assertIn(short_spf, apex_txt_values)
        self.assertIn(site_verify, apex_txt_values)

        # 3. Verify >255-byte multi-chunk SPF record reassembles into the contiguous SPF policy
        bulk_txt_ans = self.query_dns("bulk", "TXT")
        self.assertEqual(len(bulk_txt_ans), 1)
        self.assertEqual(len(bulk_txt_ans[0].strings), 2)
        self.assertEqual(b"".join(bulk_txt_ans[0].strings).decode("utf-8"), long_spf)

        # 4. Verify DMARC TXT record
        dmarc_ans = self.query_dns("_dmarc", "TXT")
        self.assertEqual(b"".join(dmarc_ans[0].strings).decode("utf-8"), dmarc_val)

        # 5. Verify all DKIM key sizes and chunk counts via DNS queries
        dkim_expectations = [
            ("ed._domainkey", 1, ed25519_dkim),
            ("rsa1024._domainkey", 1, rsa1024_dkim),
            ("rsa1024tag._domainkey", 2, rsa1024_tagged_dkim),
            ("rsa2048._domainkey", 2, rsa2048_dkim),
            ("rsa4096._domainkey", 3, rsa4096_dkim),
            ("opendkim._domainkey", 3, opendkim_expected),
        ]
        for selector, expected_chunk_count, expected_full in dkim_expectations:
            with self.subTest(selector=selector):
                ans = self.query_dns(selector, "TXT")
                self.assertEqual(len(ans), 1, f"Expected a single TXT RR at {selector}")
                rdata = ans[0]
                self.assertEqual(
                    len(rdata.strings),
                    expected_chunk_count,
                    f"Expected {expected_chunk_count} <character-string> chunk(s) for {selector}",
                )
                for chunk in rdata.strings:
                    self.assertLessEqual(len(chunk), 255)
                reassembled = b"".join(rdata.strings).decode("utf-8")
                self.assertEqual(reassembled, expected_full)

        # Also verify the 4096-bit DKIM record explicitly over TCP
        tcp_ans = self.resolver.resolve(f"rsa4096._domainkey.{USER_ORIGIN}", "TXT", tcp=True)
        self.assertEqual(b"".join(tcp_ans[0].strings).decode("utf-8"), rsa4096_dkim)

        # 6. Verify two-record CNAME-delegated DKIM rotation selectors
        c1_ans = self.query_dns("selector1._domainkey", "CNAME")
        self.assertEqual(
            str(c1_ans[0].target), "selector1-user._domainkey.mailprovider.example."
        )
        c2_ans = self.query_dns("selector2._domainkey", "CNAME")
        self.assertEqual(
            str(c2_ans[0].target), "selector2-user._domainkey.mailprovider.example."
        )

        # 7. Verify that an unsplit >255-byte single <character-string> is rejected by BIND named-checkzone
        unsplit_bad_zone = (
            base_zone
            + "\n"
            + mail_records
            + f'\nunsplit._domainkey\t300\tIN\tTXT\t"{rsa2048_dkim}"\n'
        )
        bad_resp = self.put_zonefile(unsplit_bad_zone)
        self.assertEqual(
            bad_resp.status_code,
            400,
            "Expected unsplit >255-char single <character-string> to be rejected with HTTP 400",
        )
        # Active RSA-2048 DKIM record must remain intact after the rejected update
        still_ok = self.query_dns("rsa2048._domainkey", "TXT")
        self.assertEqual(b"".join(still_ok[0].strings).decode("utf-8"), rsa2048_dkim)


class TestAdminIntegration(unittest.TestCase):
    """Integration tests for remote-groups authorization and Admin API/UI endpoints."""

    @classmethod
    def setUpClass(cls):
        zones_dir = Path(USER_ZONES_DIR)
        cls._initial_user_zones = {}
        if zones_dir.exists():
            for p in zones_dir.iterdir():
                if p.is_file():
                    cls._initial_user_zones[p.name] = p.read_text()

        backups_dir = Path(BACKUPS_DIR)
        cls._initial_backups = (
            {p.name for p in backups_dir.iterdir() if p.is_file()}
            if backups_dir.exists()
            else set()
        )

    @classmethod
    def tearDownClass(cls):
        zones_dir = Path(USER_ZONES_DIR)
        if zones_dir.exists():
            for p in zones_dir.iterdir():
                if p.is_file() and p.name not in cls._initial_user_zones:
                    p.unlink()
            for name, content in cls._initial_user_zones.items():
                (zones_dir / name).write_text(content)

        backups_dir = Path(BACKUPS_DIR)
        if backups_dir.exists():
            for p in backups_dir.iterdir():
                if p.is_file() and p.name not in cls._initial_backups:
                    p.unlink()

        zm = ZoneManager(ROOT_DOMAIN)
        zm.reset_main_zone()
        zm.reset_named_conf_local()

    def test_non_admin_user_cannot_access_admin_ui_or_api(self):
        for headers in (
            {"Remote-User": "regular_user"},
            {"Remote-User": "regular_user", "Remote-Groups": "admin,editor,billing"},
        ):
            with self.subTest(headers=headers):
                page = requests.get(f"{APP_URL}", headers=headers, timeout=REQUEST_TIMEOUT)
                self.assertEqual(page.status_code, 200)
                self.assertNotIn('id="admin-tab"', page.text)

                self.assertEqual(
                    requests.get(f"{APP_URL}/admin/users", headers=headers, timeout=REQUEST_TIMEOUT).status_code,
                    403,
                )
                self.assertEqual(
                    requests.get(
                        f"{APP_URL}/admin/users/regular_user/zonefile",
                        headers=headers,
                        timeout=REQUEST_TIMEOUT,
                    ).status_code,
                    403,
                )
                self.assertEqual(
                    requests.get(f"{APP_URL}/admin/backups", headers=headers, timeout=REQUEST_TIMEOUT).status_code,
                    403,
                )

    def test_admin_ui_users_zonefile_and_backups(self):
        admin_headers = {
            "Remote-User": "adminuser",
            "Remote-Groups": "editor, basedns-admin , billing",
        }
        alice_headers = {"Remote-User": "alice"}

        # 1. Admin UI page shows Admin tab and Users/Backups sub-tabs
        page = requests.get(f"{APP_URL}", headers=admin_headers, timeout=REQUEST_TIMEOUT)
        self.assertEqual(page.status_code, 200)
        self.assertIn('id="admin-tab"', page.text)
        self.assertIn('id="admin-users-tab"', page.text)
        self.assertIn('id="admin-backups-tab"', page.text)

        # 2. Initialize alice, set a custom alias, and add a DNS record
        self.assertEqual(
            requests.get(f"{APP_URL}", headers=alice_headers, timeout=REQUEST_TIMEOUT).status_code,
            200,
        )
        origin_resp = requests.post(
            f"{APP_URL}/origin",
            json={"subdomain": "alice-alias", "acknowledge": True},
            headers=alice_headers,
            timeout=REQUEST_TIMEOUT,
        )
        self.assertEqual(origin_resp.status_code, 200, origin_resp.text)

        alice_zone = requests.get(
            f"{APP_URL}/zonefile", headers=alice_headers, timeout=REQUEST_TIMEOUT
        ).text
        put_resp = requests.put(
            f"{APP_URL}/zonefile",
            data=alice_zone + "\nweb\tIN\tA\t192.0.2.55\n",
            headers={**alice_headers, "Content-Type": "text/plain"},
            timeout=REQUEST_TIMEOUT,
        )
        self.assertEqual(put_resp.status_code, 200, put_resp.text)

        # 3. GET /app/admin/users lists users with alias and record_count
        users_resp = requests.get(
            f"{APP_URL}/admin/users", headers=admin_headers, timeout=REQUEST_TIMEOUT
        )
        self.assertEqual(users_resp.status_code, 200, users_resp.text)
        users = users_resp.json()["users"]
        by_name = {u["username"]: u for u in users}

        self.assertIn("adminuser", by_name)
        self.assertEqual(by_name["adminuser"]["alias"], "adminuser")
        self.assertEqual(by_name["adminuser"]["record_count"], 3)

        self.assertIn("alice", by_name)
        self.assertEqual(by_name["alice"]["alias"], "alice-alias")
        self.assertEqual(by_name["alice"]["record_count"], 4)

        # 4. GET /app/admin/users/{username}/zonefile returns zonefile on demand
        alice_admin_zone = requests.get(
            f"{APP_URL}/admin/users/alice/zonefile", headers=admin_headers, timeout=REQUEST_TIMEOUT
        )
        self.assertEqual(alice_admin_zone.status_code, 200)
        self.assertIn("192.0.2.55", alice_admin_zone.text)
        self.assertIn("alice-alias", alice_admin_zone.text)

        # Non-existent user returns 404 and is not auto-created
        missing_resp = requests.get(
            f"{APP_URL}/admin/users/does-not-exist/zonefile",
            headers=admin_headers,
            timeout=REQUEST_TIMEOUT,
        )
        self.assertEqual(missing_resp.status_code, 404)
        self.assertIsNone(ZoneManager(ROOT_DOMAIN).get_user_zonefile_path("does-not-exist"))

        # 5. GET /app/admin/backups lists backup filenames
        backups_dir = Path(BACKUPS_DIR)
        backups_dir.mkdir(parents=True, exist_ok=True)
        test_backup = backups_dir / "bind-2026-01-01_00-00-00.tar.gz"
        test_backup.write_bytes(b"test-backup")
        try:
            backups_resp = requests.get(
                f"{APP_URL}/admin/backups", headers=admin_headers, timeout=REQUEST_TIMEOUT
            )
            self.assertEqual(backups_resp.status_code, 200, backups_resp.text)
            self.assertIn("bind-2026-01-01_00-00-00.tar.gz", backups_resp.json()["backups"])
        finally:
            test_backup.unlink(missing_ok=True)


if __name__ == "__main__":
    print(
        f"Running integration tests against HTTP={BASE_URL} and DNS={HOST}:{DNS_PORT} (zone: {USER_ORIGIN})"
    )
    unittest.main(verbosity=2)
