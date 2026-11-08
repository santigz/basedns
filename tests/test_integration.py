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

from app.dns_manager import BACKUPS_DIR, BIND_DIR, ZoneManager

HOST = "127.0.0.1"
HTTP_PORT = 80
DNS_PORT = 53
BASE_URL = f"http://{HOST}:{HTTP_PORT}"

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
        cls.resolver.timeout = 3.0
        cls.resolver.lifetime = 3.0

        # Ensure the user zone is initialized by hitting '/'
        resp = requests.get(f"{BASE_URL}/", headers=cls.headers, timeout=5)
        if resp.status_code != 200:
            raise RuntimeError(
                f"Failed to reach web app at {BASE_URL}/ (status {resp.status_code})"
            )

        # Extract the user's API token from the rendered HTML page for DynDNS tests
        match = re.search(r'value="([0-9a-f]{4}(?:-[0-9a-f]{4})+)"', resp.text)
        cls.api_token = match.group(1) if match else None

    def setUp(self):
        # Start each test with a clean default zone for 'user'
        resp = requests.post(
            f"{BASE_URL}/reset_zonefile", headers=self.headers, timeout=5
        )
        self.assertEqual(resp.status_code, 200, f"Reset failed: {resp.text}")

    @classmethod
    def tearDownClass(cls):
        # Leave the zone in a clean reset state after all tests finish
        requests.post(f"{BASE_URL}/reset_zonefile", headers=cls.headers, timeout=5)

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
            f"{BASE_URL}/zonefile", headers=headers or self.headers, timeout=5
        )
        self.assertEqual(resp.status_code, 200)
        return resp.text

    def put_zonefile(self, content: str, headers=None) -> requests.Response:
        req_headers = {**(headers or self.headers), "Content-Type": "text/plain"}
        return requests.put(
            f"{BASE_URL}/zonefile",
            data=content.encode("utf-8"),
            headers=req_headers,
            timeout=5,
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
            timeout=5,
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
            timeout=5,
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
            f"{BASE_URL}/reset_zonefile", headers=self.headers, timeout=5
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
        resp = requests.get(f"{BASE_URL}/", headers=new_headers, timeout=5)
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
            resp = dns.query.udp(query, HOST, port=DNS_PORT, timeout=3.0)
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
        auth_resp = dns.query.udp(auth_query, HOST, port=DNS_PORT, timeout=3.0)
        self.assertEqual(auth_resp.rcode(), dns.rcode.NOERROR)
        self.assertFalse(
            bool(auth_resp.flags & dns.flags.RA),
            "Expected RA (Recursion Available) flag to be 0 on authoritative responses",
        )

    def test_09_security_axfr_zone_transfer_refused(self):
        """Verify that unauthorized AXFR zone transfers are refused for both root and user zones."""
        for zone_origin in (ROOT_DOMAIN, USER_ORIGIN):
            axfr_query = dns.message.make_query(zone_origin, dns.rdatatype.AXFR)
            axfr_resp = dns.query.tcp(axfr_query, HOST, port=DNS_PORT, timeout=3.0)
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
        resp = dns.query.udp(update_msg, HOST, port=DNS_PORT, timeout=3.0)
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
            resp = dns.query.udp(query, HOST, port=DNS_PORT, timeout=3.0)
            self.assertEqual(
                len(resp.answer),
                0,
                f"Expected empty answer for CHAOS query {qname}, got {resp.answer}",
            )


if __name__ == "__main__":
    print(
        f"Running integration tests against HTTP={BASE_URL} and DNS={HOST}:{DNS_PORT} (zone: {USER_ORIGIN})"
    )
    unittest.main(verbosity=2)
