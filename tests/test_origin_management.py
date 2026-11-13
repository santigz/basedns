import asyncio
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

# Allow running on host Python when pure-Python dependencies live in ./venv
_venv_site = Path(__file__).resolve().parent.parent / "venv/lib/python3.10/site-packages"
if _venv_site.is_dir() and str(_venv_site) not in sys.path:
    sys.path.append(str(_venv_site))

import app.dns_manager as dm
from app.dns_manager import (
    BadZoneFile,
    InvalidSubdomainError,
    NamedCheckZoneError,
    NamedReloadError,
    SubdomainUnavailableError,
    ZoneManager,
)


class TestOriginManagement(unittest.TestCase):
    """
    Comprehensive unit and FastAPI endpoint tests for <username>@<subdomain>
    zone storage, custom origin changes, collision handling, numeric suffix
    allocation, BIND config generation, and rollback behavior.
    """

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.tmpdir.name)
        self.bind_dir = self.base_path / "bind"
        self.user_zones_dir = self.bind_dir / "user-zones"
        self.user_tokens_dir = self.bind_dir / "user-tokens"
        self.backups_dir = self.base_path / "backups"
        self.main_zone_file = self.bind_dir / "main-zone"
        self.named_conf_local_file = self.bind_dir / "named.conf.local"
        self.custom_rrs_file = self.bind_dir / "custom-records"
        self.bind_dir.mkdir(parents=True, exist_ok=True)

        self.patches = [
            patch.object(dm, "BIND_DIR", str(self.bind_dir) + "/"),
            patch.object(dm, "USER_ZONES_DIR", str(self.user_zones_dir) + "/"),
            patch.object(dm, "USER_TOKENS_DIR", str(self.user_tokens_dir) + "/"),
            patch.object(dm, "BACKUPS_DIR", str(self.backups_dir) + "/"),
            patch.object(dm, "MAIN_ZONE_FILE", str(self.main_zone_file)),
            patch.object(dm, "NAMED_CONF_LOCAL_FILE", str(self.named_conf_local_file)),
            patch.object(dm, "CUSTOM_RRS_FILE", str(self.custom_rrs_file)),
            patch.object(ZoneManager, "get_public_ip", return_value="192.0.2.1"),
            patch.object(dm.NamedManager, "check_and_run", return_value=None),
            patch.object(dm.NamedManager, "named_checkconf", return_value=""),
            patch.object(dm.NamedManager, "named_checkzone", return_value="OK"),
            patch.object(dm.NamedManager, "reload", return_value=""),
            patch.object(dm.NamedManager, "named_pid", return_value=1234),
        ]
        for p in self.patches:
            p.start()

        self.zm = ZoneManager("example.com.")

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmpdir.cleanup()

    def test_01_filename_convention_same_vs_different_subdomain(self):
        """
        When subdomain == username, file is <username>.
        When subdomain != username, file is <username>@<subdomain>.
        When changing back to username, file returns to <username>.
        """
        # 1. Default initialization for 'alice' -> file is 'alice'
        zone_text = self.zm.get_user_zonefile("alice")
        self.assertIn("$ORIGIN alice.example.com.", zone_text)
        self.assertTrue((self.user_zones_dir / "alice").is_file())
        self.assertEqual(self.zm.find_user_zones(), {"alice": "alice"})

        # 2. Change origin to 'myproject' -> file becomes 'alice@myproject', old 'alice' removed
        new_zone = self.zm.change_user_origin("alice", "myproject")
        self.assertIn("$ORIGIN myproject.example.com.", new_zone)
        self.assertFalse((self.user_zones_dir / "alice").exists())
        self.assertTrue((self.user_zones_dir / "alice@myproject").is_file())
        self.assertEqual(self.zm.find_user_zones(), {"alice": "myproject"})
        self.assertEqual(self.zm.user_zone_origin("alice"), "myproject.example.com.")

        # 3. Change origin back to 'alice' -> file becomes 'alice' again
        reverted_zone = self.zm.change_user_origin("alice", "alice")
        self.assertIn("$ORIGIN alice.example.com.", reverted_zone)
        self.assertTrue((self.user_zones_dir / "alice").is_file())
        self.assertFalse((self.user_zones_dir / "alice@myproject").exists())
        self.assertEqual(self.zm.find_user_zones(), {"alice": "alice"})

    def test_02_temp_orig_and_hidden_files_ignored(self):
        """Verify .tmp, .orig, and hidden dotfiles in USER_ZONES_DIR are ignored."""
        self.zm.get_user_zonefile("alice")
        (self.user_zones_dir / "alice.tmp").write_text("temp")
        (self.user_zones_dir / "alice@custom.orig").write_text("orig")
        (self.user_zones_dir / ".hidden").write_text("hidden")

        self.assertEqual(self.zm.find_user_zones(), {"alice": "alice"})
        self.assertEqual(self.zm.find_user_list(), ["alice"])

    def test_03_new_user_default_subdomain_taken_gets_numeric_suffix(self):
        """
        If 'alice' claims 'bob' as her subdomain before 'bob' ever logs in,
        then when 'bob' logs in for the first time, 'bob' gets 'bob-1' (file 'bob@bob-1').
        If 'bob-1' is also taken, 'bob' gets 'bob-2'.
        """
        self.zm.get_user_zonefile("alice")
        self.zm.change_user_origin("alice", "bob")
        self.assertTrue((self.user_zones_dir / "alice@bob").is_file())

        # Another user 'charlie' also takes 'bob-1'
        self.zm.get_user_zonefile("charlie")
        self.zm.change_user_origin("charlie", "bob-1")
        self.assertTrue((self.user_zones_dir / "charlie@bob-1").is_file())

        # Now 'bob' logs in for the first time
        self.assertEqual(self.zm.user_zone_origin("bob"), "bob-2.example.com.")
        bob_zone = self.zm.get_user_zonefile("bob")
        self.assertIn("$ORIGIN bob-2.example.com.", bob_zone)
        self.assertTrue((self.user_zones_dir / "bob@bob-2").is_file())
        self.assertEqual(
            self.zm.find_user_zones(),
            {"alice": "bob", "bob": "bob-2", "charlie": "bob-1"},
        )

    def test_04_new_user_with_reserved_or_long_username_gets_safe_subdomain(self):
        """
        A new user named 'ns' (reserved by main-zone) automatically lands on 'ns-1' ('ns@ns-1').
        A 63-character username that collides truncates safely to stay <= 63 characters.
        """
        # 1. Reserved username 'ns'
        ns_zone = self.zm.get_user_zonefile("ns")
        self.assertIn("$ORIGIN ns-1.example.com.", ns_zone)
        self.assertTrue((self.user_zones_dir / "ns@ns-1").is_file())

        # 2. 63-char username collision
        long_name = "a" * 63
        self.zm.get_user_zonefile("first")
        self.zm.change_user_origin("first", long_name)

        long_user_origin = self.zm.user_zone_origin(long_name)
        long_sub = self.zm.get_user_subdomain(long_name)
        self.assertLessEqual(len(long_sub), 63)
        self.assertEqual(long_sub, ("a" * 61) + "-1")
        self.assertEqual(long_user_origin, f"{long_sub}.example.com.")

    def test_05_subdomain_validation_and_punycode_normalization(self):
        """Verify valid labels, uppercase normalization, IDN Punycode conversion, and invalid rejections."""
        self.assertEqual(self.zm.validate_subdomain("MyProject-1"), "myproject-1")
        self.assertEqual(self.zm.validate_subdomain("españa"), "xn--espaa-rta")
        self.assertEqual(self.zm.validate_subdomain("123"), "123")

        invalid_cases = [
            "",
            "   ",
            "two words",
            "sub.domain",
            "trailingdot.",
            ".leadingdot",
            "@",
            "user@sub",
            "*",
            "*.wild",
            "under_score",
            "-leadinghyphen",
            "trailinghyphen-",
            "a" * 64,
            "bad;char",
            "slash/path",
            "..",
        ]
        for bad in invalid_cases:
            with self.subTest(bad=bad):
                with self.assertRaises(InvalidSubdomainError):
                    self.zm.validate_subdomain(bad)

    def test_06_availability_checks_case_insensitive_punycode_and_custom_records(self):
        """
        Verify availability checks reject:
        - Reserved 'ns'
        - Owner names in /etc/bind/custom-records (relative and FQDN)
        - Subdomains taken by other users (case-insensitively and across IDN/Punycode)
        - The user's own current subdomain when calling change_user_origin()
        """
        self.custom_rrs_file.write_text(
            "; Custom records in main zone\n"
            "portal\tIN\tA\t192.0.2.50\n"
            "mail.example.com.\t300\tIN\tA\t192.0.2.51\n"
            "sub.blog\tIN\tA\t192.0.2.52\n"
        )
        reserved = self.zm.reserved_subdomains()
        self.assertIn("ns", reserved)
        self.assertIn("portal", reserved)
        self.assertIn("mail", reserved)
        self.assertIn("sub", reserved)

        self.zm.get_user_zonefile("alice")
        self.zm.change_user_origin("alice", "españa")
        self.assertEqual(self.zm.get_user_subdomain("alice"), "xn--espaa-rta")

        self.zm.get_user_zonefile("bob")

        # Bob cannot take 'españa' or 'XN--ESPAA-RTA'
        with self.assertRaises(SubdomainUnavailableError):
            self.zm.change_user_origin("bob", "españa")
        with self.assertRaises(SubdomainUnavailableError):
            self.zm.change_user_origin("bob", "XN--ESPAA-RTA")

        # Bob cannot take reserved 'ns' or custom record 'portal' / 'mail'
        for r_name in ("ns", "NS", "portal", "PORTAL", "mail"):
            with self.assertRaises(SubdomainUnavailableError):
                self.zm.change_user_origin("bob", r_name)

        # Bob cannot "change" to his own current subdomain 'bob'
        with self.assertRaises(SubdomainUnavailableError):
            self.zm.change_user_origin("bob", "BOB")

    def test_07_main_zone_and_named_conf_local_updated_on_origin_change(self):
        """
        Verify main-zone delegations and named.conf.local zone/file entries
        accurately reflect <username>@<subdomain> and release the old subdomain.
        """
        self.zm.get_user_zonefile("alice")
        self.zm.get_user_zonefile("bob")

        self.zm.change_user_origin("alice", "wonderland")

        main_zone = self.main_zone_file.read_text()
        self.assertIn("wonderland  IN  NS  ns.wonderland", main_zone)
        self.assertIn("ns.wonderland IN  A   192.0.2.1", main_zone)
        self.assertNotIn("alice  IN  NS  ns.alice", main_zone)

        named_local = self.named_conf_local_file.read_text()
        self.assertIn('zone "wonderland.example.com."', named_local)
        self.assertIn('file "/etc/bind/user-zones/alice@wonderland";', named_local)
        self.assertNotIn('zone "alice.example.com."', named_local)
        self.assertIn('zone "bob.example.com."', named_local)
        self.assertIn('file "/etc/bind/user-zones/bob";', named_local)

        # 'alice' is now free for 'bob' to claim!
        self.zm.change_user_origin("bob", "alice")
        self.assertTrue((self.user_zones_dir / "bob@alice").is_file())

    def test_08_reset_and_full_reset_preserve_custom_origin_and_dyndns_works(self):
        """
        Verify reset_user_zonefile(), reset_all_user_zonefiles(), set_user_zonefile(),
        and update_a_record() (DynDNS) all respect the user's custom subdomain.
        """
        self.zm.get_user_zonefile("alice")
        self.zm.change_user_origin("alice", "custom")

        # 1. DynDNS update_a_record writes to alice@custom
        self.zm.update_a_record("alice", "home", "198.51.100.77")
        zone_file_path = self.user_zones_dir / "alice@custom"
        self.assertTrue(zone_file_path.is_file())
        self.assertFalse((self.user_zones_dir / "alice").exists())
        self.assertIn("home\tIN\tA\t198.51.100.77", zone_file_path.read_text())

        # 2. Normal reset_user_zonefile wipes custom records but preserves 'alice@custom'
        reset_text = self.zm.reset_user_zonefile("alice")
        self.assertIn("$ORIGIN custom.example.com.", reset_text)
        self.assertNotIn("198.51.100.77", zone_file_path.read_text())
        self.assertTrue(zone_file_path.is_file())

        # 3. full_reset / reset_all_user_zonefiles preserves 'alice@custom'
        self.zm.reset_all_user_zonefiles()
        self.assertTrue(zone_file_path.is_file())
        self.assertEqual(self.zm.find_user_zones(), {"alice": "custom"})

    def test_09_rollback_when_change_user_origin_fails_bind_check(self):
        """
        If named-checkzone or reload fails during change_user_origin(),
        the user's previous zone file, records, and BIND config must be restored.
        """
        base = self.zm.get_user_zonefile("alice")
        custom_zone = base + "\nkeepme\tIN\tA\t192.0.2.99\n"
        self.zm.set_user_zonefile("alice", custom_zone)

        with patch.object(
            dm.NamedManager,
            "named_checkzone",
            side_effect=NamedCheckZoneError("simulated checkzone failure"),
        ):
            with self.assertRaises(NamedCheckZoneError):
                self.zm.change_user_origin("alice", "broken")

        # Verify rollback restored 'alice' file with 'keepme' record and removed 'alice@broken'
        self.assertTrue((self.user_zones_dir / "alice").is_file())
        self.assertFalse((self.user_zones_dir / "alice@broken").exists())
        self.assertIn("keepme\tIN\tA\t192.0.2.99", self.zm.get_user_zonefile("alice"))
        self.assertEqual(self.zm.user_zone_origin("alice"), "alice.example.com.")

    def test_10_fastapi_origin_endpoints(self):
        """Test GET /origin/available and POST /origin endpoint logic."""
        try:
            from fastapi.testclient import TestClient
            import app.main as main_mod
            has_fastapi_runtime = True
        except ImportError:
            has_fastapi_runtime = False

        if has_fastapi_runtime:
            with patch.object(main_mod, "zonemgr", self.zm):
                client = TestClient(main_mod.app)
                alice_headers = {"Remote-User": "alice"}
                bob_headers = {"Remote-User": "bob"}

                r_alice = client.get(f"{main_mod.APP_PREFIX}", headers=alice_headers)
                self.assertEqual(r_alice.status_code, 200)
                self.assertIn("alice.example.com.", r_alice.text)

                r_bob = client.get(f"{main_mod.APP_PREFIX}", headers=bob_headers)
                self.assertEqual(r_bob.status_code, 200)

                avail = client.get(
                    f"{main_mod.APP_PREFIX}/origin/available", params={"subdomain": "fresh"}, headers=alice_headers
                ).json()
                self.assertEqual(avail["available"], True)
                self.assertEqual(avail["valid"], True)
                self.assertEqual(avail["origin"], "fresh.example.com.")

                taken = client.get(
                    f"{main_mod.APP_PREFIX}/origin/available", params={"subdomain": "bob"}, headers=alice_headers
                ).json()
                self.assertEqual(taken["available"], False)
                self.assertEqual(taken["valid"], True)
                self.assertIn("already taken", taken["reason"])

                invalid = client.get(
                    f"{main_mod.APP_PREFIX}/origin/available", params={"subdomain": "bad.sub"}, headers=alice_headers
                ).json()
                self.assertEqual(invalid["available"], False)
                self.assertEqual(invalid["valid"], False)

                no_ack = client.post(
                    f"{main_mod.APP_PREFIX}/origin",
                    json={"subdomain": "fresh", "acknowledge": False},
                    headers=alice_headers,
                )
                self.assertEqual(no_ack.status_code, 400)
                self.assertEqual(no_ack.json()["detail"]["error"], "Acknowledgement required")

                ok_resp = client.post(
                    f"{main_mod.APP_PREFIX}/origin",
                    json={"subdomain": "fresh", "acknowledge": True},
                    headers=alice_headers,
                )
                self.assertEqual(ok_resp.status_code, 200)
                data = ok_resp.json()
                self.assertEqual(data["subdomain"], "fresh")
                self.assertEqual(data["origin"], "fresh.example.com.")
                self.assertIn("$ORIGIN fresh.example.com.", data["zone"])

                conflict_resp = client.post(
                    f"{main_mod.APP_PREFIX}/origin",
                    json={"subdomain": "fresh", "acknowledge": True},
                    headers=bob_headers,
                )
                self.assertEqual(conflict_resp.status_code, 409)
        else:
            # Verify full workflow directly on ZoneManager when pydantic C-extension is unavailable on host
            self.zm.get_user_zonefile("alice")
            self.zm.get_user_zonefile("bob")
            self.assertTrue(self.zm.is_subdomain_available("fresh", exclude_user="alice"))
            self.assertFalse(self.zm.is_subdomain_available("bob", exclude_user="alice"))
            zone = self.zm.change_user_origin("alice", "fresh")
            self.assertIn("$ORIGIN fresh.example.com.", zone)
            self.assertEqual(self.zm.user_zone_origin("alice"), "fresh.example.com.")
            with self.assertRaises(SubdomainUnavailableError):
                self.zm.change_user_origin("bob", "fresh")


if __name__ == "__main__":
    unittest.main(verbosity=2)
