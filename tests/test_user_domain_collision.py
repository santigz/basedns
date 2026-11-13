from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

import app.dns_manager as dm
from app.dns_manager import ZoneManager
import app.main as main_mod


class TestUserDomainCollision(unittest.TestCase):
    """
    Regression test for REMOVE_USER_DOMAIN stripping the domain from Remote-User,
    causing users with the same local-part across different domains
    (e.g. user@alice.com and user@bob.com) to collide in the same user-zone file.
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

    def test_same_local_part_different_domains_do_not_collide(self):
        """
        user@alice.com and user@bob.com must get separate user-zone files
        and isolated DNS zones, not collide on 'user'.
        """
        with patch.object(main_mod, "zonemgr", self.zm):
            client = TestClient(main_mod.app)
            alice_headers = {"Remote-User": "user@alice.com"}
            bob_headers = {"Remote-User": "user@bob.com"}

            resp_alice = client.get(f"{main_mod.APP_PREFIX}/zonefile", headers=alice_headers)
            self.assertEqual(resp_alice.status_code, 200)
            self.assertIn("$ORIGIN user.example.com.", resp_alice.text)

            resp_bob = client.get(f"{main_mod.APP_PREFIX}/zonefile", headers=bob_headers)
            self.assertEqual(resp_bob.status_code, 200)
            self.assertIn("$ORIGIN user-1.example.com.", resp_bob.text)

            # Both users must have distinct zone files and distinct origins
            user_zones = self.zm.find_user_zones()
            self.assertEqual(
                user_zones,
                {"user@alice.com": "user", "user@bob.com": "user-1"},
            )

            zone_files = [p.name for p in self.user_zones_dir.iterdir() if p.is_file()]
            self.assertEqual(
                len(zone_files),
                2,
                f"Expected 2 separate user-zone files, got: {zone_files}",
            )

            # Adding a record to user@alice.com's zone must not appear in user@bob.com's zone
            alice_zone_updated = resp_alice.text + "\naliceonly\tIN\tA\t192.0.2.10\n"
            put_resp = client.put(
                f"{main_mod.APP_PREFIX}/zonefile",
                content=alice_zone_updated,
                headers=alice_headers,
            )
            self.assertEqual(put_resp.status_code, 200)

            bob_zone_after = client.get(f"{main_mod.APP_PREFIX}/zonefile", headers=bob_headers).text
            self.assertNotIn("aliceonly", bob_zone_after)

            # User tokens must also be isolated and preserved across dots in usernames
            alice_token = self.zm.get_user_token("user@alice.com")
            bob_token = self.zm.get_user_token("user@bob.com")
            self.assertNotEqual(alice_token, bob_token)
            self.assertEqual(self.zm.get_user_token("user@alice.com"), alice_token)
            self.assertEqual(self.zm.find_user_for_token(alice_token), "user@alice.com")
            self.assertEqual(self.zm.find_user_for_token(bob_token), "user@bob.com")


if __name__ == "__main__":
    unittest.main(verbosity=2)
