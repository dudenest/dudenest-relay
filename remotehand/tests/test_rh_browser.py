import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from rh_browser import build_command, prepare_profile


class TestBuildCommand(unittest.TestCase):
    def setUp(self):
        self.cmd = build_command("https://accounts.google.com/o/oauth2/v2/auth?x=1",
                                 "/tmp/rh-sess1")

    def test_launches_chromium_with_url_and_profile(self):
        self.assertEqual(self.cmd[0], "chromium")
        self.assertEqual(self.cmd[-1], "https://accounts.google.com/o/oauth2/v2/auth?x=1")
        self.assertIn("--user-data-dir=/tmp/rh-sess1", self.cmd)

    def test_no_automation_flags(self):
        joined = " ".join(self.cmd)
        self.assertNotIn("--remote-debugging", joined)  # CDP-free: never a debug port
        self.assertNotIn("--headless", joined)          # real, headful browser

    def test_hides_automation_controlled(self):
        self.assertIn("--disable-blink-features=AutomationControlled", self.cmd)


class TestPrepareProfile(unittest.TestCase):
    def test_creates_dir_and_clears_stale_locks_but_keeps_cookies(self):
        with tempfile.TemporaryDirectory() as base:
            profile = os.path.join(base, "profile")           # does not exist yet
            os.makedirs(profile)
            for lock in ("SingletonLock", "SingletonCookie", "SingletonSocket"):
                open(os.path.join(profile, lock), "w").close()  # stale locks from an unclean exit
            cookies = os.path.join(profile, "Cookies")
            with open(cookies, "w") as f:
                f.write("trusted-device-token")                # the whole reason to persist the profile
            prepare_profile(profile)
            for lock in ("SingletonLock", "SingletonCookie", "SingletonSocket"):
                self.assertFalse(os.path.exists(os.path.join(profile, lock)), lock)  # locks gone
            self.assertTrue(os.path.exists(cookies))           # cookies survive
            self.assertEqual(open(cookies).read(), "trusted-device-token")

    def test_creates_missing_profile_dir(self):
        with tempfile.TemporaryDirectory() as base:
            profile = os.path.join(base, "new", "profile")     # nested, absent
            prepare_profile(profile)
            self.assertTrue(os.path.isdir(profile))

    def test_idempotent_when_no_locks_present(self):
        with tempfile.TemporaryDirectory() as base:
            prepare_profile(base)                              # no locks → must not raise
            prepare_profile(base)


if __name__ == "__main__":
    unittest.main()
