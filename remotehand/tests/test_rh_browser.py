import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from rh_browser import build_command


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


if __name__ == "__main__":
    unittest.main()
