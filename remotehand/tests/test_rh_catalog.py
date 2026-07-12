import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from rh_protocol import PageState  # noqa: E402
from rh_catalog import CATALOG, ERROR_ENTRIES, classify, classify_error, match_screen  # noqa: E402


class TestCatalog(unittest.TestCase):
    def test_match_screen_returns_id_state_action(self):
        s = match_screen("Welcome\nEnter your password\nShow password\nNext")
        self.assertEqual(s.id, "password")
        self.assertEqual(s.state, PageState.PASSWORD)
        self.assertTrue(s.action.startswith("prompt_field"))

    def test_recaptcha_maps_to_recaptcha_action(self):
        s = match_screen("Confirm you're not a robot\nI'm not a robot")
        self.assertEqual(s.id, "captcha")
        self.assertEqual(s.action, "recaptcha")

    def test_consent_line_wrapped_still_matches(self):
        s = match_screen("Sign in with Google\ndudenest-relay wants\naccess to your Google\nAccount")
        self.assertEqual(s.state, PageState.CONSENT)

    def test_unrecognised_screen_is_none(self):
        self.assertIsNone(match_screen("some brand new google screen we've never seen"))
        self.assertEqual(classify("some brand new google screen"), PageState.UNKNOWN)

    def test_entries_have_unique_ids_and_an_action(self):
        ids = [s.id for s in CATALOG]
        self.assertEqual(len(ids), len(set(ids)))
        for s in CATALOG:
            self.assertTrue(s.action, f"{s.id} has no action")

    def test_classify_error_via_catalog(self):
        self.assertEqual(classify_error("Wrong password. Try again")[0], "password")
        self.assertIsNone(classify_error("Your session has expired")[0])
        self.assertTrue(all(isinstance(e.patterns, tuple) for e in ERROR_ENTRIES))


if __name__ == "__main__":
    unittest.main()
