import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from rh_protocol import Field, PageState, RhInput, rh_hello, rh_prompt, rh_state  # noqa: E402


class TestField(unittest.TestCase):
    def test_password_and_code_are_forced_sensitive(self):
        self.assertTrue(Field("p", "Password", "password").sensitive)
        self.assertTrue(Field("c", "Code", "code").sensitive)

    def test_plain_text_not_sensitive(self):
        self.assertFalse(Field("login", "Login", "text").sensitive)
        self.assertFalse(Field("phone", "Phone", "tel").sensitive)


class TestMessages(unittest.TestCase):
    def test_rh_hello_shape(self):
        m = rh_hello("s1", "PUBKEY")
        self.assertEqual(m, {"type": "rh_hello", "session_id": "s1", "relay_pubkey": "PUBKEY"})

    def test_rh_prompt_serializes_fields_and_omits_optional(self):
        m = rh_prompt("s1", "r1", "email", "Sign in", [Field("login", "Login", "text")])
        self.assertEqual(m["type"], "rh_prompt")
        self.assertEqual(m["session_id"], "s1")
        self.assertEqual(m["step"], "email")
        self.assertEqual(m["fields"][0]["name"], "login")
        self.assertNotIn("image", m)      # optional omitted when absent
        self.assertNotIn("region", m)

    def test_rh_prompt_includes_captcha_image(self):
        m = rh_prompt("s1", "r1", "captcha_static", "Solve",
                      [Field("captcha", "Type", "captcha_image")], image_b64="QUJD")
        self.assertEqual(m["image"], "QUJD")

    def test_rh_state_shape(self):
        self.assertEqual(rh_state("s1", "r1", "success", "done"),
                         {"type": "rh_state", "session_id": "s1", "request_id": "r1",
                          "state": "success", "message": "done"})


class TestRhInputParse(unittest.TestCase):
    def test_parse_valid(self):
        p = RhInput.parse({"type": "rh_input", "session_id": "s1", "request_id": "r1",
                           "step": "email", "values": {"login": "a@b.c"}})
        self.assertEqual(p.step, "email")
        self.assertEqual(p.values["login"], "a@b.c")
        self.assertIsNone(p.sealed)

    def test_parse_sealed_and_gesture(self):
        p = RhInput.parse({"type": "rh_input", "step": "password", "sealed": "SEALED",
                           "gesture": [{"x": 1, "y": 2, "t": 0, "down": True}]})
        self.assertEqual(p.sealed, "SEALED")
        self.assertEqual(p.gesture[0]["x"], 1)

    def test_parse_rejects_wrong_type(self):
        with self.assertRaises(ValueError):
            RhInput.parse({"type": "auth_done"})


class TestPageState(unittest.TestCase):
    def test_values_match_wire_strings(self):
        self.assertEqual(PageState.EMAIL.value, "email")
        self.assertEqual(PageState.SMS.value, "sms_code")


if __name__ == "__main__":
    unittest.main()
