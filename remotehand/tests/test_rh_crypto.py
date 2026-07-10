import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from rh_crypto import SessionKeys, seal_for
    HAVE_NACL = True
except Exception:
    HAVE_NACL = False


@unittest.skipUnless(HAVE_NACL, "pynacl not installed")
class TestSealedBox(unittest.TestCase):
    def test_roundtrip(self):
        keys = SessionKeys()
        sealed = seal_for(keys.public_key_b64, "P@ss-Rel4y!")
        self.assertNotIn("P@ss", sealed)              # ciphertext hides the secret
        self.assertEqual(keys.unseal(sealed), "P@ss-Rel4y!")

    def test_json_payload_roundtrip(self):
        import json
        keys = SessionKeys()
        sealed = seal_for(keys.public_key_b64, json.dumps({"password": "s3cr3t"}))
        self.assertEqual(json.loads(keys.unseal(sealed))["password"], "s3cr3t")

    def test_wrong_key_cannot_open(self):
        a, b = SessionKeys(), SessionKeys()
        sealed = seal_for(a.public_key_b64, "secret")
        with self.assertRaises(Exception):
            b.unseal(sealed)                          # sealed to A, B must fail

    def test_pubkey_is_stable_and_b64(self):
        import base64
        keys = SessionKeys()
        self.assertEqual(keys.public_key_b64, keys.public_key_b64)
        self.assertEqual(len(base64.b64decode(keys.public_key_b64)), 32)  # X25519 pubkey

    def test_wipe_blocks_further_use(self):
        keys = SessionKeys()
        keys.wipe()
        with self.assertRaises(AssertionError):
            _ = keys.public_key_b64


if __name__ == "__main__":
    unittest.main()
