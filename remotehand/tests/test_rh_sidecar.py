import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from rh_input import RecordingInjector  # noqa: E402
from rh_protocol import PageState  # noqa: E402

try:
    from rh_crypto import SessionKeys, seal_for
    from rh_sidecar import Sidecar, GatedObserver, _run_fake
    HAVE_NACL = True
except Exception:
    HAVE_NACL = False


@unittest.skipUnless(HAVE_NACL, "pynacl not installed")
class TestSidecarCore(unittest.TestCase):
    def _make(self, states):
        out = []
        obs = GatedObserver([PageState(s) for s in states])
        inj = RecordingInjector()
        sc = Sidecar(obs, inj, SessionKeys(), out.append, "sess-1")
        return sc, obs, inj, out

    def test_hello_carries_pubkey(self):
        sc, _, _, out = self._make(["email"])
        sc.hello()
        self.assertEqual(out[0]["type"], "rh_hello")
        self.assertEqual(out[0]["session_id"], "sess-1")
        self.assertEqual(len(out[0]["relay_pubkey"]), 44)  # base64 of 32 bytes

    def test_sealed_password_decrypted_and_injected(self):
        sc, obs, inj, out = self._make(["email", "password", "success"])
        sc.hello(); sc.tick()                          # EMAIL → prompt
        pubkey = out[0]["relay_pubkey"]
        sealed = seal_for(pubkey, json.dumps({"password": "TopS3cret"}))
        sc.on_input({"type": "rh_input", "session_id": "sess-1", "step": "email",
                     "values": {"login": "demo@x.com"}, "sealed": sealed})
        # login injected immediately; password is BUFFERED (scenario §7) until password page
        self.assertIn(("type", "demo@x.com"), inj.calls)
        self.assertNotIn(("type", "TopS3cret"), inj.calls)  # not yet — still buffered
        # drive to success (gated advance mirrors page changes) → password now injected
        for _ in range(4):
            obs.advance(); sc.tick()
            if sc.done: break
        self.assertTrue(sc.done)
        self.assertIn(("type", "TopS3cret"), inj.calls)     # injected on the password page
        self.assertIn("success", [m.get("state") for m in out if m["type"] == "rh_state"])

    def test_full_fake_run_reaches_success(self):
        sc, obs, inj, out = self._make(["email", "password", "success"])
        pubkey_holder = {}
        inputs = iter([None])  # set after hello

        def reader():
            # first call returns the sealed email+password input, then EOF
            try:
                return next(reader.it)
            except StopIteration:
                return ""
        reader.it = iter([])

        # Manually: hello first to learn pubkey, then feed one input, then EOF
        sc.hello()
        pubkey = out[0]["relay_pubkey"]
        line = json.dumps({"type": "rh_input", "step": "email",
                           "values": {"login": "a@b.c"},
                           "sealed": seal_for(pubkey, json.dumps({"password": "pw"}))})
        reader.it = iter([line, ""])  # one input, then EOF
        # re-run the loop body without a second hello: emulate _run_fake from tick()
        sc.tick()
        while not sc.done:
            ln = reader()
            if not ln: break
            sc.on_input(json.loads(ln))
            for _ in range(6):
                obs.advance(); sc.tick()
                if sc.done: break
        self.assertTrue(sc.done)
        self.assertEqual(sc.fsm.result, "success")

    def test_run_fake_helper_end_to_end(self):
        sc, obs, inj, out = self._make(["email", "password", "success"])
        # Build the input line up front using a freshly-known pubkey.
        keys_pub = sc.keys.public_key_b64
        line = json.dumps({"type": "rh_input", "step": "email",
                           "values": {"login": "a@b.c"},
                           "sealed": seal_for(keys_pub, json.dumps({"password": "pw"}))})
        feed = iter([line, ""])
        _run_fake(sc, obs, lambda: next(feed, ""))
        self.assertTrue(sc.done)
        self.assertEqual(sc.fsm.result, "success")
        self.assertIn(("type", "pw"), inj.calls)


if __name__ == "__main__":
    unittest.main()
