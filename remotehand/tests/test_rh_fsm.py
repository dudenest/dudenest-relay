import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from rh_protocol import PageState  # noqa: E402
from rh_input import RecordingInjector  # noqa: E402
from rh_screen import ScriptedObserver  # noqa: E402
from rh_fsm import RemoteHandFSM  # noqa: E402


class RecordingEmitter:
    def __init__(self): self.msgs = []
    def send(self, msg): self.msgs.append(msg)

    def steps(self): return [m.get("step") for m in self.msgs if m["type"] == "rh_prompt"]
    def states(self): return [m.get("state") for m in self.msgs if m["type"] == "rh_state"]


def make(states, captcha=None, err=""):
    obs = ScriptedObserver(states, captcha=captcha, err=err)
    inj = RecordingInjector()
    emit = RecordingEmitter()
    return RemoteHandFSM("s1", obs, inj, emit), inj, emit


class TestHappyPathBufferedPassword(unittest.TestCase):
    """Scenario §7: user gives login+password up front; password auto-injected
    when the password page appears; then success."""
    def test_full_flow(self):
        fsm, inj, emit = make([PageState.EMAIL, PageState.PASSWORD, PageState.SUCCESS])
        fsm.tick()                                   # EMAIL → prompt(login,password)
        self.assertEqual(emit.steps(), ["email"])
        fsm.submit("email", {"login": "demo@x.com", "password": "secret"})
        fsm.tick()                                   # PASSWORD → auto-inject buffered
        fsm.tick()                                   # SUCCESS
        self.assertTrue(fsm.done)
        self.assertEqual(fsm.result, "success")
        self.assertIn("success", emit.states())
        # injector saw: email+Return, then buffered password+Return
        self.assertEqual(inj.calls, [
            ("type", "demo@x.com"), ("key", "Return"),
            ("type", "secret"), ("key", "Return"),
        ])

    def test_password_buffer_zeroized_after_use(self):
        fsm, inj, emit = make([PageState.EMAIL, PageState.PASSWORD])
        fsm.tick(); fsm.submit("email", {"login": "a", "password": "pw"})
        fsm.tick()
        self.assertEqual(fsm._buffered.get("password"), "")  # zeroized


class TestPasswordPromptedSeparately(unittest.TestCase):
    """If no password was buffered, the password page prompts for it."""
    def test_prompts_password_when_not_buffered(self):
        fsm, inj, emit = make([PageState.PASSWORD, PageState.SUCCESS])
        fsm.tick()                                   # PASSWORD, nothing buffered → prompt
        self.assertEqual(emit.steps(), ["password"])
        fsm.submit("password", {"password": "pw"})
        self.assertIn(("type", "pw"), inj.calls)
        self.assertIn(("key", "Return"), inj.calls)


class TestTwoFactor(unittest.TestCase):
    def test_phone_then_sms(self):
        fsm, inj, emit = make([PageState.PHONE, PageState.SMS, PageState.SUCCESS])
        fsm.tick()                                   # PHONE → prompt phone
        fsm.submit("phone", {"phone": "+48123"})
        fsm.tick()                                   # SMS → prompt code
        fsm.submit("sms_code", {"code": "998877"})
        fsm.tick()                                   # SUCCESS
        self.assertEqual(emit.steps(), ["phone", "sms_code"])
        self.assertEqual(fsm.result, "success")
        self.assertIn(("type", "+48123"), inj.calls)
        self.assertIn(("type", "998877"), inj.calls)


class TestConsentAutoAccept(unittest.TestCase):
    def test_consent_pressed_return(self):
        fsm, inj, emit = make([PageState.CONSENT, PageState.SUCCESS])
        fsm.tick()
        self.assertIn(("key", "Return"), inj.calls)
        self.assertIn("working", emit.states())


class TestCaptcha(unittest.TestCase):
    def test_captcha_prompt_carries_cropped_image(self):
        fsm, inj, emit = make([PageState.CAPTCHA], captcha=b"PNGBYTES")
        fsm.tick()
        prompts = [m for m in emit.msgs if m["type"] == "rh_prompt"]
        self.assertEqual(prompts[0]["step"], "captcha_static")
        import base64
        self.assertEqual(prompts[0]["image"], base64.b64encode(b"PNGBYTES").decode())


class TestError(unittest.TestCase):
    def test_error_terminates_with_message(self):
        fsm, inj, emit = make([PageState.ERROR], err="Wrong password")
        fsm.tick()
        self.assertTrue(fsm.done)
        self.assertEqual(fsm.result, "error")
        self.assertEqual(emit.msgs[-1]["message"], "Wrong password")


class TestIdempotency(unittest.TestCase):
    """Rule #17: re-observing the same page must not double-prompt / double-type."""
    def test_email_prompted_once_across_repeated_ticks(self):
        fsm, inj, emit = make([PageState.EMAIL, PageState.EMAIL, PageState.EMAIL])
        fsm.tick(); fsm.tick(); fsm.tick()
        self.assertEqual(emit.steps(), ["email"])    # exactly one prompt

    def test_buffered_password_injected_once(self):
        fsm, inj, emit = make([PageState.EMAIL, PageState.PASSWORD, PageState.PASSWORD])
        fsm.tick(); fsm.submit("email", {"login": "a", "password": "pw"})
        fsm.tick(); fsm.tick()                       # PASSWORD observed twice
        self.assertEqual(inj.calls.count(("type", "pw")), 1)  # injected once only

    def test_tick_after_done_is_noop(self):
        fsm, inj, emit = make([PageState.SUCCESS, PageState.EMAIL])
        fsm.tick()                                   # SUCCESS → done
        before = len(emit.msgs)
        fsm.tick()                                   # must not process EMAIL
        self.assertEqual(len(emit.msgs), before)
        self.assertEqual(emit.steps(), [])


class TestUnknownWaits(unittest.TestCase):
    def test_unknown_then_email(self):
        fsm, inj, emit = make([PageState.UNKNOWN, PageState.EMAIL, PageState.SUCCESS])
        fsm.tick()                                   # UNKNOWN → no-op
        self.assertEqual(emit.msgs, [])
        fsm.tick()                                   # EMAIL → prompt
        self.assertEqual(emit.steps(), ["email"])


if __name__ == "__main__":
    unittest.main()
