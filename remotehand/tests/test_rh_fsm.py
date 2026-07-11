import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from rh_protocol import PageState  # noqa: E402
from rh_input import RecordingInjector  # noqa: E402
from rh_screen import ScriptedObserver  # noqa: E402
from rh_fsm import RemoteHandFSM, _UNKNOWN_STALL_TICKS, _ERROR_CONFIRM_TICKS  # noqa: E402


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
        self.assertEqual(emit.steps(), ["email", "password"])  # email shown at startup (instant form)
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
        self.assertEqual(emit.steps(), ["email", "phone", "sms_code"])  # email shown at startup
        self.assertEqual(fsm.result, "success")
        self.assertIn(("type", "+48123"), inj.calls)
        self.assertIn(("type", "998877"), inj.calls)


class TestConsentAutoAccept(unittest.TestCase):
    def test_consent_clicks_located_button(self):
        obs = ScriptedObserver([PageState.CONSENT, PageState.SUCCESS], locate=(947, 863))
        inj = RecordingInjector()
        emit = RecordingEmitter()
        fsm = RemoteHandFSM("s1", obs, inj, emit)
        fsm.tick()
        self.assertIn(("click", 947, 863, 1), inj.calls)  # clicked the 'Continue' button
        self.assertIn("working", emit.states())

    def test_consent_falls_back_to_return_when_button_not_found(self):
        fsm, inj, emit = make([PageState.CONSENT, PageState.SUCCESS])  # locate=None
        fsm.tick()
        self.assertIn(("key", "Return"), inj.calls)


class TestCaptcha(unittest.TestCase):
    def test_captcha_prompt_carries_cropped_image(self):
        fsm, inj, emit = make([PageState.CAPTCHA], captcha=b"PNGBYTES")
        fsm.tick()
        cap = [m for m in emit.msgs if m["type"] == "rh_prompt" and m["step"] == "captcha_static"][0]
        import base64
        self.assertEqual(cap["image"], base64.b64encode(b"PNGBYTES").decode())


class TestError(unittest.TestCase):
    def test_terminal_error_terminates(self):
        fsm, inj, emit = make([PageState.ERROR], err="Too many failed attempts, try again later")
        fsm.tick()
        self.assertTrue(fsm.done)
        self.assertEqual(fsm.result, "error")
        self.assertEqual(emit.msgs[-1]["type"], "rh_state")
        self.assertEqual(emit.msgs[-1]["state"], "error")

    def test_wrong_password_reprompts_not_terminal(self):
        fsm, inj, emit = make([PageState.ERROR], err="Wrong password. Try again")
        fsm.tick()
        self.assertFalse(fsm.done)                       # recoverable — not terminal
        prompts = [m for m in emit.msgs if m["type"] == "rh_prompt"]
        self.assertEqual(prompts[-1]["step"], "password")
        self.assertIn("password", prompts[-1]["title"].lower())

    def test_error_latched_once_until_resubmit(self):
        # Same error observed repeatedly must re-prompt only once (no spam).
        fsm, inj, emit = make([PageState.ERROR, PageState.ERROR, PageState.ERROR], err="Wrong password")
        fsm.tick(); fsm.tick(); fsm.tick()
        warnings = [m for m in emit.msgs if m["type"] == "rh_prompt" and m.get("level") == "warning"]
        self.assertEqual(len(warnings), 1)           # exactly one re-prompt despite 3 error ticks
        # After the user re-submits, a fresh error may re-prompt again
        fsm.submit("password", {"password": "again"})
        fsm.tick()
        self.assertGreaterEqual(len([m for m in emit.msgs if m["type"] == "rh_prompt" and m.get("level") == "warning"]), 2)

    def test_wrong_code_reprompts_code(self):
        fsm, inj, emit = make([PageState.ERROR], err="Wrong code, enter it again")
        fsm.tick()
        prompts = [m for m in emit.msgs if m["type"] == "rh_prompt"]
        self.assertEqual(prompts[-1]["step"], "sms_code")

    def test_no_account_reprompts_login_and_replaces_google_field(self):
        fsm, inj, emit = make([PageState.ERROR], err="Couldnt find his account")
        fsm.tick()
        prompts = [m for m in emit.msgs if m["type"] == "rh_prompt"]
        self.assertEqual(prompts[-1]["step"], "email")
        self.assertEqual(prompts[-1]["level"], "warning")
        fsm.submit("email", {"login": "correct@example.com", "password": "pw"})
        self.assertEqual(inj.calls[:3], [("key", "ctrl+a"), ("type", "correct@example.com"), ("key", "Return")])


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
        fsm.tick()                                   # startup email prompt, then SUCCESS → done
        before = len(emit.msgs)
        fsm.tick()                                   # must not process EMAIL
        self.assertEqual(len(emit.msgs), before)     # no new messages after done
        self.assertEqual(emit.steps(), ["email"])    # only the startup email prompt, never re-emitted


class TestUnknownWaits(unittest.TestCase):
    def test_unknown_then_email(self):
        fsm, inj, emit = make([PageState.UNKNOWN, PageState.EMAIL, PageState.SUCCESS])
        fsm.tick()                                   # startup email prompt; UNKNOWN → no further action
        self.assertEqual(emit.steps(), ["email"])    # instant form: email shown before the page loads
        no_stall = [m for m in emit.msgs if "Google shows" in str(m.get("message", ""))]
        self.assertEqual(no_stall, [])               # brief UNKNOWN must not surface a stall message
        fsm.tick()                                   # EMAIL observed → still one email prompt (idempotent)
        self.assertEqual(emit.steps(), ["email"])


class TestUnknownStall(unittest.TestCase):
    """A brief UNKNOWN is loading; a persistent one is an unexpected Google screen —
    never spin forever (Rule: no silent 'known limitation')."""
    def test_brief_unknown_stays_silent(self):
        fsm, inj, emit = make([PageState.UNKNOWN], err="Your session ended because there was no activity")
        for _ in range(_UNKNOWN_STALL_TICKS - 1):     # just below the stall threshold
            fsm.tick()
        surfaced = [m for m in emit.msgs if "Google shows" in str(m.get("message", ""))]
        self.assertEqual(surfaced, [])                # no stall message yet (only the startup email prompt)
        self.assertFalse(fsm.done)

    def test_persistent_unknown_recognized_terminal_ends(self):
        fsm, inj, emit = make([PageState.UNKNOWN], err="Your session ended because there was no activity")
        for _ in range(_UNKNOWN_STALL_TICKS):
            fsm.tick()
        self.assertTrue(fsm.done)
        self.assertEqual(fsm.result, "error")
        self.assertEqual(emit.msgs[-1]["state"], "error")
        self.assertIn("session expired", emit.msgs[-1]["message"].lower())

    def test_persistent_unknown_unrecognized_surfaces_once(self):
        fsm, inj, emit = make([PageState.UNKNOWN], err="Please complete this extra step to continue")
        for _ in range(_UNKNOWN_STALL_TICKS + 3):
            fsm.tick()
        self.assertFalse(fsm.done)                    # unrecognized → surfaced, not terminal
        surfaced = [m for m in emit.msgs if m["type"] == "rh_state" and "Google shows" in m.get("message", "")]
        self.assertEqual(len(surfaced), 1)            # latched — surfaced exactly once
        self.assertIn("extra step", surfaced[0]["message"])

    def test_unknown_counter_resets_on_recognized_page(self):
        # UNKNOWN just under threshold, then a real page, then UNKNOWN again must not fire early.
        states = [PageState.UNKNOWN] * (_UNKNOWN_STALL_TICKS - 1) + [PageState.EMAIL] + [PageState.UNKNOWN] * 2
        fsm, inj, emit = make(states, err="mystery screen")
        for _ in range(len(states)):
            fsm.tick()
        surfaced = [m for m in emit.msgs if m["type"] == "rh_state" and "Google shows" in m.get("message", "")]
        self.assertEqual(surfaced, [])                # reset by EMAIL → never reached threshold again


class TestInstantForm(unittest.TestCase):
    """The email form is shown before Chromium renders; the login is held and injected
    the moment the identifier page appears (user types while the browser loads)."""
    def test_email_prompt_emitted_before_any_page(self):
        fsm, inj, emit = make([PageState.UNKNOWN])
        fsm.tick()                                   # page still loading
        self.assertEqual(emit.steps(), ["email"])    # form already shown

    def test_login_buffered_while_loading_then_injected_on_email(self):
        fsm, inj, emit = make([PageState.UNKNOWN, PageState.EMAIL, PageState.PASSWORD])
        fsm.tick()                                   # UNKNOWN (loading) — email prompt shown
        fsm.submit("email", {"login": "user@x.com", "password": "pw"})  # user typed early
        self.assertNotIn(("type", "user@x.com"), inj.calls)  # NOT injected yet (page not ready)
        fsm.tick()                                   # EMAIL appears → inject buffered login
        self.assertIn(("type", "user@x.com"), inj.calls)
        self.assertIn(("key", "Return"), inj.calls)

    def test_login_injected_immediately_when_page_already_up(self):
        fsm, inj, emit = make([PageState.EMAIL, PageState.PASSWORD])
        fsm.tick()                                   # EMAIL already observed
        fsm.submit("email", {"login": "a@b.c", "password": "pw"})  # page ready → inject now
        self.assertIn(("type", "a@b.c"), inj.calls)


class TestFieldVerify(unittest.TestCase):
    """Clipboard read-back confirms what actually landed in the visible field before Enter."""
    def _fsm(self, readback):
        obs = ScriptedObserver([PageState.EMAIL, PageState.PASSWORD])
        inj = RecordingInjector(field_readback=readback)
        emit = RecordingEmitter()
        return RemoteHandFSM("s1", obs, inj, emit), inj, emit

    def test_match_submits(self):
        fsm, inj, emit = self._fsm(readback="good@x.com")
        fsm.tick()
        fsm.submit("email", {"login": "good@x.com", "password": "pw"})
        self.assertIn(("key", "Return"), inj.calls)  # verified → submitted

    def test_mismatch_reprompts_and_does_not_submit(self):
        fsm, inj, emit = self._fsm(readback="garbled")  # field never holds what we typed
        fsm.tick()
        fsm.submit("email", {"login": "good@x.com", "password": "pw"})
        self.assertNotIn(("key", "Return"), inj.calls)          # never submitted the wrong value
        warn = [m for m in emit.msgs if m["type"] == "rh_prompt" and m.get("level") == "warning"]
        self.assertEqual(warn[-1]["step"], "email")
        self.assertIn("garbled", warn[-1]["title"])             # precise: shows what the form received

    def test_blocked_readback_proceeds(self):
        # Password fields (and any blocked copy) read back '' → unverifiable → best-effort submit.
        fsm, inj, emit = self._fsm(readback="")
        fsm.tick()
        fsm.submit("email", {"login": "good@x.com", "password": "pw"})
        self.assertIn(("key", "Return"), inj.calls)


class TestTransientErrorNotTerminal(unittest.TestCase):
    """A single garbled OCR frame classified ERROR must not kill a valid flow; an
    unrecognized error only terminates if it persists, and then reports the real text."""
    def test_single_unrecognized_error_frame_does_not_terminate(self):
        # ERROR once (unrecognized), then the page settles to PASSWORD → must continue.
        fsm, inj, emit = make([PageState.ERROR, PageState.PASSWORD, PageState.SUCCESS],
                              err="garbled ocr noise xyz")
        fsm.tick()                                   # transient ERROR → wait, don't die
        self.assertFalse(fsm.done)
        fsm.tick(); fsm.tick()                       # PASSWORD → SUCCESS
        self.assertEqual(fsm.result, "success")

    def test_persistent_unrecognized_error_terminates_with_snippet(self):
        fsm, inj, emit = make([PageState.ERROR] * (_ERROR_CONFIRM_TICKS + 1),
                              err="Something weird happened on Google")
        for _ in range(_ERROR_CONFIRM_TICKS + 1):
            fsm.tick()
        self.assertTrue(fsm.done)
        self.assertEqual(fsm.result, "error")
        last = emit.msgs[-1]
        self.assertEqual(last["state"], "error")
        self.assertIn("Something weird happened", last["message"])  # real page text, not opaque


if __name__ == "__main__":
    unittest.main()
