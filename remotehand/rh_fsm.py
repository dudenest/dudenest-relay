"""Remote-Hand state machine — drives a login flow CDP-free.

Loop: observe (visual) → classify PageState → emit dynamic-form prompt to Flutter
→ receive user input → inject via XTEST → advance. Handles the scenario from
RELAY-REMOTE-HAND-PLAN.md §7: email+password up front, then 2FA phone/SMS and
captcha surface as fields that appear smoothly without a screen change.

The FSM depends only on abstract Observer/Injector/Emitter, so it is fully
unit-testable without an X server, a browser, or a network (Rule #17).
"""
from __future__ import annotations
import re
import sys
from typing import Protocol

from rh_classify import classify_error
from rh_protocol import Field, PageState, rh_prompt, rh_state


_UNKNOWN_STALL_TICKS = 10  # ~8s at 0.8s/tick before treating a stuck UNKNOWN as an unexpected screen
_ERROR_CONFIRM_TICKS = 3   # an UNRECOGNIZED error must persist this many observations before we give up
                           # (a single garbled OCR frame on a loading page must not kill the flow)

# OCR boilerplate to drop from the on-screen snippet we surface to Flutter (browser chrome,
# the --no-sandbox warning, bookmarks bar, footer) so the user sees the meaningful text.
_SNIPPET_NOISE = re.compile(
    r"(?i)you are using an unsupported command-line flag|--?no.?sandbox|"
    r"stability and security will suffer|debian\.org|latest news|"
    r"english \(united states\)|privacy terms|show password|forgot (email|password)")


def _screen_snippet(text: str, limit: int = 160) -> str:
    """Condense raw OCR into a short human-readable snippet for Flutter: drop the URL bar,
    browser chrome and known boilerplate, collapse whitespace, cap length."""
    keep = []
    for line in (text or "").splitlines():
        s = line.strip()
        if not s or s.startswith(("%", "http", "accounts.google.com")) or _SNIPPET_NOISE.search(s):
            continue
        keep.append(s)
    return " ".join(" ".join(keep).split())[:limit]


def _log(msg: str) -> None:
    sys.stderr.write(f"rh_fsm: {msg}\n"); sys.stderr.flush()


class Emitter(Protocol):
    """Sink for messages to Flutter (real = ws.Hub; test = recorder)."""
    def send(self, msg: dict) -> None: ...


class RemoteHandFSM:
    def __init__(self, session_id: str, observer, injector, emitter: Emitter,
                 request_id: str = "rh"):
        self.session_id = session_id
        self.request_id = request_id
        self._obs = observer
        self._inj = injector
        self._emit = emitter
        self._buffered: dict[str, str] = {}   # e.g. password held until PASSWORD page
        self._prompted: set[str] = set()       # steps already prompted/handled (idempotency)
        self._error_shown = False              # latch: one re-prompt per error, until user responds
        self._replace_next = False             # after Google field error, Ctrl+A before typing correction
        self._unknown_ticks = 0                # consecutive UNKNOWN observations (stall detection)
        self._unknown_surfaced = False         # latch: surface an unrecognized screen only once
        self._error_streak = 0                 # consecutive UNRECOGNIZED error observations (noise filter)
        self._started = False                  # instant-form: email prompt emitted before the browser renders
        self.done = False
        self.result: str | None = None
        self.last_state = PageState.UNKNOWN

    # ---- public API ----
    def tick(self) -> PageState:
        """One observe→act cycle. Idempotent per page state (no double-prompt)."""
        if self.done:
            return self.last_state
        if not self._started:  # instant form: show the email form at once — the first OAuth page
            self._started = True  # is always the identifier page, so the user types while Chromium loads
            self._prompt_email_once()
        st = self._obs.observe()
        self.last_state = st
        if st is not PageState.UNKNOWN:  # a recognized page resets stall detection
            self._unknown_ticks = 0
            self._unknown_surfaced = False
        if st is not PageState.ERROR:    # a non-error observation clears the unrecognized-error streak
            self._error_streak = 0
        {
            PageState.EMAIL: self._on_email, PageState.PASSWORD: self._on_password,
            PageState.CONSENT: self._on_consent, PageState.PHONE: self._on_phone,
            PageState.SEND_CODE: self._on_send_code, PageState.SMS: self._on_sms, PageState.CAPTCHA: self._on_captcha,
            PageState.SUCCESS: self._on_success, PageState.ERROR: self._on_error,
        }.get(st, self._on_unknown)()
        return st

    def submit(self, step: str, values: dict[str, str]) -> None:
        """Feed user input from Flutter (secrets already decrypted by caller)."""
        self._error_shown = False  # user is responding → next error page may re-prompt again
        if step == "email":
            self._buffered["password"] = values.get("password", "")  # keep for password page
            login = values.get("login", "")
            if self.last_state is PageState.UNKNOWN and not self._replace_next:
                # Instant form: the page is still loading (user typed before Chromium rendered).
                # Hold the login; _on_email injects it the moment the identifier page appears.
                self._buffered["login"] = login
                self._state("working", "waiting for the sign-in page")
            else:  # page ready (or correcting after an error) → inject + verify now
                self._type_and_next(login, replace=self._replace_next, verify_field="login")
                self._state("working", "submitting email")
        elif step == "password":
            self._type_and_next(values.get("password") or self._buffered.get("password", ""), replace=self._replace_next)
            self._state("working", "submitting password")
        elif step == "phone":
            self._type_and_next(values.get("phone", ""), replace=self._replace_next, verify_field="phone")
            self._state("working", "submitting phone")
        elif step == "send_code":
            if self._click_send_code():
                self._state("working", "asking Google to send the verification code")
        elif step == "sms_code":
            self._type_and_next(values.get("code", ""), replace=self._replace_next, verify_field="code")
            self._state("working", "submitting code")
        self._replace_next = False

    # ---- per-state handlers ----
    def _prompt_email_once(self) -> None:  # scenario §7 step 2: ask login + password together
        self._prompt_once("email", "Sign in", [
            Field("login", "Login / e-mail", "text"),
            Field("password", "Password", "password"),
        ])

    def _on_email(self) -> None:
        self._prompt_email_once()  # normally already shown at startup (instant form) — no-op here
        # Instant-form path: the user submitted before the page loaded, so the login was
        # buffered — inject it now that the identifier page is actually up (+ verify).
        if self._buffered.get("login") and "login_injected" not in self._prompted:
            self._prompted.add("login_injected")
            login = self._buffered.pop("login")
            self._type_and_next(login, verify_field="login")  # fresh empty field — no replace
            self._state("working", "submitting email")

    def _on_password(self) -> None:
        if self._buffered.get("password"):  # user gave it up front → auto-inject
            if "password_injected" not in self._prompted:
                self._prompted.add("password_injected")
                self._type_and_next(self._buffered["password"])
                self._buffered["password"] = ""  # zeroize buffer after use
                self._state("working", "submitting password")
        else:  # not provided earlier → ask now
            self._prompt_once("password", "Enter your password",
                              [Field("password", "Password", "password")])

    def _on_consent(self) -> None:  # auto-accept the OAuth consent screen
        if "consent" not in self._prompted:
            self._prompted.add("consent")
            # Enter does NOT activate Google's consent button (it isn't focused) —
            # locate "Continue"/"Allow" via OCR and click it (Faza 2 fix).
            pos = self._obs.locate("Continue") or self._obs.locate("Allow")
            if pos is not None:
                self._inj.click(*pos)
            else:
                self._inj.press_key("Return")  # fallback if the button text isn't found
            self._state("working", "accepting consent")

    def _on_phone(self) -> None:
        self._prompt_once("phone", "Verify it's you",
                          [Field("phone", "Phone number", "tel")])

    def _on_send_code(self) -> None:
        if "send_code" in self._prompted:
            return
        self._prompted.add("send_code")
        detail = self._send_code_detail()
        title = "Google will send a verification code"
        if detail:
            title = f"Google will send a verification code to {detail}"
        self._emit.send(rh_prompt(self.session_id, self.request_id, "send_code", title, []))

    def _click_send_code(self) -> bool:
        # The page has no input field. It asks permission to send an SMS to a known,
        # masked number. Some variants don't expose a visible 'Send' button in OCR;
        # the selectable row is 'Get a verification code'. NEVER fallback Tab+Return
        # here — it opened Google's Help link in live test.
        pos = self._obs.locate("Send", min_y=720) or self._obs.locate("Next", min_y=720)
        if pos is not None:
            self._inj.click(*pos); return True
        row = self._obs.locate("Get", min_y=500)
        if row is not None:
            self._inj.click(row[0] + 180, row[1] + 8); return True  # center of 'Get a verification code' option row
        self._state("error", "Could not find Google's verification-code button")
        return False

    def _send_code_detail(self) -> str:
        raw = self._obs.error_text() or ""
        text = " ".join(raw.split())
        m = re.search(r"google will send (?:a )?verification code to (.+?)(?:\. standard| standard| message and data|$)", text, re.I)
        return (m.group(1).strip(" .") if m else "")[:80]

    def _on_sms(self) -> None:
        self._prompt_once("sms_code", "Enter the code we texted you",
                          [Field("code", "Verification code", "code")])

    def _on_captcha(self) -> None:  # §8.1 tightly-cropped challenge image
        if "captcha" not in self._prompted:
            self._prompted.add("captcha")
            import base64
            img = self._obs.capture_captcha()
            b64 = base64.b64encode(img).decode() if img else None
            self._emit.send(rh_prompt(self.session_id, self.request_id, "captcha_static",
                                      "Solve the challenge",
                                      [Field("captcha", "Type what you see", "captcha_image")],
                                      image_b64=b64))

    def _on_success(self) -> None:
        self.done = True; self.result = "success"
        self._state("success", "login complete")

    # field → (step, [(name,label,kind), ...]) for re-prompting a mistyped value
    _REPROMPT = {
        "login": ("email", [("login", "Login / e-mail", "text"), ("password", "Password", "password")]),
        "password": ("password", [("password", "Password", "password")]),
        "phone": ("phone", [("phone", "Phone number", "tel")]),
        "code": ("sms_code", [("code", "Verification code", "code")]),
    }

    def _on_error(self) -> None:
        if self._error_shown:
            return  # already surfaced this error; the page still shows it — wait for the user
        err_text = self._obs.error_text()
        field, msg = classify_error(err_text)
        if field is not None:  # recognized recoverable error → re-prompt the offending field now
            self._error_shown = True
            _log(f"_on_error recoverable: field={field!r} msg={msg!r}")
            self._reprompt(field, msg)
            return
        if msg != "Sign-in failed":  # recognized terminal (session expired / too many / disabled)
            self._error_shown = True
            _log(f"_on_error terminal: msg={msg!r}")
            self.done = True; self.result = "error"; self._state("error", msg)
            return
        # UNRECOGNIZED error: a single frame is almost always OCR noise on a page that is
        # still settling (a garbled frame must NOT kill the flow — that terminated a valid
        # login on a normal password page). Only give up if it persists, and then tell
        # Flutter exactly what Google is showing instead of an opaque 'Sign-in failed'.
        self._error_streak += 1
        if self._error_streak < _ERROR_CONFIRM_TICKS:
            return  # re-observe; tick() clears the streak the moment a known page appears
        self._error_shown = True
        snippet = _screen_snippet(err_text)
        _log(f"_on_error unrecognized persisted x{self._error_streak}: {snippet!r}")
        self.done = True; self.result = "error"
        self._state("error", f"Sign-in failed. Google shows: {snippet}" if snippet else "Sign-in failed")

    def _reprompt(self, field: str, msg: str) -> None:
        step, specs = self._REPROMPT[field]
        self._buffered.pop("password", None)       # drop stale secret
        self._buffered.pop("login", None)          # drop stale buffered login
        self._prompted.discard("password_injected")  # allow a fresh password inject
        self._prompted.discard("login_injected")     # allow a fresh (corrected) login inject
        self._prompted.add(step)                     # don't let _on_<state> double-handle
        self._replace_next = True                    # overwrite Google's invalid value on submit
        self._emit.send(rh_prompt(self.session_id, self.request_id, step, msg,
                                  [Field(n, l, k) for (n, l, k) in specs], level="warning"))

    def _on_unknown(self) -> None:
        # A brief UNKNOWN is normal (page loading between steps). But if it persists,
        # Google is likely showing an interstitial we don't have a rule for yet — never
        # spin forever: OCR the screen and either end cleanly (recognized terminal) or
        # surface the on-screen text so the user can act (and we can add a rule later).
        self._unknown_ticks += 1
        if self._unknown_ticks < _UNKNOWN_STALL_TICKS or self._unknown_surfaced:
            return
        self._unknown_surfaced = True
        text = (self._obs.error_text() or "").strip()
        snippet = " ".join(text.split())[:200]
        field, msg = classify_error(text)
        _log(f"_on_unknown stall ({self._unknown_ticks} ticks): text={snippet!r} → field={field!r} msg={msg!r}")
        if text and field is None and msg != "Sign-in failed":  # recognized terminal (e.g. session expired)
            self.done = True
            self.result = "error"
            self._state("error", msg)
        elif snippet:  # unrecognized — show what Google displays instead of a blank spinner
            self._state("working", f"Waiting — Google shows: {snippet}")

    # ---- helpers ----
    def _type_and_next(self, text: str, replace: bool = False, verify_field: str | None = None) -> bool:
        """Type text into the focused Google field and press Enter. When verify_field is
        set (a visible field: login/phone/code), first confirm — via clipboard read-back —
        that the field actually holds what we typed BEFORE submitting; retype once on a
        mismatch, and if it still differs, re-prompt with the precise wrong value instead of
        submitting garbage. Password copy is blocked by the browser (read_field → '') so it
        is intentionally not verified here (its result is checked on the next page)."""
        if replace:
            self._inj.press_key("ctrl+a")
        self._inj.type_text(text)
        if verify_field and text and not self._field_ok(text, verify_field):
            return False  # mismatch surfaced + re-prompted; do NOT submit the wrong value
        # Dismiss Google's autocomplete/passkey popup first — it grabs the Enter key and the
        # form never submits (the clipboard read-back refreshes that popup). Then submit.
        self._inj.press_key("Escape")
        self._inj.press_key("Return")
        return True

    def _field_ok(self, expected: str, field: str) -> bool:
        actual = (self._inj.read_field() or "").strip()
        if not actual or actual == expected.strip():
            return True  # '' = unverifiable (blocked/empty clipboard) → best-effort proceed
        self._inj.press_key("ctrl+a"); self._inj.type_text(expected)  # one corrective retype
        actual = (self._inj.read_field() or "").strip()
        if not actual or actual == expected.strip():
            return True
        _log(f"field {field!r} verify FAILED: expected len={len(expected)} actual={actual!r}")
        self._reprompt(field, f"The form received '{actual[:60]}' — please re-enter")
        return False

    def _prompt_once(self, step: str, title: str, fields: list[Field]) -> None:
        if step in self._prompted:
            return
        self._prompted.add(step)
        self._emit.send(rh_prompt(self.session_id, self.request_id, step, title, fields))

    def _state(self, state: str, message: str) -> None:
        self._emit.send(rh_state(self.session_id, self.request_id, state, message))
