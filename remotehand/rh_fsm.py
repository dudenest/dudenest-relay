"""Remote-Hand state machine — drives a login flow CDP-free.

Loop: observe (visual) → classify PageState → emit dynamic-form prompt to Flutter
→ receive user input → inject via XTEST → advance. Handles the scenario from
RELAY-REMOTE-HAND-PLAN.md §7: email+password up front, then 2FA phone/SMS and
captcha surface as fields that appear smoothly without a screen change.

The FSM depends only on abstract Observer/Injector/Emitter, so it is fully
unit-testable without an X server, a browser, or a network (Rule #17).
"""
from __future__ import annotations
from typing import Protocol

from rh_classify import classify_error
from rh_protocol import Field, PageState, rh_prompt, rh_state


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
        self.done = False
        self.result: str | None = None
        self.last_state = PageState.UNKNOWN

    # ---- public API ----
    def tick(self) -> PageState:
        """One observe→act cycle. Idempotent per page state (no double-prompt)."""
        if self.done:
            return self.last_state
        st = self._obs.observe()
        self.last_state = st
        {
            PageState.EMAIL: self._on_email, PageState.PASSWORD: self._on_password,
            PageState.CONSENT: self._on_consent, PageState.PHONE: self._on_phone,
            PageState.SMS: self._on_sms, PageState.CAPTCHA: self._on_captcha,
            PageState.SUCCESS: self._on_success, PageState.ERROR: self._on_error,
        }.get(st, self._on_unknown)()
        return st

    def submit(self, step: str, values: dict[str, str]) -> None:
        """Feed user input from Flutter (secrets already decrypted by caller)."""
        self._error_shown = False  # user is responding → next error page may re-prompt again
        if step == "email":
            self._buffered["password"] = values.get("password", "")  # keep for password page
            self._type_and_next(values.get("login", ""))
            self._state("working", "submitting email")
        elif step == "password":
            self._type_and_next(values.get("password") or self._buffered.get("password", ""))
            self._state("working", "submitting password")
        elif step == "phone":
            self._type_and_next(values.get("phone", ""))
            self._state("working", "submitting phone")
        elif step == "sms_code":
            self._type_and_next(values.get("code", ""))
            self._state("working", "submitting code")

    # ---- per-state handlers ----
    def _on_email(self) -> None:  # scenario §7 step 2: ask login + password together
        self._prompt_once("email", "Sign in", [
            Field("login", "Login / e-mail", "text"),
            Field("password", "Password", "password"),
        ])

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
        self._error_shown = True
        field, msg = classify_error(self._obs.error_text())
        if field is None:  # terminal — give up
            self.done = True
            self.result = "error"
            self._state("error", msg)
            return
        self._reprompt(field, msg)  # recoverable — let the user correct the offending field

    def _reprompt(self, field: str, msg: str) -> None:
        step, specs = self._REPROMPT[field]
        self._buffered.pop("password", None)       # drop stale secret
        self._prompted.discard("password_injected")  # allow a fresh password inject
        self._prompted.add(step)                     # don't let _on_<state> double-handle
        self._emit.send(rh_prompt(self.session_id, self.request_id, step, msg,
                                  [Field(n, l, k) for (n, l, k) in specs]))

    def _on_unknown(self) -> None:
        pass  # transient/loading — re-observe on next tick

    # ---- helpers ----
    def _type_and_next(self, text: str) -> None:
        self._inj.type_text(text)
        self._inj.press_key("Return")

    def _prompt_once(self, step: str, title: str, fields: list[Field]) -> None:
        if step in self._prompted:
            return
        self._prompted.add(step)
        self._emit.send(rh_prompt(self.session_id, self.request_id, step, title, fields))

    def _state(self, state: str, message: str) -> None:
        self._emit.send(rh_state(self.session_id, self.request_id, state, message))
