"""Screen catalog — the single declarative source of known Google login screens.

Each `Screen` says how to RECOGNISE a page (regex phrases on OCR'd, whitespace-normalised
text) and — as metadata — what REACTION it needs (`action`). Today the FSM still dispatches
by `PageState`; the catalog centralises detection + documents the reaction so a new screen is a
data entry here (+ a golden test), not scattered edits. See REMOTE-HAND-SCREEN-CATALOG-PLAN.md.

Order matters: specific/terminal screens first, the generic EMAIL 'sign in' last (first match wins).
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field

from rh_protocol import PageState


@dataclass(frozen=True)
class Screen:
    id: str
    state: PageState
    patterns: tuple[str, ...]      # any regex match (on normalised OCR) → this screen
    action: str = ""              # reaction primitive (interpreter/telemetry): auto_click | recaptcha |
    #                               prompt_field | prompt_confirm | terminal | reprompt_or_terminal
    notes: str = ""


# ── The catalog (ordered, first match wins) ─────────────────────────────────────
CATALOG: tuple[Screen, ...] = (
    Screen("callback_success", PageState.SUCCESS,
           (r"authorization complete", r"you can close this (page|window|tab)"),
           action="terminal_success", notes="relay callback page after token capture — end + free display"),
    Screen("login_error", PageState.ERROR,
           (r"couldn.?t find (your|this|his) (google )?account", r"wrong password", r"too many failed",
            r"account (disabled|has been disabled)", r"couldn.?t sign you in",
            r"your session (ended|has expired|expired|timed out)",
            r"session ended because there was no activity", r"you.?ve been signed out"),
           action="reprompt_or_terminal", notes="see ERROR_ENTRIES for the field/message split"),
    Screen("unverified_app", PageState.UNVERIFIED_APP,
           (r"google hasn.?t verified this app", r"hasn.?t verified this app",
            r"continue only if you understand the risks"),
           action="auto_click", notes="Advanced → 'Go to <app> (unsafe)' link"),
    Screen("sms_entry", PageState.SMS,
           (r"enter the code", r"g-\s?\d{2,}", r"enter (the )?verification code",
            r"code (we )?(texted|sent) (you|to)", r"enter (the )?code (we )?(texted|sent)"),
           action="prompt_field:sms_code", notes="NOT 'get a verification code' (that's SEND_CODE/PHONE)"),
    Screen("send_code_known_phone", PageState.SEND_CODE,
           (r"get a verification code.*google will send (a )?verification code to",
            r"google will send (a )?verification code to .{0,80}(standard message|message and data)"),
           action="prompt_confirm", notes="masked known phone; one Continue clicks Send"),
    Screen("phone_entry", PageState.PHONE,
           (r"enter (a )?phone number", r"get a verification code", r"confirm your (recovery )?phone",
            r"a phone number where you can"),
           action="prompt_field:phone"),
    Screen("captcha", PageState.CAPTCHA,
           (r"i.?m not a robot", r"type the (text|characters|letters)",
            r"verify you.?re (a human|not a robot)", r"select all (images|squares)"),
           action="recaptcha", notes="'I'm not a robot' → auto-click; image challenge → prompt user"),
    Screen("consent", PageState.CONSENT,
           (r"wants (to )?access (to )?your google account", r"wants to access your",
            r"by continuing, google will share", r"^allow$"),
           action="auto_click", notes="scroll + click Continue/Allow"),
    Screen("password", PageState.PASSWORD,
           (r"enter your password", r"hi\b.*\benter your password"),
           action="prompt_field:password"),
    Screen("email", PageState.EMAIL,
           (r"email or phone", r"use your google account", r"forgot email", r"sign in\b(?!.*password)"),
           action="prompt_field:email", notes="generic 'sign in' — keep last so specific screens win"),
)


# ── Error sub-classification (error page → which field to re-prompt, or terminal) ─
@dataclass(frozen=True)
class ErrorRule:
    field: str | None             # login|password|phone|code to re-prompt, or None = terminal
    message: str
    patterns: tuple[str, ...]


ERROR_ENTRIES: tuple[ErrorRule, ...] = (
    ErrorRule("password", "Wrong password — try again",
              (r"wrong password", r"password (was )?incorrect", r"the password you entered is incorrect")),
    ErrorRule("code", "Wrong code — check the SMS and re-enter",
              (r"wrong code", r"incorrect code", r"invalid code", r"code (is )?(wrong|incorrect|invalid)",
               r"that code didn.?t work", r"enter a valid code")),
    ErrorRule("phone", "Couldn't verify that number — check it (with country code)",
              (r"couldn.?t verify (your )?phone", r"invalid phone", r"enter a valid phone",
               r"this phone number cannot be used", r"wrong number")),
    ErrorRule("login", "Couldn't find that account — check the email",
              (r"couldn.?t find (your|this|his) (google )?account", r"couldn.?t find .{0,24}account")),
    ErrorRule(None, "Too many attempts — try again later",
              (r"too many failed", r"too many attempts", r"try again later")),
    ErrorRule(None, "This account is unavailable",
              (r"account (disabled|has been disabled)", r"couldn.?t sign you in")),
    ErrorRule(None, "Session expired (idle too long) — please start again",
              (r"your session (ended|has expired|expired|timed out)",
               r"session ended because there was no activity", r"you.?ve been signed out")),
)


def norm(text: str) -> str:
    """Lowercase + collapse ALL whitespace to single spaces so line-wrapped OCR still matches."""
    return " ".join((text or "").lower().split())


def match_screen(text: str) -> Screen | None:
    """Return the first catalog Screen whose patterns match (None = unrecognised)."""
    t = norm(text)
    for s in CATALOG:
        if any(re.search(p, t) for p in s.patterns):
            return s
    return None


def classify(text: str) -> PageState:
    s = match_screen(text)
    return s.state if s is not None else PageState.UNKNOWN


def classify_error(text: str) -> tuple[str | None, str]:
    """Map an error page to (field_to_reprompt|None, message). Unknown = terminal (safe default)."""
    t = norm(text)
    for e in ERROR_ENTRIES:
        if any(re.search(p, t) for p in e.patterns):
            return e.field, e.message
    return None, "Sign-in failed"
