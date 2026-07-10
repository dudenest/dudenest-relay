"""Visual page classifier (CDP-free) — Tesseract OCR + phrase rules.

Maps a screenshot of the Google login page to a `PageState` by OCR-ing the visible
text and matching signature phrases. NO DOM, NO CDP — the only thing we read is
the framebuffer, so the browser stays a vanilla, un-hooked session.

Why OCR (not template matching) as primary: the *text* on screen ("Enter your
password", "Couldn't find your Google Account", "2-Step Verification") is the most
reliable, layout-independent signal of which step we're on. Template matching is a
secondary aid for locating buttons — but the main flow relies on Google's autofocus
+ Enter (proven in Faza 0 e2e), so pixel coordinates aren't needed for email/password.

Locale: English signatures. Other locales = extension (add phrases per language);
in production the relay can force `hl=en` on the OAuth URL for determinism.
"""
from __future__ import annotations
import re

from rh_protocol import PageState

# Ordered: specific/terminal states first, generic (email) last. First match wins.
# Patterns are regexes matched against lowercased OCR text.
_RULES: list[tuple[PageState, list[str]]] = [
    (PageState.ERROR, [
        r"couldn.?t find your (google )?account",
        r"wrong password",
        r"too many failed",
        r"account (disabled|has been disabled)",
        r"couldn.?t sign you in",
    ]),
    (PageState.SMS, [
        r"enter the code",
        r"g-\s?\d{2,}",
        r"2-step verification.*code",
        r"enter (the )?verification code",
        r"code (we )?(texted|sent) (you|to)",
    ]),
    (PageState.PHONE, [
        r"enter (a )?phone number",
        r"get a verification code",
        r"confirm your (recovery )?phone",
        r"a phone number where you can",
    ]),
    (PageState.CAPTCHA, [
        r"i.?m not a robot",
        r"type the (text|characters|letters)",
        r"verify you.?re (a human|not a robot)",
        r"select all (images|squares)",
    ]),
    (PageState.CONSENT, [
        r"wants (to )?access (to )?your google account",
        r"wants to access your",
        r"by continuing, google will share",
        r"^allow$",
    ]),
    (PageState.PASSWORD, [
        r"enter your password",
        r"hi\b.*\benter your password",
    ]),
    (PageState.EMAIL, [
        r"email or phone",
        r"use your google account",
        r"forgot email",
        r"sign in\b(?!.*password)",
    ]),
]


def classify_text(text: str) -> PageState:
    """Classify already-OCR'd text. Pure function — the unit-tested core."""
    t = text.lower()
    for state, patterns in _RULES:
        if any(re.search(p, t) for p in patterns):
            return state
    return PageState.UNKNOWN


# Error subclassification: which field to re-prompt (or None = terminal), + message.
# Ordered: specific field errors first, terminal last.
_ERROR_MAP: list[tuple[str | None, str, list[str]]] = [
    ("password", "Wrong password — try again",
     [r"wrong password", r"password (was )?incorrect", r"the password you entered is incorrect"]),
    ("code", "Wrong code — check the SMS and re-enter",
     [r"wrong code", r"incorrect code", r"invalid code", r"code (is )?(wrong|incorrect|invalid)",
      r"that code didn.?t work", r"enter a valid code"]),
    ("phone", "Couldn't verify that number — check it (with country code)",
     [r"couldn.?t verify (your )?phone", r"invalid phone", r"enter a valid phone",
      r"this phone number cannot be used", r"wrong number"]),
    ("login", "Couldn't find that account — check the email",
     [r"couldn.?t find your (google )?account"]),
    (None, "Too many attempts — try again later",
     [r"too many failed", r"too many attempts", r"try again later"]),
    (None, "This account is unavailable",
     [r"account (disabled|has been disabled)", r"couldn.?t sign you in"]),
]


def classify_error(text: str) -> tuple[str | None, str]:
    """Map an error page's text to (field_to_reprompt, message).

    field is one of login|password|phone|code to re-prompt that field so the user
    can correct their input; None means a terminal error (give up). Unknown errors
    are treated as terminal (safe default — don't loop on an unclassifiable page)."""
    t = text.lower()
    for field, msg, patterns in _ERROR_MAP:
        if any(re.search(p, t) for p in patterns):
            return field, msg
    return None, "Sign-in failed"


def ocr_text(png: bytes) -> str:
    """OCR a PNG via Tesseract (lazy import so tests need no deps/binaries)."""
    import io
    import pytesseract
    from PIL import Image
    return pytesseract.image_to_string(Image.open(io.BytesIO(png)))


def classify_image(png: bytes, ocr=None) -> PageState:
    """Classify a screenshot. `ocr` injectable for tests (default = Tesseract)."""
    return classify_text((ocr or ocr_text)(png))


def make_classifier(ocr=None):
    """Return a callable(png)->PageState for ScrotObserver(classifier=...)."""
    return lambda png: classify_image(png, ocr=ocr)
