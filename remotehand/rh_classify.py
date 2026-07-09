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
