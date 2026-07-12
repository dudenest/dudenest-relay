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

from rh_protocol import PageState
from rh_catalog import classify as _catalog_classify, classify_error as _catalog_classify_error, norm as _norm


def classify_text(text: str) -> PageState:
    """Classify already-OCR'd text via the declarative screen catalog (rh_catalog)."""
    return _catalog_classify(text)


def classify_error(text: str) -> tuple[str | None, str]:
    """Map an error page's text to (field_to_reprompt, message) via the catalog's error rules.

    field is one of login|password|phone|code to re-prompt that field; None = terminal (give up).
    Unknown errors are terminal (safe default — don't loop on an unclassifiable page)."""
    return _catalog_classify_error(text)


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
