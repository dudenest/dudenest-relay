"""Visual screen reading (CDP-free) — capture + classify page state.

We never touch the DOM (that would require CDP = detectable). Instead we grab
the framebuffer of DISPLAY=:N (scrot) and classify what the login page shows via
template matching / OCR. Faza 0 ships the Observer interface + a scrot capture +
a scripted test double; the real classifier (OpenCV templates + Tesseract) lands
in Faza 1.

Captcha crop (§8.1): the image handed to Flutter MUST be tightly cropped to the
challenge — never most-of-screen-empty with a 10% field. `crop_region` enforces
that here; the bbox comes from OpenCV locate in Faza 1/3.
"""
from __future__ import annotations
import subprocess
from typing import Protocol

from rh_protocol import PageState


class Observer(Protocol):
    """Abstract page-state source so the FSM is testable without a screen."""
    def observe(self) -> PageState: ...
    def capture_captcha(self) -> bytes | None: ...
    def error_text(self) -> str: ...


class ScrotObserver:
    """Real observer: grabs :N and classifies. Faza 0 = capture only; the
    classifier is injected (so Faza 1 can plug OpenCV/OCR without touching FSM)."""
    def __init__(self, display: str = ":99", classifier=None):
        self._display = display
        self._classify = classifier  # callable(png_bytes)->PageState (Faza 1)

    def grab(self, region: tuple[int, int, int, int] | None = None) -> bytes:
        """Full-screen or region PNG of :N (region = x,y,w,h)."""
        args = ["scrot", "-o", "/dev/stdout"]
        if region:
            x, y, w, h = region
            args += ["-a", f"{x},{y},{w},{h}"]
        out = subprocess.run(args, check=True, env={"DISPLAY": self._display},
                             capture_output=True)
        return out.stdout

    def observe(self) -> PageState:
        if self._classify is None:
            return PageState.UNKNOWN  # Faza 0: no classifier yet
        return self._classify(self.grab())

    def capture_captcha(self, region: tuple[int, int, int, int] | None = None) -> bytes | None:
        return self.grab(region) if region else None

    def error_text(self) -> str:
        return ""  # Faza 1: OCR the error node


def crop_region(png: bytes, region: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    """Return the tight bbox (x,y,w,h) to crop to — §8.1 no empty padding.

    Faza 0 passthrough (OpenCV locate lands in Faza 1). Kept as a seam so the
    'tight crop' requirement is a first-class, testable contract from day 1."""
    return region


class ScriptedObserver:
    """Test double — yields a scripted sequence of PageStates, one per observe()."""
    def __init__(self, states: list[PageState], captcha: bytes | None = None, err: str = ""):
        self._states = list(states)
        self._captcha = captcha
        self._err = err
        self._i = 0

    def observe(self) -> PageState:
        st = self._states[min(self._i, len(self._states) - 1)]
        self._i += 1
        return st

    def capture_captcha(self) -> bytes | None: return self._captcha
    def error_text(self) -> str: return self._err
