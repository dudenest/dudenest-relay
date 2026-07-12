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
    def locate(self, text: str, min_y: int = 0) -> tuple[int, int] | None: ...
    def save_unknown(self) -> str | None: ...


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
        """OCR the current screen so the FSM can classify which error Google shows
        (wrong password/code/phone/account) and re-prompt the offending field."""
        try:
            from rh_classify import ocr_text
            return ocr_text(self.grab())
        except Exception:
            return ""

    def save_unknown(self, directory: str = "/var/lib/dudenest/remotehand/unknown") -> str | None:
        """Persist an unrecognised screen (PNG + OCR text) so it can be reviewed and turned into
        a catalog entry (Phase 2 of the screen-catalog plan). Best-effort; never raises."""
        try:
            import os
            import time
            from rh_classify import ocr_text
            os.makedirs(directory, exist_ok=True)
            png = self.grab()
            base = os.path.join(directory, "unknown-" + time.strftime("%Y%m%d-%H%M%S"))
            with open(base + ".png", "wb") as f:
                f.write(png)
            with open(base + ".txt", "w", encoding="utf-8") as f:
                f.write(ocr_text(png))
            return base + ".png"
        except Exception:
            return None

    def locate(self, text: str, min_y: int = 0) -> tuple[int, int] | None:
        """Find the on-screen center of a word (e.g. a 'Continue'/'Allow' button)
        via OCR word boxes — so the FSM can click buttons Enter can't activate."""
        png = None
        try:
            import io
            import pytesseract
            from PIL import Image
            png = self.grab()
            data = pytesseract.image_to_data(Image.open(io.BytesIO(png)), output_type=pytesseract.Output.DICT)
            target = text.strip().lower()
            matches = []
            for i, word in enumerate(data["text"]):
                if word.strip().lower() == target:
                    y = data["top"][i] + data["height"][i] // 2
                    if y >= min_y:
                        matches.append((data["left"][i] + data["width"][i] // 2, y))
            if matches:
                return sorted(matches, key=lambda p: (p[1], p[0]))[-1]
        except Exception:
            pass
        if text.strip().lower() in ("send", "next", "continue", "allow"):
            return self._locate_blue_primary_button(png, min_y)
        return None

    def _locate_blue_primary_button(self, png: bytes | None, min_y: int = 0) -> tuple[int, int] | None:
        """Fallback for Google's primary button: white text on blue often OCRs as
        nothing (live Send button). Detect the blue rounded rectangle in lower UI."""
        try:
            import io
            from PIL import Image
            img = Image.open(io.BytesIO(png or self.grab())).convert("RGB")
            pts = []
            for y in range(max(min_y, img.height // 2), img.height - 60):
                for x in range(img.width // 3, img.width - 80):
                    r, g, b = img.getpixel((x, y))
                    if 0 <= r <= 110 and 60 <= g <= 180 and 150 <= b <= 255 and b > g + 35 and g > r + 25:
                        pts.append((x, y))
            if not pts:
                return None
            comps = []
            remaining = set(pts)
            while remaining:
                seed = remaining.pop(); stack = [seed]; comp = [seed]
                while stack:
                    x, y = stack.pop()
                    near = [p for p in list(remaining) if abs(p[0] - x) <= 2 and abs(p[1] - y) <= 2]
                    for p in near:
                        remaining.remove(p); stack.append(p); comp.append(p)
                if len(comp) >= 20:
                    xs, ys = [p[0] for p in comp], [p[1] for p in comp]
                    w, h = max(xs) - min(xs) + 1, max(ys) - min(ys) + 1
                    comps.append((len(comp), w, h, min(xs), min(ys), max(xs), max(ys)))
            candidates = [c for c in comps if c[1] >= 30 and c[2] >= 18]
            if not candidates:
                candidates = comps
            if not candidates:
                return None
            _, _, _, x1, y1, x2, y2 = sorted(candidates, key=lambda c: (c[6], c[5], c[0]))[-1]
            return ((x1 + x2) // 2, (y1 + y2) // 2)
        except Exception:
            return None


def crop_region(png: bytes, region: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    """Return the tight bbox (x,y,w,h) to crop to — §8.1 no empty padding.

    Faza 0 passthrough (OpenCV locate lands in Faza 1). Kept as a seam so the
    'tight crop' requirement is a first-class, testable contract from day 1."""
    return region


class ScriptedObserver:
    """Test double — yields a scripted sequence of PageStates, one per observe()."""
    def __init__(self, states: list[PageState], captcha: bytes | None = None, err: str = "",
                 locate: tuple[int, int] | None = None):
        self._states = list(states)
        self._captcha = captcha
        self._err = err
        self._locate = locate
        self._i = 0
        self.saved_unknown = 0

    def observe(self) -> PageState:
        st = self._states[min(self._i, len(self._states) - 1)]
        self._i += 1
        return st

    def capture_captcha(self) -> bytes | None: return self._captcha
    def error_text(self) -> str: return self._err
    def locate(self, text: str, min_y: int = 0) -> tuple[int, int] | None: return self._locate
    def save_unknown(self, directory=None) -> str | None: self.saved_unknown += 1; return None
