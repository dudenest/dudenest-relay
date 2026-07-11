"""OS-level input injection (X11 XTEST via xdotool) — CDP-free, undetectable.

xdotool injects through XTEST, so events arrive at Chromium with
`isTrusted=true` — indistinguishable from a physical keyboard/mouse (verified
empirically, Faza 0 spike). No CDP, no navigator.webdriver, no browser hook.

Typing is humanized (randomized inter-key delay) so behavioral timing looks
human — the only residual detection vector once the browser hook is gone.

Later migration target: go-vgo/robotgo (also XTEST, same isTrusted) as a Go
sidecar if we consolidate to Go — see RELAY-REMOTE-HAND-PLAN.md §5.1.
"""
from __future__ import annotations
import os
import random
import subprocess
import time
from typing import Protocol


class Injector(Protocol):
    """Abstract input sink so the FSM is testable without a real X server."""
    def type_text(self, text: str) -> None: ...
    def press_key(self, key: str) -> None: ...
    def click(self, x: int, y: int, button: int = 1) -> None: ...
    def move(self, x: int, y: int) -> None: ...
    def read_field(self) -> str: ...


class XdotoolInjector:
    """Real injection on DISPLAY=:N via xdotool (XTEST)."""
    def __init__(self, display: str = ":99", key_delay_ms: tuple[int, int] = (55, 130)):
        self._display = display
        self._lo, self._hi = key_delay_ms

    def _run(self, *args: str) -> None:
        subprocess.run(["xdotool", *args], check=True,
                       env={**os.environ, "DISPLAY": self._display}, capture_output=True)

    def type_text(self, text: str) -> None:  # per-char humanized delay
        for ch in text:
            self._run("type", "--clearmodifiers", "--delay", "0", ch)
            time.sleep(random.uniform(self._lo, self._hi) / 1000.0)

    def press_key(self, key: str) -> None:
        self._run("key", "--clearmodifiers", key)
        time.sleep(random.uniform(self._lo, self._hi) / 1000.0)

    def move(self, x: int, y: int) -> None:
        self._run("mousemove", str(x), str(y))
        time.sleep(random.uniform(0.04, 0.14))

    def click(self, x: int, y: int, button: int = 1) -> None:
        self.move(x, y)
        self._run("click", str(button))
        time.sleep(random.uniform(self._lo, self._hi) / 1000.0)

    def _clip(self, *args: str, data: bytes | None = None) -> bytes:
        return subprocess.run(["xclip", "-selection", "clipboard", *args], input=data,
                              env={**os.environ, "DISPLAY": self._display},
                              check=False, capture_output=True).stdout

    def read_field(self) -> str:
        """Select-all + copy the focused field and return the clipboard text — the
        deterministic way to confirm what actually landed in the Google form before we
        press Enter (OCR is too noisy to trust for this). Returns '' when the browser
        blocks copy (type=password) — the caller treats '' as 'unverifiable', not 'empty'."""
        try:
            self._clip(data=b"")            # clear stale clipboard so a blocked copy reads ''
            self.press_key("ctrl+a"); self.press_key("ctrl+c")
            time.sleep(0.15)
            text = self._clip("-o").decode("utf-8", "replace")
        except FileNotFoundError:            # xclip not installed → cannot verify
            return ""
        self._run("key", "--clearmodifiers", "End")  # deselect (cursor to end) before the caller hits Enter
        return text


class RecordingInjector:
    """Test double — records calls, injects nothing. Used by unit tests.

    read_field() echoes the last typed text by default (so verification passes on the
    happy path) and does NOT record calls; pass field_readback to force a value and
    exercise the mismatch path."""
    def __init__(self, field_readback: str | None = None) -> None:
        self.calls: list[tuple] = []
        self._last_type = ""
        self._readback = field_readback

    def type_text(self, text: str) -> None: self.calls.append(("type", text)); self._last_type = text
    def press_key(self, key: str) -> None: self.calls.append(("key", key))
    def click(self, x: int, y: int, button: int = 1) -> None: self.calls.append(("click", x, y, button))
    def move(self, x: int, y: int) -> None: self.calls.append(("move", x, y))
    def read_field(self) -> str: return self._readback if self._readback is not None else self._last_type
