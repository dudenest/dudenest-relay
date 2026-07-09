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


class RecordingInjector:
    """Test double — records calls, injects nothing. Used by unit tests."""
    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def type_text(self, text: str) -> None: self.calls.append(("type", text))
    def press_key(self, key: str) -> None: self.calls.append(("key", key))
    def click(self, x: int, y: int, button: int = 1) -> None: self.calls.append(("click", x, y, button))
    def move(self, x: int, y: int) -> None: self.calls.append(("move", x, y))
