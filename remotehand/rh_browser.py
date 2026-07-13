"""Vanilla Google Chrome launcher (CDP-free) — B5 anti-abuse hardened.

Deliberately NO automation flags: no --remote-debugging-port, no --headless, no
DevTools. Only page-invisible flags: --no-sandbox (root), isolated --user-data-dir,
window geometry, --disable-infobars/--disable-extensions. To Google this is an
ordinary desktop browser. Open-source Chromium fallback is intentionally disabled for
real-account OAuth because it is a known inconsistent fingerprint.
"""
from __future__ import annotations
import os
import shutil
import subprocess

_SINGLETON_LOCKS = ("SingletonLock", "SingletonCookie", "SingletonSocket")  # stale-lock names Chromium leaves on unclean exit
# B5: REAL Google Chrome only. If missing, fail closed instead of risking Google account locks.
_BROWSER_CANDIDATES = ("dudenest-browser", "google-chrome-stable", "google-chrome")


def chrome_binary() -> str:
    for cand in _BROWSER_CANDIDATES:
        found = shutil.which(cand)
        if found:
            return found
    raise RuntimeError("Google Chrome is required for Remote-Hand OAuth; Chromium fallback is disabled")


def build_command(url: str, profile_dir: str, window: str = "1280,1024", binary: str | None = None) -> list[str]:
    return [
        binary or chrome_binary(), "--no-sandbox", "--disable-dev-shm-usage", "--disable-infobars",
        "--disable-extensions", "--disable-blink-features=AutomationControlled",
        "--user-data-dir=" + profile_dir, "--window-size=" + window,
        "--window-position=0,0", "--new-window", url,
    ]


def prepare_profile(profile_dir: str) -> None:
    """Ready a PERSISTENT --user-data-dir for launch (B4).

    We keep the profile across sessions so cookies + Google's 'trusted device' survive —
    otherwise every sign-in looks like a brand-new device and trips Google's anti-abuse.
    A reused profile from a Chromium that exited uncleanly still holds Singleton* lock
    files that block the next launch; we delete ONLY those locks (never the profile, or we'd
    lose the cookies that make it worth persisting)."""
    os.makedirs(profile_dir, exist_ok=True)
    for name in _SINGLETON_LOCKS:
        try:
            os.unlink(os.path.join(profile_dir, name))
        except OSError:
            pass  # absent lock is the normal (clean-exit) case


def launch(url: str, display: str, profile_dir: str) -> subprocess.Popen:
    """Start Google Chrome on DISPLAY, navigated to the OAuth URL."""
    prepare_profile(profile_dir)
    return subprocess.Popen(
        build_command(url, profile_dir),
        env={**os.environ, "DISPLAY": display},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
