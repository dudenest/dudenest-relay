"""Vanilla Chromium launcher (CDP-free) — the exact flags validated in Faza 0/1.

Deliberately NO automation flags: no --remote-debugging-port, no --headless, no
DevTools. Only page-invisible flags: --no-sandbox (root), isolated --user-data-dir,
window geometry, --disable-infobars/--disable-extensions. To Google this is an
ordinary desktop browser (Faza 1 confirmed navigator.webdriver=false on real Google).
"""
from __future__ import annotations
import os
import shutil
import subprocess

_SINGLETON_LOCKS = ("SingletonLock", "SingletonCookie", "SingletonSocket")  # stale-lock names Chromium leaves on unclean exit
# B5: prefer REAL Google Chrome — its fingerprint (branding, WebGL, media) matches a consumer
# desktop, unlike Chromium which Google can tell apart. Fall back to the chromium symlink so a
# host that only has open-source Chromium still works.
_BROWSER_CANDIDATES = ("google-chrome-stable", "google-chrome", "chromium", "chromium-browser")


def chrome_binary() -> str:
    for cand in _BROWSER_CANDIDATES:
        found = shutil.which(cand)
        if found:
            return found
    return "google-chrome-stable"  # sensible default; install.sh guarantees it on the fleet


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
    """Start a vanilla Chromium on DISPLAY, navigated to the OAuth URL."""
    prepare_profile(profile_dir)
    return subprocess.Popen(
        build_command(url, profile_dir),
        env={**os.environ, "DISPLAY": display},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
