"""Vanilla Chromium launcher (CDP-free) — the exact flags validated in Faza 0/1.

Deliberately NO automation flags: no --remote-debugging-port, no --headless, no
DevTools. Only page-invisible flags: --no-sandbox (root), isolated --user-data-dir,
window geometry, --disable-infobars/--disable-extensions. To Google this is an
ordinary desktop browser (Faza 1 confirmed navigator.webdriver=false on real Google).
"""
from __future__ import annotations
import os
import subprocess


def build_command(url: str, profile_dir: str, window: str = "1280,1024") -> list[str]:
    return [
        "chromium", "--no-sandbox", "--disable-dev-shm-usage", "--disable-infobars",
        "--disable-extensions", "--disable-blink-features=AutomationControlled",
        "--user-data-dir=" + profile_dir, "--window-size=" + window,
        "--window-position=0,0", "--new-window", url,
    ]


def launch(url: str, display: str, profile_dir: str) -> subprocess.Popen:
    """Start a vanilla Chromium on DISPLAY, navigated to the OAuth URL."""
    return subprocess.Popen(
        build_command(url, profile_dir),
        env={**os.environ, "DISPLAY": display},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
