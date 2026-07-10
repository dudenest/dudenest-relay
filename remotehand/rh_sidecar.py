"""Remote-Hand sidecar — one process per login session, driven over stdio.

The relay (Go) spawns this with DISPLAY=:N and bridges its stdout/stdin to the
Flutter ws connection (internal/remotehand/bridge.go). Wire format = one JSON
object per line:

  sidecar → relay → Flutter:  rh_hello / rh_prompt / rh_state   (stdout)
  Flutter → relay → sidecar:  rh_input                          (stdin)

Secrets: `rh_input.sealed` is a NaCl sealed_box (base64) that decrypts to a JSON
object of sensitive field values (e.g. {"password": "..."}). Only this process
holds the private key (rh_crypto.SessionKeys) — the edge never sees plaintext.

Fake mode (env RH_FAKE=1): no X/browser — a gated scripted observer + recording
injector, so the Go bridge integration test can exercise the transport headlessly.
"""
from __future__ import annotations
import json
import os
import sys
import threading
import time
from queue import Empty, Queue

from rh_crypto import SessionKeys
from rh_fsm import RemoteHandFSM
from rh_protocol import PageState, RhInput, rh_hello


class _EmitterWriter:
    """FSM Emitter that serializes messages through a line writer.

    Re-announces rh_hello immediately before every rh_prompt so a Flutter client
    that connected AFTER the initial hello (the ws opens a beat after /start
    spawns the sidecar) still receives the session pubkey with the prompt — else
    the form renders but 'Continue' stays disabled ('Establishing secure channel')."""
    def __init__(self, write, hello=None):
        self._write = write
        self._hello = hello  # callable → rh_hello dict (re-sent before prompts)

    def send(self, msg: dict) -> None:
        if self._hello is not None and msg.get("type") == "rh_prompt":
            self._write(self._hello())
        self._write(msg)


class GatedObserver:
    """Scripted observer that advances ONLY on explicit advance() — deterministic
    for fake-mode tests (mirrors 'page changes after you submit')."""
    def __init__(self, states: list[PageState], captcha: bytes | None = None, err: str = ""):
        self._states = list(states); self._i = 0
        self._captcha = captcha; self._err = err

    def observe(self) -> PageState: return self._states[min(self._i, len(self._states) - 1)]
    def advance(self) -> None: self._i += 1
    def capture_captcha(self) -> bytes | None: return self._captcha
    def error_text(self) -> str: return self._err
    def locate(self, text: str) -> tuple[int, int] | None: return None


class Sidecar:
    """I/O-agnostic core: owns keys + FSM, decrypts sealed input, drives injection."""
    def __init__(self, observer, injector, keys: SessionKeys, write, session_id: str = "rh"):
        self.keys = keys
        self.session_id = session_id
        self._write = write
        self.fsm = RemoteHandFSM(session_id, observer, injector,
                                 _EmitterWriter(write, lambda: rh_hello(session_id, keys.public_key_b64)))

    def hello(self) -> None:
        self._write(rh_hello(self.session_id, self.keys.public_key_b64))

    def on_input(self, raw: dict) -> None:
        inp = RhInput.parse(raw)
        values = dict(inp.values)
        if inp.sealed:  # sealed decrypts to {field: secret, ...}
            values.update(json.loads(self.keys.unseal(inp.sealed)))
        self.fsm.submit(inp.step, values)
        for k in list(values):  # best-effort drop of plaintext secrets
            values[k] = ""
        values.clear()

    def tick(self) -> PageState: return self.fsm.tick()

    @property
    def done(self) -> bool: return self.fsm.done

    def close(self) -> None: self.keys.wipe()


def _stdout_writer(msg: dict) -> None:
    sys.stdout.write(json.dumps(msg) + "\n"); sys.stdout.flush()


def _run_fake(sc: Sidecar, observer: GatedObserver, read_line, max_idle_ticks: int = 6) -> None:
    """Deterministic loop for fake mode: advance the gated page after each input."""
    sc.hello(); sc.tick()
    while not sc.done:
        line = read_line()
        if not line: break
        sc.on_input(json.loads(line))
        for _ in range(max_idle_ticks):
            observer.advance(); sc.tick()
            if sc.done: break


def _run_real(sc: Sidecar, poll_s: float = 0.8) -> None:
    """Concurrent loop for real mode: a thread reads stdin; main ticks + drains."""
    q: Queue = Queue()
    def reader():
        for line in sys.stdin:
            q.put(line)
        q.put(None)
    threading.Thread(target=reader, daemon=True).start()
    sc.hello()
    while not sc.done:
        sc.tick()
        try:
            line = q.get(timeout=poll_s)
        except Empty:
            continue
        if line is None: break
        sc.on_input(json.loads(line))


def main() -> None:
    session_id = os.environ.get("RH_SESSION", "rh")
    keys = SessionKeys()
    if os.environ.get("RH_FAKE") == "1":  # headless transport test
        from rh_input import RecordingInjector
        states = [PageState(s.strip().lower()) for s in
                  os.environ.get("RH_STATES", "email,password,success").split(",")]
        observer = GatedObserver(states)
        sc = Sidecar(observer, RecordingInjector(), keys, _stdout_writer, session_id)
        _run_fake(sc, observer, sys.stdin.readline)
    else:
        from rh_input import XdotoolInjector
        from rh_screen import ScrotObserver
        from rh_classify import make_classifier
        display = os.environ.get("RH_DISPLAY", ":99")
        proc = None
        oauth_url = os.environ.get("RH_OAUTH_URL", "")
        if oauth_url:  # launch the vanilla browser to the OAuth URL on this display
            from rh_browser import launch
            proc = launch(oauth_url, display, os.environ.get("RH_PROFILE", f"/tmp/rh-{session_id}"))
        observer = ScrotObserver(display, classifier=make_classifier())
        sc = Sidecar(observer, XdotoolInjector(display), keys, _stdout_writer, session_id)
        try:
            _run_real(sc)
        finally:
            if proc is not None:
                proc.terminate()
    sc.close()


if __name__ == "__main__":
    main()
