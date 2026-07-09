# Remote-Hand — CDP-free mediated login (method 3)

Adds a third "Add cloud account" method: the user fills a **dynamic Flutter form**
while the relay drives a **vanilla Chromium** on an X display via **OS-level input
(XTEST/xdotool)** and reads the screen **visually**. No Chrome DevTools Protocol,
no `navigator.webdriver`, no browser automation hook — injected events are
`isTrusted=true`, indistinguishable from a physical keyboard/mouse.

Full design & rationale: `~/.AI/dudenest-application/RELAY-REMOTE-HAND-PLAN.md`.

## Why a Python sidecar (not in the Go relay)

The relay builds with `CGO_ENABLED=0` (pure-Go static, 6-arch cross-compile).
The CV/OCR + input stack (PyAutoGUI/xdotool + OpenCV + Tesseract) lives here as a
**separate per-session process** so it never touches that clean build. `go-vgo/robotgo`
(also XTEST → same undetectability) is the documented migration target *as a
separate Go/CGO sidecar* if we later consolidate to Go — see plan §5.1.

## Modules (Faza 0)

| File | Role |
|------|------|
| `rh_protocol.py` | ws message schema (`rh_hello`/`rh_prompt`/`rh_input`/`rh_state`), `Field`, `PageState`. Secrets go via `sealed` (NaCl sealed_box), never cleartext. |
| `rh_input.py` | `XdotoolInjector` — humanized XTEST input on `DISPLAY=:N`. `RecordingInjector` for tests. |
| `rh_screen.py` | `ScrotObserver` — framebuffer capture + (Faza 1) OpenCV/OCR classifier. Tight captcha crop (§8.1). `ScriptedObserver` for tests. |
| `rh_fsm.py` | `RemoteHandFSM` — observe→classify→prompt→inject→advance. Handles email/password/consent/phone/SMS/captcha/success/error. |

## Status

- **Faza 0**: protocol + FSM + injector skeleton + unit tests. Real page
  classifier (OpenCV/OCR) and ws wiring land in Faza 1.
- Secrets (password, SMS code) are `sensitive` → Flutter seals them; the FSM
  zeroizes buffered secrets after injection.

## Test

```bash
cd remotehand && python3 -m unittest discover -s tests -v   # 21 tests, no deps
```

Runtime deps (Faza 1+, on the relay VM): `xdotool scrot` (apt) and
`pip install -r requirements.txt`.
