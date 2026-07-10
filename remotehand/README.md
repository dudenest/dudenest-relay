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
| `rh_classify.py` | Tesseract OCR + phrase rules → `PageState` (Faza 1). Validated on real Google → EMAIL. |
| `rh_crypto.py` | NaCl sealed box (X25519), ephemeral per session — decrypts secrets sealed by Flutter (§10.1). |
| `rh_browser.py` | Vanilla Chromium launcher (validated flags, no CDP/headless). |
| `rh_sidecar.py` | stdio bridge: `rh_hello`/`rh_prompt`/`rh_state` out, `rh_input` in; decrypts `sealed`; fake mode for Go tests. |

The Go relay side lives in `internal/remotehand/`: `bridge.go` (spawn sidecar +
pipe stdio), `manager.go` (per-session routing by `session_id`, lifecycle),
`display.go` (display pool §13), `handler.go` (HTTP start/end). Hub glue:
`ws.Hub.BroadcastRaw` + `SetOnClientMessage`.

## Status

- **Faza 0**: protocol + FSM + injector + unit tests + e2e (isTrusted=true).
- **Faza 1**: OCR classifier (validated on real Google); relay integration —
  sealed box + sidecar + Go bridge/Manager + display pool + HTTP handler.
- **Remaining**: Flutter dynamic form (part 3/3); serve.go mount + OAuth
  token capture wiring; Faza 2 (2FA live), Faza 3 (captcha crop §8.1).
- Secrets (password, SMS code) are `sensitive` → Flutter seals them; the FSM
  zeroizes buffered secrets after injection.

## Test

```bash
cd remotehand && python3 -m unittest discover -s tests -v   # 48 tests (pynacl for crypto)
cd .. && go test ./internal/remotehand/ ./internal/ws/       # 14 tests (python3+pynacl for e2e)
```

## Test

```bash
cd remotehand && python3 -m unittest discover -s tests -v   # 21 tests, no deps
```

Runtime deps (Faza 1+, on the relay VM): `xdotool scrot` (apt) and
`pip install -r requirements.txt`.
