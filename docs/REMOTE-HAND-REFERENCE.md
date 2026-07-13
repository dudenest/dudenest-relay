# Remote-Hand Reference Tutorial

**Author**: Dariusz Porczyński  
**Last updated**: 2026-07-11  
**Scope**: Relay-assisted Google OAuth method 3 for Dudenest cloud-account pairing.

## 1. Purpose

Remote-Hand is the third cloud-account login method. The user sees a dynamic Flutter form, while the relay runs a real Chromium browser on an X display and performs the same actions through OS-level keyboard/mouse input. The goal is to avoid Chrome DevTools Protocol automation and keep browser events indistinguishable from physical input.

Method 3 is used when the relay can perform most Google OAuth screens automatically but still needs the user for secrets, 2FA, captcha, or explicit risk confirmations.

## 2. Core rule

Remote-Hand never reads Google DOM and never uses CDP. It reads pixels and OCR text from `DISPLAY=:99`, classifies the current screen, sends a matching prompt to Flutter, receives user input, and injects it into Chromium through X11/XTEST.

```text
Flutter dudenest.com
  ├─ HTTP POST /relay/oauth3/start {provider:gdrive}
  ├─ WebSocket /ws receives rh_hello/rh_prompt/rh_state/auth_done
  └─ HTTP POST /relay/oauth3/input sends rh_input reliably

dudenest-relay Go process
  ├─ Manager allocates display and session_id
  ├─ Bridge spawns Python sidecar
  ├─ browser.Server arms OAuth callback capture
  └─ callback saves token using the same storage path as method 2

Python sidecar on relay VM
  ├─ launches vanilla Chromium on DISPLAY=:99
  ├─ scrot + Tesseract OCR classify page state
  ├─ xdotool/xclip inject and verify input
  └─ emits prompts/states back to Flutter through Go bridge
```

## 3. Runtime components

### Relay-side Python sidecar

| File | Responsibility |
|---|---|
| `remotehand/rh_sidecar.py` | Process entrypoint. Reads `rh_input` JSON from stdin and emits `rh_hello`, `rh_prompt`, `rh_state` JSON lines on stdout. Launches browser and FSM. |
| `remotehand/rh_browser.py` | Starts vanilla Chromium with no CDP/headless/remote-debugging. Uses `RH_OAUTH_URL`, `RH_DISPLAY`, `RH_SESSION`. |
| `remotehand/rh_protocol.py` | Wire schema and `PageState` enum. Defines `Field`, `rh_hello`, `rh_prompt`, `rh_state`, `RhInput`. |
| `remotehand/rh_crypto.py` | X25519 NaCl sealed-box session key. Flutter seals sensitive values to per-session relay pubkey. |
| `remotehand/rh_classify.py` | OCR text classification. Maps framebuffer text to `PageState`. |
| `remotehand/rh_screen.py` | `scrot` capture, OCR word location, captcha capture seam, Google-blue button fallback detector. |
| `remotehand/rh_input.py` | `xdotool` typing/clicking and `xclip` visible-field readback. |
| `remotehand/rh_fsm.py` | State machine: observe → classify → prompt/inject/click → advance. |

### Relay-side Go integration

| File | Responsibility |
|---|---|
| `internal/remotehand/display.go` | Allocates/release X displays; currently `:99`, future pool can be many Xvfb displays. |
| `internal/remotehand/bridge.go` | Spawns Python sidecar and pipes stdout/stdin. Uses process group kill to remove Chromium children. |
| `internal/remotehand/manager.go` | Owns sessions, routes by `session_id`, caches last hello/prompt for late WebSocket reconnect, frees display on sidecar exit. |
| `internal/remotehand/handler.go` | HTTP handlers: `/relay/oauth3/start`, `/relay/oauth3/input`, `/relay/oauth3/end`. |
| `cmd/relay/serve.go` | Mounts handlers, configures `RH_SIDECAR_SCRIPT`, display pool, provider prep, and `StartAssistedCapture`. |

### Flutter integration

| File | Responsibility |
|---|---|
| `lib/core/network/relay_client.dart` | Calls `/relay/oauth3/start` and `/relay/oauth3/input`. |
| `lib/core/network/remote_hand.dart` | Controller/model. Parses `rh_*`, seals sensitive values, submits through HTTP input. |
| `lib/features/storage_accounts/remote_hand_form.dart` | Dynamic form UI for all `rh_prompt` fields and zero-field confirmations. |
| `lib/features/storage_accounts/accounts_screen.dart` | Adds `Relay assisted` method and starts Remote-Hand session. |

## 4. Installed locations and services

Canonical install on relay VM:

| Path/service | Meaning |
|---|---|
| `/usr/local/bin/relay` | Go relay binary. |
| `/usr/local/lib/dudenest/remotehand/` | Installed Python sidecar files. |
| `/etc/dudenest/relay.env` | Main relay runtime environment. |
| `/etc/dudenest/gdrive_client_secret.json` | Google OAuth client secret for relay-side token exchange. |
| `/etc/dudenest/relay_creds.json` | Relay registration credentials. |
| `/etc/systemd/system/dudenest-relay.service` | Relay API and OAuth capture service. |
| `/etc/systemd/system/tigervnc-99.service` | TigerVNC/X display `:99`, port `5999`. |
| `/etc/systemd/system/novnc.service` | noVNC/websockify `:6080` → `localhost:5999`. |
| `/etc/systemd/system/dudenest-kiosk.service` | Chromium kiosk on `:0` displaying `http://localhost:6080/dudenest.html`, so VM console shows `:99`. |
| `/usr/share/novnc/dudenest.html` | Custom noVNC page for relay console. |
| `/usr/share/novnc/dudenest-form.html` | Form-only noVNC view for human takeover: crops `:99` to the Google form rectangle and scales it to mobile width without resizing Chromium. |

Important display model:

```text
:99 = real OAuth work display (Google Chromium controlled by Remote-Hand)
:0  = VM console/kiosk display showing localhost:6080/dudenest.html, which displays :99
```

If Chromium is visible on `:99` but not on VM console, check `dudenest-kiosk.service` and noVNC, not the OAuth browser.

## 5. Configuration knobs

| Variable | Used by | Meaning |
|---|---|---|
| `RH_SIDECAR_SCRIPT` | Go relay | Override Python sidecar path; default `/usr/local/lib/dudenest/remotehand/rh_sidecar.py`. |
| `RELAY_DISPLAY` / config display | Go relay | Display pool seed; currently `:99`. |
| `RH_OAUTH_URL` | Sidecar env | OAuth URL opened in Chromium. Set by Manager per session. |
| `RH_DISPLAY` / `DISPLAY` | Sidecar env | X display for Chromium, scrot, xdotool. |
| `RH_SESSION` | Sidecar env | Remote-Hand session id, e.g. `rh-a231...`. |
| `RH_FAKE=1` | Tests only | Fake sidecar mode for Go tests. |
| `GDRIVE_WEB_CLIENT_ID` / `GDRIVE_WEB_CLIENT_SECRET` | Relay/browser | Google OAuth URL and token exchange. |

Runtime packages installed by `scripts/install.sh`: `tesseract-ocr`, `xdotool`, `scrot`, `xclip`, `python3-pil`, `python3-pip`, `pynacl`, `pytesseract`, plus Chromium/X/VNC/noVNC packages.

## 6. Protocol reference

### Relay → Flutter

`rh_hello` gives Flutter the per-session public key:

```json
{"type":"rh_hello","session_id":"rh-...","relay_pubkey":"base64"}
```

`rh_prompt` renders a dynamic form or a zero-field confirmation:

```json
{
  "type":"rh_prompt",
  "session_id":"rh-...",
  "request_id":"rh",
  "step":"send_code",
  "title":"Google will send a verification code to ••• ••• •90",
  "fields":[],
  "level":"info"
}
```

`rh_state` reports progress/terminal states:

```json
{"type":"rh_state","session_id":"rh-...","request_id":"rh","state":"working","message":"submitting code"}
```

For B1 human takeover, serious/unknown states keep the browser alive and include a form-only noVNC URL:

```json
{"type":"rh_state","session_id":"rh-...","request_id":"rh","state":"error","message":"Google shows: ...","takeover_url":"/vnc/dudenest-form.html?session=rh-...&crop=415,150,450,620"}
```

`dudenest-form.html` accepts `crop=x,y,w,h` in remote `:99` pixels. The default `415,150,450,620` is tuned for the centered Google OAuth card on a 1280×1024 relay display. This is a **viewer crop only**: Chromium stays full-size for OCR/FSM stability.

The relay may also broadcast existing `auth_done`; Flutter treats it as authoritative success because token capture happens server-side at the relay callback.

### Flutter → Relay/sidecar

`rh_input` is sent through HTTP POST `/relay/oauth3/input` for reliability. WebSocket input is kept as fallback only.

```json
{
  "type":"rh_input",
  "session_id":"rh-...",
  "step":"sms_code",
  "values":{},
  "sealed":"base64-sealed-json"
}
```

Sensitive fields (`password`, `code`) are inside `sealed`, not `values`.

## 7. Current recognized Google screens

| `PageState` | Classifier signatures | FSM behavior |
|---|---|---|
| `EMAIL` | `email or phone`, `use your google account`, `forgot email`, generic `sign in` | Shows login+password prompt immediately; injects login when page is ready. |
| `PASSWORD` | `enter your password` | Injects buffered password or prompts for password. |
| `PHONE` | `enter phone number`, `confirm recovery phone`, `a phone number where you can` | Shows phone-number input field. |
| `SEND_CODE` | `Get a verification code` + `Google will send a verification code to ...` | Shows zero-field confirmation with masked phone; on Continue clicks Google `Send` blue button. |
| `SMS` | `enter the code`, `G-123`, `enter verification code`, `code texted/sent` | Shows verification-code field; injects code. |
| `UNVERIFIED_APP` | `Google hasn't verified this app`, `Continue only if you understand the risks` | Clicks `Advanced`; then clicks `Go to dudenest-relay (unsafe)`. |
| `CONSENT` | `wants access to your Google Account`, `by continuing, Google will share` | Clicks `Continue`/`Allow`; fallback Return. |
| `CAPTCHA` | `I'm not a robot`, `type the characters`, `select all images` | Emits captcha prompt/image seam. Manual captcha remains accepted scope. |
| `ERROR` | wrong password/code/phone/account, too many attempts, disabled account, session expired | Recoverable errors re-prompt specific field; terminal errors stop. |
| `UNKNOWN` | No rule matched | Short waits are ignored; persistent unknown surfaces OCR text to Flutter instead of infinite spinner. |

## 8. Screen-reading technique

Remote-Hand reads the screen with `scrot` and Tesseract. It never queries DOM. The classifier first collapses OCR whitespace, then applies ordered regex rules. Specific/terminal states are before generic states so `Google hasn't verified this app` wins over generic `Google Account`/`sign in` text.

Button detection has two layers:

1. Tesseract word boxes through `pytesseract.image_to_data`, e.g. locate `Continue`, `Allow`, `Advanced`, `Goto`.
2. Pixel fallback for Google primary blue buttons. This is required for `Send`, because white text on a blue pill may not OCR. The detector finds connected components of Google-blue pixels in the lower UI and clicks the component center.

For visible text fields, `rh_input.XdotoolInjector.read_field()` uses `Ctrl+A`, `Ctrl+C`, and `xclip` to confirm the typed value before pressing Enter. Password fields intentionally may not copy back; they are best-effort and verified by the next screen.

Known implementation detail: `xclip` clipboard set must not use `capture_output`, because xclip daemonizes and can keep inherited pipes open. The code uses `DEVNULL` and timeouts.

## 9. Input technique

Input is OS-level X11/XTEST through `xdotool`:

- `type --delay ...` for text.
- `key Escape` before `Return` to close Google autocomplete/passkey popup.
- `click x y` for buttons/links that Enter does not activate.
- Humanized small delays in `rh_input.py`.

This gives page-level JavaScript keyboard events with `isTrusted=true`, unlike DOM/CDP synthetic input.

## 10. End-to-end flow tutorial

1. User selects `Relay assisted` in Flutter Add Account.
2. Flutter calls `POST /relay/oauth3/start {"provider":"gdrive"}`.
3. Relay builds Google OAuth URL and arms `StartAssistedCapture` for callback/token capture.
4. Manager allocates `:99` and spawns `rh_sidecar.py` with `RH_OAUTH_URL`, `RH_SESSION`, `DISPLAY=:99`.
5. Sidecar emits `rh_hello` with ephemeral pubkey.
6. FSM emits instant `email` prompt before browser fully renders.
7. Flutter user enters login/password; password is sealed.
8. Sidecar injects login, then password, and follows Google screens.
9. Any encountered state produces either automatic click or dynamic Flutter prompt.
10. Google redirects to `127.0.0.1:8085/oauth/callback` on relay.
11. Relay exchanges code and saves token using the same provider storage as method 2.
12. Relay broadcasts `auth_done`; Flutter shows success.

## 11. Debug checklist

### Quick state check on relay-demo

```bash
ssh -A -J root@pve101.netol.io root@192.168.0.125 '
systemctl is-active dudenest-relay.service tigervnc-99.service novnc.service dudenest-kiosk.service
pgrep -af "[r]h_sidecar.py|--user-data-dir=/tmp/[r]h-" || true
DISPLAY=:99 xdotool search --onlyvisible --class chromium getwindowname %@ 2>/dev/null || true
find /tmp -maxdepth 1 -type d -name "rh-*" | wc -l
'
```

### Capture and classify current screen

```bash
ssh -A -J root@pve101.netol.io root@192.168.0.125 '
DISPLAY=:99 scrot /tmp/rh-current.png
tesseract /tmp/rh-current.png stdout
PYTHONPATH=/usr/local/lib/dudenest/remotehand python3 - <<"PY"
from pathlib import Path
from rh_classify import classify_image
print(classify_image(Path("/tmp/rh-current.png").read_bytes()))
PY
'
```

### Check OCR word boxes

```bash
ssh -A -J root@pve101.netol.io root@192.168.0.125 '
tesseract /tmp/rh-current.png stdout tsv 2>/dev/null | awk -F"\t" "NR==1 || tolower(\$12) ~ /advanced|unsafe|send|continue|allow|code|password|phone/ {print}"
'
```

### Safe cleanup of one Remote-Hand attempt

Use `[r]h-` patterns to avoid killing the SSH command itself.

```bash
ssh -A -J root@pve101.netol.io root@192.168.0.125 '
for pid in $(pgrep -f "[r]h_sidecar.py|--user-data-dir=/tmp/[r]h-" || true); do
  pg=$(ps -o pgid= -p "$pid" | tr -d " ")
  [ -n "$pg" ] && kill -9 -"$pg" 2>/dev/null || kill -9 "$pid" 2>/dev/null || true
done
find /tmp -maxdepth 1 -type d -name "rh-*" -exec rm -rf {} +
'
```

Do not use broad `pkill -f chromium` from an SSH command that contains the word `chromium`; it can kill the command itself.

## 12. Test commands

Relay Python sidecar:

```bash
cd ~/Architect/github.com/dudenest/dudenest-relay
python3 -m unittest discover -s remotehand/tests
```

Relay Go integration:

```bash
cd ~/Architect/github.com/dudenest/dudenest-relay
go test ./internal/remotehand ./internal/ws
```

Flutter controller/UI:

```bash
cd ~/Architect/github.com/dudenest/dudenest
flutter test test/rh_validate_test.dart test/remote_hand_form_test.dart test/remote_hand_test.dart
```

## 13. Adding a new Google screen

1. Capture the screen with `scrot` and save the OCR text.
2. Add or adjust a `PageState` in `rh_protocol.py` if this is a new class of page.
3. Add regex rules in `rh_classify.py`, above generic `EMAIL` rules.
4. Add FSM behavior in `rh_fsm.py`.
5. If a button is not OCR-visible, add locate fallback in `rh_screen.py`.
6. Add unit tests in `remotehand/tests/test_rh_classify.py` and `test_rh_fsm.py`.
7. Run Python tests and relevant Go/Flutter tests.
8. Deploy sidecar files to `/usr/local/lib/dudenest/remotehand/` for relay-demo and restart/cleanup the active attempt.
9. Document the screen and the acceptance result in the session file.

## 14. Current known limitations

- Captcha is intentionally still a manual/interactive path unless a tightly-cropped captcha implementation is added.
- The classifier is English-locale. OAuth URL should keep Google in English for deterministic rules.
- Existing deployed relays only receive Python sidecar files through install/bootstrap, not binary auto-update. A fleet release must include sidecar deployment strategy or rerun install on existing relays.
- Main release is tag-gated; push to `main` alone does not publish binaries to the fleet.
