# Changelog

All notable changes to dudenest-relay are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.9.1] — 2026-05-19 — Standby auto-recovers after first OAuth (no manual restart)

### Fixed
- **`/files` stayed 503 forever after first cloud account added** (`cmd/relay/serve.go`): when the relay started without any cloud providers it correctly entered standby mode, but the pipeline was never re-initialized after the user completed OAuth via the Flutter app. The standby HTTP server kept returning 503 from `/files`/`/files/upload` indefinitely, forcing a manual `systemctl restart dudenest-relay` to recover. Symptom in user logs: `noVNC auth done — <email>` followed by `STANDBY (pipeline init: no cloud providers available)` every 5 min, with `HTTP 503` on every `/files/upload` attempt.
- **Root cause**: `runServe` called `getPipeline()` exactly once. On `isCredentialError` it handed the listen address to `degradedServerWithAuth` and blocked there forever — there was no path back to pipeline init. The `auth_done` WebSocket broadcast (sent by `handleSession` after `SaveToken`) had no effect on the standby server.
- **Fix**: wrapped pipeline init in a standby loop. `ws.Hub` gained `SetOnAuthDone(func())` which `runServe` uses to send to a buffered `reload` channel BEFORE the first `getPipeline()` call (so a token saved during the tiny window between that call and callback registration still triggers reload — the channel is drained on every standby cycle). `degradedServerWithAuth` now runs `http.Server` in a goroutine and selects on `reload`: a `Shutdown(5s)` is issued and the function returns `nil` so the outer loop retries `getPipeline()`. On success, the loop breaks, the callback is detached (full-mode does not act on `auth_done` — provider hot-add for *additional* providers is out of scope), and the normal full server starts.
- **Result**: a fresh relay can now go zero-touch from `install.sh` → ZT bootstrap → user adds first cloud account in the Flutter app → relay exits standby within ~3 seconds (graceful HTTP shutdown + pipeline init) → `/files` serves 200 and uploads work — **with no operator SSH and no systemd restart at any point**.

### Compatibility
- Wire protocol unchanged. Older Flutter clients still receive the same `auth_done` WebSocket message; new behavior is server-side only.
- The auth_done callback is automatically cleared when the relay reaches full mode, so subsequent provider additions behave exactly as in v0.9.0 (no spurious reloads, no race with file traffic).

---

## [0.9.0] — 2026-05-18 — Fleet-wide OAuth credentials auto-distribution

### Added
- **`BootstrapPayload.GdriveClientSecret`** (`internal/register/client.go`): new JSON field in the `/relay/bootstrap` response delivering the Google OAuth client JSON (either `installed` or `web` format — both supported by `oauth2.ConfigFromJSON`; Dudenest uses `installed` today on relay-poc) for the entire fleet. Sourced from a Docker Swarm secret on `dudenest-backup` (`relay_gdrive_client_secret`); rotated centrally with a single `docker secret update` → every relay receives the new value within one `dudenest-relay-update.timer` cycle (24 h), without any operator SSH.
- **`shouldReplaceOAuth()` guard** (`internal/register/client.go`): the relay overwrites `gdrive_client_secret.json` ONLY when the on-disk file is missing or contains a known placeholder marker (`"placeholder"` from install.sh v0.8.x, `"service_account"` from older bootstraps). Real OAuth client JSON in either format (`{"installed":{"client_id":"..."}}` as on relay-poc, or `{"web":{"client_id":"..."}}`) is preserved, so hand-configured legacy relays (e.g. relay-poc with `client_id 932297984145-…`) are NEVER overwritten by a re-register or auto-update.
- **`WriteBootstrapCreds` writes `gdrive_client_secret.json`** when the payload field is non-empty AND the guard allows it. Logs success/skip distinctly for monitoring.
- **`internal/register/client_test.go`**: pins the `shouldReplaceOAuth` contract (placeholder/service_account/missing → replaceable; real OAuth JSON in both `installed` and `web` formats → preserved) and full `WriteBootstrapCreds` end-to-end paths (fresh VM, legacy relay re-register, empty payload backward-compat, placeholder replacement).

### Changed
- **`scripts/install.sh` (step 7)**: no longer writes the `{"installed":{"client_id":"placeholder"}}` placeholder when `gdrive_client_secret.json` is missing — the relay binary v0.9.0+ pulls real credentials from the hub on the first `/relay/bootstrap` poll. Existing real credentials (including the legacy `client_secret.json` symlink) are kept untouched.

### Compatibility (forward + backward)
- **Older relay (≤ v0.8.2) on new backend**: relay ignores unknown JSON field `gdrive_client_secret` — keeps existing placeholder/credentials.
- **New relay (v0.9.0+) on older backend (pre-this-change)**: backend returns no `gdrive_client_secret` → relay sees empty string → no write → keeps existing placeholder/credentials. Zero crash, zero regression.
- **Empty Docker secret on new backend**: backend serves `""` → relay no-op. Configuration is opt-in by setting `GDRIVE_CLIENT_SECRET_JSON_FILE` env on `dudenest-backup` (auto-wired via `deploy/backup-stack.yml` when GitHub secret `RELAY_GDRIVE_CLIENT_SECRET_B64` is populated).

### Result
- **Zero-touch bootstrap**: `curl install.sh | sudo bash` on a fresh Debian 12 / Ubuntu 24.04 VM now ends with a relay that can register Google Drive accounts immediately — no operator SSH, no `scp gdrive_client_secret.json` from `relay-poc`, no Google Cloud Console registration per relay. The OAuth client credentials live once in `dudenest-backup` and are distributed transparently to every current and future relay.
- **Rotation**: changing the Google OAuth app credentials becomes a single Docker secret rotation; the entire fleet picks up the new value within 24 h via the existing `dudenest-relay-update.timer`.

### Related repos
- `dudenest-backup` ships the matching API change (`gdrive_client_secret` field in `/relay/bootstrap` response, loaded from `GDRIVE_CLIENT_SECRET_JSON_FILE` / `GDRIVE_CLIENT_SECRET_JSON` env).

---

## [0.8.2] — 2026-05-18 — Xfce panel renders correctly (`~/.config` ownership + `dbus-run-session`)

### Fixed
- **Critical permission bug**: `install -d -o dude -g dude /home/dude/.config/autostart` only chowned the **leaf** directory — `~/.config` itself stayed `root:root` from when `install` created the missing parents. `xfconfd` running as `dude` then couldn't create `~/.config/xfce4/xfconf/` → died with `Unable to create configuration directory "(null)"` → `xfce4-panel` fell back to its built-in stub geometry (128×50 in the top-left corner) on every fresh bootstrap. Now uses `mkdir -p` + explicit `chown -R dude:dude` of `.config`, `.local`, `.vnc`, which guarantees dude owns every parent.
- **dudenest-xsession + :99 xstartup** wrap the Xfce component launch in `dbus-run-session` so the session bus is clean and `xfconfd` activation gets the right env (HOME, XDG_CONFIG_HOME) inherited. Without this, even with the ownership fix Xfce components hit `GLib-GIO-CRITICAL: g_dbus_proxy_call_sync_internal: assertion 'G_IS_DBUS_PROXY (proxy)' failed` and panel could not bind to its config.
- **Stale autostart files from v0.8.0** (`chromium-novnc.desktop`, `xhost-allow-root.desktop`, `xfwm4-nocomp.desktop` and the matching helper shell scripts) are now explicitly removed by every install.sh run. They were launching a SECOND Chromium under `dude` that fought the `dudenest-kiosk.service` Chromium for the same `--user-data-dir`.

### Added
- `dudenest-xsession` (the lightdm autologin script) and `~/.vnc/xstartup` (TigerVNC `:99`) now create `~/.config/xfce4/xfconf/xfce-perchannel-xml` and export `HOME`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME` before invoking `dbus-run-session -- xfwm4 + xfsettingsd + xfce4-panel + xfdesktop`.

### Result
End-to-end visual parity with the reference `relay-poc` (Debian 12):
- Xfce panel at the top of the screen (Applications menu, system tray, clock, user)
- `xfdesktop` wallpaper + desktop icons (Home, …)
- Chromium kiosk maximized below the panel with proper xfwm4 window decorations (min / max / close), no `--no-sandbox` banner
- `localhost:6080/dudenest.html` loaded, green VNC connection indicator in the bottom-right
- Same result on Debian 12 (`relay-poc`) and Ubuntu 24.04 (`relay-poc2`); install.sh stays idempotent and safe to re-run

---

## [0.8.1] — 2026-05-18 — Kiosk visuals match relay-poc (Xfce panel + xfwm4 + maximize)

### Added
- **`xfce4-panel`, `xfdesktop4`, `xfsettingsd`** plus `xfconfd` launched explicitly from the autologin X session — gives the relay console a normal Xfce desktop (panel, wallpaper, taskbar) instead of a bare X server.
- **`/usr/local/bin/dudenest-maximize-kiosk`** — helper script invoked from `dudenest-kiosk.service` `ExecStartPost`. Polls `wmctrl -l` for the Chromium window and forces `add,maximized_vert,maximized_horz`. Fixes the case where Chromium ignores `--start-maximized` because it has a saved (non-maximized) window state in `Preferences`.
- **`wmctrl`** added to APT_PKGS (required by `dudenest-maximize-kiosk`).
- **`dbus-user-session`, `at-spi2-core`, `xfce4-panel`** explicitly in APT_PKGS — needed by the Xfce components when launched outside of `xfce4-session`.
- **`XDG_CURRENT_DESKTOP=XFCE` + `GTK_USE_PORTAL=0`** set in `dudenest-kiosk.service` `Environment=`. Tells Google Chrome (Ubuntu) to use server-side decorations drawn by xfwm4 instead of its built-in CSD frame.
- **Pre-seeded Chrome `Preferences`** at `/var/lib/dudenest/kiosk-chrome/Default/Preferences` with `{"browser":{"custom_chrome_frame":false,"window_placement":{"maximized":true}}}` — second line of defense for the maximize state.

### Changed
- **`dudenest-xsession`** now launches Xfce components directly (`xfconfd`, `xfwm4`, `xfsettingsd`, `xfce4-panel`, `xfdesktop`) rather than running as a sleep-infinity stub. On Ubuntu 24.04 this avoids the `xfce4-session` "Unable to load a failsafe session" popup while still giving the user a familiar Xfce-style desktop with panel + window decorations.
- **`~/.vnc/xstartup`** (display `:99`) launches the same Xfce component set as `:0`, so the Chromium window the relay opens for Google OAuth gets proper decorations inside the noVNC viewer.
- **`dudenest-kiosk.service`** `ExecStartPre` waits for `xfwm4` to be running (not just the X socket) — otherwise Chromium starts before the window manager and ends up undecorated.
- **`--test-type`** re-added to the kiosk Chromium flags to suppress the yellow `--no-sandbox` warning banner.

### Fixed
- **Kiosk Chromium did not auto-start after VM reboot on relay-poc-style installs** — historical setup relied on Xfce `~/.config/autostart/chromium-novnc.desktop`, which is only fired on the first lightdm-autologin session and not on subsequent reboots. New installs use the systemd-managed `dudenest-kiosk.service` which is unconditionally started on boot. Re-running `install.sh` on the legacy relay-poc migrates it to the systemd-based kiosk.
- **Kiosk Chromium window was not maximized after reboot on Ubuntu 24.04** — `--start-maximized` only applies on first launch; after Chrome saves window state the saved geometry wins. `dudenest-maximize-kiosk` enforces the maximize state via `wmctrl` after every launch.
- **`--no-sandbox` warning banner ate the top of the kiosk viewport** — `--test-type` suppresses it (the banner is informational, not a security control we change with the flag).

---

## [0.8.0] — 2026-05-18 — Full-Stack Bootstrap (Chromium + X11 + noVNC)

### Added
- **scripts/install.sh — full media-capable bootstrap** — single `curl | sudo bash` command now installs every component a fully-functional relay needs, not just the Go binary. Previous installer left machines unable to register Google Drive accounts because Chromium and an X server were missing. New installer is idempotent and safe to re-run on existing relays.
  - **apt packages**: `xorg`, `lightdm`, `xfce4` (+ session/settings/wm/desktop), `tigervnc-standalone-server`, `novnc`, `python3-websockify`, `chromium`, `chromium-sandbox`, `unattended-upgrades`
  - **Linux user `dude`** (uid 1000) with `audio,video,plugdev` groups
  - **LightDM autologin** → `/etc/lightdm/lightdm.conf.d/50-dudenest-autologin.conf` — boots straight into Xfce on display `:0` for `dude`
  - **`/home/dude/.vnc/xstartup`** — Xfce session for TigerVNC on `:99`
  - **`/home/dude/kiosk-novnc.sh`** — Chromium autostart on `:0` (`--start-maximized`, isolated `--user-data-dir`), opens `http://localhost:6080/dudenest.html` — visible on the VM console as soon as the machine boots
  - **`/usr/share/novnc/dudenest.html`** — custom noVNC viewer that crops the Chromium title bar (115px) so the relay's OAuth window fills the kiosk frame edge-to-edge; small green status dot indicates VNC connection
  - **Xfwm4 compositing disabled on `:99`** — smoother Chromium rendering inside VNC
- **4 systemd units**
  - `tigervnc-99.service` — TigerVNC standalone server on `:99` (rfb 5999, no auth, `dude` user)
  - `novnc.service` — websockify bridge `:6080` → `localhost:5999`, requires `tigervnc-99.service`
  - `dudenest-relay.service` — relay binary with `--display :99 --config-dir /etc/dudenest --map-store /var/lib/dudenest/maps`, requires `tigervnc-99.service`, `ExecStartPre=-relay update`
  - `dudenest-relay-update.timer` + `.service` — daily check of GitHub Releases API; runs `relay update` and `systemctl restart dudenest-relay` only when a new tag is fetched (10 min after boot + every 24h, randomized 30 min jitter)
- **deploy/relay-poc/ canonical reference files** — each systemd unit, autostart desktop entry, helper script and `dudenest.html` checked in as the IaC source of truth. install.sh embeds the same content via heredocs so the bootstrap stays a single self-contained file.

### Changed
- **install.sh path conventions** — `RELAY_KEY`, `BACKUP_URL`, `ZT_ANNOUNCE` now live in `/etc/dudenest/relay.env` (chmod 600); maps in `/var/lib/dudenest/maps`; OAuth secret in `/etc/dudenest/gdrive_client_secret.json`. Previous `relay.service` unit name (`relay.service`) is disabled by the new install in favor of `dudenest-relay.service`.
- **deploy/relay-poc/relay.service** — updated to standard `/etc/dudenest/` paths, depends on `tigervnc-99.service`, and gains `ExecStartPre=-/usr/local/bin/relay update` so every restart pulls the newest release before launch.

### Fixed
- **relay-poc2 was structurally unable to register cloud accounts** — bootstrap-installed relays were missing Chromium and the X server, so the relay binary's OAuth flow had nowhere to draw a browser. New install closes that gap on first install and on every re-run of `install.sh` on existing hosts.

---

## [0.7.0] — 2026-05-18 — Media Processing Pipeline

### Added
- **Video thumbnails via ffmpeg** — `VideoThumbnail()` extracts first frame of any video file (mp4, mov, avi, mkv, webm, m4v, 3gp) as center-cropped 200×200 JPEG; auto-detects video by file extension from FileMap
- **HEIC→JPEG conversion** — `ConvertHEIC()` converts HEIC/HEIF photos to JPEG before thumbnail generation (Apple device uploads)
- **Medium preview (800px)** — `GenerateMedium()` creates an 800px longest-side aspect-preserving JPEG preview for fast fullscreen loading; stored at `<configDir>/thumbnails/<fileID>_medium.jpg`
- **LQIP placeholder** — `LQIPBase64()` generates a 20px-wide base64 data-URI JPEG from the medium preview (not the square thumbnail); returned in `GET /files` response as `lqip` field; used by app for blurred placeholder before full image loads
- **EXIF DateTimeOriginal** — pure-Go JPEG EXIF extraction (zero CGO, zero deps); `taken_at` returned in `GET /files` response for chronological gallery ordering
- **Dimension sidecar (.dims)** — `width`, `height`, `taken_at` written to `<fileID>.dims` at upload time; returned in `GET /files` as `width`/`height`/`taken_at` fields
- **ReadDims()** — reads pixel dimensions from any cached JPEG without re-generating thumbnail
- **MediumExists / LQIPExists** — cache-hit helpers for conditional generation
- **ffmpeg auto-install** — `EnsureFFmpeg()` installs ffmpeg via `apt-get` on Linux if not found in PATH (non-interactive)

### Changed
- **Lazy sidecar generation** — `lazyGenSidecars(fileID, name)` background goroutine: downloads original file, generates missing thumbnail + medium preview + LQIP for files uploaded before this version; deduplication via `sync.Map lazyGenMu`
- **handleList** — when `.dims` sidecar missing, reads dims from medium preview if available; launches `lazyGenSidecars` in background for files lacking dims or LQIP
- **handleUpload** — LQIP now generated from `_medium.jpg` (800px, aspect-preserving), not from `<fileID>.jpg` (200×200 square); fixes aspect ratio in placeholder
- **handleThumbnail** — detects video files by extension, calls `VideoThumbnail()` instead of `Generate()`; triggers `lazyGenSidecars` after first generation

### Fixed
- **Square LQIP bug** — LQIP was generated from the 200×200 square thumbnail → placeholder always had 1:1 ratio → images appeared square in justified grid; now generated from medium preview (correct AR)
- **Old files missing AR** — files uploaded before `.dims` sidecar was added showed as 1:1 squares in gallery; lazy gen backfills all sidecars on first access
- **Video thumbnail failure** — `thumbnail.Generate()` (image decoder) was called for video files → always failed silently; now correctly routes to `VideoThumbnail()` via ffmpeg
- **Ext detection bug in lazyGenSidecars** — passing `ext` (e.g. `.jpg`) instead of full `name` caused `filepath.Ext(".jpg")=""` (dotfile treatment); now passes `fm.Name` (e.g. `photo.jpg`)

---

## [0.6.2] — 2026-05-15 — Standby Ping Loop Fix

- 🐛 **RELAY_ID/RELAY_SECRET env fix**: `RegisterOnceWithUserID` return value was discarded (`_, err2`); now captured (`creds2, err2`) → `os.Setenv("RELAY_ID", creds2.RelayID)` executes → `backup.New()` gets valid env → ping loop starts
- ✅ **Verified**: `last_seen_at` updates in CockroachDB, `relay_version` shows `v0.6.2` in Flutter My Relays

## [0.6.1] — 2026-05-15 — Build Fix

- 🐛 **backup.New() signature**: Added missing `version` arg in test calls

## [0.6.0] — 2026-05-14 — Relay Version + Auto-Update

- ✨ **Auto-update**: `ExecStartPre=-/usr/local/bin/relay update` checks GitHub Releases API on startup, downloads newer binary if available
- ✨ **Version embed**: binary version embedded via `-ldflags "-X main.version=vX.Y.Z"` at build time
- ✨ **Ping loop carries version**: `POST /relay/ping` sends `relay_version` → visible in Flutter My Relays

## [0.5.9] — 2026-05-08 — install.sh UX

- ✨ **install.sh**: Better UX with step progress; added `uninstall.sh`

## [0.5.8] — 2026-05-08 — ZT Auto-Provisioning

- ✨ **ZeroTier auto-provisioning**: relay detects missing `relay_creds.json` → POST `/relay/announce` → relay-provisioner assigns ZT IP + subdomain
- ✨ **user_id auto-pairing**: relay updates `user_id` on first JWT `/files` request via `POST /relay/update-user-id`

## [0.5.7] — 2026-05-08 — Security Hardening + Per-User Routing

- 🔒 **3-Layer Security**: L1 network isolation, L2 JWT sub owner check, L3 HMAC relay_token (signed by backup service)
- 🔍 **Security Logging**: L2/L3 rejections logged with `sub`, `owner`, `path` for diagnostics
- 🔄 **Relay URL Routing**: relay registers its public HTTPS URL (`RELAY_PUBLIC_URL`) in CRDB; Flutter fetches per-user relay URL automatically from API — no manual config
- 🔁 **Startup CRDB Sync**: relay syncs `user_id` and `relay_url` to CRDB on every restart
- 📡 **Ping Loop**: relay sends `POST /relay/ping` every 5 minutes → `last_seen_at` visible in Flutter "My Relays"
- 📸 **Initial Backup**: first backup snapshot sent immediately after registration
- 🐛 **Bootstrap Deadlock Fix**: L3 skipped when `ownerUserID=""` → new relay registers without relay_token (which it can't have yet)

## [0.5.0] — 2026-05-06 — Config System

- ⚙️ **relay.json**: All hardcoded values moved to `~/.config/dudenest/relay.json` (stdlib `encoding/json`, no external deps)
- 🔧 **`--config` flag**: `relay --config <path>` overrides default config path
- 📦 **Priority chain**: CLI flag > env var > relay.json > built-in defaults
- 🔑 **Lazy Registration**: Relay registers with backup on first valid JWT request (`sync.Once`), using `user_id` from JWT `Sub` claim

## [0.4.2] — 2026-04-27 — Replica Storage Strategy

- ✨ **Replica strategy**: Full file stored as-is on up to 2 cloud providers (no chunking, no encryption at storage level)
- 🗑️ **Chunking/Reed-Solomon removed as default**: Replica is now the only active strategy; legacy blockstore/erasure code retained but unused
- 🐛 **getCloudByName legacy fallback**: supports old `scheme:path` format alongside new `scheme:email:path`
- ✨ **HTTP Range requests**: `http.ServeContent` for proper video/audio streaming in Flutter

## [0.4.1] — 2026-04-12 — Security & Stability

- 🔐 **JWT Enforcement**: All Relay API endpoints now strictly require HS256 JWT authorization
- 🚀 **v0.4.1 Release**: Official cross-compiled binaries for Linux x86_64 and ARM64
- 🔧 **Service Restoration**: Successfully restored service on `relay-poc` after `pve101` host crash

## [0.4.0] — 2026-04-09 — Browser Auth & VNC UX

- 🖥️ **noVNC Browser Auth**: Implemented integrated `/vnc` proxy for OAuth flow without leaving the app
- ✂️ **VNC Crop**: Optimized VNC view with 115px top crop to hide browser chrome and title bar
- 🐛 **Port 8085 Fix**: Resolved `cbCancel` lifecycle bug affecting authentication sessions
- 🌐 **HTTPS Protocol Forwarding**: Correctly handle `X-Forwarded-Proto: https` for Cloudflare tunnels

---

**Author**: Dariusz Porczyński
**Organization**: https://github.com/dudenest
