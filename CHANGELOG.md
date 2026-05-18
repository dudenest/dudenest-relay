# Changelog

All notable changes to dudenest-relay are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
