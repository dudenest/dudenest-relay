# dudenest-relay

![Version](https://img.shields.io/badge/Version-v0.5.0-blue) ![Status](https://img.shields.io/badge/Status-Pre--Alpha-orange) ![Language](https://img.shields.io/badge/Language-Go-00ADD8) ![License](https://img.shields.io/badge/License-Apache%202.0-green) ![Hardware](https://img.shields.io/badge/Hardware-Raspberry%20Pi%20Zero%202W%2B-red) ![Last Update](https://img.shields.io/badge/Update-2026--05--06-lightgrey)

**The privacy-preserving bridge between your Dudenest app and your cloud storage accounts.**

Dudenest Relay is a lightweight Go daemon that runs on a Raspberry Pi (or any Linux device) in your home. It is the heart of Dudenest's zero-knowledge architecture: your files never leave your network unencrypted.

## What Relay Does

```
Your Home Network
┌───────────────────────────────────────────────────────────────┐
│                                                               │
│   ┌──────────────┐                ┌──────────────────────┐   │
│   │  Relay Daemon│                │  Your Cloud Accounts │   │
│   │  (this repo) │◄──────────────►│  Google Drive        │   │
│   │              │                │  MEGA                │   │
│   │  • Chunking  │                │  OneDrive            │   │
│   │  • AES-256   │                │  pCloud              │   │
│   │  • Reed-     │                │  Filen...            │   │
│   │    Solomon   │                └──────────────────────┘   │
│   │  • Block Map │                                           │
│   │  • Thumbnails│                                           │
│   └──────────────┘                                           │
│          │                                                    │
│          │ WireGuard (Headscale)                              │
│          │                                                    │
└──────────┼────────────────────────────────────────────────────┘
           │
           ▼
   Dudenest App (your phone/computer)
```

## Core Responsibilities

| Function | Description |
|----------|-------------|
| **Chunking** | Split files into 5-10 MB blocks |
| **Encryption** | AES-256-GCM per-block with HKDF-SHA256 derived keys |
| **Erasure Coding** | Reed-Solomon 6+3: survive loss of 3 cloud accounts |
| **Block Map** | SQLite index: which block is on which account |
| **Thumbnail Cache** | Local thumbnails for instant gallery scrolling |
| **Prefetch** | Smart prediction of what to pre-download while scrolling |
| **Cloud Connectors** | rclone-based adapters for each cloud provider |
| **Tunnel** | WireGuard via Headscale for secure app connection |

## Supported Cloud Providers

| Provider | Free Tier | Status |
|----------|-----------|--------|
| Google Drive | 15 GB | Planned |
| MEGA | 20 GB | Planned |
| OneDrive | 5 GB | Planned |
| pCloud | 10 GB | Planned |
| Filen | 10 GB | Planned |
| Box | 10 GB | Planned |
| Icedrive | 10 GB | Planned |
| Koofr | 10 GB | Planned |
| Backblaze B2 | 10 GB | Planned |
| Storj | 25 GB | Planned |

## Hardware Requirements

| Device | RAM | Storage | Status |
|--------|-----|---------|--------|
| Raspberry Pi Zero 2W | 512 MB | 8+ GB SD | Minimum spec |
| Raspberry Pi 4 (2GB) | 2 GB | 16+ GB SD | Recommended |
| Raspberry Pi 5 | 4-8 GB | 32+ GB SD | Performance |
| Any Linux x86_64 | 512 MB+ | Any | Supported |
| Docker container | 256 MB+ | Any | Supported |

## Getting Started

### Quick Install (Raspberry Pi)

```bash
curl -sSL https://get.dudenest.com/relay | bash
```

### Manual Install

```bash
# Download binary
wget https://github.com/dudenest/dudenest-relay/releases/latest/download/relay-linux-arm64
chmod +x relay-linux-arm64

# Create config directory and copy example config
mkdir -p ~/.config/dudenest
cp configs/relay.json.example ~/.config/dudenest/relay.json
# Edit relay.json with your values (see Configuration section below)

# Run (config auto-loaded from ~/.config/dudenest/relay.json)
./relay-linux-arm64

# Or specify config path explicitly
./relay-linux-arm64 --config /path/to/relay.json
```

### Docker

```bash
docker run -d \
  --name dudenest-relay \
  -v ~/.config/dudenest-relay:/config \
  -v /mnt/relay-data:/data \
  ghcr.io/dudenest/relay:latest
```

## Configuration

Config file: `~/.config/dudenest/relay.json` (default) or set with `relay --config <path>`.

Priority chain: **CLI flag > env var > relay.json > built-in defaults**

```json
{
  "server": {
    "listen": "0.0.0.0:8086",
    "display": ":99"
  },
  "oauth": {
    "callback_port": 8085,
    "web_redirect_url": "https://dudenest.com/auth"
  },
  "browser": {
    "session_timeout_hours": 4
  },
  "backup": {
    "url": "https://backup.dudenest.com",
    "debounce_seconds": 3
  },
  "novnc": {
    "backend_addr": "127.0.0.1:6080"
  },
  "upload": {
    "max_size_mb": 32
  }
}
```

See `configs/relay.json.example` for a fully-annotated example.

## Project Structure

```
cmd/relay/          # Entry point (main.go)
internal/
├── blockstore/     # Chunking engine
├── crypto/         # AES-256-GCM, HKDF
├── erasure/        # Reed-Solomon wrappers
├── thumbnail/      # Thumbnail generation (libvips/ffmpeg)
├── blockmap/       # SQLite block index
├── cloudconn/      # Cloud provider connectors
│   ├── gdrive/     # Google Drive
│   ├── mega/       # MEGA
│   ├── onedrive/   # OneDrive
│   ├── pcloud/     # pCloud
│   └── filen/      # Filen
├── tunnel/         # WireGuard / Headscale
├── prefetch/       # Smart prefetch engine
├── api/            # Local REST API (for app)
└── config/         # Config loading
pkg/
├── reedsolomon/    # Reed-Solomon implementation wrappers
└── types/          # Shared types
```

## Security

- **Zero-Knowledge**: Decryption keys and file maps never leave the Relay. Dudenest SaaS servers only see encrypted, erasure-coded chunks.
- **API Hardening**: All Relay API endpoints (except `/health` and noVNC static assets) require JWT authentication.
- **Shared Secret**: Relay validates tokens issued by `dudenest-backend` using a shared `JWT_SECRET`.
- **Per-block keys**: Each block has a unique HKDF-derived key.
- **Memory safety**: Go's memory model prevents buffer overflows.

## Environment Variables

Required secrets (never in relay.json — use env vars):

| Variable | Description | Example |
|----------|-------------|---------|
| `RELAY_KEY` | Master encryption key (hex or passphrase) | `32-char-hex-string` |
| `JWT_SECRET` | Shared secret for JWT validation (HS256) | `HS256-signing-key` |
| `GDRIVE_WEB_CLIENT_ID` | Google OAuth Web Client ID | `...googleusercontent.com` |
| `GDRIVE_WEB_CLIENT_SECRET` | Google OAuth Web Client Secret | `GOCSPX-...` |
| `RELAY_ID` | Set automatically after registration | `relay-abc123` |
| `RELAY_SECRET` | Set automatically after registration | `secret-xyz...` |

Optional overrides for relay.json values:

| Variable | Overrides | Default |
|----------|-----------|---------|
| `RELAY_LISTEN` | `server.listen` | `0.0.0.0:8086` |
| `RELAY_DISPLAY` | `server.display` | `:99` |
| `BACKUP_URL` | `backup.url` | `https://backup.dudenest.com` |

## License

Apache License 2.0

---

**Author**: Dariusz Porczyński
**Organization**: https://github.com/dudenest

## Changelog

### v0.5.0 — 2026-05-06 — Config System
- ⚙️ **relay.json**: All hardcoded values moved to `~/.config/dudenest/relay.json` (stdlib `encoding/json`, no external deps)
- 🔧 **`--config` flag**: `relay --config <path>` overrides default config path
- 📦 **Priority chain**: CLI flag > env var > relay.json > built-in defaults
- 🔑 **Lazy Registration**: Relay registers with backup on first valid JWT request (`sync.Once`), using `user_id` from JWT `Sub` claim

### v0.4.1 — 2026-04-12 — Security & Stability
- 🔐 **JWT Enforcement**: All Relay API endpoints now strictly require HS256 JWT authorization.
- 🚀 **v0.4.1 Release**: Official cross-compiled binaries for Linux x86_64 and ARM64.
- 🔧 **Service Restoration**: Successfully restored service on `relay-poc` after `pve101` host crash.

### v0.4.0 — 2026-04-09 — Browser Auth & VNC UX
- 🖥️ **noVNC Browser Auth**: Implemented integrated `/vnc` proxy for OAuth flow without leaving the app.
- ✂️ **VNC Crop**: Optimized VNC view with 115px top crop to hide browser chrome and title bar.
- 🐛 **Port 8085 Fix**: Resolved `cbCancel` lifecycle bug affecting authentication sessions.
- 🌐 **HTTPS Protocol Forwarding**: Correctly handle `X-Forwarded-Proto: https` for Cloudflare tunnels.
