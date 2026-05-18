# dudenest-relay

[![Version](https://img.shields.io/github/v/release/dudenest/dudenest-relay?color=blue&label=Version)](https://github.com/dudenest/dudenest-relay/releases/latest) [![Release Date](https://img.shields.io/github/release-date/dudenest/dudenest-relay?color=lightgrey&label=Released)](https://github.com/dudenest/dudenest-relay/releases/latest) ![Last Update](https://img.shields.io/badge/Update-2026--05--18-orange) ![Status](https://img.shields.io/badge/Status-Pre--Alpha-orange) ![Language](https://img.shields.io/badge/Language-Go-00ADD8) ![License](https://img.shields.io/badge/License-Apache%202.0-green) ![Hardware](https://img.shields.io/badge/Hardware-Raspberry%20Pi%20Zero%202W%2B-red) ![Deployment](https://img.shields.io/badge/Deployment-VM%20%2F%20RPi%20only-blue)

> ⚠️ **2026-05-16**: Swarm deployment has been **removed** — `dudenest-relay` runs only as VM or Raspberry Pi binary now. See [`docs/RELAY-OPS.md`](docs/RELAY-OPS.md) for details.
>
> ✨ **2026-05-18 (v0.8.0)**: `scripts/install.sh` now provisions a **fully media-capable relay** in one command — X server, Chromium, TigerVNC, noVNC and a daily auto-update timer are installed automatically. Cloud-account registration (Google OAuth) works out of the box on every new install.

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
│   │  • Replica   │                │  OneDrive            │   │
│   │    storage   │                │  pCloud              │   │
│   │  • FileMap   │                │  Filen...            │   │
│   │    (SQLite)  │                └──────────────────────┘   │
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
| **Replica Storage** | Full file stored as-is on up to 2 cloud accounts (1 per provider email) |
| **Failover** | Download tries Main replica first; falls back to Backup replica on error |
| **FileMap** | SQLite index: file_id → list of `scheme:email:path` locations |
| **Media Cache** | 200×200 thumbnail + 800 px medium preview + LQIP placeholder + `.dims` sidecar per file |
| **Prefetch** | Smart prediction of what to pre-download while scrolling |
| **Cloud Connectors** | Adapters for each cloud provider (Google Drive, etc.) |
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

### One-line bootstrap (VM / Raspberry Pi)

```bash
curl -sSL https://raw.githubusercontent.com/dudenest/dudenest-relay/main/scripts/install.sh | sudo bash
```

This installs **everything** a fully-functional relay needs:

| Layer | Component | Purpose |
|-------|-----------|---------|
| **Display** | `lightdm` + autologin (user `dude`) | Boots straight into a graphical session on display `:0` |
| **Desktop** | `xfce4` + `xorg` | Lightweight Xfce for `:0` and `:99` |
| **OAuth display** | `tigervnc-standalone-server` on `:99` | Where the relay launches Chromium for Google OAuth |
| **Web bridge** | `novnc` + `websockify` on `:6080` | Streams `:99` to a browser as HTML5 + WebSocket |
| **Console kiosk** | `chromium --start-maximized → http://localhost:6080/dudenest.html` | Always-on Chromium on the VM screen showing the OAuth session live |
| **Relay** | `/usr/local/bin/relay serve --display :99` | Go binary from GitHub Releases; talks to GDrive, MEGA, etc. |
| **Auto-update** | `dudenest-relay-update.timer` (24 h) + `ExecStartPre=-relay update` | Pulls the newest release from GitHub Releases and restarts the service |
| **Networking** | `zerotier-one` joined to overlay `932df01efb1ebd71` | Hub auto-provisions `relay_id`, `relay_url`, `JWT_SECRET`, etc. |

The script is **idempotent** — running it again on an already-installed host only fills in the missing pieces (e.g. adding Chromium/X to a relay that was bootstrapped before v0.8.0).

After it finishes, the VM console shows the noVNC view (green status dot bottom-right) and the relay listens on `0.0.0.0:8086`. Open the Dudenest app → **Settings → My Relays → Add Cloud Account** to start the OAuth flow.

### Manual install (binary only — no desktop)

If you already have your own X / Chromium / VNC stack (e.g. when embedding the relay inside a custom appliance) you can install just the binary:

```bash
# Download the binary
wget https://github.com/dudenest/dudenest-relay/releases/latest/download/relay-linux-arm64
chmod +x relay-linux-arm64 && sudo mv relay-linux-arm64 /usr/local/bin/relay

# Minimal config
sudo mkdir -p /etc/dudenest /var/lib/dudenest/maps
sudo tee /etc/dudenest/relay.env >/dev/null <<EOF
RELAY_KEY=$(openssl rand -hex 32)
BACKUP_URL=https://backup.dudenest.com
EOF
sudo chmod 600 /etc/dudenest/relay.env

# Run pointing at your own X display
DISPLAY=:99 /usr/local/bin/relay serve \
  --display :99 \
  --listen 0.0.0.0:8086 \
  --config-dir /etc/dudenest \
  --map-store /var/lib/dudenest/maps
```

### Docker (binary only — OAuth disabled)

The Docker image ships without Chromium / X11, so Google OAuth flows do **not** work. Use it only as a non-interactive backend node (e.g. behind a hub that handles registration elsewhere):

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
├── pipeline/       # Replica upload/download engine (current default)
├── blockmap/       # SQLite FileMap index (file→provider locations)
├── cloudconn/      # Cloud provider connectors (Google Drive, ...)
├── thumbnail/      # Media processing: 200px thumbnail, 800px preview, LQIP, EXIF, video thumbs via ffmpeg
├── prefetch/       # Smart prefetch engine
├── api/            # Local REST API (for app)
├── auth/           # JWT validation, relay token (L2/L3 security)
├── backup/         # Backup client (ping loop, FileMap sync)
├── register/       # Relay registration with backup.dudenest.com
├── config/         # Config loading (relay.json)
├── blockstore/     # Legacy chunking engine (unused, Replica is default)
├── crypto/         # Legacy AES-256-GCM/HKDF (unused in Replica mode)
└── erasure/        # Legacy Reed-Solomon wrappers (unused in Replica mode)
pkg/
├── reedsolomon/    # Legacy Reed-Solomon implementation
└── types/          # Shared types
```

## Security

- **Privacy-First**: File content never passes through Dudenest SaaS servers — files go directly from Relay to your cloud accounts.
- **API Hardening**: All Relay API endpoints (except `/health` and noVNC static assets) require JWT authentication.
- **3-Layer Security**: L1 network isolation (ZeroTier/Headscale), L2 JWT `sub` == owner check, L3 HMAC `relay_token` signed by backup service.
- **Shared Secret**: Relay validates tokens issued by `dudenest-backend` using a shared `JWT_SECRET`.
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

See [CHANGELOG.md](CHANGELOG.md) for the full version history.
