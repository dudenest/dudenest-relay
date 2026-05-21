# dudenest-relay — Operational Guide

**Last Updated**: 2026-05-18
**Author**: Dariusz Porczyński
**Status**: ✅ Relay deployed as VM / Raspberry Pi only (binary from GitHub Releases). Full-stack bootstrap (X11 + Chromium + noVNC) shipped in v0.8.0.

---

## 🧭 Architecture boundary — what runs where in Dudenest

This is the most common source of confusion when reading the dudenest sources. Be explicit:

| Component | Deployment | Why |
|-----------|-----------|-----|
| **`dudenest-relay`** (this repo) | **VM or Raspberry Pi binary** — NEVER a container, NEVER on Docker, NEVER on Swarm | The relay launches Chromium for Google OAuth on a real X server. Containers without an attached display can't do that. Swarm-hosted relay was tried (until 2026-05-16) and removed for exactly this reason. |
| `dudenest-backup` (hub for `/relay/announce`, `/relay/bootstrap`, etc.) | **Docker Swarm service** on NETOL | Standard SaaS — `deploy/backup-stack.yml` + `docker stack deploy` in CI. Secrets via Docker Swarm secrets (`relay_jwt_secret`, etc.). |
| `dudenest-backend` (Flutter app API) | **Docker Swarm service** on NETOL | Same pattern. |
| `dudenest` (Flutter SaaS web/mobile) | **Docker Swarm service** for the web bundle | Same pattern. |
| Everything else in NETOL (HAProxy, Headscale, CRDB, runners, monitoring, …) | **Docker Swarm** | NETOL is a Swarm-first infrastructure. |

**Implication for design docs in this repo**: when a plan mentions "Docker secret" or "Swarm secret", it almost always refers to the **backup side** (or another SaaS component the relay talks to), not the relay itself. The relay only ever speaks HTTP to those services. If you see a design suggesting the relay runs in a container, that's a mistake — the explicit decision (with full rationale in §"DEPRECATED: Swarm deployment" below) is that it does not.

---

## 🧩 Architecture: Full-Stack Relay (v0.8.0+)

A fully-functional relay needs more than the Go binary. To register a Google Drive (or any OAuth-based) cloud account the relay launches a real Chromium window — there's no headless API for Google's web sign-in. That Chromium has to draw somewhere, and an operator needs to be able to see it on the VM console.

```
VM console (your monitor / Proxmox noVNC tab)
       │
       ▼  display :0
┌─────────────────────────────────────────────────────────────────┐
│ lightdm autologin (user: dude)                                  │
│   └── Xfce session                                              │
│         └── chromium --start-maximized                          │
│               └── http://localhost:6080/dudenest.html  ◄──┐     │
│                     (custom noVNC viewer, title cropped)  │     │
└──────────────────────────────────────────────────────────│─────┘
                                                           │ ws
                                            display :99    │
┌──────────────────────────────────────────────────────────▼─────┐
│ TigerVNC standalone (rfb 5999, no auth, dude user)             │
│   └── Xfce session                                             │
│         └── Chromium spawned by /usr/local/bin/relay for OAuth │
│                                                                │
│ relay listens on 0.0.0.0:8086 (Files API + /auth/url + /vnc/*) │
└────────────────────────────────────────────────────────────────┘
```

| Process | Display | Started by | Visible to user as |
|---------|---------|------------|-------------------|
| `lightdm` + Xfce | `:0` | systemd | The VM's main screen |
| `chromium --start-maximized` (noVNC viewer) | `:0` | `~/.config/autostart/chromium-novnc.desktop` | The kiosk-like view filling the screen |
| `tigervncserver :99` | `:99` | `tigervnc-99.service` | Streamed back to `:0` via the noVNC viewer |
| `websockify` | n/a | `novnc.service` | TCP `:6080` (HTTP + WS bridge → `:5999`) |
| `relay serve --display :99` | `:99` (spawns Chromium here) | `dudenest-relay.service` | TCP `:8086` (Files API), and Chromium windows appear in the noVNC view |
| `relay update` | n/a | `dudenest-relay-update.timer` (24h) + `ExecStartPre` on boot | Auto-pulls newest release from GitHub Releases |

### Why two Xfce sessions?

The kiosk-novnc autostart script guards with `[ "$DISPLAY" = ":0" ] || exit 0` so it does **not** loop when Xfce also auto-starts on `:99`. Only `:0` runs the maximized Chromium viewer; `:99` is empty until the relay binary opens a Chromium window for OAuth.

---

## 🛠️ Bootstrap installation

Single command on a fresh Debian 12 VM / RPi (idempotent — safe to re-run):

```bash
curl -sSL https://raw.githubusercontent.com/dudenest/dudenest-relay/main/scripts/install.sh | sudo bash
```

What it installs:

| Step | What | Where |
|------|------|-------|
| 1 | apt packages (xorg, lightdm, xfce4, tigervnc, novnc, websockify, chromium, …) | system-wide |
| 2 | `dude` user (uid 1000, groups audio/video/plugdev) | `/etc/passwd` |
| 3 | LightDM autologin → Xfce | `/etc/lightdm/lightdm.conf.d/50-dudenest-autologin.conf` |
| 4 | Xfce autostart files (kiosk Chromium, no-compositing, hide light-locker) | `/home/dude/.config/autostart/*.desktop` |
| 5 | `dudenest.html` — cropped noVNC viewer | `/usr/share/novnc/dudenest.html` |
| 6 | ZeroTier client + join `932df01efb1ebd71` | `/var/lib/zerotier-one` |
| 7 | Relay binary from GitHub Releases + `relay.env` (preserved if exists) | `/usr/local/bin/relay`, `/etc/dudenest/` |
| 8 | 4 systemd units (`tigervnc-99`, `novnc`, `dudenest-relay`, `dudenest-relay-update.{service,timer}`) | `/etc/systemd/system/` |
| 9 | Wait for ZT hub to authorize + provision `relay_id` | logs |

Re-running on an existing relay (e.g. one bootstrapped before v0.8.0):
- apt packages already installed → skipped
- `dude` user exists → only group membership refreshed
- `relay.env` exists → **preserved** (`RELAY_KEY` is **never** overwritten)
- systemd units overwritten with the new canonical content → harmless restart

---

## 🌐 Public URL lifecycle (`RELAY_PUBLIC_URL` semantics)

**Critical**: how a relay learns and publishes its public URL determines whether Flutter can reach it.

### Two URL sources (mutually exclusive)

| Source | Used by | Value | Set by |
|--------|---------|-------|--------|
| **Auto (default for new relays)** | All relays bootstrapped via ZT `/relay/announce` flow | `https://relay-<8hex>.dudenest.com` | Hub: `dudenest-backup` `RegisterProvisionedRelay` (`uuid.New()[:8]`) |
| **Legacy hardcoded** | Only `relay-poc1` (historical) | `https://relay.dudenest.com` | `build.yml` job `deploy-relay-poc` writes `RELAY_PUBLIC_URL` to `relay.env` |

For **all new relays**, `install.sh` deliberately does **NOT** write `RELAY_PUBLIC_URL` to `relay.env`. The relay binary reads `cfg.Backup.PublicURL` (from env), and if empty, **trusts the URL the hub provided in `/relay/bootstrap` response** (persisted in `relay_creds.json`).

### Anti-regression guard (s313, 2026-05-21)

In `cmd/relay/serve.go:219`:

```go
if cfg.Backup.PublicURL != "" {
    if err2 := bc.UpdateURL(cfg.Backup.PublicURL); err2 != nil {
        log.Printf("⚠️  backup: update-url: %v", err2)
    }
}
```

**Why**: prior to s313, every relay restart unconditionally called `bc.UpdateURL(cfg.Backup.PublicURL)` → POST `/relay/update-url` to the hub. If an operator manually set `RELAY_PUBLIC_URL=https://relay2.dudenest.com` in `relay.env` (per an obsolete documentation plan), every restart re-asserted that manual URL to CRDB, **overwriting the auto-URL** generated at bootstrap. Flutter then routed to a non-existent URL.

Pair this with the **hub-side guard** in `dudenest-backup/internal/api/server.go` (`autoURLPattern` regex) which refuses 409 Conflict for any `/relay/update-url` request that downgrades an auto-URL to a manual URL. Defense in depth.

### When you DO need to set `RELAY_PUBLIC_URL`

Only on a legacy single-relay deployment that pre-dates ZT auto-provisioning (i.e., `relay-poc1`). For any new relay, leave it unset.

### Diagnosing URL mismatches

```bash
# Inspect what the relay believes its URL is:
ssh root@<relay> 'cat /etc/dudenest/relay_creds.json | python3 -m json.tool'

# Inspect what the hub has in CRDB:
ssh root@<swarm-node> 'docker exec dudenest-backup_backup wget -qO- http://localhost:8087/internal/relay/routes' \
  | python3 -m json.tool

# Inspect what Flutter receives:
curl -H "Authorization: Bearer <JWT>" "https://api.dudenest.com/api/v1/relays" | python3 -m json.tool
```

All three should agree on `https://relay-<8hex>.dudenest.com`. If `/etc/dudenest/relay.env` contains `RELAY_PUBLIC_URL=...` for a non-poc1 relay, **that's the bug** — remove it, restart relay, verify CRDB updated (or re-bootstrap).

Full recovery procedure: `~/.AI/dudenest-application/INCIDENT-RUNBOOK.md` "Relay-VM w CRDB ma zły relay_url".

---

## 🔄 Auto-update

Two complementary mechanisms:

1. **On every service start** — `dudenest-relay.service` has `ExecStartPre=-/usr/local/bin/relay update`, so a `systemctl restart dudenest-relay` always pulls the newest release first.
2. **Daily timer** — `dudenest-relay-update.timer`:
   - `OnBootSec=10min` (one check shortly after boot)
   - `OnUnitActiveSec=24h` (every 24h after that)
   - `RandomizedDelaySec=30min` (avoid thundering-herd against GitHub)
   - `Persistent=true` (runs at next boot if missed)
   The timer fires `dudenest-relay-update.service` which calls `relay update` and only restarts `dudenest-relay.service` if the binary was actually replaced (`grep -q "Updated to"`).

Status:

```bash
systemctl list-timers dudenest-relay-update.timer
journalctl -u dudenest-relay-update.service -n 20
/usr/local/bin/relay version
```

---

## ⚠️ DEPRECATED: Swarm deployment (2026-05-16)

**Decision**: Swarm-hosted `dudenest-relay_relay` service was **removed** on 2026-05-16.

**Why**: Alpine Docker container has no Chromium / X server → cannot run OAuth interactive flow. Service was structurally unable to authorize GDrive accounts and crashed on startup when env vars were unset (`GDRIVE_WEB_CLIENT_ID=""`). Multiple incidents traced to phantom replicas and overlay routing complexity with no operational benefit.

**Removed**:
- Swarm service `dudenest-relay_relay` (`docker stack rm dudenest-relay`)
- `deploy/relay-stack.yml`
- `.github/workflows/deploy.yml` (Swarm deploy)
- `docker` + `deploy-swarm` jobs from `build.yml`
- Step "Deploy dudenest-relay" from `dudenest-infra/disaster-recovery.yml`

**Retained** (current architecture — VM/RPi only):
- Binary build (Linux amd64/arm64/armv7, Darwin, Windows) — `.github/workflows/build.yml`
- GitHub Releases — `https://github.com/dudenest/dudenest-relay/releases/latest`
- `deploy-relay-poc` job → SSH to VM `relay-poc` (10.51.1.119) via ZeroTier
- `scripts/install.sh` — one-command setup for new VMs/RPi (Caddy + relay binary + systemd)
- HAProxy `relay.dudenest.com` routing → VM relay-poc:8086 (unchanged, no Swarm involvement)

**Future**: SaaS-managed relay (hosted by us in cloud, multi-tenant) is **planned** but on hold. Will require dedicated container image with Chromium baked in, or alternative non-interactive OAuth (Method A: Flutter-side OAuth — already supported by current relay binary). Re-evaluate when there's user demand.

The sections below describe the OLD Swarm architecture for historical reference. **DO NOT USE** for current deployments — see `scripts/install.sh` and `deploy/relay-poc/` for active deployment paths.

---

## Architecture Overview (DEPRECATED — historical reference)

```
Flutter app
  └── relay.dudenest.com (DNS A → 206.189.31.117 DigitalOcean, STATIC)
        └── HAProxy ns2 — TCP SNI frontend_443_prod → :12446
              └── frontend_relay_dudenest_12446 (SSL termination)
                    └── backend_relay_swarm → 10.51.1.{242,245,67,173}:8086 (ZeroTier)
                          └── Docker Swarm routing mesh → relay container
```

Key: ns2 has STATIC DigitalOcean IP. ZeroTier provides stable internal addresses.
Old route (BROKEN): Cloudflare → 82.6.132.243 (Virgin Media, DC-HFX, DYNAMIC) — DO NOT USE.

---

## Current State (2026-04-25)

| Component | Status | Detail |
|-----------|--------|--------|
| `relay.dudenest.com` DNS | ✅ | A record → 206.189.31.117 (ns2 DigitalOcean) |
| HAProxy ns2 | ✅ | SNI relay.dudenest.com → :12446 → backend_relay_swarm |
| Docker Swarm stack | ✅ | `dudenest-relay_relay` service, 1 replica |
| GHCR image | ✅ | `ghcr.io/dudenest/dudenest-relay:latest` (private, CI login) |
| Docker secrets | ✅ | relay_key, relay_jwt_secret, relay_gdrive_client_secret |
| `/health` | ✅ | HTTP 200 `{"status":"degraded","reason":"no cloud providers"}` |
| `/auth/url` | ✅ | HTTP 401 (needs JWT Bearer) — ACTIVE even in standby |
| `/files` | ⚠️ | HTTP 503 — standby, no OAuth tokens yet |
| OAuth tokens | ❌ | None — fresh install, no user has authorized yet |

---

## Docker Secrets (3 total)

| Secret name | Purpose | How to create |
|-------------|---------|---------------|
| `relay_key` | Master encryption key (DB at rest) | `openssl rand -hex 32` |
| `relay_jwt_secret` | JWT signing (shared with dudenest-backend) | `openssl rand -base64 32` |
| `relay_gdrive_client_secret` | Google OAuth app registration | `base64 -w0 gdrive_client_secret.json` → GitHub Secret `RELAY_GDRIVE_CLIENT_SECRET_B64` |

**NOT a secret**: Per-user GDrive tokens — stored at runtime in `relay_maps` volume per user.

Secrets are created automatically by `deploy-swarm` CI job (idempotent — skip if exists).
To rotate: use `.github/workflows/rotate-secrets.yml` (workflow_dispatch).

---

## First-Time OAuth Flow (to bring relay fully operational)

After fresh install, relay starts in standby. To add first GDrive account:

1. **Open dudenest Flutter app** → sign in → backend issues JWT
2. **In app: add GDrive account** → Flutter calls `GET https://relay.dudenest.com/auth/url` with `Authorization: Bearer <JWT>`
3. **Relay returns Google OAuth URL** (auth routes are ACTIVE in standby since s270)
4. **User authorizes** Google account in browser
5. **Token saved** to `/var/lib/dudenest/maps/providers/gdrive_*.json` (relay_maps volume)
6. **Restart relay container** (required — `getPipeline()` runs once at startup):
   ```bash
   docker service update --force dudenest-relay_relay
   ```
7. **Relay goes fully operational** — `/files` returns 200, `/health` returns `{"status":"ok"}`

---

## Routine Operations

### Check relay status
```bash
curl https://relay.dudenest.com/health
# Standby: {"status":"degraded","reason":"pipeline init: no cloud providers available"}
# Operational: ok
```

### View relay logs
```bash
# On any Swarm manager node:
docker service logs dudenest-relay_relay --tail 50 -f
```

### Force restart relay (e.g., after OAuth)
```bash
docker service update --force dudenest-relay_relay
```

### Check which Swarm node runs relay
```bash
docker service ps dudenest-relay_relay
```

### Deploy new version manually
```bash
# Push to main branch — CI/CD does it automatically
# Or trigger manually via GitHub Actions UI: Actions → Build Relay Binaries → Run workflow
```

---

## CI/CD Pipeline (`.github/workflows/build.yml`)

| Job | Trigger | Action |
|-----|---------|--------|
| `test` | push to main/tags | `go test ./... -v -race` |
| `build` | after test | Cross-compile 6 platforms → upload artifacts |
| `docker` | push to main/tags | Build multi-arch image (amd64/arm64/armv7) → push to GHCR |
| `deploy-swarm` | push to main | Create/verify Docker secrets → `docker stack deploy` |
| `release` | tags only | Create GitHub Release with all binaries |

**Runner**: `deploy-swarm` uses `self-hosted, netol-swarm` runner (ns2, has Docker socket).

**GHCR auth**: deploy-swarm logs into GHCR before deploy — `--with-registry-auth` distributes credentials to all Swarm nodes (needed because package is private).

---

## Secrets Rotation

```bash
# Via GitHub Actions UI (no SSH needed):
# Actions → Rotate Docker Secrets → Run workflow
# Select: relay_key | relay_jwt_secret | relay_gdrive_client_secret | all
```

**WARNING**: Rotating `relay_key` invalidates all encrypted data in relay_maps. Only rotate if key is compromised.

---

## Backup & Recovery

### Automated backup
`backup-volumes.yml` runs every 6h — copies `relay_maps` volume to ns2 (`/var/backups/dudenest/relay_maps/`).

### Manual backup
```bash
# On Swarm node where relay runs:
docker run --rm -v dudenest-relay_relay_maps:/data -v /var/backups:/backup \
  alpine tar czf /backup/relay_maps_$(date +%Y%m%d_%H%M%S).tar.gz -C /data .
```

### Restore from backup
```bash
# See: dudenest-infra/scripts/restore-relay-volume.sh
# Or: dudenest-infra/.github/workflows/disaster-recovery.yml
```

---

## Known Issues & Limitations

### P1: No `/admin/reload` endpoint
After OAuth via Flutter, relay must be manually restarted (`docker service update --force`).
`getPipeline()` is called once at startup — no hot reload.
**Workaround**: Manual restart. **Future fix**: Implement `POST /admin/reload` endpoint.

### P2: relay_maps volume on single node
`replicas: 1` — volume is local to the node running the container.
If that node dies: data not lost (backup every 6h on ns2), but manual restore required.
**Restore**: `dudenest-infra/scripts/restore-relay-volume.sh`

### P3: Old relay-poc VM (DC-HFX)
VM at 192.168.0.119 (Headscale 10.71.0.1) still exists, still has crash loop.
**Not used** — routing changed to Swarm. Can be powered off.
If re-auth needed: noVNC at `http://192.168.0.119:6080` via SSH tunnel through pve2.

---

## Network Reference

```
DigitalOcean (STATIC):
  ns2: 206.189.31.117 / ZeroTier 10.51.1.2
    └── HAProxy (TCP SNI → Swarm backends)

ZeroTier 10.51.1.0/24 (network 932df01efb506678):
  Swarm managers/workers: node001(221) node002(242) node003(245) node004(67) node005(173)

DC-HFX (DYNAMIC — NOT used for relay anymore):
  pve2: 192.168.0.48 / ZeroTier 10.51.1.22
    └── relay-poc VM: 192.168.0.119 (DEPRECATED)
```

---

## Files Reference

```
dudenest-relay/
  cmd/relay/serve.go          ← HTTP server, standby logic, isCredentialError
  cmd/relay/main.go           ← CLI, getClouds() path fix
  entrypoint.sh               ← Docker entrypoint, reads Docker secrets
  deploy/relay-stack.yml      ← Swarm stack (secrets, volumes, constraints)
  .github/workflows/
    build.yml                 ← CI/CD: test → docker → deploy-swarm → release
    rotate-secrets.yml        ← Secret rotation (workflow_dispatch)
    backup-volumes.yml        ← Volume backup (cron 6h)
    disaster-recovery.yml     ← Full DR pipeline

~/.AI/dudenest-application/
  STATE.md                    ← Project state, update after each session
  RELAY-OPS.md                ← THIS FILE (copy in .AI for agents)
  session-2026-04-25-relay-swarm-routing-fix.md  ← s270 session notes

dudenest-infra/
  docs/DISASTER-RECOVERY.md  ← DR runbook, secrets table
  scripts/restore-relay-volume.sh
  ansible/playbooks/bootstrap-ns2-runner.yml
```
