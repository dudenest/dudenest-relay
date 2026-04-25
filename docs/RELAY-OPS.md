# dudenest-relay — Operational Guide

**Last Updated**: 2026-04-25 (s270)
**Author**: Dariusz Porczyński
**Status**: ✅ Relay deployed on NETOL Docker Swarm — standby mode, awaiting first OAuth

---

## Architecture Overview

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
