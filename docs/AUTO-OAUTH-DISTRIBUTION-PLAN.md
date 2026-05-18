# Auto-Distribution of GDrive OAuth Credentials — Implementation Plan

**Author**: Dariusz Porczyński
**Created**: 2026-05-18
**Status**: 📐 design — ready for implementation by next agent
**Priority**: 🔴 P0 — blocks every new relay from registering Google Drive accounts
**Scope**: 🌍 **GLOBAL — fleet-wide infrastructure change**. This is NOT a one-off fix for relay-poc2; it is the missing piece of the Dudenest relay fleet's secret-distribution architecture. After this lands, **every relay that ever exists** (relay-poc, relay-poc2, relay-poc3, ..., relay-poc-N — and every future user's home relay) pulls the OAuth Web Client credentials from the hub at provisioning time, with zero per-machine touching. The same mechanism also gives us a single-point rotation surface: change one Docker Swarm secret in `dudenest-backup`, restart every relay, and the entire fleet is on the new OAuth app credentials within a single auto-update cycle.

---

## 1. Problem statement

Today every Dudenest Relay bootstrapped via `scripts/install.sh` (v0.6.x through v0.8.2 inclusive) starts with a **placeholder** `/etc/dudenest/gdrive_client_secret.json` such as `{"type":"service_account"}` or `{"installed":{"client_id":"placeholder"}}`. When a user tries to add a Google Drive account via the Dudenest app, the relay launches Chromium with an invalid `client_id` and Google answers with:

```
Access blocked: Authorization Error
Missing required parameter: client_id
Error 400: invalid_request
```

This affects the entire relay fleet — every relay bootstrapped by the script is **structurally unable** to register a single cloud account. Today (2026-05-18) the impact is visible on relay-poc2; tomorrow it will affect relay-poc3, relay-poc4, and every home VM/RPi a user provisions. The only relay where OAuth works (`relay-poc`, `10.51.1.119`, Debian 12) was configured **by hand before the bootstrap existed** — it carries `client_id 932297984145-…googleusercontent.com` in a manually-installed `gdrive_client_secret.json`. That manual configuration is exactly the workflow we are eliminating.

The same Google OAuth **Web Client** credentials (registered once for the single Dudenest app at https://console.cloud.google.com) must end up on **every** relay in the fleet. They are not user-specific and not per-relay — per-user Google Drive tokens are obtained later via the OAuth flow and stored separately under `/var/lib/dudenest/maps/providers/`. The OAuth Web Client credentials are a **fleet-wide shared secret** that lives at the application level, identical on every machine.

### Why fleet-wide and not per-relay

- The Dudenest app is registered as a single OAuth client at Google. Every relay opening the OAuth flow MUST present the same `client_id`/`client_secret` — that is what Google authorized for the app.
- Treating this as a per-relay configuration is wrong by design: it would mean every user provisioning a home relay needs to register their own OAuth app at Google Cloud Console, which contradicts the Dudenest product promise of "plug in the relay, sign in to Google".
- This is the same pattern as `JWT_SECRET` and `BACKUP_URL` — fleet-wide values already delivered by the hub at provisioning time. We are just adding one more field to the same payload.

## 2. Architecture decision

Extend the **existing** ZT auto-provisioning bootstrap. Today the flow is:

```
relay.install.sh → relay binary at startup → POST /relay/announce        (dudenest-backup)
                                          ← {announce_id}
                                            GET  /relay/bootstrap?token=… (poll, hub-side ZT auth)
                                          ← {relay_id, relay_secret, relay_url, jwt_secret, backup_url}
```

The bootstrap response already delivers the most sensitive shared secret (`jwt_secret`). Adding the OAuth client_secret to the same response is **the cheapest, lowest-risk change** — no new endpoint, no new code path, no extra auth surface. The relay simply writes the extra field to a file at the canonical path.

**Single source of truth**: `dudenest-backup` reads the OAuth JSON from a deployment secret (e.g. Docker Swarm secret `relay_gdrive_client_secret`) and serves it as part of `/relay/bootstrap`. Rotation of the OAuth app credentials becomes a single Docker secret update; every relay picks up the new credentials on its next restart/registration without any per-host action.

## 3. Repos & files to change

### 3.1 `dudenest-backup` — extend bootstrap response

**File**: `internal/api/server.go`

```go
// Server struct (around line 25-30) — add field
type Server struct {
    // … existing fields …
    jwtSecret             string
    gdriveClientSecretJSON string // raw JSON content of Google OAuth Web Client (Server.handleBootstrap returns this)
}

// NewServer(...) — accept additional arg, populate from env var or file at startup
// (env var GDRIVE_CLIENT_SECRET_JSON or file pointed at by GDRIVE_CLIENT_SECRET_JSON_FILE)
```

**File**: `internal/api/server.go` — `handleBootstrap` (line 315-343)

```go
json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
    "relay_id":              relay.RelayID,
    "relay_secret":          relay.RelaySecret,
    "relay_url":             relay.RelayURL,
    "jwt_secret":            s.jwtSecret,
    "backup_url":            "https://backup.dudenest.com",
    "gdrive_client_secret":  s.gdriveClientSecretJSON, // NEW — full JSON contents
})
```

**File**: `cmd/backup/main.go` (or wherever `NewServer` is constructed) — load the env/file at startup, pass to `NewServer`.

**File**: `internal/api/server_test.go` — extend `TestBootstrap*` to assert the new field is in the response.

### 3.2 `dudenest-relay` — accept + persist OAuth credentials

**File**: `internal/register/client.go` — `BootstrapPayload` (line 156-163)

```go
type BootstrapPayload struct {
    JWTSecret          string `json:"jwt_secret"`
    RelayID            string `json:"relay_id"`
    RelaySecret        string `json:"relay_secret"`
    RelayURL           string `json:"relay_url"`
    BackupURL          string `json:"backup_url"`
    GdriveClientSecret string `json:"gdrive_client_secret"` // NEW — written to <configDir>/gdrive_client_secret.json
}
```

**File**: `internal/register/client.go` — `WriteBootstrapCreds` (line 202-216)

```go
func WriteBootstrapCreds(configDir string, p *BootstrapPayload) (*Credentials, error) {
    // … existing logic to write relay_creds.json + jwt_secret.txt …
    if p.GdriveClientSecret != "" {
        path := filepath.Join(configDir, "gdrive_client_secret.json")
        // Only overwrite a placeholder, not real credentials that may have been set manually
        if shouldReplace(path) {
            if err := os.WriteFile(path, []byte(p.GdriveClientSecret), 0o600); err != nil {
                log.Printf("register: ⚠️  failed to write gdrive_client_secret.json: %v", err)
            } else {
                log.Printf("register: ✅ gdrive_client_secret.json updated from hub")
            }
        }
    }
    // … existing log.Printf …
}

// shouldReplace returns true if the file is missing OR contains a placeholder
// like `{"type":"service_account"}` or `{"installed":{"client_id":"placeholder"}}`.
func shouldReplace(path string) bool {
    data, err := os.ReadFile(path)
    if err != nil { return true } // missing
    s := string(data)
    return strings.Contains(s, `"placeholder"`) || strings.Contains(s, `"service_account"`)
}
```

**File**: `internal/register/client_test.go` — add test that `WriteBootstrapCreds` writes the JSON when payload contains `gdrive_client_secret`, and that it preserves an existing real credential file.

### 3.3 `dudenest-relay/scripts/install.sh` — drop the placeholder

Around the current block (Step 7):

```bash
# REPLACE this …
if [[ -f "$CONFIG_DIR/client_secret.json" && ! -e "$CONFIG_DIR/gdrive_client_secret.json" ]]; then
  ln -s client_secret.json "$CONFIG_DIR/gdrive_client_secret.json"
  …
elif [[ ! -f "$CONFIG_DIR/gdrive_client_secret.json" ]]; then
  echo '{"installed":{"client_id":"placeholder"}}' > "$CONFIG_DIR/gdrive_client_secret.json"
  …
fi

# … with this (no placeholder; relay will fetch on first bootstrap):
if [[ -f "$CONFIG_DIR/client_secret.json" && ! -e "$CONFIG_DIR/gdrive_client_secret.json" ]]; then
  ln -s client_secret.json "$CONFIG_DIR/gdrive_client_secret.json"
  ok "Linked legacy client_secret.json → gdrive_client_secret.json"
else
  ok "OAuth gdrive_client_secret.json will be delivered by hub on first /relay/bootstrap"
fi
```

Also document in CHANGELOG.md (v0.8.1 or v0.9.0) that OAuth credentials no longer need to be pre-provisioned.

### 3.4 `dudenest-infra` — wire the secret into the deployment

The deployment for `dudenest-backup` (or whichever service serves `/relay/bootstrap`) needs to mount the OAuth JSON.

**Architecture boundary** (important — easy to misread):
- `dudenest-relay` is a VM/RPi binary; **it never touches Docker, never runs as a container, never knows about Swarm**. Removed from Swarm on 2026-05-16 specifically because it needs Chromium + X server (see §RELAY-OPS for full reasoning).
- `dudenest-backup` (the hub that serves `/relay/bootstrap`) **runs on Docker Swarm** as a normal NETOL SaaS service. See `dudenest-backup/deploy/backup-stack.yml`. The OAuth credentials need to be available to that container as a file or env var — using a Docker Swarm secret is the natural mechanism because that's how every other secret in the backup deployment is wired (`CRDB_DSN`, `JWT_SECRET`, `HUB_INTERNAL_TOKEN` per `deploy/backup-stack.yml`).
- So when this section talks about "Docker secret" it means **on the backup side only**. The relay binary fetches the credentials via plain HTTP — it doesn't care how the backend stored them.

Concrete change for backup:

- Add a Docker Swarm secret `relay_gdrive_client_secret` populated from GitHub Actions secret `RELAY_GDRIVE_CLIENT_SECRET_B64` (already present per legacy `docs/RELAY-OPS.md` — it was originally created for the now-removed Swarm-hosted relay, but the GH secret can be reused 1:1). The CI workflow base64-decodes and creates the Swarm secret at deploy time, the backup container reads it via a mounted file.

  ```yaml
  # dudenest-backup/deploy/backup-stack.yml
  services:
    backup:
      environment:
        - CRDB_DSN=${CRDB_DSN}
        - JWT_SECRET=${JWT_SECRET}
        - HUB_INTERNAL_TOKEN=${HUB_INTERNAL_TOKEN}
        - GDRIVE_CLIENT_SECRET_JSON_FILE=/run/secrets/relay_gdrive_client_secret   # NEW
      secrets:                                                                       # NEW
        - relay_gdrive_client_secret                                                 # NEW
  secrets:                                                                           # NEW
    relay_gdrive_client_secret:                                                      # NEW
      external: true                                                                 # NEW
  ```

  ```bash
  # dudenest-backup/.github/workflows/build.yml — Deploy stack step
  echo "${{ secrets.RELAY_GDRIVE_CLIENT_SECRET_B64 }}" | base64 -d | \
    docker secret create relay_gdrive_client_secret - || true   # idempotent
  ```

- The backup Go service then loads it at startup. From `cmd/backup/main.go`, before constructing `Server`:

  ```go
  oauthJSON := os.Getenv("GDRIVE_CLIENT_SECRET_JSON")
  if path := os.Getenv("GDRIVE_CLIENT_SECRET_JSON_FILE"); path != "" {
      b, err := os.ReadFile(path)
      if err != nil { log.Fatalf("read GDRIVE_CLIENT_SECRET_JSON_FILE: %v", err) }
      oauthJSON = string(b)
  }
  // pass oauthJSON into NewServer(...)
  ```

  Supporting both env var and file lets the same code run under Docker Swarm (file from `/run/secrets/...`) AND in local dev (just set the env var). No other deployment path is needed today — the entire Dudenest SaaS surface runs on the NETOL Swarm.

## 4. Acceptance criteria — fleet-wide

These criteria apply to **every relay in the fleet**, current and future. The implementation is not done until all four pass on at least two distinct relays (one Debian, one Ubuntu) AND on a fresh-from-scratch VM.

1. **Fresh-VM bootstrap (zero-touch)** — provision a brand-new Debian 12 or Ubuntu 24.04 VM (no prior dudenest state), run `curl -sSL https://raw.githubusercontent.com/dudenest/dudenest-relay/main/scripts/install.sh | sudo bash`, wait for ZT provisioning. After the run:
   - `/etc/dudenest/gdrive_client_secret.json` exists and contains `"client_id":"932297984145-…"` (or the current Dudenest OAuth Web Client ID).
   - Opening the Dudenest app → Add Cloud Account → Google OAuth flow shows the Google login screen (not "Authorization Error").
   - No operator ever SSH'd into the VM to touch credentials.
2. **OAuth rotation across the entire fleet** — operator changes the Docker secret `relay_gdrive_client_secret` in production once; restarts `dudenest-backup`. Then for every relay (relay-poc, relay-poc2, every future relay): a single `systemctl restart dudenest-relay` (or just waiting one `dudenest-relay-update.timer` cycle = 24 h) replaces `/etc/dudenest/gdrive_client_secret.json` with the new value. **Zero per-relay touching.**
3. **No regression on hand-configured legacy relays** — relay-poc (originally configured by hand, now migrated to v0.8.2 paths) carries `client_id 932297984145-…` and continues to work. Re-running `install.sh` does not overwrite it. Verified by `shouldReplace()` returning `false` for files that don't contain placeholder markers (`"placeholder"`, `"service_account"`).
4. **install.sh stops creating placeholders** — every reference to writing `{"installed":{"client_id":"placeholder"}}` or `{"type":"service_account"}` is removed from `scripts/install.sh`. After a fresh `install.sh` run before `/relay/bootstrap` returns, the file simply does not exist — there is nothing to "replace later". The bootstrap fetch is the only source of truth.

## 5. Rollout sequence — fleet-wide

This is a 4-repo coordinated rollout. Order matters: backend must serve the new field BEFORE relay binary tries to consume it.

1. **`dudenest-infra`** — add Docker Swarm secret `relay_gdrive_client_secret` (populated from existing GitHub Actions secret `RELAY_GDRIVE_CLIENT_SECRET_B64` — already present per `dudenest-relay/docs/RELAY-OPS.md`), mount into `dudenest-backup` service. Deploy. Backend now has the secret available but doesn't serve it yet.
2. **`dudenest-backup`** — implement the API change (§3.1). Tag + release. CI redeploys the backup service. Verify: `curl ".../relay/bootstrap?announce_token=<test>"` returns the new `gdrive_client_secret` field for a test announce.
3. **`dudenest-relay`** — implement the consumer side (§3.2) + drop install.sh placeholder (§3.3). Tag v0.9.0. CI publishes binaries. **Critical**: relay code must tolerate older backends (empty `gdrive_client_secret` → no-op, keep whatever is there) so the relay binary release can land before EVERY infrastructure node finishes upgrading.
4. **Fleet rollout — automatic** — `dudenest-relay-update.timer` (already on every relay since v0.8.0) picks up the new relay binary within 24 h. On the next `systemctl restart dudenest-relay` (also automatic via the timer's restart-if-updated logic), every relay calls `/relay/bootstrap` and receives the OAuth credentials. **No manual SSH to any relay.**

## 6. Interim manual fix (TEMPORARY — must be deleted after §5 lands)

Until the four-repo rollout in §5 ships, an operator with access to `relay-poc` (the only relay with real credentials today) can seed any other relay manually:

```bash
scp root@10.51.1.119:/etc/dudenest/gdrive_client_secret.json root@<new-relay-ip>:/etc/dudenest/gdrive_client_secret.json
ssh root@<new-relay-ip> 'systemctl restart dudenest-relay'
```

This is the **only** manual step that is allowed to exist in the project, and only while §5 is in progress. The day §5 ships, this section is deleted from the docs, the placeholder-creation logic is removed from install.sh, and the fleet operates fully hands-off — every new relay (relay-poc-N for N > 2, every user's home VM) bootstraps without anyone running `scp` or `systemctl restart` by hand.

## 7. Risks & mitigations

| Risk | Mitigation |
|------|-----------|
| OAuth Web Client secret leaks via `/relay/bootstrap` (currently a public endpoint guarded only by a single-use `announce_token`) | The endpoint is already used to ship `jwt_secret`, which is at least as sensitive. The `announce_token` is one-time and consumed atomically. No new attack surface. |
| Real credentials on relay-poc get overwritten with placeholder during a re-register | `shouldReplace()` guards against this by inspecting the existing file for known placeholder markers before writing. Real credentials (contain `"web":{"client_id":"932297984145-..."}`) are never touched. |
| Operator forgets to populate `RELAY_GDRIVE_CLIENT_SECRET_B64` in CI secrets before merging the backend change | Backup returns an empty `gdrive_client_secret` field → relay logs `register: gdrive_client_secret empty in payload — keeping existing file` and falls back to whatever was there. No crash, easy to spot in monitoring. |
| Older relay binary (pre-v0.9.0) hits the new backend and ignores the unknown field | JSON unmarshal in Go silently drops unknown fields. Pre-v0.9.0 relays keep working with their placeholder (no behavior change). The transition is forward-compatible. |
| Newer relay binary (v0.9.0+) hits an older backend that doesn't serve the field | Empty string is the zero value. `if p.GdriveClientSecret != ""` skips the write. The relay falls back to whatever was already on disk. Forward + backward compatible. |

## 8. Future extensions (out of scope for this PR, but built on the same mechanism)

The fleet-wide credential delivery channel established here unblocks several follow-ups. Each of these is **out of scope for the v0.9.0 release** but should be filed as separate tickets so the design intent isn't lost:

- **Multi-provider OAuth**: MEGA, OneDrive, pCloud, Filen, Box, Icedrive, Koofr, Backblaze B2, Storj — same pattern with `mega_client_secret`, `onedrive_client_secret`, etc. fields. Implement per-provider when each is wired into the relay's `internal/cloudconn/`.
- **JWT_SECRET rotation visibility**: today JWT_SECRET is delivered by the same `/relay/bootstrap` payload but rotation requires a full relay reboot. Could be hot-reloaded by the same code path on subsequent fetches.
- **Per-relay distinct OAuth clients**: current design intentionally uses a single shared Dudenest OAuth Web Client across the whole fleet. If multi-tenancy (e.g. each user gets their own Google Cloud project + OAuth app for stricter isolation) is ever required, the mechanism extends naturally — backend just looks up the per-relay OAuth client by `relay_id` instead of returning the fleet-wide one.

---

**Next agent: see `~/.AI/dudenest-application/NEXT-AGENT-INSTRUCTIONS.md` for a self-contained handoff checklist. This plan is FLEET-WIDE infrastructure, not a one-off patch.**
