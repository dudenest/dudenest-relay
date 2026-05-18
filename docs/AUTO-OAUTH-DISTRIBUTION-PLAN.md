# Auto-Distribution of GDrive OAuth Credentials — Implementation Plan

**Author**: Dariusz Porczyński
**Created**: 2026-05-18
**Status**: 📐 design — ready for implementation by next agent
**Priority**: 🔴 P0 — blocks every new relay from registering Google Drive accounts

---

## 1. Problem statement

Today every new Dudenest Relay (e.g. relay-poc2 bootstrapped via `scripts/install.sh v0.8.0`) starts with a **placeholder** `/etc/dudenest/gdrive_client_secret.json` such as `{"type":"service_account"}` or `{"installed":{"client_id":"placeholder"}}`. When the user tries to add a Google Drive account via the Dudenest app, the relay launches Chromium with an invalid `client_id` and Google answers with:

```
Access blocked: Authorization Error
Missing required parameter: client_id
Error 400: invalid_request
```

This affects relay-poc2 right now (`192.168.1.127`, Ubuntu 24.04) and will affect every future relay (relay-poc3, relay-poc4, …) unless the OAuth credentials are distributed automatically.

The same Google OAuth **Web Client** credentials (registered for the single Dudenest app at https://console.cloud.google.com) must end up on every relay. They are not user-specific — per-user Google Drive tokens are obtained later via the OAuth flow and stored separately under `/var/lib/dudenest/maps/providers/`.

The existing reference relay (`relay-poc`, `10.51.1.119`, Debian 12) was configured by hand before the bootstrap was automated, so it already has the right `gdrive_client_secret.json` (`932297984145-…googleusercontent.com`).

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

- Add Docker Swarm secret `relay_gdrive_client_secret` populated from GitHub Actions secret `RELAY_GDRIVE_CLIENT_SECRET_B64` (already exists per old `docs/RELAY-OPS.md` — it was used for the Swarm relay before Swarm was removed). Decode at deploy time:

  ```yaml
  # deploy/backup-stack.yml (or equivalent)
  services:
    backup:
      environment:
        - GDRIVE_CLIENT_SECRET_JSON_FILE=/run/secrets/relay_gdrive_client_secret
      secrets:
        - relay_gdrive_client_secret
  secrets:
    relay_gdrive_client_secret:
      external: true
  ```

- CI job to create the secret (similar to the existing `relay_jwt_secret` creation):

  ```bash
  echo "$RELAY_GDRIVE_CLIENT_SECRET_B64" | base64 -d | docker secret create relay_gdrive_client_secret -
  ```

- If the backup service is not running under Swarm, mount as a file via the equivalent mechanism (systemd EnvironmentFile, Kubernetes Secret, etc.).

## 4. Acceptance criteria

1. **Fresh-VM bootstrap** — provision a fresh Debian 12 or Ubuntu 24.04 VM, run `curl -sSL https://raw.githubusercontent.com/dudenest/dudenest-relay/main/scripts/install.sh | sudo bash`, wait for ZT provisioning to complete. After the run:
   - `/etc/dudenest/gdrive_client_secret.json` exists and contains `"client_id":"932297984145-…"` (or the current Dudenest OAuth Web Client ID).
   - Opening the Dudenest app → Add Cloud Account → Google OAuth flow shows the Google login screen (not "Authorization Error").
2. **OAuth rotation** — change the Docker secret `relay_gdrive_client_secret` in production; restart `dudenest-backup`; restart any relay (e.g. `systemctl restart dudenest-relay` on relay-poc); the relay's `/etc/dudenest/gdrive_client_secret.json` updates to the new value within one bootstrap cycle.
3. **No regression on existing relays** — relay-poc (already manually configured) re-runs `install.sh` (or upgrades to the new relay binary); its existing real credentials are NOT overwritten. Verified by `shouldReplace()` returning `false` for files that don't contain placeholder markers.

## 5. Rollout sequence

1. **dudenest-backup** PR → merge → CI deploys backup with the new env/secret wired in.
2. **dudenest-infra** PR (if separate) → adds the Docker secret + secret to the stack.
3. **dudenest-relay** PR → release as v0.9.0 (or v0.8.1 if treated as fix). CI publishes GH Release with binaries.
4. **dudenest-relay-update.timer** on every existing relay picks up the new binary within 24 h; on next restart, relay calls `/relay/bootstrap` and receives the OAuth credentials.

## 6. Interim manual fix (one-time, only for relays bootstrapped before this plan lands)

Until the above is shipped, an operator with access to `relay-poc` can copy the JSON to any new relay:

```bash
scp root@10.51.1.119:/root/.config/dudenest/gdrive_client_secret.json root@<new-relay-ip>:/etc/dudenest/gdrive_client_secret.json
ssh root@<new-relay-ip> 'rm -f /etc/dudenest/client_secret.json && systemctl restart dudenest-relay'
```

This is the **only manual step** that needs to exist while the auto-distribution is being implemented. Once shipped, it goes away forever.

## 7. Risks & mitigations

| Risk | Mitigation |
|------|-----------|
| OAuth Web Client secret leaks via `/relay/bootstrap` (which is currently a public endpoint guarded only by a single-use `announce_token`) | The endpoint is already used to ship `jwt_secret`, which is at least as sensitive. The `announce_token` is one-time and consumed atomically. No new attack surface. |
| Real credentials on relay-poc get overwritten with placeholder during a re-register | `shouldReplace()` guards against this by inspecting the existing file for known placeholder markers before writing. |
| Operator forgets to populate `RELAY_GDRIVE_CLIENT_SECRET_B64` in CI secrets before merging | Backup will return an empty `gdrive_client_secret` field → relay logs `register: gdrive_client_secret empty in payload — keeping existing file` and falls back to whatever was there. No crash. |

## 8. Out of scope

- Multi-provider OAuth (MEGA, OneDrive, pCloud, …) — same pattern can be applied with `mega_client_secret`, `onedrive_client_secret`, etc. fields. Implement when those providers are wired up.
- Per-relay distinct OAuth clients — current design intentionally uses a single shared Dudenest OAuth Web Client across all relays. If multi-tenancy ever requires per-relay OAuth apps, that's a separate design.

---

**Next agent: see `~/.AI/dudenest-application/NEXT-AGENT-INSTRUCTIONS.md` for a self-contained handoff checklist.**
