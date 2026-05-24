# Multi-Account Orchestration — Reference

**Status**: Phase α LIVE (v0.17.2+). Phase β/γ planned — see `~/.AI/dudenest-application/CLOUD-ACCOUNT-POLICY-PLAN.md`.
**Last updated**: 2026-05-22 (post v0.17.3 hotfix for folder classification)

This document is the **operator + developer reference** for the multi-account selection layer.
Every public function, every CloudAccount field, every AccountPolicyConfig knob is described here.
If a future agent needs to understand "what does X do, why does it exist, when does it fire" — this is the doc.

---

## 1. Why this exists

Pre-v0.17.2 behavior:
- `upload` hardcoded `limit := 2` and `p.clouds[:limit]`.
- `p.clouds` came from `factory.LoadAllProviders` which iterated `os.ReadDir(providers/)` — **filesystem order**, typically alphabetical by `gdrive_<email>.json`.
- User with 3+ cloud accounts: **only the first two alphabetically** got new files. Account #3 was effectively dead for upload (still visible via scan engine for read).
- Zero configurability without code change.

Phase α (v0.17.2) replaced this with a policy-driven selector. The design goal: support **dozens of accounts per user** with per-account roles, priority, quota gates, and content-type filters — all configurable from one place (Settings → Cloud Accounts in Flutter, Phase β UI).

---

## 2. Data model

### `pkg/types/accounts.go`

#### `CloudAccount` struct

One record per cloud account the user has attached. Stored as `[]CloudAccount` in `~/.config/dudenest/accounts.json`. **Soft-deleted (Status=Removed) records are retained** for audit + scan reconciliation; IDs are never reused.

| Field | Type | Default | Purpose |
|-------|------|---------|---------|
| `ID` | `int64` | auto monotonic | Stable identifier. NEVER reused, even after Drain+Remove. NextID = max(all IDs)+1. |
| `Provider` | `string` | required | Cloud type: `"gdrive"`, `"mega"`, `"onedrive"`, `"local"`. |
| `Email` | `string` | required | User-recognizable label. Unique per `(Provider, relay)`. Used to map back to `CloudProvider.ID()` via `"<provider>:<email>"`. |
| `AddedAt` | `time.Time` | now | When the account was first attached. Used as a tie-breaker in selection (older wins on equal priority + free space). |
| `RemovedAt` | `*time.Time` | nil | Set when Drain completes. nil for active accounts. |
| `Role` | `Role` | `PrimaryWrite` for #1, `ReplicaWrite` for #2+ | State machine bucket (see §2.2). |
| `Priority` | `int` | dense, 0..N-1 | Ordering within selection. 0 = highest. Reordered on add/remove. |
| `Pinned` | `bool` | false | When true, `ReconcileRoles` skips auto-demote/promote for this account (user override). |
| `QuotaTotalBytes` | `int64` | 0 | Total capacity from provider API. 0 means "unknown" — `FreeBytes()` returns 0 in that case to avoid claiming infinite room. |
| `QuotaUsedBytes` | `int64` | 0 | Bytes consumed on this account. |
| `QuotaCheckedAt` | `time.Time` | zero | Last successful quota refresh. Drives the polling cadence. |
| `SoftCapPct` | `*int` | inherit cfg | If non-nil, overrides global `SoftCapDefaultPct`. % at which the role auto-demotes from PrimaryWrite to ReplicaWrite. |
| `HardCapPct` | `*int` | inherit cfg | If non-nil, overrides global `HardCapDefaultPct`. % at which writes are rejected outright (`SelectReplicas` excludes). |
| `MaxFileSizeBytes` | `*int64` | inherit cfg `MaxFileSizeDefaultMB*1MB` | If non-nil, per-file cap. Useful for MEGA free (~100 MB) or any provider with per-file limits. |
| `AcceptsContentTypes` | `*[]string` | nil = accept all | Whitelist e.g. `["photos"]` to make this account photos-only. Compared case-insensitive against `FileMeta.ContentType` (`"photos"` or `"files"`). |
| `Region` | `string` | "" | Forward-compat F4 multi-region (e.g. `"eu-west"`). When set + `DiversityRegionRequired=true`, replicas spread across regions. |
| `CompressionLevel` | `int` | 0 | Forward-compat F3 deep archive (zstd 0-9). Used only by future age-rotation worker, not by SelectReplicas. |
| `LogicalAliasOK` | `bool` | false | Forward-compat F2 dedup. When true, this account may host LogicalAlias targets. |
| `Status` | `Status` | `Active` | Lifecycle state (see §2.3). |
| `LastError` | `string` | "" | Last error message (rotation tracking). |
| `LastSeenAt` | `time.Time` | zero | Last successful API call. |
| `QuarantineUntil` | `*time.Time` | nil | Exp-backoff target. While set + after now, account is excluded from selection. |

#### `Role` enum (§2.2)

```go
const (
    RolePrimaryWrite Role = "primary_write" // takes new uploads first (highest-priority pool)
    RoleReplicaWrite Role = "replica_write" // takes replicas after PrimaryWrite (default for accounts #2+)
    RoleReadOnly     Role = "read_only"     // no writes; serves reads only (scan files / cold pre-existing content)
    RoleColdArchive  Role = "cold_archive"  // receives age-rotated files (zstd-compressed) — user-opt-in via cfg.AgeBasedRotation
    RoleDrain        Role = "drain"         // user-initiated remove — Phase β worker migrates files away then transitions to Removed
    RoleQuarantine   Role = "quarantine"    // transient — auth/API issue, exp backoff, returns to previous role on success
)
```

Selection eligibility: only `PrimaryWrite` and `ReplicaWrite` receive new uploads. ColdArchive receives content via age-rotation worker (Phase γ), never via direct upload. ReadOnly/Drain/Quarantine are read-only.

#### `Status` enum (§2.3)

```go
const (
    StatusActive       Status = "active"        // healthy; obeys Role for read+write
    StatusReauthNeeded Status = "reauth_needed" // OAuth expired/revoked; user must re-auth in UI (Phase β)
    StatusOverQuota    Status = "over_quota"    // exceeded HardCapPct; writes rejected, reads continue
    StatusError        Status = "error"         // generic API failure; may be quarantined
    StatusRemoved      Status = "removed"       // soft-deleted (Drain done); audit-retained
)
```

`Status` is orthogonal to `Role`. SelectReplicas requires `Status == StatusActive`.

#### `AccountPolicyConfig` (global)

Stored as `~/.config/dudenest/account_policy.json`. 26 fields, **every one user-configurable from UI** (Phase β `/admin/policy` endpoint).

Replication:
- `ReplicationFactor int` — default 2; how many replicas SelectReplicas tries to return. Legal `[1, len(active_accounts)]`.
- `DiversityRequired bool` — default false; when true, each replica must be on a different `Provider` type.
- `DiversityRegionRequired bool` — F4 multi-region; default false.
- `AllowSingleReplicaWithWarning bool` — default true; when true, SelectReplicas returns whatever it can (even 1 replica) + caller logs warning. When false, fewer-than-RF candidates → `ErrInsufficientReplicas`.

Quotas:
- `QuotaCheckIntervalMin int` — default 30; how often Phase β quota poller refreshes per-account capacity.
- `SoftCapDefaultPct int` — default 90; the % above which Phase β auto-demotes PrimaryWrite to ReplicaWrite (per-account override via `CloudAccount.SoftCapPct`).
- `HardCapDefaultPct int` — default 98; absolute write cutoff (per-account override).
- `MaxFileSizeDefaultMB int64` — default 5000; per-file write cap.

Promotion / demotion (Phase β):
- `AutoDemoteOnSoftCap bool` — default true.
- `AutoPromoteOnSpace bool` — default true.
- `PromoteStrategy string` — default `"by_priority"`. Alternatives: `"by_free_pct"`, `"by_age_oldest_first"`, `"round_robin"`.

Age-based rotation (Phase γ):
- `AgeBasedRotation bool` — default false; master switch.
- `AgeRotationDays int` — default 30; files older than this become candidates for migration off PrimaryWrite.
- `AgeRotationTargetRole string` — default `"read_only"`. Set to `"cold_archive"` to migrate to compressed cold tier.

Re-add semantics:
- `OnReAddSameEmail string` — default `"prompt_user"`. Alternatives: `"restore_old_id"`, `"create_new_id"`. Controls what happens when the user attaches an account whose `(provider, email)` matches a previously-Removed record.

Rebalance:
- `RebalanceOnAdd string` — default `"manual"`. Alternatives: `"auto_if_imbalance_pct_above"`, `"never"`.
- `RebalanceImbalanceThresholdPct int` — default 30.

Path layout (§5):
- `PathScheme string` — default `"year_month"` (unchanged from pre-Phase α per user decision §11 #5). Alternatives: `"year_month_day"`, `"flat"`.
- `PathRoot string` — default `"dudenest"`. **All cloud paths prefixed with this**, e.g. `dudenest/photos/2026/05/foo.jpg`. Empty string means no prefix (legacy).

Drain / Remove (Phase β):
- `DrainMaxConcurrentMigrations int` — default 4.
- `DrainBatchSizeBytes int64` — default 100 MB.
- `DrainBandwidthLimitMBPerSec int` — default 0 (no limit).

Future-compat (F1-F3, Phase γ):
- `DuplicateDetectionEnabled bool` — default false.
- `DuplicateDetectionMethod string` — `"sha256"` or `"perceptual_hash_for_images"`.
- `DedupEnabled bool` — default false; requires F1.
- `DeepArchiveEnabled bool` — default false.
- `DeepArchiveMinAgeDays int` — default 180.
- `DeepArchiveCompressionLevel int` — default 3 (zstd).

`DefaultPolicy()` returns the **Standard** preset (user decision §11 #2) — the values shown above.

#### Helper methods on `CloudAccount`

| Method | Returns | What it does |
|--------|---------|--------------|
| `DisplayID() string` | e.g. `"ID001"`, `"ID042"`, `"ID999"`, `"ID1000"` | User-facing label. Zero-padded to 3 digits below 1000, no padding above. |
| `FreeBytes() int64` | `int64` ≥ 0 | `QuotaTotalBytes - QuotaUsedBytes` clamped to ≥ 0. **Returns 0** when `QuotaTotalBytes == 0` (unknown). |
| `UsedPercent() int` | 0..100 | `100 * QuotaUsedBytes / QuotaTotalBytes`, defensive clamp. Returns 0 if quota unknown. |
| `AcceptsContentType(ct string) bool` | bool | True if `AcceptsContentTypes` is nil/empty (accept all) or contains `ct` (case-insensitive trim). |

#### Helper methods on `AccountPolicyConfig`

| Method | Returns | Behavior |
|--------|---------|----------|
| `PathFor(folder, name string, when time.Time) string` | e.g. `"dudenest/photos/2026/05/foo.jpg"` | Renders cloud path per `PathScheme`. Unknown scheme falls back to `"year_month"` (production default). Always UTCs `when`. |

---

## 3. Manager — `internal/account/manager.go`

The Manager owns the on-disk state plus pure selection algorithm. One `Manager` per relay (singleton). Created in `cmd/relay/serve.go` after pipeline initialization.

### `New(configDir string) (*Manager, error)`

Loads `accounts.json` + `account_policy.json` from `configDir`. Missing files are silently initialized:
- Missing `account_policy.json` → `DefaultPolicy()`
- Missing `accounts.json` → `nil` (empty list)

Both subsequent saves use atomic write (tmp+rename), safe against crash mid-write.

### `Accounts() []*CloudAccount`

Returns a **deep copy** of all accounts (active + Removed). Caller may not mutate the returned slice — use the typed mutators (`AddAccount`, `Reorder`, `SetRole`).

### `ActiveAccounts() []*CloudAccount`

Like `Accounts()` but filters `Status != Removed`. This is what UI lists show + what the selection algorithm sees.

### `Policy() AccountPolicyConfig` / `UpdatePolicy(p) error`

Read/write the global policy. `UpdatePolicy` persists immediately (atomic write).

### `NextID() int64`

Returns `max(all_IDs) + 1`. Walks **all** records including Removed so IDs never collide.

### `AddAccount(provider, email string) (*CloudAccount, error)`

Creates a new record:
- ID = `NextID()`
- AddedAt = now
- Role = `PrimaryWrite` if no other Active accounts exist, else `ReplicaWrite`
- Priority = `max(active_priorities) + 1`
- Status = `Active`

Returns the new account + persists. **Special return**: `errReAddDetected` (check via `IsReAddError(err)`) when `(provider, email)` matches an existing record. In Phase α this surfaces the existing record to the caller; Phase β's UI prompts user per `cfg.OnReAddSameEmail`.

### `Reorder(ids []int64) error`

Applies a new priority sequence given the desired order. IDs missing from the list keep their relative order and go to the back (dense indexing). Errors on unknown IDs. Persists on success.

This is the path used when a user drags-and-drops in the UI.

### `SetRole(id int64, role Role) error`

Flips a single account's role + persists. Used by:
- Phase β `ReconcileRoles` loop (auto-demote/promote)
- Phase β admin endpoint `PATCH /admin/accounts/{id}`
- Drain workflow (`Drain → Removed`)

### `BootstrapFromProviders(providerIDs []string) (int, error)`

**Migration helper.** First-run path for existing relays (relay-poc1/poc2) that had `providers/*.json` files but no `accounts.json` yet. Called from `cmd/relay/serve.go` when `len(Accounts()) == 0`.

Parses each `providerID` (format `"<provider>:<email>"`, e.g. `"gdrive:user@x.com"`) and creates a `CloudAccount`:
- ID = `1, 2, 3, ...` (filesystem-iteration order)
- AddedAt = now
- Role = `PrimaryWrite` for the first one, `ReplicaWrite` for the rest
- Priority = index in the input slice
- Status = `Active`

Returns the number of accounts created (0 if `accounts.json` was already populated — idempotent).

Logged at startup: `✅ account bootstrap: created N CloudAccount records from existing providers (edit priorities in Settings → Cloud Accounts)`.

### `SaveAccounts()` / `SavePolicy()`

Public wrappers around the same atomic-write that mutators use internally. Useful for admin endpoints that build up changes and persist once.

---

## 4. The selection algorithm — `SelectReplicas`

**Pure function. No I/O.** This is the heart of Phase α — every upload decision goes through here.

```go
func SelectReplicas(file FileMeta, accounts []*CloudAccount, cfg AccountPolicyConfig) ([]*CloudAccount, error)
```

Inputs:
- `file.Size` — bytes
- `file.ContentType` — `"photos"` or `"files"` (from `mediaFolder()` in pipeline.go)
- `accounts` — typically `manager.ActiveAccounts()`
- `cfg` — typically `manager.Policy()`

Returns up to `cfg.ReplicationFactor` accounts, or one of two errors:
- `ErrNoEligibleAccounts` — pool is empty after filtering (no accounts pass the gates)
- `ErrInsufficientReplicas` — fewer eligible than RF AND `AllowSingleReplicaWithWarning=false`

### Step 1: Filter

Each account passes IFF:
1. `a.Status == StatusActive`
2. `a.Role in {PrimaryWrite, ReplicaWrite}` — ColdArchive/ReadOnly/Drain/Quarantine excluded
3. `a.UsedPercent() < HardCap` (uses per-account override if set, else `cfg.HardCapDefaultPct`)
4. `file.Size <= MaxFileSize` (override or `cfg.MaxFileSizeDefaultMB*1MB`)
5. `a.AcceptsContentType(file.ContentType)` (nil/empty allows all)

If 0 pass → `ErrNoEligibleAccounts`.

### Step 2: Sort (stable)

Comparator: `(Priority ASC, FreeBytes DESC, AddedAt ASC)`.

- **Priority ASC** — primary intent. Lower number wins.
- **FreeBytes DESC** — tie-breaker. Spreads load away from accounts about to fill up. Critical when quota polling lands (Phase β).
- **AddedAt ASC** — secondary tie-breaker for stability. Older accounts (with more historical files) win equal-tie races so we don't keep oscillating between fresh siblings.

Stable sort guarantees deterministic ordering — same input → same output → debuggable.

### Step 3: Diversity pick

Walk sorted candidates, take first `RF` accepting diversity constraints:
- `DiversityRequired` (Provider): skip if `Provider` already chosen
- `DiversityRegionRequired` (Region): skip if `Region` already chosen (only checked when `Region != ""`)

### Step 4: Insufficient-replicas

If `len(chosen) < RF`:
- `AllowSingleReplicaWithWarning=true` → return what we have (caller logs warning + UI badge)
- `AllowSingleReplicaWithWarning=false` → `ErrInsufficientReplicas` (strict mode for compliance)

If `len(chosen) == 0` we returned `ErrNoEligibleAccounts` already in Step 1.

### Test net (14 cases in `manager_test.go`)

- α-1 zero accounts → `ErrNoEligibleAccounts`
- α-2 single+warning allowed → 1 chosen + no error
- α-3 single+strict → `ErrInsufficientReplicas`
- α-4 three accounts, RF=2 → first two by priority
- α-5 priority tie → free-space tie-break
- α-6 over HardCap → excluded
- α-7 diversity → no two replicas on same provider
- α-8 content-type filter → photos-only account skipped for "files" upload
- AddAccount first→PrimaryWrite, rest→ReplicaWrite
- NextID monotonic across Removed
- Reorder produces dense priorities
- DisplayID padding rules
- PathFor defaults to year_month (per §11 #5)
- Round-trip JSON serialization
- On-disk persistence (load after restart)

---

## 5. Cloud path layout

Generated by `cfg.PathFor(folder, name, when)`:

| `PathScheme` | Format | Example |
|--------------|--------|---------|
| `"year_month"` (default) | `<root>/<folder>/YYYY/MM/<name>` | `dudenest/photos/2026/05/IMG_001.jpg` |
| `"year_month_day"` | `<root>/<folder>/YYYY/MM/DD/<name>` | `dudenest/photos/2026/05/22/IMG_001.jpg` |
| `"flat"` | `<root>/<folder>/<name>` | `dudenest/photos/IMG_001.jpg` |

`<root>` = `cfg.PathRoot` (default `"dudenest"`, empty string = no prefix).
`<folder>` = `"photos"` or `"files"` from `mediaFolder()` based on MIME sniff + extension fallback.

### Folder classification — TWO scanners, must agree

**Upload time** (`pipeline.go:mediaFolder()`): inspects file content (`http.DetectContentType` magic bytes) + extension fallback for HEIC/RAW/MOV/MKV. Returns `PhotosFolder` or `FilesFolder`. This decides the `<folder>` component in the upload path.

**List time** (`cmd/relay/serve.go:folderFromFileMap()`): inspects `FileMap.Replicas[0].Location` after the fact. Scans for either `/photos/` (Phase α format with PathRoot) or `:photos/` (legacy format without root). Returns same enum. This drives the Flutter Photos vs Files tab filter.

**Three location formats** are supported by the list-time scanner (depending on writer version):
1. **v0.17.2+ Phase α**: `gdrive:<email>:dudenest/photos/2026/05/foo.jpg` — has PathRoot prefix
2. **v0.11.0..v0.17.1**: `gdrive:<email>:photos/2026/05/foo.jpg` — no PathRoot
3. **pre-v0.11.0 legacy**: `gdrive:<email>:files/<hash>/0/0` — hash-based, always files

> **Historical note (v0.17.3 hotfix)**: when Phase α added the PathRoot prefix, the old `:photos/` scanner missed the new format and every JPG started appearing in the Files tab. Same flaw existed in `handleMeta` PATCH `TakenAtOverride` (parser produced `top = "email:dudenest"` instead of `"photos"`, which would have broken `MoveFile` on date edits). Both fixed in v0.17.3 with regression tests in `cmd/relay/folder_test.go`. **Lesson**: if `Pipeline.upload` ever changes the path layout again, every classifier scanning `Location` must be re-verified — grep `Replica.Location` to find them all.

---

## 6. Pipeline integration — `internal/pipeline/pipeline.go`

### `Pipeline` struct

New field (Phase α): `accts *account.Manager`. nil = legacy path ("first 2 in slice", kept for CLI + tests). Non-nil = SelectReplicas + PathFor.

### `New(masterKey, clouds, mapStorePath, accts)`

4-arg constructor. Pass `nil` as 4th arg from CLI / tests / single-shot paths to get legacy behavior.

### `SetAccountManager(m)` / `AccountManager() *account.Manager`

Setter + getter for the optional Manager. `cmd/relay/serve.go` calls `SetAccountManager` after pipeline construction. `cmd/relay/serve.go:handleMeta` calls `AccountManager()` to read `PathRoot` policy when computing `MoveFile` destination.

### `findProviderByAccount(a *CloudAccount) types.CloudProvider`

Maps a CloudAccount to the loaded CloudProvider. Match is `a.Provider+":"+a.Email == cloud.ID()` (the format `factory.LoadAllProviders` produces). Returns `nil` if no provider is loaded for that account (e.g. its `gdrive_<email>.json` was deleted) — `upload` logs + skips that pick.

### `upload(fm, filePath)` — selection logic

1. Read file from disk.
2. Compute `folder := mediaFolder(...)`, `when` (from `fm.Created` if set, else `time.Now()`).
3. **Resolve targets**:
   - If `p.accts != nil`: call `account.SelectReplicas(FileMeta{Size, ContentType: folder}, mgr.ActiveAccounts(), mgr.Policy())`. Translate each chosen `*CloudAccount` to its `CloudProvider` via `findProviderByAccount`. Build `picks []{cloud, accID, path}` with `path = cfg.PathFor(folder, fm.Name, when)`.
   - Else (legacy): pick `p.clouds[0]` and `p.clouds[1]` (or fewer if less available), path = `<folder>/YYYY/MM/<name>` (no PathRoot).
4. Upload to each pick concurrently (`sync.WaitGroup`). Prefer `CloudIDUploader.UploadAndReturnID` (P5a — captures Drive file ID for ID-stable downloads) over plain `Upload`.
5. Build `Block` entries with `Location: fmt.Sprintf("%s:%s", pick.cloud.ID(), pick.path)`.
6. Save the FileMap. Return.

### Logging contract

- **Degraded redundancy** (when `len(picks) < RF`): `upload: degraded redundancy — picked N of RF requested replicas (policy.AllowSingleReplicaWithWarning may be true)`.
- **Missing provider** (account chosen but no matching CloudProvider loaded): `upload: no provider loaded for account ID00X (provider=gdrive email=...) — skip`.

There's deliberately **no per-upload "success" log** to keep journals quiet under load. Phase β admin endpoints will surface aggregate counters via `/admin/stats`.

---

## 7. Bootstrap flow (cmd/relay/serve.go)

After the pipeline is constructed in `serve.go`:

```go
if accMgr, err := account.New(authConfigDir); err == nil {
    if len(accMgr.Accounts()) == 0 {
        if clouds, _ := getClouds(); clouds != nil {
            ids := []string{}
            for _, c := range clouds { ids = append(ids, c.ID()) }
            n, _ := accMgr.BootstrapFromProviders(ids)
            if n > 0 { log.Printf("✅ account bootstrap: created %d ...", n) }
        }
    }
    p.SetAccountManager(accMgr)
    log.Printf("✅ account.Manager attached: %d accounts, replication_factor=%d, diversity=%v",
        len(accMgr.ActiveAccounts()), accMgr.Policy().ReplicationFactor, accMgr.Policy().DiversityRequired)
}
```

This runs on every relay start. The Bootstrap is **idempotent** — re-running on a relay that already has `accounts.json` does nothing.

---

## 8. Operator runbook — common tasks

### Inspect current accounts + policy

```bash
ssh root@<relay-vm> 'cat /root/.config/dudenest/accounts.json | python3 -m json.tool'
ssh root@<relay-vm> 'cat /root/.config/dudenest/account_policy.json | python3 -m json.tool 2>/dev/null || echo "(no policy file — using DefaultPolicy)"'
```

### Reorder priorities (before Phase β UI lands)

Direct edit + restart:

```bash
ssh root@<relay-vm> 'jq ".[].priority = (.[]|.priority - .[0].priority)" /root/.config/dudenest/accounts.json > /tmp/x && mv /tmp/x /root/.config/dudenest/accounts.json && systemctl restart dudenest-relay'
```

Or hand-edit the `priority` field in `accounts.json` and restart the unit. SaveAccounts uses atomic write so a partial edit + restart is safe.

### Promote a specific account to PrimaryWrite

```bash
ssh root@<relay-vm> 'jq ".[].role = if .id == 3 then \"primary_write\" else \"replica_write\" end" /root/.config/dudenest/accounts.json > /tmp/x && mv /tmp/x /root/.config/dudenest/accounts.json && systemctl restart dudenest-relay'
```

(Substitute `3` for the target ID.)

### Change replication factor globally

```bash
ssh root@<relay-vm> '
test -f /root/.config/dudenest/account_policy.json || cat > /root/.config/dudenest/account_policy.json <<EOF
$(cat <<JSON
{"replication_factor": 2, "diversity_required": false, ...}
JSON
)
EOF
jq ".replication_factor = 3" /root/.config/dudenest/account_policy.json > /tmp/x && mv /tmp/x /root/.config/dudenest/account_policy.json && systemctl restart dudenest-relay'
```

### Verify selection on next upload

```bash
ssh root@<relay-vm> 'journalctl -u dudenest-relay -f' | grep -E "(upload|account.Manager)"
```

Look for `account.Manager attached: N accounts, ...` at startup and `degraded redundancy` warnings during operation. Absence of warnings + visible upload activity = working.

### Find which provider a CloudAccount maps to

`CloudAccount.Provider+":"+CloudAccount.Email` is the lookup key. Verify a matching file exists:

```bash
ssh root@<relay-vm> 'ls /root/.config/dudenest/providers/ | grep <email>'
```

If missing, the account is **orphaned** — Manager keeps the record but `upload` skips it (logs the skip). Re-auth via Flutter to recreate the provider token file.

---

## 9. Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Photos showing up in Files tab | Pre-v0.17.3 binary with PathRoot prefix mismatch (see §5 historical note) | Update to v0.17.3+ |
| Upload fails with `ErrNoEligibleAccounts` | All accounts hit HardCap, or all in Quarantine/ReadOnly | Lower per-account `HardCapPct`, re-auth Quarantined accounts, or promote a ReadOnly to ReplicaWrite |
| Upload fails with `ErrInsufficientReplicas` | Fewer eligible than `ReplicationFactor` + `AllowSingleReplicaWithWarning=false` | Either lower RF or set `AllowSingleReplicaWithWarning=true` |
| `degraded redundancy — picked N of RF replicas` warning | Same as above but in permissive mode | Add more accounts |
| `no provider loaded for account ID00X` log spam | CloudAccount record exists but `providers/gdrive_<email>.json` was deleted | Re-add the account via Flutter (will be detected as re-add per `OnReAddSameEmail`) |
| `relay update` returns `403 GitHub API` | Hub poll (60/h) + manual updates exceed unauth limit | Use `gh release download` + `scp` workaround, or wait an hour |
| `accounts.json` doesn't auto-create after upgrade to v0.17.2 | `len(Accounts()) > 0` (stale entry) — Bootstrap is idempotent | Inspect file; delete it if needed and restart to re-bootstrap |
| `factory: failed to init gdrive:<email>: oauth2: invalid_grant` | Token revoked or expired with no refresh | User re-auth via Flutter; the provider token file is rebuilt automatically |

---

## 10. What lives where

| Path | Purpose |
|------|---------|
| `pkg/types/accounts.go` | Data model: `CloudAccount`, `Role`, `Status`, `AccountPolicyConfig`, `DefaultPolicy`, helpers, marshal funcs |
| `internal/account/manager.go` | `Manager` (load/save mutators), `SelectReplicas` pure function, `BootstrapFromProviders` migration helper |
| `internal/account/manager_test.go` | 14 unit tests (α-1..α-8 + edge cases) |
| `internal/pipeline/pipeline.go` | Wire-up: `Pipeline.accts`, `New(.., accts)`, `SetAccountManager`, `AccountManager()`, `findProviderByAccount`, modified `upload` |
| `internal/pipeline/factory.go` | Provider discovery (unchanged from pre-Phase α — Manager wraps its output) |
| `cmd/relay/serve.go` | Bootstrap + attach + Photos/Files classifier (`folderFromFileMap`) + meta PATCH MoveFile |
| `cmd/relay/folder_test.go` | 8 regression tests for `folderFromFileMap` (v0.17.3 hotfix) |
| `~/.config/dudenest/accounts.json` | Per-relay account list (created by Bootstrap or AddAccount) |
| `~/.config/dudenest/account_policy.json` | Per-relay global policy (created on first UpdatePolicy or AddAccount; before that `DefaultPolicy()` applies in-memory) |
| `~/.config/dudenest/providers/gdrive_<email>.json` | Per-provider OAuth token (created by browser auth flow, unrelated to Phase α) |

---

## 11. What Phase α explicitly does NOT do (deferred to β/γ)

Reading this doc and thinking "X is missing" — that's almost certainly Phase β or γ. Quick reference:

| Feature | Phase | Why deferred |
|---------|-------|--------------|
| Quota polling (Drive about.get) | β | Needs per-provider API integration |
| Auto-demote on SoftCap | β | Depends on quota polling |
| Auto-promote on space | β | Depends on quota polling |
| Admin REST endpoints (`/admin/accounts`, `/admin/policy`) | β | Phase α is library-level only; UI ships next |
| Flutter Settings → Cloud Accounts UI | β | Depends on admin endpoints |
| Encrypted backup blob (zero-knowledge hub) | β | Existing snapshot still uses plaintext `maps_json`; encryption work is its own item |
| Drain workflow (Drain→Removed with file migration) | β | Background worker + progress UI |
| Re-add detection dialog | β | UI-driven |
| Age-based rotation | γ | Cold archive worker |
| Duplicate detection (F1) | γ | sha256 indexing per file |
| Cross-account dedup (F2) | γ | Requires F1 |
| Deep archive (F3) | γ | zstd compression on ColdArchive accounts |
| Multi-region diversity (F4) | γ | Region field exists; just needs operator setup + DiversityRegionRequired toggle |

Roadmap details: `~/.AI/dudenest-application/CLOUD-ACCOUNT-POLICY-PLAN.md`.

---

## 12. Phase β — Quota polling, ReconcileRoles, admin REST (v0.18.0)

### 12.1. Quota polling

#### `types.QuotaReporter` interface (`pkg/types/types.go`)

Optional sub-interface, paralleled to `CloudLister`, `CloudIDDownloader` etc. Providers that can report storage usage implement it; those that can't (local FS) are skipped silently by the polling loop.

```go
type QuotaReporter interface {
    Quota() (usedBytes, totalBytes int64, err error)
}
```

**Important convention**: when `totalBytes == 0`, it means **unknown** (e.g. Google Workspace unlimited reports `limit=0`). `CloudAccount.FreeBytes()` defensively returns 0 in that case to prevent `SelectReplicas` from blindly favoring "infinite" accounts.

#### `gdrive.Provider.Quota()` (`internal/cloudconn/gdrive/gdrive.go`)

Single Drive API call per invocation:

```go
about, err := p.svc.About.Get().Fields("storageQuota").Do()
// returns about.StorageQuota.Usage, about.StorageQuota.Limit
```

Compile-time assertion `var _ types.QuotaReporter = (*Provider)(nil)` catches signature drift at build.

#### `Manager.RefreshQuota(id, lookup)` (`internal/account/manager.go`)

On-demand quota fetch for a single account. Side effects:
- Looks up the provider via `lookup ProviderLookup` callback.
- Calls `QuotaReporter.Quota()` — if provider doesn't implement, returns `nil` silently.
- On success: writes `QuotaUsedBytes`, `QuotaTotalBytes`, `QuotaCheckedAt`, `LastSeenAt`. Clears `Status=Error` if previously set.
- On error: `Status=Error`, `LastError=<msg>`, `QuarantineUntil=now+5min`. Persists.

```go
func (m *Manager) RefreshQuota(id int64, lookup ProviderLookup) error
```

#### `Manager.StartQuotaPollLoop(ctx, lookup)`

Background goroutine. First poll happens 30 s after start (gives Flutter time to make initial requests before competing for Drive API). Subsequent polls every `cfg.QuotaCheckIntervalMin` (default 30 min). Goroutine exits when ctx cancels.

```go
func (m *Manager) StartQuotaPollLoop(ctx context.Context, lookup ProviderLookup)
```

`ProviderLookup` is a callback type `func(*CloudAccount) types.CloudProvider`. Defined in account package so the package doesn't import `internal/cloudconn` (would be a layering violation).

### 12.2. ReconcileRoles

#### `Manager.ReconcileRoles() (demoted, promoted int)`

Pure-ish function — reads manager state, mutates via `SetRole`, no I/O. Two steps:

**Step 1: auto-demote.** For each `Role=PrimaryWrite` and `!Pinned`:
- Resolve `softCap` (per-account override or `cfg.SoftCapDefaultPct`).
- If `QuotaTotalBytes > 0 && UsedPercent() >= softCap`: `SetRole(id, RoleReplicaWrite)`. Increments `demoted` counter.

**Step 2: auto-promote.** Only fires when zero PrimaryWrite remain after step 1:
- Build candidate pool: `Role=ReplicaWrite && !Pinned`.
- `pickPromoteCandidate(candidates, cfg.PromoteStrategy)` returns the chosen account.
- `SetRole(id, RolePrimaryWrite)`. Increments `promoted`.

#### `pickPromoteCandidate(candidates, strategy)` (`internal/account/manager.go`)

Four strategies:

| `strategy` | Winner |
|------------|--------|
| `"by_priority"` (default + fallback) | Lowest `Priority` value |
| `"by_free_pct"` | Highest `100 - UsedPercent()` |
| `"by_age_oldest_first"` | Earliest `AddedAt` |
| `"round_robin"` | Index `(time.Now().Minute() % len)` — deterministic per minute |

Unknown strategy falls back to `by_priority` (defensive — typo in policy.json doesn't break the loop).

#### `Manager.StartReconcileLoop(ctx)`

Background goroutine, fires `ReconcileRoles` every 1 minute (cheap — no I/O). Promotions surface within ~1 min of a quota refresh detecting SoftCap crossing.

### 12.3. Admin REST endpoints (`cmd/relay/admin_accounts.go`)

All routes share the same auth chain as `/files`: `requireAuthWithReg(lr, handler)` = JWT Bearer + X-Relay-Token HMAC. Registered only when `globalAdminAccounts != nil` (the package-level var set by serve.go after Manager construction).

| Route | Method | Body | Returns |
|-------|--------|------|---------|
| `/admin/accounts` | GET | – | `{accounts: [CloudAccount...], policy: AccountPolicyConfig}` |
| `/admin/accounts/reorder` | POST | `{ids: [3,1,2]}` | refreshed accounts list with dense priorities |
| `/admin/accounts/{id}` | GET | – | single CloudAccount |
| `/admin/accounts/{id}` | PATCH | overlay (any subset of `role`, `priority`, `pinned`, `soft_cap_pct`, `hard_cap_pct`, `max_file_size_mb`, `accepts_content_types`, `region`, `compression_level`) | refreshed account |
| `/admin/accounts/{id}` | DELETE | – | `{status: "drain_initiated"}` — flips Role to Drain; background worker takes over |
| `/admin/accounts/{id}/refresh-quota` | POST | – | account with fresh QuotaUsed/Total |
| `/admin/policy` | GET | – | full `AccountPolicyConfig` |
| `/admin/policy` | PATCH | overlay (any subset of policy fields) | merged + persisted policy |

#### PATCH semantics (overlay merge)

For `PATCH /admin/policy`, body is decoded into `map[string]any`, applied onto the marshaled current policy, re-marshaled, then `Unmarshal` into typed `AccountPolicyConfig`. Type validation happens implicitly — a typo like `"replication_factor": "two"` fails the round-trip with a clean error.

For `PATCH /admin/accounts/{id}`, body fields are individually pointer-typed (`*int`, `*bool`, `*string`) so unset fields are easy to distinguish from explicit zero. Special handling: `max_file_size_mb` is multiplied by `1024*1024` to set `MaxFileSizeBytes`. `role` change goes through `Manager.SetRole()` (which persists immediately); other fields are applied to a `live := m.Accounts()` slice + `ReplaceAll`.

#### DELETE = Drain stub → real workflow

In Phase β, DELETE flipped the account to `Role=Drain` but no background worker existed. Phase γ (v0.19.0) added the worker (§13). The response is `{"status": "drain_initiated", "note": "background migration worker pending Phase β implementation; account will not receive new uploads"}` — the note is now stale post-v0.19.0 but the JSON shape stays stable for UI compat.

### 12.4. `Manager.ReplaceAll([]*CloudAccount)`

Atomic swap of the in-memory slice + disk persist. Used by `PATCH /admin/accounts/{id}` after building an edited view from `Accounts()` (which returns deep copies). Caller must NOT remove accounts — IDs aren't reusable; to soft-delete use `SetRole(id, RoleDrain)` and let the drain worker mark `Status=Removed`.

---

## 13. Phase γ — Drain workflow (v0.19.0)

### 13.1. Design

When the user calls `DELETE /admin/accounts/{id}` (or Flutter `Remove (drain)` menu item), the account flips to `Role=Drain` immediately and stops receiving new uploads (SelectReplicas filters out non-`PrimaryWrite/ReplicaWrite`). A background worker then walks every FileMap, finds replicas on that account, copies them to other still-active accounts, rewrites `Location`+`CloudID`, persists, best-effort deletes from source. When zero replicas remain → `Status=Removed`, `RemovedAt=now`. The account record stays in `accounts.json` for audit.

### 13.2. `PipelineDrainer` interface (`internal/account/drain.go`)

Minimal Pipeline surface the worker needs. Defined in `account` package to avoid `pipeline ↔ account` import cycle.

```go
type PipelineDrainer interface {
    ListFiles() ([]*types.FileMap, error)
    GetFileMap(fileID string) (*types.FileMap, error)
    SaveFileMap(fm *types.FileMap) error
    CloudByID(providerID string) types.CloudProvider
}
```

`Pipeline` satisfies this — `Pipeline.SaveFileMap` and `Pipeline.CloudByID` were added in v0.19.0 specifically for this purpose. `Pipeline.ListFiles` and `Pipeline.GetFileMap` existed pre-Phase α.

### 13.3. `Manager.StartDrainLoop(ctx, drainer, state, interval)`

Background goroutine. Initial delay 1 min (lets quota poll + reconcile bootstrap first). Subsequent sweeps every `interval` (default 2 min).

```go
func (m *Manager) StartDrainLoop(ctx context.Context, drainer PipelineDrainer, state *DrainState, interval time.Duration)
```

Each sweep calls `m.drainOnePass()` which iterates `Role=Drain` accounts and dispatches `drainOneAccount(d, ...)`.

### 13.4. `drainOneAccount`

For one draining account:

1. Build `drainProviderID := d.Provider + ":" + d.Email` — the Location prefix that identifies its replicas.
2. `ListFiles()`, iterate all FileMaps and their Replicas. Match on `strings.HasPrefix(sh.Location, drainProviderID+":")`.
3. Build `otherAccounts` pool — all Active, NOT this one, NOT `Role=Drain`.
4. **Safety**: if `len(otherAccounts) == 0` → log warning, set `prog.LastErr = "no migration target accounts"`, exit. User must add another account first; the next sweep retries.
5. For each matching replica: spawn `migrateOneReplica` goroutine, capped by semaphore `cfg.DrainMaxConcurrentMigrations` (default 4).
6. Wait for all goroutines, then re-scan to confirm zero replicas remain. If `prog.ReplicasFailed == 0 && stillThere == 0`: transition account to `Status=Removed`, `Role=ReadOnly` (terminal), `RemovedAt=now`. Log `✅ drain ID%03d done: %d replicas migrated, account marked Removed (audit-retained)`.

### 13.5. `migrateOneReplica`

For one replica:

1. Resolve source provider via `drainer.CloudByID(srcID)`.
2. Parse Location: `parts := strings.SplitN(sh.Location, ":", 3)` (format `<provider>:<email>:<path>`). Extract `srcPath = parts[2]`.
3. **Download**: prefer `CloudIDDownloader.DownloadByID(sh.CloudID)` if known (ID-stable, survives renames), fall back to `src.Download(srcPath)`.
4. Infer `contentType` from path (`/photos/` or `/files/`).
5. `SelectReplicas(FileMeta{Size, ContentType}, otherAccounts, cfg)` → take the highest-priority chosen (we replace one replica, not create multiple).
6. **Upload** to target: prefer `CloudIDUploader.UploadAndReturnID(destPath, data)`, fall back to `Upload`. Captures new `cloudID` if supported. Destination path = source path (same relative path on the new provider's base folder — keeps directory structure consistent).
7. **Atomically rewrite replica**: `GetFileMap` again (catches concurrent meta edits), find the matching replica, rewrite `Location` + `CloudID` + `Created`, `SaveFileMap`. If a concurrent update already migrated this replica (prefix changed), bail silently — no double-migration.
8. **Best-effort delete from source**: `idd.DeleteByID(sh.CloudID)` + `src.Delete(srcPath)`. Failure non-fatal (the data is already safely replicated; the scan engine will catch orphans later).
9. **Bandwidth throttle**: if `cfg.DrainBandwidthLimitMBPerSec > 0`, sleep `bytes / (limit_mbps * 1MB) * 1sec`.

### 13.6. `DrainState` tracker (`internal/account/drain.go`)

In-memory only — per relay start. Holds `drainProgress` per account:

```go
type drainProgress struct {
    StartedAt        time.Time
    FileMapsScanned  int
    ReplicasToMigrate  int
    ReplicasMigrated   int
    ReplicasFailed     int
    LastErr          string
}
```

`NewDrainState()` returns empty tracker. `Snapshot(id)` returns a copy (thread-safe via `sync.RWMutex`). Future admin endpoint `/admin/accounts/{id}/drain-progress` (not yet implemented) reads from this to feed UI progress bar.

Restart-resume: the in-memory counters reset, but `Location` pointers on disk drive the actual resumption — already-migrated replicas have different prefixes so they're invisibly skipped on next sweep.

### 13.7. Wire-up in `cmd/relay/serve.go`

```go
bgCtx, _ := context.WithCancel(context.Background())
provLookup := func(a *types.CloudAccount) types.CloudProvider {
    want := a.Provider + ":" + a.Email
    cs, _ := getClouds()
    for _, c := range cs { if c.ID() == want { return c } }
    return nil
}
accMgr.StartQuotaPollLoop(bgCtx, provLookup)
accMgr.StartReconcileLoop(bgCtx)
globalDrainState = account.NewDrainState()
accMgr.StartDrainLoop(bgCtx, p, globalDrainState, 2*time.Minute)
log.Printf("✅ account.Manager: quota poll + reconcile + drain loops started ...")
globalAdminAccounts = &accountAdmin{mgr: accMgr, provLookup: provLookup}
```

Three loops + admin handlers all hang off the same `bgCtx`. Process exit cancels them.

---

## 14. Tests — complete catalog (22 tests)

All in `internal/account/manager_test.go`. Run: `go test ./internal/account/...`.

### Phase α (8 acceptance + 6 unit/integration)

| Test | What it asserts |
|------|-----------------|
| `TestSelectReplicas_NoAccounts` | Empty pool → `ErrNoEligibleAccounts` |
| `TestSelectReplicas_SingleAccountWithWarningAllowed` | RF=2, 1 account + `AllowSingleReplicaWithWarning=true` → 1 chosen, no error |
| `TestSelectReplicas_SingleAccountStrictFailsClosed` | RF=2, 1 account + `false` → `ErrInsufficientReplicas` |
| `TestSelectReplicas_PicksFirstTwoByPriority` | 3 accounts RF=2 → first two by Priority (no waste of #3) |
| `TestSelectReplicas_TieBreakByFreeSpace` | Equal Priority → more free space wins |
| `TestSelectReplicas_OverHardCapExcluded` | UsedPercent >= HardCap → account excluded entirely |
| `TestSelectReplicas_DiversityRequired` | `DiversityRequired=true` → no two replicas on same Provider type |
| `TestSelectReplicas_ContentTypeFilter` | photos-only account skipped for "files" upload |
| `TestAddAccount_FirstIsPrimarySubsequentIsReplica` | First add → PrimaryWrite/Priority 0; rest → ReplicaWrite/Priority N |
| `TestNextID_MonotonicAcrossRemoved` | IDs never reused, even past Removed entries |
| `TestReorder_Dense` | UI drag-drop produces dense [0,1,2,...] priorities |
| `TestDisplayID_PaddingRules` | `ID%03d` for <1000, no pad above |
| `TestPathFor_DefaultsToYearMonth` | Default scheme matches user decision §11 #5 |
| `TestAccountsRoundTrip` + `TestPolicyRoundTrip` + `TestManagerPersistence` | JSON storage integrity across restart |

### Phase β (5 tests)

| Test | What it asserts |
|------|-----------------|
| `TestReconcileRoles_AutoDemoteOnSoftCap` | Account hits SoftCap → demote PrimaryWrite → ReplicaWrite, persisted |
| `TestReconcileRoles_AutoPromoteWhenNoPrimary` | Demote leaves pool empty → promote best ReplicaWrite |
| `TestReconcileRoles_RespectsPinned` | Pinned account stays PrimaryWrite even over cap |
| `TestPickPromoteCandidate_Strategies` | All 4 strategies pick distinct winners; unknown falls back to by_priority |
| `TestReplaceAll_Persistence` | ReplaceAll atomically swaps + persists |

### Phase γ (3 tests)

| Test | What it asserts |
|------|-----------------|
| `TestDrainState_NilSnapshotForUnknown` | UI safety: nil snapshot for unknown account ID |
| `TestDrain_NoOpWhenNoDrainAccounts` | Early exit when no Role=Drain — doesn't accidentally drain healthy accounts |
| `TestDrain_RefusesWhenNoOtherAccounts` | Last-account safety — won't mark Removed without target |

### Hotfix v0.17.3 (`cmd/relay/folder_test.go`, 8 tests)

| Test | What it asserts |
|------|-----------------|
| `TestFolderFromFileMap` (6 subtests) | Phase α PathRoot format + v0.11..v0.17.1 + pre-v0.11.0 legacy + MEGA provider, photos vs files for each |
| `TestFolderFromFileMap_EmptyOrInvalid` (4 subtests) | Defensive defaults to FilesFolder for empty/malformed |

### Phase 0 fast-update (`internal/backup/client_test.go`, 4 tests)

| Test | What it asserts |
|------|-----------------|
| `TestPing_BackwardCompatOldHub` | Old hub `{"status":"ok"}` response doesn't trigger update |
| `TestPing_TriggersUpdateOnNewerVersion` | Mock hub + mock updateTrigger → triggers exactly once |
| `TestPing_DoesNotTriggerOnSameVersion` | Even if hub says update_now=true, client-side version check guards |
| `TestPing_DoesNotTriggerOnMissingDownloadURL` | Empty download_url (unknown arch) → no trigger |
| `TestPing_NilClientSafe` | Nil receiver doesn't panic |

---

## 15. Cross-references

- Design doc: `~/.AI/dudenest-application/CLOUD-ACCOUNT-POLICY-PLAN.md`
- Flutter UI reference: `~/Architect/github.com/dudenest/dudenest/docs/FLUTTER-CLOUD-ACCOUNTS-UI.md`
- Fast-update mechanism: `~/.AI/dudenest-application/FAST-UPDATE-PLAN.md`
- Relay URL routing: `~/.AI/dudenest-application/RELAY-URL-ROUTING.md`
- Operator incident playbook: `~/.AI/dudenest-application/INCIDENT-RUNBOOK.md`
- Photos/Files classification note: `~/.AI/dudenest-application/PHOTOS-FILES-CLASSIFICATION-NOTE.md`
- Session files: `~/.AI/dudenest-application/session-2026-05-22-phase-alpha-multi-account.md`, `session-2026-05-23-phase-beta-multi-account.md`, `session-2026-05-23-phase-gamma-drain-ops.md`, `session-2026-05-23-flutter-cloud-accounts-ui.md`
