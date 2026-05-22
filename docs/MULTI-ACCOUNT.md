# Multi-Account Orchestration — Reference

**Status**: Phase α LIVE (v0.17.2+). Phase β/γ planned — see `~/.AI/dudenest-application/CLOUD-ACCOUNT-POLICY-PLAN.md`.
**Last updated**: 2026-05-22 (post v0.17.3 hotfix for folder classification)

This document is the **operator + developer reference** for the multi-account selection layer.
Every public function, every CloudAccount field, every AccountPolicyConfig knob is described here.
If a future agent needs to understand "what does X do, why does it exist, when does it fire" — this is the doc.

---

## 1. Why this exists

Pre-v0.17.2 behavior:
- `uploadReplica` hardcoded `limit := 2` and `p.clouds[:limit]`.
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

**List time** (`cmd/relay/serve.go:folderFromFileMap()`): inspects `FileMap.Chunks[0].Shards[0].Location` after the fact. Scans for either `/photos/` (Phase α format with PathRoot) or `:photos/` (legacy format without root). Returns same enum. This drives the Flutter Photos vs Files tab filter.

**Three location formats** are supported by the list-time scanner (depending on writer version):
1. **v0.17.2+ Phase α**: `gdrive:<email>:dudenest/photos/2026/05/foo.jpg` — has PathRoot prefix
2. **v0.11.0..v0.17.1**: `gdrive:<email>:photos/2026/05/foo.jpg` — no PathRoot
3. **pre-v0.11.0 legacy**: `gdrive:<email>:files/<hash>/0/0` — hash-based, always files

> **Historical note (v0.17.3 hotfix)**: when Phase α added the PathRoot prefix, the old `:photos/` scanner missed the new format and every JPG started appearing in the Files tab. Same flaw existed in `handleMeta` PATCH `TakenAtOverride` (parser produced `top = "email:dudenest"` instead of `"photos"`, which would have broken `MoveFile` on date edits). Both fixed in v0.17.3 with regression tests in `cmd/relay/folder_test.go`. **Lesson**: if `Pipeline.uploadReplica` ever changes the path layout again, every classifier scanning `Location` must be re-verified — grep `Shard.Location` to find them all.

---

## 6. Pipeline integration — `internal/pipeline/pipeline.go`

### `Pipeline` struct

New field (Phase α): `accts *account.Manager`. nil = legacy path ("first 2 in slice", kept for CLI + tests). Non-nil = SelectReplicas + PathFor.

### `New(masterKey, clouds, mapStorePath, accts)`

4-arg constructor. Pass `nil` as 4th arg from CLI / tests / single-shot paths to get legacy behavior.

### `SetAccountManager(m)` / `AccountManager() *account.Manager`

Setter + getter for the optional Manager. `cmd/relay/serve.go` calls `SetAccountManager` after pipeline construction. `cmd/relay/serve.go:handleMeta` calls `AccountManager()` to read `PathRoot` policy when computing `MoveFile` destination.

### `findProviderByAccount(a *CloudAccount) types.CloudProvider`

Maps a CloudAccount to the loaded CloudProvider. Match is `a.Provider+":"+a.Email == cloud.ID()` (the format `factory.LoadAllProviders` produces). Returns `nil` if no provider is loaded for that account (e.g. its `gdrive_<email>.json` was deleted) — `uploadReplica` logs + skips that pick.

### `uploadReplica(fm, filePath)` — selection logic

1. Read file from disk.
2. Compute `folder := mediaFolder(...)`, `when` (from `fm.Created` if set, else `time.Now()`).
3. **Resolve targets**:
   - If `p.accts != nil`: call `account.SelectReplicas(FileMeta{Size, ContentType: folder}, mgr.ActiveAccounts(), mgr.Policy())`. Translate each chosen `*CloudAccount` to its `CloudProvider` via `findProviderByAccount`. Build `picks []{cloud, accID, path}` with `path = cfg.PathFor(folder, fm.Name, when)`.
   - Else (legacy): pick `p.clouds[0]` and `p.clouds[1]` (or fewer if less available), path = `<folder>/YYYY/MM/<name>` (no PathRoot).
4. Upload to each pick concurrently (`sync.WaitGroup`). Prefer `CloudIDUploader.UploadAndReturnID` (P5a — captures Drive file ID for ID-stable downloads) over plain `Upload`.
5. Build `Block` entries with `Location: fmt.Sprintf("%s:%s", pick.cloud.ID(), pick.path)`.
6. Save the FileMap. Return.

### Logging contract

- **Degraded redundancy** (when `len(picks) < RF`): `uploadReplica: degraded redundancy — picked N of RF requested replicas (policy.AllowSingleReplicaWithWarning may be true)`.
- **Missing provider** (account chosen but no matching CloudProvider loaded): `uploadReplica: no provider loaded for account ID00X (provider=gdrive email=...) — skip`.

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
ssh root@<relay-vm> 'journalctl -u dudenest-relay -f' | grep -E "(uploadReplica|account.Manager)"
```

Look for `account.Manager attached: N accounts, ...` at startup and `degraded redundancy` warnings during operation. Absence of warnings + visible upload activity = working.

### Find which provider a CloudAccount maps to

`CloudAccount.Provider+":"+CloudAccount.Email` is the lookup key. Verify a matching file exists:

```bash
ssh root@<relay-vm> 'ls /root/.config/dudenest/providers/ | grep <email>'
```

If missing, the account is **orphaned** — Manager keeps the record but `uploadReplica` skips it (logs the skip). Re-auth via Flutter to recreate the provider token file.

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
| `internal/pipeline/pipeline.go` | Wire-up: `Pipeline.accts`, `New(.., accts)`, `SetAccountManager`, `AccountManager()`, `findProviderByAccount`, modified `uploadReplica` |
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

## 12. Cross-references

- Design doc: `~/.AI/dudenest-application/CLOUD-ACCOUNT-POLICY-PLAN.md`
- Fast-update mechanism: `~/.AI/dudenest-application/FAST-UPDATE-PLAN.md`
- Relay URL routing: `~/.AI/dudenest-application/RELAY-URL-ROUTING.md`
- Operator incident playbook: `~/.AI/dudenest-application/INCIDENT-RUNBOOK.md`
- Photos/Files classification note: `~/.AI/dudenest-application/PHOTOS-FILES-CLASSIFICATION-NOTE.md` (to merge into this doc when next agent revises)
