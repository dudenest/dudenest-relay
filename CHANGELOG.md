# Changelog

All notable changes to dudenest-relay are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.20.5] — 2026-05-24 — F1 alias resolve in Download + handleList

Critical follow-up to v0.20.4. v0.20.4 introduced dedup at upload time but Download + handleList did not resolve aliases — meaning users could upload a duplicate (alias FileMap saved, zero Chunks), then receive a download error when fetching it back. v0.20.5 closes this gap.

### `Pipeline.Download` (`internal/pipeline/pipeline.go`)

If `fm.LogicalAlias != ""`, load the target FileMap (max 1 hop — aliases never chain by design, defensive check returns error if they do) and borrow its `Chunks` + `Strategy`. Verify post-reassemble still uses alias's `Name + Hash + Size` so user sees their own filename.

### `handleList` folder classification (`cmd/relay/serve.go`)

`folderFromFileMap(fm)` returns `FilesFolder` when `fm.Chunks` is empty (default fallback). For alias FileMaps (Chunks empty by design), this incorrectly classified the file as `Files` even if the canonical content was a photo. Fix: when `LogicalAlias != ""` AND chunks empty, look up canonical and call `folderFromFileMap(canonical)`. One extra `GetFileMap` per alias in the list — cheap.

### What was broken in v0.20.4 (pre-v0.20.5)

If user re-uploaded a photo (dedup hit):
- Upload: ✅ succeeded, returned alias FileMap
- Photos tab: ❌ photo appeared in Files tab instead (wrong folder classification)
- Download: ❌ "load filemap: chunks empty" or similar — file unrecoverable from UI

After v0.20.5 fleet adoption (~60s via Phase 0 auto-update): both paths work transparently.

### Tests

Existing 8 F1 unit tests still pass (test the index, not pipeline integration). Integration test: manual via Section G of `dudenest-infra/docs/MANUAL-TESTING.md` (upload same photo twice → verify both visible in Photos tab + both downloadable).

---

## [0.20.4] — 2026-05-24 — F1 duplicate detection (sha-256 dedup index)

Non-breaking additive. Opt-in via Index presence (wired in serve.go by default). Saves significant quota when users replicate same file across devices/accounts.

### `internal/index/sha_index.go` (NEW, ~160 LOC)

JSON-on-disk per-relay content index. Maps `SHA-256(file plaintext)` → `[]Entry{FileID, IsAlias, CreatedAt}`. Persisted to `<configDir>/sha_index.json` with atomic write (tmp + rename). Thread-safe via `sync.RWMutex`. No new dependencies (uses `encoding/json` stdlib).

API:
- `New(configDir) *Index` + `Load() error` (handles missing file as empty)
- `Lookup(hash) → fileID` (returns canonical = first non-alias, "" if unknown)
- `Insert(hash, fileID)` + `InsertAlias(hash, fileID)` — sorted canonical-first, idempotent on duplicate fileID, persists on each call
- `Stats() (hashes, entries, aliases int)` for ops queries
- `BootstrapFromList([]struct{FileID, Hash, IsAlias})` — rebuilds from FileMap data, decoupled from pipeline to avoid import cycle

### `pkg/types/types.go`

`FileMap.LogicalAlias string` field added (omitempty) — empty for canonical FileMaps, FileID-of-target for dedup aliases.

### `internal/pipeline/pipeline.go`

`Pipeline.idx *index.Index` field + `SetIndex(i)` / `Index()` accessors.

`Upload()` short-circuit before chunking/replica: if `idx.Lookup(fm.Hash)` returns existing FileID, set `fm.LogicalAlias = existing`, save alias FileMap (zero Chunks), call `idx.InsertAlias(hash, fm.FileID)`. Log: `upload: ✅ dedup hit — <fileID> aliased to <existing> (skipped N bytes upload)`.

On successful canonical upload (no dedup hit): `idx.Insert(fm.Hash, fm.FileID)` registers for future dedup. Index insert failure is logged but not fatal (upload already succeeded).

### `cmd/relay/serve.go`

Wire-up after `p.SetAccountManager(accMgr)`:
- `shaIdx := index.New(authConfigDir)` (sibling of accounts.json)
- `shaIdx.Load()` (graceful on missing/corrupt)
- Bootstrap from existing `p.ListFiles()` → `BootstrapFromList` (handles initial deploy with pre-existing FileMaps)
- `p.SetIndex(shaIdx)` activates dedup
- Log: `✅ sha_index attached: N unique hashes, M entries (K aliases) — F1 dedup active`

### Tests (`internal/index/sha_index_test.go`)

8 unit tests:
- F1-1 `TestInsertAndLookup` — basic roundtrip
- F1-2 `TestPersistAndLoad` — survives process restart
- F1-3 `TestInsertIdempotent` — same fileID twice = no-op
- F1-4 `TestCanonicalPreferredOverAlias` — Lookup prefers canonical even if alias inserted first
- F1-5 `TestStats` — hashes/entries/aliases counters
- F1-6 `TestConcurrentInserts` — 50 parallel inserts, mutex correctness
- F1-7 `TestBootstrapFromList` — rebuild from raw data
- F1-8 `TestAtomicWrite` — .tmp removed after rename

### Migration / backward-compat

Existing relays: on first start with v0.20.4, serve.go bootstraps index from all known FileMaps (all become canonical since pre-v0.20.4 had no LogicalAlias). After that, any new upload of an already-seen hash skips cloud I/O.

Download path: caller must check `fm.LogicalAlias != ""` and resolve to target FileMap before reading Chunks. (Pipeline.Download / Flutter UI integration deferred to follow-up commit — current PR delivers index + upload path; download path defaults to "no Chunks" error which Flutter UI can handle as "load aliased FileMap by ID".)

### Forward-compat F2 (cross-account dedup)

This commit lays groundwork for F2 (`CloudAccount.LogicalAliasOK` flag, already defined). F2 would let an account explicitly host dedup targets vs source files. Out of scope for v0.20.4.

---

## [0.20.3] — 2026-05-24 — Bulk refresh-quota endpoint

Non-breaking additive. Quick-win for UI responsiveness — operator doesn't wait 30 min for scheduled quota poll.

### `POST /admin/accounts/refresh-quota` (no ID)

New bulk variant of existing per-id `POST /admin/accounts/{id}/refresh-quota`. Triggers `RefreshQuota` concurrently for ALL non-Removed accounts (semaphore cap 8 to avoid Drive API hammering). Fire-and-forget: returns `202 Accepted` immediately with `{status, accounts_queued}`. Next GET /admin/accounts shows refreshed values within ~5-10s (Drive about.get latency per provider).

Mux routing: `handleListOrReorder` now distinguishes 3 POST sub-routes by path suffix:
- `/admin/accounts/reorder` → bulk priority reorder
- `/admin/accounts/refresh-quota` → bulk quota refresh (NEW)
- `/admin/accounts` (no suffix) → reserved for future "add account" workflow (404 currently)

---

## [0.20.2] — 2026-05-24 — Age-based rotation worker (Phase γ continue)

Non-breaking additive. Worker disabled by default (`cfg.AgeBasedRotation=false`) — operator opts in.

### `internal/account/age_rotation.go` (NEW, ~100 LOC)

- `StartAgeRotationLoop(ctx, drainer, interval)` — daily sweep (default 24h interval, 5min initial delay so it doesn't compete with quota poll / reconcile / drain at startup)
- `ageRotateOnePass(drainer, cfg)`: walk all FileMaps → find shards on non-ColdArchive accounts where `FileMap.Modified` is older than `cfg.AgeRotationDays` → migrate to ColdArchive target via `migrateOneShard` (reused from drain). Returns count of migrated shards for ops logging.
- Target selection: filters `Role=ColdArchive` accounts with quota headroom (`UsedPercent < HardCapPct`); skips when zero targets exist (silent no-op).
- Source filter: skips shards already on ColdArchive accounts (idempotent — subsequent passes invisible).
- Concurrency: shares `cfg.DrainMaxConcurrentMigrations` budget with drain worker (one global semaphore vs two competing).
- Bandwidth throttle: inherits `cfg.DrainBandwidthLimitMBPerSec` via `migrateOneShard` reuse.

### `cmd/relay/serve.go`

Loop wire-up after `StartDrainLoop`:
```go
accMgr.StartAgeRotationLoop(bgCtx, p, 24*time.Hour)
```
Startup log updated: `account.Manager: quota poll + reconcile + drain + age-rotation loops started`.

### Tests (`internal/account/manager_test.go`)

- γ-5 `TestAgeRotation_NoOpWhenNoColdArchive`: enables age rotation but has no Role=ColdArchive account → `ageRotateOnePass` returns 0 (defensive — operator misconfig doesn't crash).
- γ-6 `TestAgeRotation_SkipsFreshFiles`: ColdArchive present + AgeRotationDays=30 + noopDrainer returns no files → `ageRotateOnePass` returns 0 (boundary condition).

### Operator usage

```bash
# Add a ColdArchive account first (via Flutter UI or PATCH role)
curl -X PATCH http://localhost:8086/admin/accounts/3 -d '{"role":"cold_archive"}' ...

# Enable age rotation (default 30 days):
curl -X PATCH http://localhost:8086/admin/policy -d '{"age_based_rotation":true,"age_rotation_days":30}' ...

# Next 24h tick (or relay restart): worker migrates files older than 30 days to ID 003.
# Watch: journalctl -u dudenest-relay -f | grep age-rotation
```

---

## [0.20.1] — 2026-05-24 — drain-progress endpoint + drain DELETE note update

Non-breaking additive. Carry-over from s317 / Phase γ continue.

### `GET /admin/accounts/{id}/drain-progress`

New admin sub-route exposes live `DrainState.Snapshot(id)` from the background drain worker so Flutter UI can show `437/1247 copies migrated (35%)` instead of opaque `Role=Drain`. Response shape:

```json
{ "account_id": 7, "role": "drain", "status": "active", "in_progress": true,
  "snapshot": { "started_at": "...", "shards_to_migrate": 1247, "shards_migrated": 437,
                "shards_failed": 0, "file_maps_scanned": 89, "last_err": "" } }
```

`snapshot: null` when account is `Role=Drain` but `StartDrainLoop` hasn't run its first sweep yet (waiting up to 2 min). `503` when `globalDrainState == nil` (legacy/CLI build).

### `DELETE /admin/accounts/{id}` note refreshed

Old text said "background migration worker pending Phase β implementation" — false since v0.19.0. New text points operator at `/admin/accounts/{id}/drain-progress` for live status.

### `DrainProgress` exported (was lower-case `drainProgress`)

Required to surface JSON-encodable fields with explicit tags (`json:"started_at"` etc.). No behavior change. Tests updated (γ-4 `TestDrainState_SnapshotIsCopy` verifies defensive copy semantics).

---

## [0.20.0] — 2026-05-23 — Zero-knowledge backup blob + ReconcileRoles loop fix

Non-breaking on hub side (hub v2026-05-23+ accepts both formats). Breaking nothing visible to operator.

### Zero-knowledge backup (`internal/backup/client.go`)

Relay now encrypts the full snapshot (`{maps, providers_enc, provider_ids}`) into a single AES-256-GCM blob keyed with HKDF(`relay-backup-v1:<relay_id>:<version>`). The blob is sent as `backup_blob` field instead of plaintext `maps_json`. Hub stores opaque bytes in new `relay_backups.backup_blob` column. Hub now sees only: `relay_id`, `backup_version`, `provider_ids` (display index — non-sensitive), `backup_blob` (opaque), `created_at`.

Migration: hub accepts EITHER legacy `maps_json+providers_enc` OR new `backup_blob` (XOR validated, 400 on both). v0.20.0+ relays always send blob; legacy relays continue working unchanged. After 30 days fleet-wide v0.20.0+ adoption, legacy hub columns can be dropped.

Restore path: tries `backup_blob` decryption first (with version-pinned HKDF info), falls back to legacy fields. Logs which format was restored.

Tests: `TestBackupBlobRoundtrip` (encrypt+decrypt symmetry), `TestBackupBlobTampering` (GCM auth tag rejects bit flips), `TestBackupBlobVersionSwap` (HKDF info change rejects cross-version replay), updated `TestSendEncryptsAndPosts` (asserts `maps_json` NOT sent by v0.20.0+).

### Bug fix: `ReconcileRoles` Step 2 over-cap loop (`internal/account/manager.go`)

Step 2 (auto-promote when no PrimaryWrite) was selecting from ALL ReplicaWrite accounts including ones over SoftCap — which meant Step 1 demoting an over-cap account would be undone by Step 2 re-promoting it in the same tick, looping forever. Fix: Step 2 now filters out candidates with `UsedPercent >= SoftCap`. `TestReconcileRoles_AutoDemoteOnSoftCap` + `TestReconcileRoles_AutoPromoteWhenNoPrimary` now pass.

---

## [0.19.0] — 2026-05-23 — Phase γ drain workflow + ops fixes (GITHUB_TOKEN, dual-service cleanup)

Non-breaking. Three independent items in one release:

### Phase γ — Drain workflow (`internal/account/drain.go`)

Implements the file migration that closes the loop on DELETE /admin/accounts/{id}. Before v0.19.0, deleting an account just flipped its Role to Drain and stopped new uploads to it — historical pliki stayed on the (now-orphan) cloud account indefinitely. Phase γ adds the background worker that actually moves the data.

**Worker semantics:**
- `Manager.StartDrainLoop(ctx, drainer, state, 2*time.Minute)` — sweep every 2 minutes (initial delay 1 min after relay start).
- For each Role=Drain account: walk every FileMap, find shards whose Location starts with that account's `<provider>:<email>:` prefix, download each shard, pick a new home via `SelectReplicas` (with the draining account excluded), upload, rewrite `Shard.Location` + `Shard.CloudID`, persist FileMap, best-effort delete from source.
- Concurrent migrations capped by `cfg.DrainMaxConcurrentMigrations` (default 4) via semaphore.
- Bandwidth throttle: `cfg.DrainBandwidthLimitMBPerSec` > 0 sleeps proportional to bytes after each transfer.
- Idempotent: a partial drain that gets interrupted (relay restart, network blip) picks up exactly where it left off on the next sweep — each shard is checked individually via the Location prefix, already-migrated ones simply have a different prefix now and are skipped.
- Safety: if a Drain account has zero other active accounts available as targets, the worker logs a warning and refuses to proceed (avoids data loss). User must add another account first.
- On zero shards remaining: account transitions to `Status=Removed` + `RemovedAt=now`. The record stays in `accounts.json` for audit; no UI selection or new uploads touch it.

**Pipeline contract** (`internal/pipeline/pipeline.go`):
- `Pipeline.SaveFileMap(fm)` — atomic persist after Location rewrite. Used by drain worker.
- `Pipeline.CloudByID(providerID)` — look up CloudProvider by its ID() string. Used for both source download and target upload.
- `Pipeline` satisfies `account.PipelineDrainer` interface (defined in drain.go to avoid import cycle).

**Drain state tracking** (`account.DrainState`):
- In-memory only (per relay start). Holds per-account `{FileMapsScanned, ShardsToMigrate, ShardsMigrated, ShardsFailed, LastErr, StartedAt}`.
- Exposed via `globalDrainState` package var so future admin endpoint `/admin/accounts/{id}/drain-progress` can read it (UI side — pending Flutter implementation).
- Restart resumes from where `Location` pointers stand; the lost in-memory state just resets counters.

**Tests** (`internal/account/manager_test.go`): 3 new γ-* tests covering nil-snapshot defense, no-op when no Drain accounts, and refuse-when-no-targets edge case. End-to-end migration test deferred to live production exercise (requires real provider credentials).

### Ops — `relay update` GitHub auth (`cmd/relay/update.go`)

The unauthenticated GitHub API gives 60 req/h per IP — easy to exceed when the hub polls /releases/latest every minute baseline + the auto-update timer fires across multiple relays from the same NAT. `relay update` now reads a `GITHUB_TOKEN` value from (in order): env var, `/etc/dudenest/relay.env`, `$HOME/.config/dudenest/relay.env`. When found, the API call uses `Authorization: Bearer <token>` and the rate limit jumps to 5000 req/h. Empty value = unauthenticated (same as before — backward compat). Helper: `githubToken()` — clean fallback chain.

### Ops — relay-poc1 dual-service consolidation

Documented for ops record: relay-poc1 had **two competing systemd units** for the same binary:
- `relay.service` — legacy from manual setup, config dir `/root/.config/dudenest/`, `ExecStartPre=relay update`
- `dudenest-relay.service` — Phase 0 install.sh standard, config dir `/etc/dudenest/`

Both directories were symlink-linked (`/root/.config/dudenest → /etc/dudenest`) so they shared the same files; the conflict was strictly at the systemd level (both tried bind 0.0.0.0:8086 → "address already in use" on whichever started second). Resolution: `systemctl stop+disable relay`, move unit file aside (`relay.service.disabled-2026-05-23`), `systemctl enable --now dudenest-relay`. Other relays (poc2 and any new bootstrap from install.sh) already use only `dudenest-relay.service` — poc1 is now consistent with the fleet.

### Upgrade

Standard relay update; the drain worker idle if no Role=Drain accounts exist. After deploy, DELETE /admin/accounts/{id} (Phase β) becomes a real Drain workflow rather than a stub — files migrate within minutes.

---

## [0.18.0] — 2026-05-23 — Phase β: quota polling + ReconcileRoles + admin REST endpoints

Non-breaking. Builds on Phase α (v0.17.2). Brings the multi-account orchestration to production-grade: per-account capacity is now tracked, role transitions happen automatically when accounts fill up, and the entire state is mutable via REST.

### Quota polling (`types.QuotaReporter` + `Manager.RefreshQuota` + `StartQuotaPollLoop`)

- New optional sub-interface `pkg/types.QuotaReporter` with `Quota() (used, total int64, err error)`.
- `internal/cloudconn/gdrive.Provider` implements it via Drive's `About.Get().Fields("storageQuota")` — single API call per refresh. Compile-time assertion `var _ types.QuotaReporter = (*Provider)(nil)` catches signature drift.
- `Manager.RefreshQuota(id, lookup)` writes `QuotaUsedBytes` / `QuotaTotalBytes` / `QuotaCheckedAt`. On error, transitions account to `Status=Error` + `QuarantineUntil = now+5min`; success clears the quarantine.
- `Manager.StartQuotaPollLoop(ctx, lookup)` background goroutine: refreshes all active accounts every `cfg.QuotaCheckIntervalMin` (default 30 min). First refresh delayed 30 s after relay start so initial Flutter requests aren't competing with Drive API.
- Local FS and any provider without `QuotaReporter` is skipped silently — `FreeBytes()` then returns 0 (defensive: `SelectReplicas` won't blindly favor an account with unknown capacity).

### ReconcileRoles (`Manager.ReconcileRoles` + `StartReconcileLoop`)

- Pure-ish function (reads manager state, mutates via SetRole; no network).
- Step 1: every PrimaryWrite with `UsedPercent() >= SoftCap` and `!Pinned` demotes to ReplicaWrite.
- Step 2: when no PrimaryWrite remains, pick the best ReplicaWrite per `cfg.PromoteStrategy` and promote it:
  - `"by_priority"` (default): lowest Priority value wins.
  - `"by_free_pct"`: highest free percent wins (load-balance fresh capacity).
  - `"by_age_oldest_first"`: oldest AddedAt wins (rotation stability).
  - `"round_robin"`: deterministic-per-minute round-robin.
- `StartReconcileLoop(ctx)` fires every 1 minute. Cheap — no I/O.
- Pinned accounts are immune to both demote and promote (user-override escape hatch for `/admin/accounts/{id}` PATCH `pinned=true`).

### Admin REST endpoints (`cmd/relay/admin_accounts.go`)

Same auth chain as `/files` (JWT + X-Relay-Token via `requireAuthWithReg`). Only the paired Flutter user can mutate. Routes:

| Route | Method | Body | Returns |
|-------|--------|------|---------|
| `/admin/accounts` | GET | – | `{accounts:[...], policy:{...}}` |
| `/admin/accounts/reorder` | POST | `{ids:[3,1,2]}` | refreshed account list with dense priorities |
| `/admin/accounts/{id}` | GET | – | one CloudAccount |
| `/admin/accounts/{id}` | PATCH | overlay (any subset: `role`, `priority`, `pinned`, `soft_cap_pct`, `hard_cap_pct`, `max_file_size_mb`, `accepts_content_types`, `region`, `compression_level`) | refreshed account |
| `/admin/accounts/{id}` | DELETE | – | sets Role=Drain (Phase β stub; full migration worker pending) |
| `/admin/accounts/{id}/refresh-quota` | POST | – | account with fresh QuotaUsed/Total |
| `/admin/policy` | GET | – | full AccountPolicyConfig |
| `/admin/policy` | PATCH | overlay (any subset of policy fields) | merged + persisted policy |

Routes only registered when `globalAdminAccounts != nil` (i.e. account.Manager attached). Legacy / CLI paths without Manager skip them silently.

### Manager additions

- `ReplaceAll([]*CloudAccount) error` — atomic swap of the in-memory list + disk write. Used by admin PATCH path to commit a batch of edits made via Accounts() copies.

### Tests — 5 new in `internal/account/manager_test.go`

- `TestReconcileRoles_AutoDemoteOnSoftCap` — verifies SoftCap → demote.
- `TestReconcileRoles_AutoPromoteWhenNoPrimary` — verifies promote fires after demote leaves the pool empty.
- `TestReconcileRoles_RespectsPinned` — pinned account stays PrimaryWrite even over cap.
- `TestPickPromoteCandidate_Strategies` — all 4 strategies pick distinct winners + unknown falls back to by_priority.
- `TestReplaceAll_Persistence` — round-trip after disk reload.

Total Phase α+β: 19 unit tests in the account package.

### Upgrade

Pure-additive: deploy v0.18.0, restart relay; new endpoints + loops start immediately. Existing accounts.json + account_policy.json are picked up unchanged. First quota poll fires 30 s after restart; first ReconcileRoles tick 1 minute later.

### What's still pending (Phase γ)

- Flutter Settings → Cloud Accounts UI (admin endpoints exist; UI lands next).
- Drain workflow — actual file migration before Status=Removed (currently the DELETE endpoint just sets Role=Drain and stops new uploads).
- Re-add detection dialog (the `OnReAddSameEmail` policy is read but UI prompt not yet implemented).
- Encrypted backup blob (`maps_json` still plaintext on hub).
- Age-based rotation worker (`AgeBasedRotation=true` policy switch is honored only by Phase γ worker).
- Duplicate detection, dedup, deep archive, multi-region — F1-F4 features per `~/.AI/dudenest-application/CLOUD-ACCOUNT-POLICY-PLAN.md`.

### Reference

`docs/MULTI-ACCOUNT.md` — full per-function reference (Phase α model + algorithms + operator runbook; will be updated for Phase β routes in next agent cycle).

---

## [0.17.3] — 2026-05-22 — hotfix: folder classification for Phase α PathRoot

Patch hot off v0.17.2. After Phase α started prefixing cloud paths with `PathRoot` (`dudenest/photos/2026/05/foo.jpg`), two classifiers still assumed the legacy "no root" format and produced wrong results:

### Bug — `folderFromFileMap` in `cmd/relay/serve.go`

This function decides whether a FileMap shows up in the Flutter **Photos** tab or **Files** tab. It scanned `Shard.Location` for the substring `":photos/"` (the legacy format had the folder directly after the `:` separator). With Phase α, the path becomes `gdrive:email:dudenest/photos/2026/05/foo.jpg` — the photos folder is now after `dudenest/`, not after `:`, so the check missed and the new JPG fell through to the default `FilesFolder`. User saw: **photos appearing in the Files tab.**

Fix: scan for `"/photos/"` (matches the new PathRoot format) AND keep `":photos/"` (matches legacy). Same for `files`. Added 8 unit tests in `cmd/relay/folder_test.go` covering all three location formats (Phase α / v0.11..v0.17.1 / pre-v0.11.0 legacy) for both photos and files, plus defensive cases (empty location, no shards).

### Bug — `handleMeta` PATCH `TakenAtOverride` in `cmd/relay/serve.go`

Same root cause. When a user edits a photo's date in the UI, `Pipeline.MoveFile` rebuckets the file into the new YYYY/MM directory. The destination directory was derived by parsing `Shard.Location` with `strings.SplitN(":", 2)` then `strings.SplitN("/", 2)` — which on the new format yielded `top = "email:dudenest"` (the email gobbled into segment 0) instead of `"photos"`. Result: the file would have been moved into a directory like `email:dudenest/2026/05/` — broken.

Fix: same scan strategy as `folderFromFileMap`; additionally if the location contains the configured `PathRoot`, preserve it in the destination directory so `MoveFile` keeps the file under `dudenest/`. Added `Pipeline.AccountManager()` accessor so `handleMeta` can read the active `PathRoot` from policy without going through unexported fields.

### Upgrade

Pure hotfix — no schema/state changes. Update via `relay update` (or scp if GitHub rate-limit hit) + restart. After restart, all previously-uploaded photos that were on Phase α path become immediately visible in the Photos tab; no migration job needed.

---

## [0.17.2] — 2026-05-22 — Phase α: multi-account orchestration (CloudAccount model + SelectReplicas)

Non-breaking. Solves the problem that the previous version hard-coded `limit := 2` and `p.clouds[:2]` in upload — meaning that for users with 3+ cloud accounts, only the first two (in filesystem order) were ever written to. Phase α replaces this with a policy-driven selector.

### Model — `pkg/types/accounts.go` (new file)

- `CloudAccount` struct — identity (`int64` monotonic ID, `Provider`, `Email`, `AddedAt`), role machine (`Role`, `Priority`, `Pinned`), quota cache (`QuotaTotalBytes`, `QuotaUsedBytes`, `QuotaCheckedAt`), per-account policy overrides (`SoftCapPct`, `HardCapPct`, `MaxFileSizeBytes`, `AcceptsContentTypes`), forward-compat (`Region`, `CompressionLevel`, `LogicalAliasOK`), state (`Status`, `LastError`, `LastSeenAt`, `QuarantineUntil`).
- `Role` enum: PrimaryWrite / ReplicaWrite / ReadOnly / ColdArchive / Drain / Quarantine.
- `Status` enum: Active / ReauthNeeded / OverQuota / Error / Removed.
- `AccountPolicyConfig` — 26 fields, ALL user-configurable from the UI (no hardcoded behavior). The Standard preset is in `DefaultPolicy()`.
- `DisplayID()` → `"ID001".."ID999"` then `"ID1000+"` (auto-expanding pad).
- `PathFor()` → cloud-side path per `cfg.PathScheme` (`"year_month"` default per design decision §11 #5 — no migration from existing).
- `AcceptsContentType()` filter.

### Engine — `internal/account/manager.go` (new file)

- `Manager` owns `accounts.json` + `account_policy.json` (atomic-write on every mutation).
- `SelectReplicas(file, accounts, cfg)` — **pure function** (no I/O, fully unit-testable). Four steps:
  1. Filter: Active + writable role + below HardCap + within MaxFileSize + AcceptsContentType.
  2. Stable-sort by `(Priority ASC, FreeBytes DESC, AddedAt ASC)`.
  3. Pick up to `cfg.ReplicationFactor`, honoring `DiversityRequired` (Provider) + `DiversityRegionRequired` (Region).
  4. Insufficient-replicas: return error or partial+warning per `AllowSingleReplicaWithWarning`.
- `BootstrapFromProviders(providerIDs)` — first-run migration helper. When `accounts.json` is empty, auto-creates CloudAccount records from existing `providers/*.json` (first → PrimaryWrite/Priority 0, rest → ReplicaWrite/Priority N).
- `AddAccount`, `Reorder`, `SetRole`, `NextID`, `Accounts`, `ActiveAccounts` mutators (goroutine-safe via `sync.RWMutex`).

### Tests — 14 new (`internal/account/manager_test.go`)

`SelectReplicas` acceptance α-1..α-8 (zero accounts, single+warning allowed, single strict, picks-first-2-by-priority, tie-break-by-free-space, over-hard-cap-excluded, diversity-required, content-type-filter) + `AddAccount` first-vs-subsequent + `NextID` monotonic-across-removed + `Reorder` dense-priorities + `DisplayID` padding + `PathFor` default-year-month + accounts/policy round-trip + on-disk persistence.

### Pipeline integration — `internal/pipeline/pipeline.go`

- `Pipeline.accts *account.Manager` field (nil = legacy "first 2 in slice" fallback, kept for tests + CLI).
- `New(masterKey, clouds, mapStorePath, accts)` — new 4th arg, `nil` opts into legacy path. All existing callers updated (CLI in `cmd/relay/main.go`, test files).
- `SetAccountManager(m)` setter for `cmd/relay/serve.go` to attach the long-lived Manager after pipeline construction.
- `findProviderByAccount(a)` maps `CloudAccount → CloudProvider` via `"<provider>:<email>"` match on `CloudProvider.ID()`.
- `uploadReplica` now calls `SelectReplicas` when `accts != nil`, falls back to old behavior otherwise. Path generation goes through `cfg.PathFor()`.

### Bootstrap — `cmd/relay/serve.go`

After pipeline init: `account.New(authConfigDir)` loads existing `accounts.json` (or creates empty Manager). If empty + providers exist, `BootstrapFromProviders` auto-populates with current filesystem order. Manager attached via `p.SetAccountManager(accMgr)`. Logs `✅ account bootstrap: created N CloudAccount records from existing providers (edit priorities in Settings → Cloud Accounts)`.

### User-visible behavior

| Setup | Pre-Phase α | Post-Phase α |
|-------|-------------|--------------|
| 2 accounts | Replicates to both (alphabetic by email) | Replicates to both, in Priority order |
| 3+ accounts | Replicates ONLY to first 2 (rest invisible to upload) | Replicates to top-RF by Priority + quota |
| Account full | Upload to that account fails, others unaffected | Account excluded if over HardCap (configurable per-account) |
| Single account | Upload OK (1 replica only, silent) | Upload OK + warning logged (`AllowSingleReplicaWithWarning=true` default) |

### Upgrade path

This is a non-breaking patch — both relays update via `dudenest-relay-update.timer` within 24h, or immediately with `ssh root@<relay> /usr/local/bin/relay update && systemctl restart …`. First start after update creates `accounts.json` from existing providers (idempotent — re-running does nothing). Configuration UI (Settings → Cloud Accounts) lands in Phase β.

### What's NOT in this release (Phase β/γ pending)

- Quota polling — `QuotaUsedBytes` stays at 0 until Phase β wires `Drive.about.get` etc. Until then the HardCap gate is inactive (everything is "0% used"); only Role + Priority drive selection.
- `ReconcileRoles` loop (auto-demote/promote) — Phase β.
- Admin endpoints (`/admin/accounts`, `/admin/policy`) + Flutter UI — Phase β.
- Encrypted backup blob (currently `maps_json` is still plaintext on the hub) — Phase β.
- Age-based rotation, deep archive, dedup — Phase γ.

### Design doc

`~/.AI/dudenest-application/CLOUD-ACCOUNT-POLICY-PLAN.md` (full data model + state machine + scenarios + CRUSH analysis + 3-phase roadmap).

---

## [0.17.1] — 2026-05-22 — s313: Phase 0 fast-update mechanism + RELAY_PUBLIC_URL anti-regression guard

Patch release closing s313 carry-overs. Non-breaking: backward-compatible with older hubs (`{"status":"ok"}`-only response) and with relays that never get `RELAY_PUBLIC_URL` set.

### Phase 0 fast-update (relay client side)

The 24h `dudenest-relay-update.timer` is too slow for hot-fixes — Phase 0 cuts mean update latency to ~30 seconds in steady state, ~5 seconds during the release burst window.

- `internal/backup/client.go`:
  - `Ping()` signature changed: now returns `(*PingResponse, error)` instead of `error`. The response carries hub-provided `latest_version`, `download_url`, `update_now`, `next_ping_seconds`. Old `{"status":"ok"}`-only responses still decode cleanly (unknown fields → zero values, no update push).
  - `Ping()` body now includes `arch` (`runtime.GOOS + "-" + runtime.GOARCH`) so the hub can dispatch the right `linux-amd64` / `linux-arm64` / `darwin-*` download URL.
  - On `update_now=true && latest_version != Version && download_url != ""`, fires `systemctl start dudenest-relay-update.service` in the background (fire-and-forget; the service replaces the binary and restarts the relay, which kills the calling goroutine).
  - Defense-in-depth: client-side checks `latest_version != Version` before triggering, even if hub claims `update_now=true` — guards against a buggy hub flapping the whole fleet.
  - `StartPingLoop(initial)` now adopts hub-driven `next_ping_seconds` after each ping, clamped to `[1s, 5min]`. Default in `cmd/relay/serve.go` lowered from `5*time.Minute` to `30*time.Second` (3 callsites).
  - New package-level `updateTrigger` var allows test injection without spawning real `systemctl`.

- Tests: `TestPing_BackwardCompatOldHub`, `TestPing_TriggersUpdateOnNewerVersion`, `TestPing_DoesNotTriggerOnSameVersion`, `TestPing_DoesNotTriggerOnMissingDownloadURL`, `TestPing_NilClientSafe`.

### s313 — `RELAY_PUBLIC_URL` anti-regression guard

Per `~/.AI/dudenest-application/session-2026-05-21-prod-incident-oauth.md`: relay-poc2 had `RELAY_PUBLIC_URL=https://relay2.dudenest.com` manually set in `/etc/dudenest/relay.env` per an obsolete plan. Every restart called `bc.UpdateURL("https://relay2.dudenest.com")` → CRDB overwrote the auto-provisioned `relay-<8hex>.dudenest.com` URL. Flutter then resolved a routing-less hostname.

- `cmd/relay/serve.go:219`: wraps `bc.UpdateURL(cfg.Backup.PublicURL)` in `if cfg.Backup.PublicURL != ""` — empty env means "trust the hub's auto-URL".
- Paired with server-side guard in `dudenest-backup` (`autoURLPattern` regex) — `/relay/update-url` rejects 409 Conflict for any auto→manual downgrade.

### Documentation

- `docs/RELAY-OPS.md`: new "🌐 Public URL lifecycle" section explaining auto vs legacy, anti-regression rationale, diagnosis commands.

### Upgrade

`dudenest-relay-update.timer` will pick this up within 24h. To accelerate: `ssh root@<relay-vm> /usr/local/bin/relay update`. After the binary swap and restart, the relay adopts the new 30s default ping interval and starts honouring hub-driven `next_ping_seconds` — meaning **any subsequent v0.17.2+ release reaches the fleet within ~30 seconds** without anyone touching the timer.

---

## [0.17.0] — 2026-05-20 — P5 (P5a + P5b + P5c bundled): CloudID-as-index + date-bucketed uploads + scan engine

### P5a — CloudID-as-index (replaces path as primary addressing)

Per user decision 2026-05-20: Drive's permanent file ID (`1o_qJz-ItwQzmp4rUCyygaZsrRjlBNDa0`) becomes the primary identifier in our blockmap, replacing path-based addressing. User renames/moves files on Drive directly → our index keeps working. One API call per Download (was 2).

**`pkg/types`** additions (all additive, no breaking changes):
- `Entry.CloudID string` — populated by `gdrive.Provider.List` from Drive's `files.id` field.
- `Block.CloudID string` — set by `pipeline.uploadReplica` from `UploadAndReturnID`; backfilled at relay startup for legacy entries.
- `CloudIDDownloader` interface (`DownloadByID` + `DeleteByID`) — one-call ID-stable ops.
- `CloudIDUploader` interface (`UploadAndReturnID`) — Upload returning the new file's ID.
- `CloudIDResolver` interface (`ResolvePathToID`) — for backfill.
- `CloudMover` interface (`MoveByID`) — re-bucket without re-upload (P5b auto-move).
- `StrategyForeign = "Foreign"` — files indexed but not uploaded by us (P5c scan engine).

**`gdrive.Provider`** implements all 4 new sub-interfaces (compile-time `var _ = ...` assertions). `Upload` keeps its CloudProvider-required signature but internally delegates to `UploadAndReturnID`.

**`pipeline`** addressing priority per Block: `CloudID → DownloadByID/DeleteByID` first, falls back to path-based `Download/Delete` only when CloudID is empty (pre-P5a entries) or the ID-based call fails. Pre-existing FileMaps load fine — `CloudID` is `omitempty`.

**Proactive backfill at relay startup**: `Pipeline.BackfillCloudIDs` walks every FileMap, resolves missing CloudIDs via `CloudIDResolver`, persists. Runs in background goroutine — doesn't block server start. For relay-poc with ~hundreds of legacy entries, completes in a few minutes; on the order of one Drive API call per file.

### P5b — Date-bucketed uploads + editable date with auto-move

**`pipeline.uploadReplica`** path template changed from `<folder>/<hash[:8]>/<name>` to `<folder>/<YYYY>/<MM>/<name>` where date comes from `fm.Created` (server time for now; full EXIF wiring in this codebase happens inside the thumbnail pipeline — see P5b open follow-up). Name collisions are OK: each upload gets a new Drive file ID even when name+parent match (per Drive's create-not-update semantics for replicated user data).

**`fileMeta.TakenAtOverride`** (new field in `/files/{id}/meta` JSON) — when user sets/changes via PATCH, `handleMeta` recomputes the date-bucket path and calls `Pipeline.MoveFile(fileID, newDir)`. CloudID is preserved (Drive `files.update(addParents, removeParents)`). Best-effort — failure logs `⚠️` but doesn't fail the PATCH (meta is persisted regardless).

`Pipeline.MoveFile` walks all replicas, calls `CloudMover.MoveByID` per shard, rewrites `Block.Location` to the new path. Atomicity not guaranteed across multi-replica moves; partial state self-heals on next download.

### P5c — Background scan engine (`internal/scan/`)

Discovers files already on cloud providers and registers them as `Strategy=Foreign` FileMaps (CloudID-addressed, no re-upload). User immediately sees their existing Drive content in Photos/Files tabs after authorizing the account.

**Triggers**:
1. `auth_done` WebSocket event from browser auth flow — newly authorized provider kicks off scan automatically.
2. `Scanner.AutoRescanLoop` — relay-wide goroutine checks every 5 min, starts scans when `now - last_finished ≥ interval`. Configurable per `<configDir>/scan/config.json`:
   ```json
   {"auto_rescan_enabled": true, "auto_rescan_interval_hours": 24, "skip_files_above_bytes": 0}
   ```
   Defaults: enabled, 24h, no size limit (per user decisions 2026-05-20).
3. Manual: `POST /admin/scan/start?provider=<id>` — Flutter Settings button.

**State machine per provider** (`<configDir>/scan/<provider_id>.json`): `idle | running | pausing | paused | error`. Counters: `files_discovered, files_newly_indexed, files_skipped, errors`. Resume from `current_folder` after pause.

**Pause = per-file immediate** (per user decision 2026-05-20): `cancel chan struct{}` checked between each `List` call and each entry iteration. Per-folder checkpoint persisted so resume is clean.

**Dedup**: at scan start, walker builds an in-memory set of all CloudIDs present in any existing FileMap. Re-scans are idempotent (already-known CloudIDs skipped).

**Admin endpoints** (same `requireAuthWithReg` auth as `/files`):
- `GET /admin/scan/status` — full JSON map of all providers' states.
- `POST /admin/scan/start?provider=<id>` — start/resume.
- `POST /admin/scan/pause?provider=<id>` — request pause (settles in seconds).
- `GET|POST /admin/scan/config` — read/write global config.

### Migration & fleet rollout

- Pre-P5a FileMaps: load fine (CloudID is `omitempty`). Backfill goroutine handles migration in the background; old Download paths keep working via Location fallback during the transition.
- Pre-P5b uploaded files (in `<folder>/<hash[:8]>/<name>`): keep their existing Location and CloudID; new uploads go to `<folder>/<YYYY>/<MM>/<name>`. Both schemes coexist indefinitely — no forced migration.
- Pre-P5c blockmaps: scan engine ignores existing entries by CloudID dedup. First scan after deploy discovers any files the user already had on Drive but never indexed (i.e. files on relay-poc's Drive that pre-date this relay). Background; user can monitor via `/admin/scan/status`.
- Fleet auto-update timer pulls v0.17.0 within 24 h; maintainer also pushes immediate update per session-end protocol so relay-poc/relay-poc2 get it in minutes, not hours.

### Known limitations (deferred to P6/P7)

- **No throttle (P6)** — scan walker calls `provider.List` as fast as the API allows. Drive's 1000 req/100s default is plenty for thousands of folders but a 50k-folder drive could brush against limits. User-aware throttling (slow when Flutter is hitting `/files`, full speed when idle) lands in P6.
- **No thumbnail generation for foreign files** — `lazyGenSidecars` handles it on first preview request (download-once-then-cache). Foreign files show generic icon until first view.
- **No Flutter scan UI yet (P7)** — endpoints are wired but no Settings → Sync Status screen yet. User can `curl` endpoints to inspect. P7 ships the visual progress bar + monogram provenance icons per user's earlier 2026-05-18 spec.
- **EXIF DateTimeOriginal not yet read in uploadReplica** — date-bucket source is currently `fm.Created` (≈ server upload time). When EXIF is read at upload time (existing thumbnail pipeline reads it for `taken_at` sidecar), the date-bucket path will start matching the photo's actual capture date. Until then, user can manually correct via `TakenAtOverride` in meta PATCH (which DOES trigger MoveFile).

---

## [0.14.0] — 2026-05-19 — P4: CloudLister sub-interface + gdrive Provider.List for scan engine foundation

### Added
- **`pkg/types.CloudLister`** — new sub-interface (NOT a change to `CloudProvider`):
  ```go
  type CloudLister interface {
      List(prefix string) ([]Entry, error)
  }
  ```
  Optional capability — scan engine (P5) type-asserts (`l, ok := provider.(CloudLister)`) and skips providers that don't implement it. Backward compatible: existing `CloudProvider` implementers compile unchanged. Go-idiomatic pattern (like `io.ReadSeeker` on top of `io.Reader`).
- **`pkg/types.Entry`** — single child of a folder returned by `List`:
  - `Path` (relative to provider base, `<prefix>/<name>`)
  - `Name` (leaf name)
  - `Size` (bytes; 0 for folders)
  - `MTime` (`time.Time` from provider's modified-time)
  - `IsDir` (true for folders; caller recurses with `List(entry.Path)`)
- **`gdrive.Provider.List(prefix)`** — implements `CloudLister`:
  - Resolves `prefix` to a folder ID via existing read-only `findPath`. Returns an error if any intermediate folder is missing — clean miss, no side effects.
  - Queries Drive API with `"<parentID>" in parents and trashed=false`, `PageSize=1000`, fields `nextPageToken, files(id, name, mimeType, size, modifiedTime)`.
  - Internally paginates via `NextPageToken` until exhausted; returned slice contains all entries under `prefix` (typical first-level: 1-2 API calls even for thousands of files).
  - Maps Drive's `mimeType=='application/vnd.google-apps.folder'` → `IsDir=true` (`Size=0`); files use Drive's `size` directly and `modifiedTime` parsed as RFC3339.
- Compile-time assertion `var _ types.CloudLister = (*Provider)(nil)` in `gdrive.go` so removal of `List` becomes a build error in CI.

### Scope decisions
- **First-level only** — `List` does NOT recurse. Caller (P5 scan engine) walks the tree by re-invoking `List(entry.Path)` for each `IsDir==true` entry, with throttling layered on top (P6 user-aware scan throttle).
- **No pagination knob in V1 interface** — provider handles `NextPageToken` internally; caller sees a single slice. If a single folder ever has >10k entries (rare in practice), V2 can add `ListOptions{PageToken string}` and `(entries, nextToken, err)` without breaking V1 callers (different method signature, both can coexist).
- **No legacy `/dudenest-relay/` fallback in List** — per user decision (2026-05-19, drop legacy). List operates only on the primary base folder. relay-poc's legacy tree is invisible to the scanner.

### Other providers
- `mega` and `local` do NOT implement `CloudLister` (per design — scan engine skips them via type assertion). To add MEGA listing later, implement `Provider.List(prefix string) ([]types.Entry, error)` on `internal/cloudconn/mega/mega.Provider`; for local, wrap `os.ReadDir`.

### Migration & fleet rollout
- Interface addition is purely additive — no existing code paths change. v0.13.0 binaries keep running fine.
- Fleet pulls v0.14.0 within 24h via timer; maintainer pushes immediate update to test relays per session-end protocol (s306).

### Tests
- No unit tests in this release — Drive API is awkward to mock cleanly without a full `httptest.Server` Drive emulator. P5 (scan engine) will exercise `List` end-to-end against the real GDrive on relay-poc, which is sufficient regression coverage given the simplicity of the query construction and pagination loop. If a regression slips in, it'll be visible as an empty scan or a 404 in the engine; the failure mode is loud.

---

## [0.13.0] — 2026-05-19 — Add `folder` field to GET /files response

### Added
- **`fileSummary.Folder`** field in `GET /files` response — `"photos"` or `"files"` derived from the first Shard's Location path prefix (matches the cloud-side folder picked at upload by P2's `mediaFolder()` helper).
- **`folderFromFileMap(fm)` helper** — single source of truth for classifying a `FileMap` into the right Flutter tab. Defaults to `"files"` for legacy entries with no recognizable prefix.
- Powers the Flutter Photos / Files tab filter introduced in P3 (s306).

---

## [0.12.0] — 2026-05-19 — Drop legacy /dudenest-relay/ alias + admin endpoints (version + update) for Flutter Update screen

### Removed
- **`/dudenest-relay/` legacy base folder support** in gdrive provider (per user decision 2026-05-19 — "zapominamy o legacy" / "drop it entirely"). All read-alias plumbing introduced in v0.10.0 is gone:
  - `legacyBasePath` constant — deleted
  - `Provider.legacyBaseFolderID` field — deleted
  - `Provider.resolveFile` method (primary→legacy fallback) — deleted
  - Folder cache key prefixing (`"P:"`/`"L:"`) — reverted to plain dir keys (single base, no collision possible)
  - Startup `findFolder("dudenest-relay", "root")` probe — gone
- **Consequence for relay-poc** (only relay with legacy data): existing FileMap entries that point at files which live ONLY under `/dudenest-relay/` are now unresolvable. Download will 404; Flutter shows a broken-thumbnail placeholder. User can delete those entries through the Flutter UI or `rm -rf` the `/dudenest-relay/` folder directly on Google Drive (relay no longer touches it).

### Added
- **`GET /admin/version`** (auth: JWT + X-Relay-Token, same as /files) — returns the running relay version, the latest GitHub release tag, and canonical links (repo, release, changelog, latest). Drives the Flutter "Update" screen header.
- **`POST /admin/update`** (same auth) — downloads the matching binary from GitHub release assets for the current `runtime.GOOS/GOARCH`, atomically replaces the relay executable, sends `{status: "updating", from_version, to_version}` back to the caller, then SIGTERMs the process after 2 seconds so systemd (`Restart=always`) brings the new version up. Lets the user one-click upgrade from the Flutter app without waiting for the 24-hour auto-update timer.
- **`cmd/relay/admin.go`** — new file housing both handlers. Reuses `fetchLatestRelease`, `archSuffix`, and `downloadReplace` from the existing `relay update` CLI command (single source of truth for the update mechanics).

### Kept (from v0.10.0 read-alias work)
- **`Provider.findPath` / `findFolder`** — read-only path resolution (NEVER creates folders on miss). This was the right side-effect-free fix for the pre-v0.10.0 bug where Download/Delete silently provisioned empty trees for every missing FileMap. The legacy fallback piece is gone; the read-only walk remains.

### Migration / fleet rollout
- Fleet auto-update timer pulls v0.12.0 within 24 h on every relay. Per the session protocol updated 2026-05-19, the maintainer also pushes `relay update && systemctl restart` to each test relay at session end so the new version is live immediately (no 24 h wait for manual testing).
- After v0.12.0 deploy, any relay that still has legacy `/dudenest-relay/...` files indexed will start returning 404s for them — that's the intended behavior; the index is allowed to drift until the user cleans it via the Flutter delete flow.

---

## [0.11.0] — 2026-05-19 — Content-type routing: media → /dudenest/photos/, non-media → /dudenest/files/

### Changed
- **`pipeline.uploadReplica` cloud path template**: was `files/<hash>/<name>` regardless of content type, now `<folder>/<hash>/<name>` where `<folder>` is decided by a single call to `mediaFolder(name, data)` before the parallel replica goroutines spawn. P2 of `docs/PHOTOS-FILES-REDESIGN.md`.
- **`pkg/types`**: added public constants `PhotosFolder = "photos"` and `FilesFolder = "files"` so future scan engine (P5) and Flutter UI (P3) can reference the same canonical folder names instead of hard-coded strings.

### Added
- **`internal/pipeline.mediaFolder(name, data)`** (private helper): chooses `PhotosFolder` vs `FilesFolder`.
  - Primary: `net/http.DetectContentType` magic-byte sniff (first 512 bytes). Top-level MIME `image/*` or `video/*` → `PhotosFolder`.
  - Fallback: when sniff returns `application/octet-stream` (no signature recognized), file extension routing for formats Go stdlib can't sniff confidently:
    - **HEIC/HEIF** (Apple iPhone photos — critical, every iPhone photo would otherwise be misrouted), **RAW** family (.raw, .arw, .nef, .cr2, .cr3, .dng, .rw2, .orf, .pef, .rwl, .srw — camera photographers), **video** containers (.mov, .mkv, .m4v, .3gp, .mts, .m2ts, .avi).
  - Everything else → `FilesFolder`.
  - Sniff takes precedence over extension when conclusive — a PDF renamed `disguised.jpg` still routes to `FilesFolder`.
- **`internal/pipeline/media_folder_test.go`** (10+ test cases): pins JPEG/PNG/GIF/WEBP/MP4 magic-byte detection, PDF/ZIP/text non-media routing, HEIC and RAW extension fallback (case-insensitive), short-data safety, and the sniff-overrides-extension contract.
- **`TestReplicaRoutesByContentType`** in `replica_test.go`: end-to-end via `MockCloud` — uploads a PNG and a text file, asserts that `MockCloud.storage` keys start with `photos/` and `files/` respectively, then downloads the PNG to confirm `FileMap.Location` round-trips correctly under the new path layout.

### Migration & compatibility
- **`uploadChunking` is UNCHANGED** — Reed-Solomon shard uploads keep using `blocks/<hash>/<chunk>/<shard>` regardless of content type. Splitting blocks by media-vs-non-media adds no user value (they're encrypted opaque chunks).
- **`FileMap.Location` schema unchanged** — Locations stored before v0.11.0 (`gdrive:<email>:files/<hash>/<name>`) keep working unmodified: gdrive provider downloads from whatever path is stored.
- **Existing files in `/dudenest/files/`** (uploaded between v0.10.0 and v0.11.0) — small window where media also landed there. They keep resolving via Location lookup. No migration needed.
- **`/dudenest-relay/files/` legacy** — still served via the v0.10.0 read-alias fallback in `gdrive.Provider.resolveFile`.
- Fleet auto-update timer pulls v0.11.0 within 24 h on every relay. Restart picks up new routing. **No operator action**.

### Result
After v0.11.0 deploy, a fresh upload of `IMG_0123.HEIC` (iPhone photo) lands at `/dudenest/photos/<hash>/IMG_0123.HEIC` on Google Drive (verifiable via Drive web UI). A fresh upload of `invoice.pdf` lands at `/dudenest/files/<hash>/invoice.pdf`. Old files (chunked Reed-Solomon and legacy replicas under `/files/`) remain readable.

---

## [0.10.0] — 2026-05-19 — Cloud folder rename: dudenest-relay → dudenest (read-aliased legacy)

### Changed
- **`--gdrive-path` default**: `dudenest-relay` → `dudenest` (`cmd/relay/main.go`). All new GDrive uploads on every relay land under `/dudenest/files/<hash>/<name>` instead of the legacy `/dudenest-relay/files/...`. First step of the redesign in `docs/PHOTOS-FILES-REDESIGN.md` — P2 (next release) splits `/files/` into `/photos/` for media and `/files/` for non-media.
- **`--mega-path` default**: same rename (`dudenest-relay` → `dudenest`). MEGA legacy read-alias deferred to a follow-up — `internal/cloudconn/mega` does not yet support fallback lookup (no user has legacy MEGA data per current fleet).

### Added
- **`gdrive.Provider.legacyBaseFolderID`** — at provider startup, if a `dudenest-relay` folder already exists at Drive root (pre-v0.10.0 install), its ID is captured for read-only fallback. New folder is NEVER created at the legacy name. Empty string means no legacy content — `Download`/`Delete` skip the fallback path.
- **`gdrive.Provider.resolveFile(path)`** — internal helper that tries the primary base first, then the legacy base. Returns `(fileID, "primary"|"legacy", err)` so logging can surface where the file came from. Used by `Download` and `Delete`.
- **`gdrive.Provider.findPath` / `findFolder`** — read-only counterparts of `ensurePath`/`ensureFolder`. They never create folders, so a Download/Delete miss is fast and side-effect-free (previously every miss provisioned an empty folder tree on Drive).
- **Folder cache key prefixing** (`P:` for primary, `L:` for legacy) — both bases coexist in the same `folderCache` map without collisions (e.g. `dudenest/files/abc` and `dudenest-relay/files/abc` would otherwise overwrite each other's IDs).

### Migration & compatibility
- **Read-alias forever** (per `PHOTOS-FILES-REDESIGN.md` §3.1 option B): existing files on relay-poc and any other pre-v0.10.0 deployment STAY where they are. The relay reads them transparently from the legacy base. Over time the legacy tree drains naturally (when users delete files or replace them with new uploads that go to the new base).
- **Forward-only writes**: `Upload` ALWAYS lands in the primary base. The legacy tree is read-only from v0.10.0 onward.
- **Blockmap untouched**: `FileMap.Chunks[].Shards[].Location` (`gdrive:<email>:files/<hash>/<name>`) is unchanged — same relative path stored, the provider resolves it.
- **No operator action**: fleet auto-update timer pulls v0.10.0 within 24 h. Restart picks up new default. Existing uploads remain readable.

### Result on relay-poc (Debian 12, real test target with legacy `/dudenest-relay/files/` content)
After v0.10.0 deploy:
1. New uploads go to `/dudenest/files/<hash>/<name>` (verifiable via Drive web UI).
2. Old uploads downloaded via `/files/{id}` resolve transparently — relay logs `download path X resolved=legacy`.
3. Delete of an old file removes it from the legacy tree.
4. `/dudenest-relay/` shrinks over time as users replace photos.

---

## [0.9.2] — 2026-05-19 — Fix --client-secret / --gdrive-secret flag mismatch (relay-poc2 503 root cause)

### Fixed
- **`factory: failed to init gdrive:<email>: read client_secret: open /root/.config/dudenest/gdrive_client_secret.json: no such file or directory`** — root cause of the persistent `/files=503` on relay-poc2 even after auth_done.
- Two separate flags refer to the SAME OAuth client_secret.json file:
  - `--client-secret` (in `serveCmd`, default `~/.config/dudenest/gdrive_client_secret.json`) — used by the browser auth flow.
  - `--gdrive-secret` (root persistent flag, default `/root/.config/dudenest/gdrive_client_secret.json`) — used by `getClouds()` → `pipeline.LoadAllProviders` → `gdrive.New`.
- The systemd unit shipped by `scripts/install.sh` only passes `--client-secret /etc/dudenest/gdrive_client_secret.json` (the canonical config-dir location). `--gdrive-secret` was never set, so `getClouds()` looked at the stale legacy default which doesn't exist on standard `install.sh` deployments. Result: provider init failed → standby → 503 forever (with v0.9.1 the standby loop is in place, but it has nothing to do because the file isn't where the factory looks for it).
- **Fix**: in `runServe`, if `gdriveSecretPath` is unchanged from its default (or simply differs from `authClientSecret`), set `gdriveSecretPath = authClientSecret` before any pipeline init. The two flags now point at the same file in serve mode, which is the only mode where both matter.

### Compatibility
- No flag, config, or systemd-unit changes required. Existing deployments pick up the fix transparently on next `dudenest-relay-update.timer` cycle.

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
