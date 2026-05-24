# CloudID-as-Index — Architectural Analysis for P5 (Scan Engine)

**Author**: Dariusz Porczyński
**Created**: 2026-05-20
**Status**: 📐 design — awaiting user confirmation before P5 implementation
**Context**: User decisions Q5-Q8 from PHOTOS-FILES-REDESIGN.md, answered 2026-05-20

---

## TL;DR

User's Q6 answer reshapes the data model: **Drive file ID becomes the primary identifier of every file in our index**, replacing path-based addressing. This is *more robust* than what we have today, not a workaround. Implementation is realistic and breaks down into 3 incremental ship-able pieces (P5a / P5b / P5c).

Other answers (Q5 all-files, Q7 per-file pause, Q8 24h auto-rescan default ON) integrate cleanly with the CloudID model.

---

## Why CloudID-as-Index is actually better

Today (post-P2):
- `FileMap.Replicas[0].Location = "gdrive:<email>:<relative_path>"`
- `gdrive.Provider.Download(path)` walks Drive's folder tree, calls `files.list(q=...)` to resolve the path to a file ID, then fetches by ID.
- Two API calls per Download (list to find ID, then get).
- **Fragile**: if user renames/moves the file on Drive directly, our blockmap entry is stale. Next Download → 404.

With CloudID:
- `FileMap.Replicas[0].CloudID = "1o_qJz-ItwQzmp4rUCyygaZsrRjlBNDa0"` (Drive's permanent file ID)
- `gdrive.Provider.DownloadByID(id)` is `svc.Files.Get(id).Download()` — **one API call**.
- Renames/moves on Drive side: file ID stays the same → our index keeps working.
- Path information becomes informational (for UI display, for organizing new uploads) rather than addressing.

Drive API natively operates on file IDs; we're aligning with the platform.

The same idea applies to MEGA, OneDrive, pCloud (each has a per-file permanent ID separate from path). The `CloudLister.Entry` and `CloudProvider` interfaces will gain a CloudID field/method that providers implement as appropriate.

---

## Q6 in detail — implementation plan

User asked: file at `https://drive.google.com/file/d/1o_qJz-ItwQzmp4rUCyygaZsrRjlBNDa0/view` — the path segment `1o_qJz-ItwQzmp4rUCyygaZsrRjlBNDa0` is the Drive file ID. Use that as our index key.

### Schema changes (`pkg/types/types.go`)

```go
// Add CloudID to Entry (returned by CloudLister.List in P4):
type Entry struct {
    Path    string    `json:"path"`     // informational — relative to provider base
    Name    string    `json:"name"`
    Size    int64     `json:"size"`
    MTime   time.Time `json:"mtime"`
    IsDir   bool      `json:"is_dir"`
    CloudID string    `json:"cloud_id,omitempty"` // NEW — provider's permanent file ID (Drive: 28-char alphanum)
}

// Add CloudID to Replica:
type Block struct {
    ID       string    `json:"id"`
    ReplicaIdx int       `json:"replica_idx"`
    Size     int64     `json:"size"`
    Location string    `json:"location"`           // KEPT for back-compat + debugging
    CloudID  string    `json:"cloud_id,omitempty"` // NEW — primary addressing key; Location becomes fallback
    Created  time.Time `json:"created"`
}
```

`Location` stays for backward compat with existing FileMaps (relay-poc has thousands of pre-CloudID entries). Migration: when Download via Location succeeds, we capture the CloudID into the FileMap and persist — lazy backfill, no separate migration job needed.

### Provider interface (`pkg/types/types.go`)

Add an optional sub-interface (same pattern as `CloudLister`):

```go
type CloudIDDownloader interface {
    DownloadByID(cloudID string) ([]byte, error)
    DeleteByID(cloudID string) error
}
```

`gdrive.Provider` implements both `CloudLister` and `CloudIDDownloader`. Other providers gain it incrementally.

Pipeline.Download logic:
```go
r := fm.Replicas[0]
if r.CloudID != "" {
    return idProv.DownloadByID(r.CloudID)
}
// Fallback: legacy path-based
data, err := p.Download(r.Location)
if err == nil && idProv != nil {
    // Lazy capture: resolve path → ID once, persist for next time
    if id := p.resolvePathToID(r.Location); id != "" {
        r.CloudID = id
        bm.Save(fm)
    }
}
return data, err
```

### Cloud paths for NEW uploads (date-bucketed, name collisions OK)

```go
func datePath(folder string, when time.Time, name string) string {
    return fmt.Sprintf("%s/%04d/%02d/%s", folder, when.Year(), int(when.Month()), name)
    // e.g. "photos/2026/05/IMG_0001.JPG"
}
```

Date source priority:
1. EXIF `DateTimeOriginal` (for image/video — extracted by existing `internal/thumbnail` pipeline)
2. Client-provided upload timestamp (if Flutter sends it)
3. Server upload time

Two `IMG_0001.JPG` in the same month → both upload to `photos/2026/05/IMG_0001.JPG`. Drive's `files.create` ALWAYS creates a new file with a new ID, even when name+parent match (no automatic dedup). Our blockmap records each with its own `CloudID`. UI shows both, distinguishes by CloudID + thumbnail.

**Why this works**: Drive folder structure is no longer our addressing mechanism. CloudID is. Folders are just for user's eyeball browsing in Drive UI.

### Scanned files keep their original location (no cloud-side restructure)

`scan.Walker` calls `provider.List(prefix)` recursively starting from base folder root. Each Entry already has CloudID. We create a FileMap with:
- `Strategy: types.StrategyForeign`
- `Name: entry.Name`
- `Size: entry.Size`
- `Created: entry.MTime`
- `Replicas: [{CloudID: entry.CloudID, Location: entry.Path}]`

**No file is moved or renamed on the cloud side.** User's Drive structure is preserved exactly as they have it.

---

## Q5 (all files, no limit)

Straightforward — no per-file size check in walker. Estimated impact for 50k photos / 500GB drive: ~3-5 hours of scanning at 30 RPS Drive API rate (well under the 1000/100s limit with conservative throttling). Each List call returns up to 1000 entries; for 50k files in ~5k folders, that's ~5k List calls + 50k metadata fetches if we need per-file Drive `files.get` (we don't — List already includes `id, name, mimeType, size, modifiedTime`).

The `--no-tree-shake-icons` Flutter regression (s309) is unrelated to this — scan engine is server-side Go.

---

## Q7 (per-file immediate pause)

State machine has a `cancel chan struct{}` checked between each Drive API call. When user clicks Pause in Settings:
1. Set state to `pausing`, close cancel chan
2. Worker goroutine sees cancel — drops in-progress file (any partial state: no FileMap saved yet, no thumbnail written → nothing to roll back; thumbnail temp files auto-cleaned)
3. State transitions to `paused`, persists `{provider_id, last_walked_folder, status: paused}`
4. Resume: re-walk from `last_walked_folder` (idempotent — entries already in blockmap are skipped by CloudID dedup check)

Per-file granularity is more responsive than per-folder; partial state is handled by "blockmap entry written" as the commit boundary.

---

## Q8 (24h auto-rescan default ON, configurable, scan-now button, progress animation)

Settings keys (persisted in `<configDir>/scan/config.json`):
```json
{
  "auto_rescan_enabled": true,
  "auto_rescan_interval_hours": 24,
  "skip_files_above_bytes": null
}
```

Background goroutine in relay: every 5 min checks if any provider's `last_scan_finished + interval` ≤ now → triggers scan for that provider.

UI animation (P7 — separate Flutter session):
- Progress bar based on estimate: `(scanned_count / estimated_total) * 100%`
- Estimate source: Drive `about.get(fields=storageQuota,storage)` returns approximate file counts per drive; if unavailable, use running rate to extrapolate
- If estimate unknown, show indeterminate spinner + live counter ("Found 12,453 files…")
- Per-folder breadcrumb of current location

`POST /admin/scan/start?provider=<id>` — manual trigger
`POST /admin/scan/pause?provider=<id>` — pause
`GET /admin/scan/status` — returns per-provider state for the UI

---

## Migration concerns

### Existing relay-poc blockmap (pre-CloudID)

relay-poc has thousands of FileMaps with `Location` only, no `CloudID`. Three paths:

**Option A (recommended) — lazy backfill on first Download/scan**:
- Schema change is additive: `CloudID` field is `omitempty`. Old FileMaps load fine.
- First time we Download a file with empty CloudID, we resolve path → ID via existing logic, then save the ID into the FileMap.
- After a few weeks, most accessed files are backfilled. Unaccessed legacy entries don't need backfill (they're not blocking anything).

**Option B — proactive backfill at relay startup**:
- Walk all FileMaps with empty CloudID, resolve via Drive API, save.
- One-shot cost on first startup post-deploy: for relay-poc with ~hundreds of files, a few minutes of Drive API calls.
- Trade-off: startup latency, one-time API cost. Predictable, no surprises.

Recommend **A** (lazy). If user wants instant consistency, add as Settings → "Backfill all CloudIDs now" button.

### Pre-P2 files in legacy `/files/` (uploaded before content-type routing)

Already handled: Location string contains the actual path, no migration needed. CloudID backfill works the same way regardless of which folder the file lives in.

---

## Phased delivery plan

### P5a — Schema + GDrive CloudID plumbing (~0.5 day)
- `pkg/types`: add `Entry.CloudID`, `Block.CloudID`, `CloudIDDownloader` interface
- `gdrive.Provider`: capture ID in `Upload` return + `List` Entry; implement `DownloadByID` + `DeleteByID`
- `pipeline.Download/Delete`: prefer CloudID, fall back to Location, lazy-capture ID on first success
- Existing FileMaps continue working; new uploads get CloudID immediately
- Tag v0.15.0, deploy
- **No user-visible change** (other than slightly faster downloads). Foundation only.

### P5b — Date-bucketed uploads (~0.5 day)
- `pipeline.uploadReplica`: `<folder>/<YYYY>/<MM>/<name>` instead of `<folder>/<hash>/<name>`
- Date source: EXIF if available, else upload time
- Name collisions explicitly OK (Drive creates separate IDs)
- Tag v0.16.0, deploy
- **User-visible**: new uploads land in date folders on Drive; UI uses CloudID so no app change needed

### P5c — Scan engine (~2 days)
- `internal/scan/scanner.go`: state machine, per-provider goroutine, persistence in `<configDir>/scan/<provider_id>.json`
- `internal/scan/throttle.go`: stub for P6 (user-aware throttling, separate session)
- Triggers: `auth_done` WebSocket event (new provider) + 24h timer (configurable) + manual `/admin/scan/start`
- Walker: `provider.List(prefix)` recursive, FileMap with `Strategy: Foreign + CloudID`, dedup by CloudID
- Endpoints: `/admin/scan/{status,start,pause,resume,config}`
- Tag v0.17.0, deploy
- Acceptance: relay-poc2 added `cryptoeco.co.uk@gmail.com` → background scan kicks in → after some hours, all photos visible in Photos tab + all docs in Files tab, all with original Drive filenames + folder structure preserved

### P6 — User-aware throttling (~0.5 day) — separate session
### P7 — Flutter UI for scan progress + monogram provenance + Settings sync report (~1.5 day) — separate session

---

## What to confirm before implementation

1. **OK na lazy backfill (Option A)** dla migracji relay-poc, czy chcesz Backfill button w Settings od razu?
2. **EXIF first, upload-time fallback** dla date-bucket source — OK? Albo wolisz inną hierarchię?
3. **Phased delivery (P5a → P5b → P5c)** — OK, możemy review po każdej fazie? Lub wolisz monolityczny P5 z jednym tagiem?
4. **24h auto-rescan default ON od pierwszego deploy v0.17.0** — OK, czy wolisz default OFF z opt-in w Settings (mniej "magic" przy pierwszym uruchomieniu)?

Po Twoich odpowiedziach na te 4 startujemy implementację. Każda faza ~ kilka godzin pracy → deploy → review → następna.
