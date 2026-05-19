# Photos / Files / Auto-Scan — Architectural Redesign Proposal

**Author**: Dariusz Porczyński
**Created**: 2026-05-19
**Status**: 📐 design — pending user review
**Scope**: 🟥 MAJOR — touches dudenest-relay, dudenest (Flutter), dudenest-backup; multi-week effort, recommended to ship in 7 phases (each = separate session + tag)

---

## 1. What changes

### 1.1 Bottom nav (Flutter)

Today: `Files | Settings`. After redesign: `Photos | Files | Upload | Settings`.

- **Photos**: ALL media (image + video) — both Dudenest-uploaded and scanned-from-cloud.
- **Files**: ALL non-media (documents, archives, etc.) — both Dudenest-uploaded and scanned-from-cloud.
- **Upload**: extracted from FAB into its own nav slot (more discoverable).
- **Settings**: same as today, plus a new "Scan progress" section.

### 1.2 Cloud folder layout

| Type | Old path (today) | New path (target) |
|------|------------------|-------------------|
| Media (photo, video) uploaded via Dudenest | `/dudenest-relay/files/<hash>/<name>` | `/dudenest/photos/<hash>/<name>` |
| Non-media uploaded via Dudenest | `/dudenest-relay/files/<hash>/<name>` | `/dudenest/files/<hash>/<name>` |
| Erasure-coded blocks (legacy chunking strategy) | `/dudenest-relay/blocks/...` | `/dudenest/blocks/...` |

Path classification is **content-type-driven** at upload time (`magic-number` sniff, fallback to extension).

### 1.3 Auto-scan after cloud account add

When a new provider is authorized (relay's `auth_done` ws event):
1. **Phase A (priority)**: walk `/dudenest/photos/` and `/dudenest/files/` — fast import of Dudenest-uploaded content from another relay (e.g. relay-poc files visible immediately on relay-poc2 when same GDrive is added).
2. **Phase B (background, low priority)**: walk the **entire cloud root** — every other file the user has in that account gets indexed (photos appear under `Photos`, everything else under `Files`).

Per-file work: `HEAD`/metadata fetch → MIME sniff → thumbnail (if media) → blockmap entry (Strategy=`Foreign` — see §2.3).

### 1.4 Throttling (user-aware)

- Relay tracks `lastUserHTTP` timestamp (any non-internal endpoint hit).
- Two scan modes:
  - **Full speed** when `now - lastUserHTTP > 60s` (default).
  - **Throttled** (1 file every 5s, single goroutine, no parallel decode) when user active.
- Implementation: `internal/scan/throttle.go` — a token bucket whose fill rate is gated by a `userActive() bool` polled each iteration.

### 1.5 Scan progress UI

- Each folder card in Photos/Files shows:
  - File count (real if provider supports `count`, otherwise running estimate).
  - "Scanning… N/M done" badge while in progress.
  - Spinner overlay at folder level until walk completes.
- New Settings → "Sync status" screen:
  - Per-account: total files known, scanned, thumbnails generated, errors, last scan finished/in-progress, ETA (based on current rate).
  - Per-account: pause / resume / re-scan buttons.

### 1.6 Provenance icons (hover)

Per-file overlay (top-right corner of tile, fade in on hover/long-press on mobile):
- **Green Dudenest leaf** 🌱 — file was Dudenest-uploaded (lives in `/dudenest/photos/` or `/dudenest/files/`).
- **Provider color chip** — single-letter or 2-letter monogram tinted with provider brand color:
  - GDrive: blue/green/yellow tri-color or simple "G".
  - MEGA: red "M".
  - OneDrive: blue cloud silhouette or "O".
  - pCloud: yellow "p".
  - Filen: dark grey "F".
- Multiple chips if the file lives on multiple accounts (replica strategy).

**My recommendation**: use **monogram chips** rather than upstream brand logos. Reasons:
1. Brand logos require licensing review for each provider.
2. Monograms render crisp at 16px (logos blur).
3. Consistent visual rhythm across providers.
4. Easier to add a new provider later — just a letter + color.

If you prefer real logos: store SVGs under `assets/provider_logos/<provider>.svg`, license-checked. Implementation cost is the same on Flutter side.

---

## 2. Implementation plan — 7 phases

Each phase is **independently shippable** + reversible. Tag at the end of each (e.g. v0.10.0 … v0.13.0 → v1.0.0 when last lands). User reviews after every phase before next starts.

| Phase | Scope | Touches | Estimated work | Risk |
|-------|-------|---------|----------------|------|
| **P1** | Path rename `/dudenest-relay/` → `/dudenest/`, with backward-compat alias reads | relay (`gdriveBasePath` default, `uploadReplica` path templates), migration script | 0.5 day | LOW — alias keeps old paths readable; no data move |
| **P2** | Content-type-driven upload routing: media → `/dudenest/photos/`, non-media → `/dudenest/files/` | relay (`pipeline.Upload` adds MIME sniff + path selection) | 0.5 day | LOW — new uploads only, doesn't touch existing |
| **P3** | Flutter nav restructure: bottom nav with Photos / Files / Upload / Settings; filter `/files` response by media-vs-non-media client-side | dudenest (Flutter only — `main.dart` nav, `relay_screen` → `photos_screen`, new `files_screen`, dedicated `upload_screen` as nav root) | 1 day | LOW — pure UI, no API changes |
| **P4** | `CloudProvider.List(prefix) ([]Entry, error)` interface + gdrive implementation. Per-entry returns `{path, size, mtime, mime_type_hint, sha256_if_available}`. | relay (`pkg/types.CloudProvider`, `internal/cloudconn/gdrive`), other providers stubbed with `ErrUnimplemented` | 1 day | MED — interface change, all providers must compile |
| **P5** | Scan engine: persistent state machine (`{provider_id, last_token, status, counts}` in JSON sidecar), 2-phase walker (priority `/dudenest/*` then root), thumbnail pipeline, blockmap `Strategy=Foreign` for indexed-not-uploaded entries | relay (new `internal/scan/`), blockmap schema bump | 2 days | MED — non-trivial state, restartability matters |
| **P6** | Throttling — user-active detection + token-bucket scheduler | relay (`internal/scan/throttle.go`, middleware tap on every non-internal request) | 0.5 day | LOW — isolated, easy to tune |
| **P7** | Flutter scan-progress UI + Settings → "Sync status" + hover provenance icons | dudenest (Flutter only — new widgets, WS event handlers for scan progress) | 1.5 days | LOW — UI, but lots of state surfaces |

**Total**: ~7 days of focused work, spread across 7 sessions for review/iteration.

---

## 3. Migration considerations

### 3.1 Existing relay-poc files (legacy `/dudenest-relay/files/`)

Two paths, my recommendation is the second:

- **A. Move files** — relay walks legacy path, copies each blob to new path, updates blockmap, deletes old. Risky: I/O-heavy, can fail mid-way, doubles cost during transition.
- **B. Read-alias** — keep blockmap entries pointing at legacy paths exactly as they were. Add a path-resolver: when scanner encounters `/dudenest-relay/files/` while walking root, recognize as legacy Dudenest content, treat identically to `/dudenest/files/`. New uploads always land in `/dudenest/...`. No file is ever moved. Over time legacy paths drain naturally as files are deleted/re-uploaded.

### 3.2 Backwards compatibility for `dudenest-backup`

Relay sends `FileMap` JSON to backup. Adding `Strategy=Foreign` and a `ProvenanceProvider` field is additive — old backups load fine (empty fields), new ones round-trip cleanly.

---

## 4. Open questions for you

### Q1 — provider icons

Monograms (my proposal) or upstream brand logos? If logos, do we have license clearance for GDrive/MEGA/OneDrive marks at scale?

### Q2 — migration strategy

A (move legacy files to new layout) or B (read-alias forever)? B is dramatically simpler — recommend B.

### Q3 — phase order

Are you OK with the 7-phase split, with review/tag at each phase end? Or do you want everything in one branch over weeks?

### Q4 — non-media classification rule

How granular: a `.zip` of photos — is that "Files" (because zip) or "Photos" (because contents)? My proposal: pure top-level MIME — `.zip` always lives in Files. We don't peek inside archives.

### Q5 — scan scope (re-confirm)

Per your message: scan the WHOLE cloud root, even 50k files. Confirmed I should not cap or filter by size? (Some users may have 500GB of `.bak` files they don't want indexed.) Could we add a Settings toggle "Skip files >100MB" to opt out? Default = scan all.

### Q6 — per-provider folder structure inside `/dudenest/photos/`

Should it mirror upload order (`/dudenest/photos/<hash>/<name>`) or be organized into date buckets (`/dudenest/photos/2026/05/<name>`)? Date buckets help users who later open GDrive directly. Hash-based keeps current behavior and avoids name collisions. My recommendation: stay with `<hash>/<name>` for predictability; user can browse via Dudenest UI for date view.

### Q7 — pause/resume granularity

Pause at: account level (entire scan paused) | folder level (current folder finishes, then pauses) | file level (immediate)? My recommendation: folder level (clean checkpoint, simple state).

### Q8 — incremental re-scan

When user adds a new file to GDrive directly (not via Dudenest), should the scanner detect and index it? My proposal: re-run Phase B (full scan) on demand from Settings, plus an optional 24h auto-recheck timer (configurable, default off).

### Q9 — for the 503 bug fix (v0.9.1) — already shipped this session

Confirmed shipped. relay-poc2 currently in standby with creds on disk — would auto-recover on next restart even without v0.9.1, because creds are now present and `getPipeline()` succeeds at startup. v0.9.1 is the fix for the ORIGINAL bug pattern (relay starts → user adds creds → relay supposed to recover without restart). Auto-update timer pulls v0.9.1 on every relay within 24h.

### Q10 — first phase to start?

Once you've reviewed and answered Q1–Q8, which phase do you want me to start? My recommendation: **P3 (Flutter nav restructure)** first, because:
1. Lowest risk (no backend changes).
2. Immediately visible to you for usability feedback.
3. Doesn't lock anything else in.
4. Once nav is settled, P1 and P2 cement the storage layout, P4–P7 build out scan engine.

Alternatively: **P1 + P2 + P4 backend foundation first** (no user-visible change), then P3 once we know APIs.

---

## 5. What's NOT in this proposal

- **Pause/Resume mid-upload**: orthogonal feature, not part of this redesign.
- **Multi-account merge view**: if same photo lives on GDrive AND MEGA via replica strategy, it appears once in the UI today; that stays.
- **Sharing / external links**: not in scope here.
- **Search/filter**: future work, after scan engine produces a queryable index.
