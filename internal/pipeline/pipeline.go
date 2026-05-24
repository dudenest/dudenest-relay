// Package pipeline orchestrates the upload/download lifecycle for files stored by the relay.
//
// Storage model (the only one — there is no other):
//   - Every file is stored as a single whole on N independent cloud accounts (one file → N replicas).
//   - account.SelectReplicas (policy: Priority / FreeBytes / Diversity / quota gates) picks which N.
//   - FileMap.Replicas records where each copy lives.
//   - Download fetches from the first available replica; FileMap.Hash verifies integrity.
//   - No file splitting, no erasure coding, no encryption-at-rest (relay's RELAY_KEY only encrypts
//     the backup blob sent to the hub, not the user files on their own cloud accounts).
//
// F1 dedup: before uploading, the SHA-256 of the file is looked up in the per-relay index. If a
// canonical FileMap with the same hash already exists, the new FileMap is saved as a LogicalAlias
// pointer with no replicas — zero cloud I/O happens. Download resolves aliases transparently.
//
// Historical note: pre-v0.21.0 the codebase carried legacy Reed-Solomon "chunking" structures
// (FileMap.Chunks/Shards, internal/erasure, internal/blockstore). v0.21.0 deletes all of that —
// every record is migrated to the Replica-only schema on first load (see blockmap.unmarshalWithMigration).
package pipeline

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dudenest/dudenest-relay/internal/account"
	"github.com/dudenest/dudenest-relay/internal/blockmap"
	"github.com/dudenest/dudenest-relay/internal/index"
	"github.com/dudenest/dudenest-relay/pkg/types"
)

// mediaFolder picks the cloud-side folder for an upload based on content type.
// Primary detection: net/http.DetectContentType (magic-byte sniff of first 512B).
// Fallback: file extension when DetectContentType returns the generic "application/octet-stream"
// — covers HEIC/HEIF (Apple iPhone photos), MOV (legacy QuickTime), MKV, and common RAW formats
// that Go's stdlib doesn't have signatures for. Anything not media goes to FilesFolder.
// Decoupled from upload so it can be unit-tested in isolation.
func mediaFolder(name string, data []byte) string {
	n := 512
	if len(data) < n { n = len(data) }
	mime := http.DetectContentType(data[:n])
	if strings.HasPrefix(mime, "image/") || strings.HasPrefix(mime, "video/") {
		return types.PhotosFolder
	}
	if mime == "application/octet-stream" { // sniff inconclusive — fall back to extension for known-but-unsniffable media
		switch strings.ToLower(filepath.Ext(name)) {
		case ".heic", ".heif", ".raw", ".arw", ".nef", ".cr2", ".cr3", ".dng", ".rw2", ".orf", ".pef", ".rwl", ".srw":
			return types.PhotosFolder
		case ".mov", ".mkv", ".m4v", ".3gp", ".mts", ".m2ts", ".avi":
			return types.PhotosFolder
		}
	}
	return types.FilesFolder
}

// Pipeline ties together blockmap (FileMap persistence), the configured cloud providers,
// the account.Manager (replica selection policy), and the F1 dedup index.
type Pipeline struct {
	bm     *blockmap.Manager
	clouds []types.CloudProvider // cloud accounts the relay can write to
	accts  *account.Manager      // nil → legacy first-2-in-slice fallback (only used by tests)
	idx    *index.Index          // nil → dedup disabled (only used by tests)
}

// New creates a pipeline with cloud providers + an account.Manager (may be nil for legacy/test paths).
// masterKey is reserved for the backup client's encryption; pipeline itself does no crypto.
// Production startup wires accts + idx via SetAccountManager + SetIndex after construction.
func New(_ []byte, clouds []types.CloudProvider, mapStorePath string, accts *account.Manager) (*Pipeline, error) {
	return &Pipeline{
		bm:     blockmap.New(mapStorePath),
		clouds: clouds,
		accts:  accts,
	}, nil
}

// SetAccountManager attaches/replaces the account.Manager used for replica selection.
// nil = legacy "first 2 providers in slice" fallback (tests only).
func (p *Pipeline) SetAccountManager(m *account.Manager) { p.accts = m }

// AccountManager returns the currently-attached Manager (may be nil).
func (p *Pipeline) AccountManager() *account.Manager { return p.accts }

// SetIndex attaches the F1 sha-256 dedup index. nil = dedup disabled.
func (p *Pipeline) SetIndex(i *index.Index) { p.idx = i }

// Index returns the attached dedup index (may be nil).
func (p *Pipeline) Index() *index.Index { return p.idx }

// findProviderByAccount maps a CloudAccount → the CloudProvider that handles its uploads.
// Match is on CloudProvider.ID() == "<provider>:<email>" (the format factory.go uses).
// Returns nil if no provider is loaded for that account.
func (p *Pipeline) findProviderByAccount(a *types.CloudAccount) types.CloudProvider {
	want := a.Provider + ":" + a.Email
	for _, c := range p.clouds {
		if c.ID() == want { return c }
	}
	return nil
}

// Upload stores a file by writing it whole to N replicas chosen by account.SelectReplicas.
// F1 dedup short-circuit: if Index is attached and fm.Hash matches an existing canonical entry,
// returns a FileMap with LogicalAlias=existingFileID + empty Replicas — skipping all cloud I/O.
// Saves user quota when same content is uploaded from multiple devices. Download resolves aliases
// transparently via the canonical FileMap's Replicas.
func (p *Pipeline) Upload(filePath string) (*types.FileMap, error) {
	fm, err := blockmap.NewFileMap(filePath)
	if err != nil { return nil, fmt.Errorf("new filemap: %w", err) }
	// F1 dedup short-circuit
	if p.idx != nil && fm.Hash != "" {
		if existing := p.idx.Lookup(fm.Hash); existing != "" && existing != fm.FileID {
			fm.LogicalAlias = existing
			fm.Replicas = nil // alias FileMaps own no copies
			if err := p.bm.Save(fm); err != nil { return nil, fmt.Errorf("save alias filemap: %w", err) }
			if err := p.idx.InsertAlias(fm.Hash, fm.FileID); err != nil {
				log.Printf("upload: dedup alias saved but index update failed: %v (filemap persisted)", err)
			}
			log.Printf("upload: ✅ dedup hit — %s aliased to %s (skipped %d bytes upload)", fm.FileID, existing, fm.Size)
			return fm, nil
		}
	}
	out, err := p.uploadReplicas(fm, filePath)
	if err == nil && p.idx != nil && fm.Hash != "" {
		if ierr := p.idx.Insert(fm.Hash, fm.FileID); ierr != nil {
			log.Printf("upload: index insert failed after successful upload: %v (non-fatal)", ierr)
		}
	}
	return out, err
}

// uploadReplicas writes the whole file to the N accounts chosen by SelectReplicas.
// No chunking, no erasure coding, no encryption — bytes go to the cloud as-is.
func (p *Pipeline) uploadReplicas(fm *types.FileMap, filePath string) (*types.FileMap, error) {
	if len(p.clouds) == 0 { return nil, fmt.Errorf("no cloud providers available") }
	data, err := os.ReadFile(filePath)
	if err != nil { return nil, fmt.Errorf("read file: %w", err) }
	folder := mediaFolder(fm.Name, data) // photos/ for media, files/ for everything else
	when := time.Now().UTC()
	if !fm.Created.IsZero() { when = fm.Created.UTC() }

	type pick struct {
		cloud types.CloudProvider
		accID int64 // 0 in legacy mode
		path  string
	}
	var picks []pick
	if p.accts != nil {
		cfg := p.accts.Policy()
		all := p.accts.ActiveAccounts()
		chosen, err := account.SelectReplicas(account.FileMeta{Size: int64(len(data)), ContentType: folder}, all, cfg)
		if err != nil { return nil, fmt.Errorf("select replicas: %w", err) }
		path := cfg.PathFor(folder, fm.Name, when)
		for _, a := range chosen {
			cloud := p.findProviderByAccount(a)
			if cloud == nil {
				log.Printf("upload: no provider loaded for account %s (provider=%s email=%s) — skip", a.DisplayID(), a.Provider, a.Email)
				continue
			}
			picks = append(picks, pick{cloud: cloud, accID: a.ID, path: path})
		}
		if len(picks) == 0 {
			return nil, fmt.Errorf("select replicas returned %d accounts but none have a loaded provider", len(chosen))
		}
		if len(picks) < cfg.ReplicationFactor {
			log.Printf("upload: degraded redundancy — picked %d of %d requested replicas (policy.AllowSingleReplicaWithWarning may be true)", len(picks), cfg.ReplicationFactor)
		}
	} else {
		// Legacy fallback for tests / CLI paths where account.Manager isn't wired.
		limit := 2
		if len(p.clouds) < limit { limit = len(p.clouds) }
		legacyPath := fmt.Sprintf("%s/%04d/%02d/%s", folder, when.Year(), int(when.Month()), fm.Name)
		for j := 0; j < limit; j++ {
			picks = append(picks, pick{cloud: p.clouds[j], path: legacyPath})
		}
	}

	replicas := make([]types.Replica, len(picks))
	errs := make([]error, len(picks))
	var wg sync.WaitGroup
	for j, pk := range picks {
		wg.Add(1)
		go func(j int, pk pick) {
			defer wg.Done()
			var cloudID string
			var upErr error
			if u, ok := pk.cloud.(types.CloudIDUploader); ok {
				cloudID, upErr = u.UploadAndReturnID(pk.path, data)
			} else {
				upErr = pk.cloud.Upload(pk.path, data)
			}
			if upErr != nil { errs[j] = upErr; return }
			replicas[j] = types.Replica{
				ID:         fmt.Sprintf("%s.r%d", fm.FileID, j),
				ReplicaIdx: j,
				Size:       int64(len(data)),
				Location:   fmt.Sprintf("%s:%s", pk.cloud.ID(), pk.path),
				CloudID:    cloudID, // empty when provider doesn't implement CloudIDUploader; Download falls back to Location
				Created:    time.Now().UTC(),
			}
		}(j, pk)
	}
	wg.Wait()
	var good []types.Replica
	for _, r := range replicas {
		if r.ID != "" { good = append(good, r) }
	}
	if len(good) == 0 { return nil, fmt.Errorf("all replicas failed: %v", errs[0]) }
	fm.Replicas = good
	if err := p.bm.Save(fm); err != nil { return nil, fmt.Errorf("save filemap: %w", err) }
	return fm, nil
}

// Download fetches a file from any available replica and writes it to outputPath.
// Verifies Hash after reassembly. F1: resolves LogicalAlias by loading the canonical FileMap and
// borrowing its Replicas — user-visible Name + Hash stay from the alias (the original upload).
func (p *Pipeline) Download(fileID, outputPath string) error {
	fm, err := p.bm.Load(fileID)
	if err != nil { return fmt.Errorf("load filemap: %w", err) }
	if fm.LogicalAlias != "" {
		canonical, cerr := p.bm.Load(fm.LogicalAlias)
		if cerr != nil { return fmt.Errorf("load alias target %s: %w", fm.LogicalAlias, cerr) }
		if canonical.LogicalAlias != "" {
			return fmt.Errorf("alias chain detected: %s → %s → %s (data integrity issue)", fileID, fm.LogicalAlias, canonical.LogicalAlias)
		}
		fm.Replicas = canonical.Replicas
	}
	if len(fm.Replicas) == 0 { return fmt.Errorf("no replicas recorded for %s", fileID) }
	data, err := p.downloadFromAnyReplica(fm.Replicas)
	if err != nil { return fmt.Errorf("download: %w", err) }
	if err := os.WriteFile(outputPath, data, 0o600); err != nil { return fmt.Errorf("write output: %w", err) }
	return blockmap.Verify(outputPath, fm)
}

// downloadFromAnyReplica tries each replica in order. Prefers CloudID lookup (survives cloud-side
// rename/move); falls back to Location-based Download. Returns the first successful read.
func (p *Pipeline) downloadFromAnyReplica(replicas []types.Replica) ([]byte, error) {
	var lastErr error
	for _, r := range replicas {
		cloud := p.getCloudByLocation(r.Location)
		if cloud == nil { continue }
		if r.CloudID != "" {
			if idd, ok := cloud.(types.CloudIDDownloader); ok {
				if data, dlErr := idd.DownloadByID(r.CloudID); dlErr == nil { return data, nil } else { lastErr = dlErr }
			}
		}
		if data, dlErr := cloud.Download(parseCloudPath(r.Location)); dlErr == nil { return data, nil } else { lastErr = dlErr }
	}
	return nil, fmt.Errorf("all replicas unavailable: %v", lastErr)
}

// GetFileMap returns a specific FileMap by ID from local storage.
func (p *Pipeline) GetFileMap(fileID string) (*types.FileMap, error) { return p.bm.Load(fileID) }

// SaveFileMap persists an externally-mutated FileMap. Used by the drain + age-rotation workers
// to rewrite Replica.Location after migrating data to a different account.
func (p *Pipeline) SaveFileMap(fm *types.FileMap) error { return p.bm.Save(fm) }

// CloudByID looks up a CloudProvider by its ID() string ("gdrive:user@x.com"). Returns nil
// if no provider with that ID is loaded.
func (p *Pipeline) CloudByID(providerID string) types.CloudProvider {
	for _, c := range p.clouds {
		if c.ID() == providerID { return c }
	}
	return nil
}

// ListFiles returns all uploaded FileMaps from local storage.
func (p *Pipeline) ListFiles() ([]*types.FileMap, error) { return p.bm.List() }

// DeleteFile removes every replica from its cloud provider and deletes the local FileMap entry.
// Per-replica addressing priority: DeleteByID first (one API call, ID-stable), Location fallback.
func (p *Pipeline) DeleteFile(fileID string) error {
	fm, err := p.bm.Load(fileID)
	if err != nil { return fmt.Errorf("load filemap: %w", err) }
	var firstErr error
	for _, r := range fm.Replicas {
		cloud := p.getCloudByLocation(r.Location)
		if cloud == nil { continue }
		var dErr error
		if r.CloudID != "" {
			if idd, ok := cloud.(types.CloudIDDownloader); ok { dErr = idd.DeleteByID(r.CloudID) }
		}
		if r.CloudID == "" || dErr != nil { // path-based fallback
			if e := cloud.Delete(parseCloudPath(r.Location)); e != nil { dErr = e }
		}
		if dErr != nil && firstErr == nil { firstErr = fmt.Errorf("delete replica %s: %w", r.ID, dErr) }
	}
	return firstErr
}

// RegisterForeign creates a FileMap with Strategy=Foreign pointing at an existing cloud file
// (discovered by the scan engine). We never touched the bytes — we only record their location so
// they show up in /files. Download uses CloudID. fileID is derived from CloudID for idempotency
// across re-scans.
func (p *Pipeline) RegisterForeign(providerID, cloudID, name, path string, size int64, mtime time.Time) error {
	if cloudID == "" { return fmt.Errorf("cloudID required") }
	fileID := "foreign-" + cloudID // deterministic; safe across re-scans
	fm := &types.FileMap{
		Version:  blockmap.CurrentFileMapVersion,
		FileID:   fileID,
		Name:     name,
		Size:     size,
		Created:  mtime,
		Modified: mtime,
		Replicas: []types.Replica{{
			ID:         fileID + ".r0",
			ReplicaIdx: 0,
			Size:       size,
			Location:   providerID + ":" + path,
			CloudID:    cloudID,
			Created:    time.Now().UTC(),
		}},
	}
	return p.bm.Save(fm)
}

// MoveFile relocates every replica of a file to a new folder on its cloud provider, using
// CloudMover.MoveByID (one Drive API call per replica, no data transfer). Replica.CloudID stays
// the same after the move — Drive's file ID is permanent. Replica.Location is rewritten to
// reflect the new path so legacy path-based access still works.
//
// newDir is the folder path RELATIVE to the provider's base folder (e.g. "photos/2026/05").
// The leaf filename is preserved from the existing Location.
//
// Skips replicas where: (a) CloudID is empty (path-only legacy entry — needs backfill first),
// or (b) the provider doesn't implement CloudMover. Returns the first error but continues with
// the rest; FileMap is saved only if at least one replica moved successfully.
func (p *Pipeline) MoveFile(fileID, newDir string) error {
	fm, err := p.bm.Load(fileID)
	if err != nil { return fmt.Errorf("load: %w", err) }
	var firstErr error
	anyMoved := false
	for i, r := range fm.Replicas {
		cloud := p.getCloudByLocation(r.Location)
		if cloud == nil { continue }
		if r.CloudID == "" { continue }
		mover, ok := cloud.(types.CloudMover)
		if !ok { continue }
		if mErr := mover.MoveByID(r.CloudID, newDir); mErr != nil {
			if firstErr == nil { firstErr = fmt.Errorf("move replica %d: %w", i, mErr) }
			continue
		}
		parts := strings.SplitN(r.Location, ":", 2)
		if len(parts) == 2 {
			leaf := filepath.Base(parts[1])
			fm.Replicas[i].Location = parts[0] + ":" + newDir + "/" + leaf
			anyMoved = true
		}
	}
	if anyMoved {
		if sErr := p.bm.Save(fm); sErr != nil && firstErr == nil { firstErr = fmt.Errorf("save filemap after move: %w", sErr) }
	}
	return firstErr
}

// BackfillCloudIDs walks every FileMap and, for each Replica missing CloudID, asks the
// corresponding provider's CloudIDResolver to translate the Location path into the permanent
// file ID, then persists the FileMap. Idempotent.
type BackfillStats struct{ Scanned, Backfilled, Skipped, Errors int }

func (p *Pipeline) BackfillCloudIDs() (BackfillStats, error) {
	var stats BackfillStats
	maps, err := p.bm.List()
	if err != nil { return stats, fmt.Errorf("list filemaps: %w", err) }
	for _, fm := range maps {
		stats.Scanned++
		changed := false
		for i, r := range fm.Replicas {
			if r.CloudID != "" { continue }
			cloud := p.getCloudByLocation(r.Location)
			if cloud == nil { stats.Skipped++; continue }
			resolver, ok := cloud.(types.CloudIDResolver)
			if !ok { stats.Skipped++; continue }
			id, rErr := resolver.ResolvePathToID(parseCloudPath(r.Location))
			if rErr != nil { stats.Errors++; continue }
			fm.Replicas[i].CloudID = id
			changed = true
		}
		if changed {
			if sErr := p.bm.Save(fm); sErr != nil { stats.Errors++; continue }
			stats.Backfilled++
		}
	}
	return stats, nil
}

// getCloudByLocation resolves a Replica.Location string to its cloud provider.
// Location format: "<provider>:<email>:<path>" (current), "<provider>:<path>" (legacy single-account uploads).
func (p *Pipeline) getCloudByLocation(location string) types.CloudProvider {
	parts := strings.SplitN(location, ":", 3)
	if len(parts) < 2 { return nil }
	if len(parts) == 3 { // current format: scheme:email:path
		id := parts[0] + ":" + parts[1]
		for _, c := range p.clouds {
			if c.ID() == id { return c }
		}
	}
	scheme := parts[0] // legacy or fallback: first provider matching scheme prefix
	for _, c := range p.clouds {
		if c.ID() == scheme || strings.HasPrefix(c.ID(), scheme+":") { return c }
	}
	return nil
}

// parseCloudPath extracts the cloud-side path from a Location string.
// "gdrive:email:photos/2026/05/foo.jpg" → "photos/2026/05/foo.jpg"
// "gdrive:photos/2026/05/foo.jpg"       → "photos/2026/05/foo.jpg"  (legacy)
func parseCloudPath(location string) string {
	parts := strings.SplitN(location, ":", 3)
	if len(parts) == 3 { return parts[2] }
	if len(parts) == 2 { return parts[1] }
	return location
}
