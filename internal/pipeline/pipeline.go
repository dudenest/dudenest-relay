// Package pipeline orchestrates chunk → encrypt → erasure-code → upload and reverse.
package pipeline

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dudenest/dudenest-relay/internal/blockmap"
	"github.com/dudenest/dudenest-relay/internal/blockstore"
	"github.com/dudenest/dudenest-relay/internal/crypto"
	"github.com/dudenest/dudenest-relay/internal/erasure"
	"github.com/dudenest/dudenest-relay/pkg/types"
)

// mediaFolder picks the cloud-side folder for a replica upload based on content type.
// Primary detection: net/http.DetectContentType (magic-byte sniff of first 512B).
// Fallback: file extension when DetectContentType returns the generic "application/octet-stream"
// — covers HEIC/HEIF (Apple iPhone photos), MOV (legacy QuickTime), MKV, and common RAW formats
// that Go's stdlib doesn't have signatures for. Anything not media goes to FilesFolder.
// Decoupled from uploadReplica so it can be unit-tested in isolation.
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

// Pipeline ties together all relay components.
type Pipeline struct {
	enc     *crypto.Encryptor
	rs      *erasure.Encoder
	bm      *blockmap.Manager
	clouds  []types.CloudProvider // multiple providers for Replica strategy
	chunkSz int
}

// New creates a pipeline with a master key and cloud providers.
func New(masterKey []byte, clouds []types.CloudProvider, mapStorePath string) (*Pipeline, error) {
	enc, err := crypto.New(masterKey)
	if err != nil {
		return nil, fmt.Errorf("crypto init: %w", err)
	}
	rs, err := erasure.New()
	if err != nil {
		return nil, fmt.Errorf("erasure init: %w", err)
	}
	return &Pipeline{
		enc:     enc,
		rs:      rs,
		bm:      blockmap.New(mapStorePath),
		clouds:  clouds,
		chunkSz: types.ChunkSize,
	}, nil
}

// Upload stores a file using the selected strategy.
// StrategyReplica: stores full file (unencrypted) on 1-2 providers in parallel.
// StrategyChunking (legacy): Reed-Solomon 6+3 shards, encrypted.
func (p *Pipeline) Upload(filePath string, strategy string) (*types.FileMap, error) {
	fm, err := blockmap.NewFileMap(filePath)
	if err != nil {
		return nil, fmt.Errorf("new filemap: %w", err)
	}
	fm.Strategy = strategy
	if strategy == types.StrategyReplica {
		return p.uploadReplica(fm, filePath)
	}
	return p.uploadChunking(fm, filePath)
}

func (p *Pipeline) uploadChunking(fm *types.FileMap, filePath string) (*types.FileMap, error) {
	metas, chunks, err := blockstore.ChunkFile(filePath, p.chunkSz)
	if err != nil {
		return nil, fmt.Errorf("chunk: %w", err)
	}
	cloud := p.clouds[0] // Default to first cloud for legacy chunking
	for i, chunk := range chunks {
		shards, err := p.rs.Split(chunk)
		if err != nil {
			return nil, fmt.Errorf("chunk %d split: %w", i, err)
		}
		meta := &metas[i]
		blocks := make([]types.Block, len(shards))
		errs := make([]error, len(shards))
		var wg sync.WaitGroup
		for j, shard := range shards {
			wg.Add(1)
			go func(j int, shard []byte) {
				defer wg.Done()
				blockID := fmt.Sprintf("%s.%d.%d", fm.FileID, i, j)
				encrypted, encErr := p.enc.Encrypt(blockID, shard)
				if encErr != nil {
					errs[j] = fmt.Errorf("encrypt chunk %d shard %d: %w", i, j, encErr)
					return
				}
				cloudPath := fmt.Sprintf("blocks/%s/%d/%d", meta.Hash[:8], i, j)
				if upErr := cloud.Upload(cloudPath, encrypted); upErr != nil {
					errs[j] = fmt.Errorf("upload chunk %d shard %d: %w", i, j, upErr)
					return
				}
				blocks[j] = types.Block{
					ID: blockID, ShardIdx: j, Size: int64(len(encrypted)),
					Location: fmt.Sprintf("%s:%s", cloud.ID(), cloudPath), Created: time.Now().UTC(),
				}
			}(j, shard)
		}
		wg.Wait()
		for _, e := range errs {
			if e != nil {
				return nil, e
			}
		}
		meta.Shards = blocks
		fm.Chunks = append(fm.Chunks, metas[i])
	}
	if err := p.bm.Save(fm); err != nil {
		return nil, fmt.Errorf("save filemap: %w", err)
	}
	return fm, nil
}

// uploadReplica stores the full file (unencrypted) on up to 2 available providers.
// No chunking, no erasure coding — files are stored as-is for direct streaming.
func (p *Pipeline) uploadReplica(fm *types.FileMap, filePath string) (*types.FileMap, error) {
	if len(p.clouds) == 0 {
		return nil, fmt.Errorf("no cloud providers available")
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	limit := 2 // max 2 replicas
	if len(p.clouds) < limit {
		limit = len(p.clouds)
	}
	chunk := types.ChunkMeta{Index: 0, Offset: 0, Size: int64(len(data)), Hash: fm.Hash}
	folder := mediaFolder(fm.Name, data) // P2: photos/ for media, files/ for everything else — computed once before parallel replica upload
	blocks := make([]types.Block, limit)
	errs := make([]error, limit)
	var wg sync.WaitGroup
	for j := 0; j < limit; j++ {
		wg.Add(1)
		go func(j int) {
			defer wg.Done()
			cloud := p.clouds[j]
			// P5b: date-bucketed path (was hash-based pre-P5b). Date source priority: EXIF DateTimeOriginal
			// (P5b-future when exif extraction wired in here — currently the EXIF write happens later in
			// thumbnail pipeline, so for now we use server upload time. Editable-date logic in
			// /files/{id}/meta will MoveByID into the correct bucket once EXIF gets read.)
			when := time.Now().UTC()
			if fm.Created.IsZero() == false { when = fm.Created.UTC() }
			cloudPath := fmt.Sprintf("%s/%04d/%02d/%s", folder, when.Year(), int(when.Month()), fm.Name)
			var cloudID string
			var upErr error
			if u, ok := cloud.(types.CloudIDUploader); ok {
				cloudID, upErr = u.UploadAndReturnID(cloudPath, data)
			} else {
				upErr = cloud.Upload(cloudPath, data)
			}
			if upErr != nil {
				errs[j] = upErr
				return
			}
			blocks[j] = types.Block{
				ID: fmt.Sprintf("%s.r%d", fm.FileID, j), ShardIdx: j, Size: int64(len(data)),
				Location: fmt.Sprintf("%s:%s", cloud.ID(), cloudPath),
				CloudID:  cloudID, // P5a: empty when provider doesn't implement CloudIDUploader; pipeline.Download then uses Location lookup
				Created:  time.Now().UTC(),
			}
		}(j)
	}
	wg.Wait()
	var goodBlocks []types.Block
	for _, b := range blocks {
		if b.ID != "" {
			goodBlocks = append(goodBlocks, b)
		}
	}
	if len(goodBlocks) == 0 {
		return nil, fmt.Errorf("all replicas failed: %v", errs[0])
	}
	chunk.Shards = goodBlocks
	fm.Chunks = []types.ChunkMeta{chunk}
	if err := p.bm.Save(fm); err != nil {
		return nil, fmt.Errorf("save filemap: %w", err)
	}
	return fm, nil
}

// Download retrieves and reassembles a file from its FileMap.
// Replica strategy: returns raw bytes (unencrypted).
// Chunking strategy (legacy): decrypts and Reed-Solomon reconstructs.
func (p *Pipeline) Download(fileID, outputPath string) error {
	fm, err := p.bm.Load(fileID)
	if err != nil {
		return fmt.Errorf("load filemap: %w", err)
	}
	var allChunks [][]byte
	for _, meta := range fm.Chunks {
		var chunk []byte
		if fm.Strategy == types.StrategyReplica {
			chunk, err = p.downloadReplica(meta) // unencrypted
		} else {
			chunk, err = p.downloadChunking(meta) // legacy encrypted
		}
		if err != nil {
			return fmt.Errorf("chunk %d: %w", meta.Index, err)
		}
		allChunks = append(allChunks, chunk)
	}
	if err := blockstore.ReassembleFile(outputPath, allChunks); err != nil {
		return fmt.Errorf("reassemble: %w", err)
	}
	return blockmap.Verify(outputPath, fm)
}

func (p *Pipeline) downloadChunking(meta types.ChunkMeta) ([]byte, error) {
	shards := make([][]byte, types.TotalShards)
	var wg sync.WaitGroup
	for _, block := range meta.Shards {
		wg.Add(1)
		go func(block types.Block) {
			defer wg.Done()
			cloud := p.getCloudByName(block.Location)
			if cloud == nil {
				return
			}
			data, dlErr := cloud.Download(parseCloudPath(block.Location))
			if dlErr != nil {
				return
			}
			plain, decErr := p.enc.Decrypt(block.ID, data)
			if decErr == nil {
				shards[block.ShardIdx] = plain
			}
		}(block)
	}
	wg.Wait()
	return p.rs.Join(shards, int(meta.Size))
}

// downloadReplica downloads the first available unencrypted replica.
// P5a addressing priority per block: (1) Block.CloudID via DownloadByID — one Drive API call,
// survives user-side renames. (2) fallback to Location-based Download (parseCloudPath +
// Provider.Download) for pre-P5a entries without CloudID.
func (p *Pipeline) downloadReplica(meta types.ChunkMeta) ([]byte, error) {
	var lastErr error
	for _, block := range meta.Shards {
		cloud := p.getCloudByName(block.Location)
		if cloud == nil { continue }
		if block.CloudID != "" {
			if idd, ok := cloud.(types.CloudIDDownloader); ok {
				data, dlErr := idd.DownloadByID(block.CloudID)
				if dlErr == nil { return data, nil }
				lastErr = dlErr // fall through to path-based as last resort
			}
		}
		data, dlErr := cloud.Download(parseCloudPath(block.Location))
		if dlErr != nil { lastErr = dlErr; continue }
		return data, nil // raw bytes, no decryption
	}
	return nil, fmt.Errorf("all replicas unavailable: %v", lastErr)
}

// GetFileMap returns a specific FileMap by ID from local storage.
func (p *Pipeline) GetFileMap(fileID string) (*types.FileMap, error) { return p.bm.Load(fileID) }

// ListFiles returns all uploaded FileMaps from local storage.
func (p *Pipeline) ListFiles() ([]*types.FileMap, error) { return p.bm.List() }

// DeleteFile removes all cloud blocks for a file and its local FileMap.
// P5a addressing priority per block: DeleteByID first (one API call, ID-stable), Location fallback.
func (p *Pipeline) DeleteFile(fileID string) error {
	fm, err := p.bm.Load(fileID)
	if err != nil { return fmt.Errorf("load filemap: %w", err) }
	var firstErr error
	for _, meta := range fm.Chunks {
		for _, block := range meta.Shards {
			cloud := p.getCloudByName(block.Location)
			if cloud == nil { continue }
			var dErr error
			if block.CloudID != "" {
				if idd, ok := cloud.(types.CloudIDDownloader); ok { dErr = idd.DeleteByID(block.CloudID) }
			}
			if block.CloudID == "" || dErr != nil { // path-based fallback
				if e := cloud.Delete(parseCloudPath(block.Location)); e != nil { dErr = e }
			}
			if dErr != nil && firstErr == nil { firstErr = fmt.Errorf("delete block %s: %w", block.ID, dErr) }
		}
	}
	return firstErr
}

// RegisterForeign creates a new FileMap with Strategy=Foreign pointing at an existing file
// in a cloud provider (discovered by the scan engine). The cloud file is NOT touched — we
// just record its existence in our index so it shows up in /files. Download uses CloudID,
// no decryption happens (Foreign means user-uploaded, not encrypted by us).
//
// fileID is generated from CloudID (deterministic dedup — re-registering the same CloudID
// twice produces the same FileMap entry, idempotent for repeated scans).
func (p *Pipeline) RegisterForeign(providerID, cloudID, name, path string, size int64, mtime time.Time) error {
	if cloudID == "" { return fmt.Errorf("cloudID required") }
	fileID := "foreign-" + cloudID // deterministic; safe across re-scans
	fm := &types.FileMap{
		Version:  1,
		FileID:   fileID,
		Strategy: types.StrategyForeign,
		Name:     name,
		Size:     size,
		Created:  mtime,
		Modified: mtime,
		Chunks: []types.ChunkMeta{{
			Index: 0, Offset: 0, Size: size,
			Shards: []types.Block{{
				ID: fileID + ".0", ShardIdx: 0, Size: size,
				Location: providerID + ":" + path,
				CloudID:  cloudID,
				Created:  time.Now().UTC(),
			}},
		}},
	}
	return p.bm.Save(fm)
}

// MoveFile relocates every replica of a file to a new folder on its cloud provider, using
// CloudMover.MoveByID (one Drive API call per shard, no data transfer). Block.CloudID stays
// the same after the move — Drive's file ID is permanent. Block.Location is rewritten to
// reflect the new path so legacy path-based access still works.
//
// newDir is the folder path RELATIVE to the provider's base folder, e.g. "photos/2026/05".
// The leaf filename is preserved from the existing Location.
//
// Skips shards where: (a) Block.CloudID is empty (path-only legacy entry — needs backfill
// first), or (b) the matching provider doesn't implement CloudMover. Returns the first
// error encountered but continues attempting the rest; FileMap is saved only if at least
// one shard moved successfully (atomicity isn't guaranteed across multi-replica moves —
// out-of-sync replicas are recovered on next download attempt).
func (p *Pipeline) MoveFile(fileID, newDir string) error {
	fm, err := p.bm.Load(fileID)
	if err != nil { return fmt.Errorf("load: %w", err) }
	var firstErr error
	anyMoved := false
	for ci, meta := range fm.Chunks {
		for si, block := range meta.Shards {
			cloud := p.getCloudByName(block.Location)
			if cloud == nil { continue }
			if block.CloudID == "" { continue }
			mover, ok := cloud.(types.CloudMover)
			if !ok { continue }
			if mErr := mover.MoveByID(block.CloudID, newDir); mErr != nil {
				if firstErr == nil { firstErr = fmt.Errorf("move shard %d/%d: %w", ci, si, mErr) }
				continue
			}
			// Rewrite Location: "<provider>:<newDir>/<filename>"
			parts := strings.SplitN(block.Location, ":", 2)
			if len(parts) == 2 {
				oldPath := parts[1]
				leaf := filepath.Base(oldPath)
				fm.Chunks[ci].Shards[si].Location = parts[0] + ":" + newDir + "/" + leaf
				anyMoved = true
			}
		}
	}
	if anyMoved {
		if sErr := p.bm.Save(fm); sErr != nil && firstErr == nil { firstErr = fmt.Errorf("save filemap after move: %w", sErr) }
	}
	return firstErr
}

// BackfillCloudIDs walks every FileMap in the blockmap and, for each Block missing CloudID,
// asks the corresponding provider's CloudIDResolver to translate the Block.Location path
// into the permanent file ID, then persists the FileMap. Idempotent; safe to run repeatedly.
// Called at relay startup (proactive backfill, user decision 2026-05-20) so legacy entries get
// migrated to ID-based addressing within minutes of v0.17.0 deploy.
//
// Returns counts so the caller can log a summary. Errors per FileMap are logged but don't abort
// the whole pass — one missing/renamed file shouldn't stop migration of the rest.
type BackfillStats struct{ Scanned, Backfilled, Skipped, Errors int }
func (p *Pipeline) BackfillCloudIDs() (BackfillStats, error) {
	var stats BackfillStats
	maps, err := p.bm.List()
	if err != nil { return stats, fmt.Errorf("list filemaps: %w", err) }
	for _, fm := range maps {
		stats.Scanned++
		changed := false
		for ci, meta := range fm.Chunks {
			for si, block := range meta.Shards {
				if block.CloudID != "" { continue }
				cloud := p.getCloudByName(block.Location)
				if cloud == nil { stats.Skipped++; continue }
				resolver, ok := cloud.(types.CloudIDResolver)
				if !ok { stats.Skipped++; continue }
				id, rErr := resolver.ResolvePathToID(parseCloudPath(block.Location))
				if rErr != nil { stats.Errors++; continue }
				fm.Chunks[ci].Shards[si].CloudID = id
				changed = true
			}
		}
		if changed {
			if sErr := p.bm.Save(fm); sErr != nil { stats.Errors++; continue }
			stats.Backfilled++
		}
	}
	return stats, nil
}

// getCloudByName resolves a block location to its cloud provider.
// Handles two location formats:
//   - new: "gdrive:email@domain.com:path/to/file"  (3 parts)
//   - legacy: "gdrive:blocks/hash/chunk/shard"      (2 parts, no email)
func (p *Pipeline) getCloudByName(location string) types.CloudProvider {
	parts := strings.SplitN(location, ":", 3)
	if len(parts) < 2 {
		return nil
	}
	if len(parts) == 3 { // new format: scheme:email:path
		id := parts[0] + ":" + parts[1]
		for _, c := range p.clouds {
			if c.ID() == id {
				return c
			}
		}
	}
	// legacy format or fallback: find first provider matching scheme prefix
	scheme := parts[0]
	for _, c := range p.clouds {
		if c.ID() == scheme || strings.HasPrefix(c.ID(), scheme+":") {
			return c
		}
	}
	return nil
}

// parseCloudPath extracts the cloud-side path from a location string.
// "gdrive:email:blocks/x/0/1" → "blocks/x/0/1"
// "gdrive:blocks/x/0/1"       → "blocks/x/0/1"  (legacy)
func parseCloudPath(location string) string {
	parts := strings.SplitN(location, ":", 3)
	if len(parts) == 3 {
		return parts[2]
	}
	if len(parts) == 2 {
		return parts[1]
	}
	return location
}
