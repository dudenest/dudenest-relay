// Package blockmap manages the FileMap — the per-file metadata record (identity + list of replicas).
// One FileMap per uploaded file, persisted as JSON in <configDir>/maps/<file_id>.json.
//
// Load is migration-aware: it transparently upgrades legacy v1 records (which carried "chunks/shards"
// structures from the abandoned Reed-Solomon design) to v2 (Replicas slice). The migration is
// lossless — every replica/location/cloud_id from the old format is preserved 1:1 in the new one.
// Migrated records are re-saved to disk so subsequent Loads are fast and the legacy fields disappear.
package blockmap

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/dudenest/dudenest-relay/pkg/types"
	"github.com/google/uuid"
)

// CurrentFileMapVersion is written by NewFileMap. Older records load via the migration path in Load.
const CurrentFileMapVersion = 2

// Manager handles FileMap persistence and lookup.
type Manager struct {
	storePath string // local path to store FileMaps (dev mode)
}

func New(storePath string) *Manager {
	os.MkdirAll(storePath, 0700) //nolint:errcheck
	return &Manager{storePath: storePath}
}

// StorePath returns the local directory where FileMaps are stored.
func (m *Manager) StorePath() string { return m.storePath }

// NewFileMap creates a fresh v2 FileMap for a file at path. Replicas is empty — Pipeline.Upload
// populates it after the cloud uploads succeed.
func NewFileMap(path string) (*types.FileMap, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	hash, err := hashFile(path)
	if err != nil {
		return nil, fmt.Errorf("hash %s: %w", path, err)
	}
	return &types.FileMap{
		Version:  CurrentFileMapVersion,
		FileID:   uuid.New().String(),
		Name:     info.Name(),
		Size:     info.Size(),
		Hash:     hash,
		Created:  time.Now().UTC(),
		Modified: info.ModTime().UTC(),
	}, nil
}

// Save writes a FileMap to local storage (dev mode — prod stores on cloud too via backup hub).
func (m *Manager) Save(fm *types.FileMap) error {
	data, err := json.MarshalIndent(fm, "", "  ")
	if err != nil {
		return err
	}
	path := fmt.Sprintf("%s/%s.json", m.storePath, fm.FileID)
	return os.WriteFile(path, data, 0600)
}

// Load reads a FileMap from local storage. Transparently migrates legacy v1 (chunks/shards) records
// to v2 (Replicas) and rewrites them on disk — so the next Load returns clean v2 data.
func (m *Manager) Load(fileID string) (*types.FileMap, error) {
	path := fmt.Sprintf("%s/%s.json", m.storePath, fileID)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	fm, migrated, err := unmarshalWithMigration(data)
	if err != nil {
		return nil, err
	}
	if migrated {
		// Best-effort write-back; if it fails the FileMap is still usable in-memory.
		if err := m.Save(fm); err != nil {
			log.Printf("blockmap: migrated %s but write-back failed: %v (in-memory only)", fileID, err)
		}
	}
	return fm, nil
}

// unmarshalWithMigration decodes JSON into a FileMap. If the input is a legacy v1 record (has
// "chunks" key), it flattens chunks[0].shards into Replicas (legacy Replica strategy always wrote
// exactly one entry in chunks[]). Returns migrated=true when the input needed conversion.
// Pure function (no I/O) — easy to test against fixture JSONs.
func unmarshalWithMigration(data []byte) (*types.FileMap, bool, error) {
	// First decode into a tolerant map so we can detect legacy "chunks" key without committing to a struct.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, false, fmt.Errorf("parse json: %w", err)
	}
	if _, hasChunks := raw["chunks"]; hasChunks {
		if _, hasReplicas := raw["replicas"]; !hasReplicas {
			fm, err := decodeLegacyAndConvert(data)
			if err != nil {
				return nil, false, fmt.Errorf("legacy migration: %w", err)
			}
			return fm, true, nil
		}
	}
	// Already v2 (or no chunks at all, e.g. alias FileMap).
	var fm types.FileMap
	if err := json.Unmarshal(data, &fm); err != nil {
		return nil, false, fmt.Errorf("decode v2: %w", err)
	}
	return &fm, false, nil
}

// decodeLegacyAndConvert reads a pre-v0.21.0 FileMap (with chunks/shards) and produces a v2 FileMap.
// Legacy Replica strategy invariant: exactly one element in chunks[], containing N entries in shards[]
// where each shard is one replica of the whole file. We flatten that into Replicas[].
// For the abandoned Chunking strategy (multiple chunks, 9 shards each Reed-Solomon) we still convert
// what we can — the file is unreadable anyway (legacy chunking was never live in production), but we
// preserve the Location pointers so an admin can manually clean up the orphaned uploads.
func decodeLegacyAndConvert(data []byte) (*types.FileMap, error) {
	// Anonymous struct mirroring the old schema — only the fields we still need.
	var legacy struct {
		Version      int       `json:"version"`
		FileID       string    `json:"file_id"`
		Strategy     string    `json:"strategy"`
		Name         string    `json:"name"`
		Size         int64     `json:"size"`
		Hash         string    `json:"hash"`
		ChunkSize    int       `json:"chunk_size"`
		Chunks       []struct {
			Index  int `json:"index"`
			Offset int64 `json:"offset"`
			Size   int64 `json:"size"`
			Hash   string `json:"hash"`
			Shards []struct {
				ID       string    `json:"id"`
				ShardIdx int       `json:"shard"`
				Size     int64     `json:"size"`
				Location string    `json:"location"`
				CloudID  string    `json:"cloud_id,omitempty"`
				Created  time.Time `json:"created"`
			} `json:"shards"`
		} `json:"chunks"`
		Created      time.Time `json:"created"`
		Modified     time.Time `json:"modified"`
		LogicalAlias string    `json:"logical_alias,omitempty"`
	}
	if err := json.Unmarshal(data, &legacy); err != nil { return nil, err }
	fm := &types.FileMap{
		Version:      CurrentFileMapVersion,
		FileID:       legacy.FileID,
		Name:         legacy.Name,
		Size:         legacy.Size,
		Hash:         legacy.Hash,
		Created:      legacy.Created,
		Modified:     legacy.Modified,
		LogicalAlias: legacy.LogicalAlias,
	}
	// Flatten chunks[].shards[] → Replicas[]. Replica strategy: one chunk, N copies.
	// Legacy chunking strategy: many chunks × 9 shards — we preserve as many entries as the slice
	// lets us; data is unreadable either way (the abandoned strategy never reached production).
	for _, ch := range legacy.Chunks {
		for _, sh := range ch.Shards {
			fm.Replicas = append(fm.Replicas, types.Replica{
				ID:         sh.ID,
				ReplicaIdx: sh.ShardIdx, // preserve original positional index
				Size:       sh.Size,
				Location:   sh.Location,
				CloudID:    sh.CloudID,
				Created:    sh.Created,
			})
		}
	}
	return fm, nil
}

// List returns all FileMaps from local storage, sorted newest first.
func (m *Manager) List() ([]*types.FileMap, error) {
	entries, err := os.ReadDir(m.storePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var maps []*types.FileMap
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		fm, err := m.Load(strings.TrimSuffix(e.Name(), ".json"))
		if err != nil {
			continue
		}
		maps = append(maps, fm)
	}
	return maps, nil
}

// CountFilesForProvider counts FileMaps that have at least one replica stored on the given provider.
// providerPrefix must be the full provider ID, e.g. "gdrive:piowin00@gmail.com".
func (m *Manager) CountFilesForProvider(providerPrefix string) int64 {
	maps, _ := m.List()
	var count int64
	prefix := providerPrefix + ":"
	for _, fm := range maps {
		for _, r := range fm.Replicas {
			if strings.HasPrefix(r.Location, prefix) {
				count++
				break
			}
		}
	}
	return count
}

// Verify checks that a reconstructed file matches the FileMap hash.
func Verify(path string, fm *types.FileMap) error {
	hash, err := hashFile(path)
	if err != nil {
		return err
	}
	if hash != fm.Hash {
		return errors.New("hash mismatch: file is corrupted or tampered")
	}
	return nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
