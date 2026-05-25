// Package blockmap manages the FileMap — the per-file metadata record (identity + list of replicas).
// One FileMap per uploaded file, persisted as JSON in <storePath>/<file_id>.json.
//
// Load is migration-aware: legacy v1 records (pre-v0.21.0 wire format) are transparently upgraded
// to v2 (Replicas slice). The migration is lossless — every replica location + cloud_id from the
// old format is preserved 1:1 in the new one. Migrated records are re-saved to disk so subsequent
// Loads are fast. All the legacy-format parsing code is isolated in `legacy_v1_migration.go`.
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

// Delete removes a FileMap from local storage. Idempotent: missing file is not an error.
// s320 Phase 2: used by pipeline.DeleteByCloudID to drop foreign FileMaps when Drive reports
// the underlying cloud file was trashed/deleted.
func (m *Manager) Delete(fileID string) error {
	path := fmt.Sprintf("%s/%s.json", m.storePath, fileID)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) { return err }
	return nil
}

// Load reads a FileMap from local storage. Transparently migrates legacy v1 records to v2
// (Replicas) and rewrites them on disk — so the next Load returns clean v2 data.
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

// unmarshalWithMigration decodes JSON into a FileMap. If the input is a legacy v1 record, it
// dispatches to the isolated migration code in legacy_v1_migration.go. Returns migrated=true
// when the input needed conversion. Pure function (no I/O) — easy to test against fixtures.
func unmarshalWithMigration(data []byte) (*types.FileMap, bool, error) {
	if isLegacyV1(data) {
		fm, err := decodeLegacyV1(data)
		if err != nil {
			return nil, false, fmt.Errorf("legacy v1 migration: %w", err)
		}
		return fm, true, nil
	}
	var fm types.FileMap
	if err := json.Unmarshal(data, &fm); err != nil {
		return nil, false, fmt.Errorf("decode v2: %w", err)
	}
	return &fm, false, nil
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
