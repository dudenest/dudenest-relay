// Package blockmap manages the FileMap — the index of all blocks for a file.
// The FileMap itself is stored encrypted on the cloud (bootstrap problem solved
// by storing its location in the relay's local SQLite DB or config).
package blockmap

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/dudenest/dudenest-relay/pkg/types"
	"github.com/google/uuid"
)

// Manager handles FileMap persistence and lookup.
type Manager struct {
	storePath string // local path to store FileMaps (dev mode)
}

func New(storePath string) *Manager {
	os.MkdirAll(storePath, 0700) //nolint:errcheck
	return &Manager{storePath: storePath}
}

// NewFileMap creates a FileMap for a file at path.
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
		Version:   1,
		FileID:    uuid.New().String(),
		Name:      info.Name(),
		Size:      info.Size(),
		Hash:      hash,
		ChunkSize: types.ChunkSize,
		Created:   time.Now().UTC(),
		Modified:  info.ModTime().UTC(),
	}, nil
}

// Save writes a FileMap to local storage (dev mode — prod stores on cloud).
func (m *Manager) Save(fm *types.FileMap) error {
	data, err := json.MarshalIndent(fm, "", "  ")
	if err != nil {
		return err
	}
	path := fmt.Sprintf("%s/%s.json", m.storePath, fm.FileID)
	return os.WriteFile(path, data, 0600)
}

// Load reads a FileMap from local storage.
func (m *Manager) Load(fileID string) (*types.FileMap, error) {
	path := fmt.Sprintf("%s/%s.json", m.storePath, fileID)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var fm types.FileMap
	if err := json.Unmarshal(data, &fm); err != nil {
		return nil, err
	}
	return &fm, nil
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
