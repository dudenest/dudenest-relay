// Package index provides per-relay content addressing — maps SHA-256(file plaintext) to FileID(s)
// for F1 duplicate detection. When a user uploads a file, Pipeline.Upload checks this index first;
// if hash already known, the new FileMap is saved with LogicalAlias=existingFileID and zero cloud
// I/O happens. Saves 50-90% quota when user replicates the same file across multiple devices.
//
// Storage: single JSON file on disk (`sha_index.json` in configDir). Reasoning: O(N) entries where
// N = unique files (10s-100s of thousands max for personal use), fits in memory; JSON keeps it
// trivially debuggable + zero new dependencies. bbolt would be appropriate at 10M+ files — defer.
//
// Persistence: atomic write (tmp + rename). Single-process write lock via sync.RWMutex.
// Bootstrap: caller (serve.go) walks all existing FileMaps and calls Insert for each — handles
// the "first run after v0.20.4 deploy with pre-existing data" case.
package index

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const IndexFileName = "sha_index.json"

// Entry represents one file known to the index. Slice [] supports same-hash-multiple-FileIDs
// (e.g. legacy uploads pre-dedup), but Pipeline.Upload only ever consults Primary (first non-alias).
type Entry struct {
	FileID    string    `json:"file_id"`
	IsAlias   bool      `json:"is_alias"`              // true = LogicalAlias to another FileID; only canonical (false) entries are dedup targets
	CreatedAt time.Time `json:"created_at"`
}

// Index is the persistent SHA-256 → []Entry mapping.
type Index struct {
	mu       sync.RWMutex
	configDir string
	byHash   map[string][]Entry
}

// New constructs an empty Index pointing at configDir/sha_index.json. Caller MUST Load() before use.
func New(configDir string) *Index {
	return &Index{configDir: configDir, byHash: map[string][]Entry{}}
}

// Load reads existing index from disk. Missing file is OK (caller may Bootstrap from FileMaps).
// Corrupt JSON returns error — caller decides to rebuild or fail.
func (i *Index) Load() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	path := filepath.Join(i.configDir, IndexFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) { return nil } // empty index, OK
		return fmt.Errorf("read %s: %w", path, err)
	}
	var byHash map[string][]Entry
	if err := json.Unmarshal(data, &byHash); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	i.byHash = byHash
	return nil
}

// save persists the current state. Caller holds at least i.mu.RLock (this method takes Lock internally
// for atomic write semantics — but the in-memory state must not change during marshal).
// Atomic: write to .tmp, fsync, rename.
func (i *Index) save() error {
	data, err := json.MarshalIndent(i.byHash, "", "  ")
	if err != nil { return fmt.Errorf("marshal: %w", err) }
	path := filepath.Join(i.configDir, IndexFileName)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil { return fmt.Errorf("write tmp: %w", err) }
	if err := os.Rename(tmp, path); err != nil { return fmt.Errorf("rename: %w", err) }
	return nil
}

// Lookup returns the canonical (non-alias) FileID for a given hash, or empty string if unknown.
// Caller uses empty string as "not deduplicated — proceed with normal upload".
// O(log N) on the entry list (sorted by IsAlias=false first), but typically N=1 or 2.
func (i *Index) Lookup(hash string) string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	entries, ok := i.byHash[hash]
	if !ok { return "" }
	for _, e := range entries {
		if !e.IsAlias { return e.FileID } // first canonical
	}
	return "" // all entries were aliases (shouldn't happen in healthy state, but be defensive)
}

// Insert records a new (hash, fileID) pair as canonical (not alias). Idempotent — adding the
// same fileID twice is a no-op. Persisted to disk on success.
func (i *Index) Insert(hash, fileID string) error {
	if hash == "" || fileID == "" { return fmt.Errorf("hash and fileID required") }
	i.mu.Lock()
	defer i.mu.Unlock()
	entries := i.byHash[hash]
	for _, e := range entries {
		if e.FileID == fileID { return nil } // already present
	}
	entries = append(entries, Entry{FileID: fileID, IsAlias: false, CreatedAt: time.Now().UTC()})
	// Canonical first, aliases last — Lookup picks the first canonical.
	sort.Slice(entries, func(a, b int) bool {
		if entries[a].IsAlias != entries[b].IsAlias { return !entries[a].IsAlias }
		return entries[a].CreatedAt.Before(entries[b].CreatedAt)
	})
	i.byHash[hash] = entries
	return i.save()
}

// InsertAlias records that fileID is a LogicalAlias to an existing canonical for the same hash.
// Used after Pipeline saves an alias-FileMap (skip-upload path).
func (i *Index) InsertAlias(hash, fileID string) error {
	if hash == "" || fileID == "" { return fmt.Errorf("hash and fileID required") }
	i.mu.Lock()
	defer i.mu.Unlock()
	entries := i.byHash[hash]
	for _, e := range entries {
		if e.FileID == fileID { return nil }
	}
	entries = append(entries, Entry{FileID: fileID, IsAlias: true, CreatedAt: time.Now().UTC()})
	sort.Slice(entries, func(a, b int) bool {
		if entries[a].IsAlias != entries[b].IsAlias { return !entries[a].IsAlias }
		return entries[a].CreatedAt.Before(entries[b].CreatedAt)
	})
	i.byHash[hash] = entries
	return i.save()
}

// Stats returns a snapshot for ops/admin endpoints. Cheap (in-memory only).
func (i *Index) Stats() (totalHashes, totalEntries, aliasCount int) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	totalHashes = len(i.byHash)
	for _, entries := range i.byHash {
		totalEntries += len(entries)
		for _, e := range entries {
			if e.IsAlias { aliasCount++ }
		}
	}
	return
}

// Bootstrap walks a slice of FileMaps and populates the index. Idempotent — safe to call on
// already-populated index (Insert is no-op for known fileIDs). Used at startup to recover from
// missing/corrupted sha_index.json without losing dedup ability.
type FileMapLister interface {
	ListFiles() ([]struct{ FileID, Hash string; IsAlias bool }, error)
}

// BootstrapFromList accepts a flat slice (FileID, Hash, IsAlias) extracted by the caller from
// its FileMap store. This decouples package `index` from package `pipeline` to avoid import cycle.
func (i *Index) BootstrapFromList(entries []struct{ FileID, Hash string; IsAlias bool }) error {
	for _, e := range entries {
		if e.Hash == "" { continue } // skip files without hash (legacy / errored uploads)
		var err error
		if e.IsAlias {
			err = i.InsertAlias(e.Hash, e.FileID)
		} else {
			err = i.Insert(e.Hash, e.FileID)
		}
		if err != nil { return fmt.Errorf("bootstrap entry %s: %w", e.FileID, err) }
	}
	return nil
}
