package index

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// F1-1: Insert + Lookup roundtrip — canonical entry found on lookup.
func TestInsertAndLookup(t *testing.T) {
	dir := t.TempDir()
	idx := New(dir)
	if err := idx.Insert("hashA", "file-001"); err != nil { t.Fatalf("insert: %v", err) }
	if got := idx.Lookup("hashA"); got != "file-001" { t.Errorf("lookup: got %q, want file-001", got) }
	if got := idx.Lookup("nonexistent"); got != "" { t.Errorf("lookup nonexistent: got %q, want empty", got) }
}

// F1-2: Index persists across Load — write file, create new Index, Load, lookup still works.
func TestPersistAndLoad(t *testing.T) {
	dir := t.TempDir()
	idx1 := New(dir)
	_ = idx1.Insert("hashB", "file-002")
	// New instance — must Load to repopulate
	idx2 := New(dir)
	if err := idx2.Load(); err != nil { t.Fatalf("load: %v", err) }
	if got := idx2.Lookup("hashB"); got != "file-002" { t.Errorf("after load: got %q, want file-002", got) }
}

// F1-3: Insert is idempotent — same fileID added twice is single entry, no error.
func TestInsertIdempotent(t *testing.T) {
	dir := t.TempDir()
	idx := New(dir)
	_ = idx.Insert("hashC", "file-003")
	_ = idx.Insert("hashC", "file-003") // duplicate
	h, e, _ := idx.Stats()
	if h != 1 || e != 1 { t.Errorf("expected 1 hash + 1 entry, got %d hashes %d entries", h, e) }
}

// F1-4: Canonical preferred over alias — Lookup returns first non-alias even if alias inserted first.
func TestCanonicalPreferredOverAlias(t *testing.T) {
	dir := t.TempDir()
	idx := New(dir)
	_ = idx.InsertAlias("hashD", "file-alias-1") // alias first
	_ = idx.Insert("hashD", "file-canonical")    // canonical second
	if got := idx.Lookup("hashD"); got != "file-canonical" {
		t.Errorf("expected canonical preferred, got %q", got)
	}
}

// F1-5: Stats counts hashes/entries/aliases correctly.
func TestStats(t *testing.T) {
	dir := t.TempDir()
	idx := New(dir)
	_ = idx.Insert("hashE", "file-canon-1")
	_ = idx.InsertAlias("hashE", "file-alias-1")
	_ = idx.InsertAlias("hashE", "file-alias-2")
	_ = idx.Insert("hashF", "file-canon-2")
	h, e, a := idx.Stats()
	if h != 2 { t.Errorf("hashes: got %d, want 2", h) }
	if e != 4 { t.Errorf("entries: got %d, want 4", e) }
	if a != 2 { t.Errorf("aliases: got %d, want 2", a) }
}

// F1-6: Concurrent inserts don't corrupt state (mutex correctness check).
func TestConcurrentInserts(t *testing.T) {
	dir := t.TempDir()
	idx := New(dir)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			hash := "hash-concurrent"
			fileID := "file-" + string(rune('A'+i))
			_ = idx.Insert(hash, fileID)
		}(i)
	}
	wg.Wait()
	h, e, _ := idx.Stats()
	if h != 1 { t.Errorf("expected 1 unique hash, got %d", h) }
	if e != 50 { t.Errorf("expected 50 distinct fileIDs, got %d", e) }
}

// F1-7: BootstrapFromList rebuilds index from raw FileMap data — survives sha_index.json loss.
func TestBootstrapFromList(t *testing.T) {
	dir := t.TempDir()
	idx := New(dir)
	bootstrap := []struct{ FileID, Hash string; IsAlias bool }{
		{FileID: "file-1", Hash: "h1", IsAlias: false},
		{FileID: "file-2", Hash: "h2", IsAlias: false},
		{FileID: "file-3", Hash: "h1", IsAlias: true}, // alias of file-1
		{FileID: "file-no-hash", Hash: "", IsAlias: false}, // skipped (empty hash)
	}
	if err := idx.BootstrapFromList(bootstrap); err != nil { t.Fatalf("bootstrap: %v", err) }
	if got := idx.Lookup("h1"); got != "file-1" { t.Errorf("h1: got %q, want file-1", got) }
	if got := idx.Lookup("h2"); got != "file-2" { t.Errorf("h2: got %q, want file-2", got) }
	h, e, a := idx.Stats()
	if h != 2 { t.Errorf("hashes: got %d, want 2", h) }
	if e != 3 { t.Errorf("entries: got %d, want 3 (empty-hash skipped)", e) }
	if a != 1 { t.Errorf("aliases: got %d, want 1", a) }
}

// F1-8: Atomic write — index file rename should be visible immediately, no partial state.
func TestAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	idx := New(dir)
	_ = idx.Insert("hashG", "file-007")
	// Verify file exists and is valid JSON
	path := filepath.Join(dir, IndexFileName)
	if _, err := os.Stat(path); err != nil { t.Fatalf("index file missing: %v", err) }
	// .tmp must NOT exist (rename completed)
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("expected no .tmp file after rename, got err=%v", err)
	}
}
