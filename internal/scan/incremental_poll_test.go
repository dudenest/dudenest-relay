package scan

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/dudenest/dudenest-relay/pkg/types"
)

// fakePipeline implements Pipeliner for tests (counts calls, no real blockmap).
type fakePipeline struct {
	mu              sync.Mutex
	registerCalls   []registerCall
	deleteCalls     []deleteCall
}

type registerCall struct{ providerID, cloudID, name, path string; size int64; mtime time.Time }
type deleteCall struct{ providerID, cloudID string }

func (f *fakePipeline) ListFiles() ([]*types.FileMap, error) { return nil, nil }
func (f *fakePipeline) RegisterForeign(providerID, cloudID, name, path string, size int64, mtime time.Time) error {
	f.mu.Lock(); defer f.mu.Unlock()
	f.registerCalls = append(f.registerCalls, registerCall{providerID, cloudID, name, path, size, mtime})
	return nil
}
func (f *fakePipeline) DeleteByCloudID(providerID, cloudID string) error {
	f.mu.Lock(); defer f.mu.Unlock()
	f.deleteCalls = append(f.deleteCalls, deleteCall{providerID, cloudID})
	return nil
}

// fakePoller implements both types.CloudProvider + types.CloudChangesPoller for tests.
type fakePoller struct {
	id          string
	startToken  string
	changesQ    [][]types.ChangedEntry // each call returns one slice; last slice signals end-of-log
	newStartTok string
	callCount   int
}

func (f *fakePoller) ID() string                                                        { return f.id }
func (f *fakePoller) Upload(path string, data []byte) error                             { return nil }
func (f *fakePoller) Download(path string) ([]byte, error)                              { return nil, nil }
func (f *fakePoller) Delete(path string) error                                          { return nil }
func (f *fakePoller) Available() bool                                                   { return true }
func (f *fakePoller) GetStartPageToken() (string, error)                                { return f.startToken, nil }
func (f *fakePoller) GetChanges(pageToken string) ([]types.ChangedEntry, string, error) {
	idx := f.callCount
	f.callCount++
	if idx >= len(f.changesQ) { return nil, f.newStartTok, nil }
	return f.changesQ[idx], f.newStartTok, nil
}

func makeProviderFn(pp ...types.CloudProvider) func() []types.CloudProvider {
	return func() []types.CloudProvider { return pp }
}

// IncrementalPoll on first ever call seeds the pageToken without making any RegisterForeign calls.
// This proves we don't double-count files that already exist (the seed marks the high-water mark).
func TestIncrementalPoll_FirstCallSeedsTokenWithoutPolling(t *testing.T) {
	fp := &fakePipeline{}
	pp := &fakePoller{id: "gdrive:test@example.com", startToken: "tok-init", newStartTok: "tok-2"}
	s, err := New(fp, makeProviderFn(pp), t.TempDir())
	if err != nil { t.Fatalf("scanner.New: %v", err) }
	if err := s.IncrementalPoll(pp.ID()); err != nil { t.Fatalf("IncrementalPoll: %v", err) }
	if len(fp.registerCalls) != 0 || len(fp.deleteCalls) != 0 {
		t.Fatalf("expected no Register/Delete on seed, got register=%d delete=%d", len(fp.registerCalls), len(fp.deleteCalls))
	}
	// Verify token persisted to status file.
	st, err := s.loadStatus(pp.ID())
	if err != nil || st == nil { t.Fatalf("loadStatus after seed: status=%v err=%v", st, err) }
	if st.ChangesPageToken != "tok-init" { t.Fatalf("ChangesPageToken=%q, want tok-init", st.ChangesPageToken) }
}

// On the second poll (with seeded token), changes drain into RegisterForeign + DeleteByCloudID per entry.
func TestIncrementalPoll_DrainsChangesAndUpdatesToken(t *testing.T) {
	fp := &fakePipeline{}
	now := time.Now().UTC()
	pp := &fakePoller{
		id:         "gdrive:test@example.com",
		startToken: "tok-seed",
		newStartTok: "tok-after-drain",
		changesQ: [][]types.ChangedEntry{{
			{CloudID: "f1", Name: "photo.jpg", Path: "photo.jpg", Size: 1234, MTime: now},
			{CloudID: "f2", Name: "doc.pdf", Path: "doc.pdf", Size: 5678, MTime: now},
			{CloudID: "f3", Removed: true},
		}},
	}
	s, err := New(fp, makeProviderFn(pp), t.TempDir())
	if err != nil { t.Fatalf("scanner.New: %v", err) }
	// Seed first.
	_ = s.IncrementalPoll(pp.ID())
	// Now drain.
	if err := s.IncrementalPoll(pp.ID()); err != nil { t.Fatalf("IncrementalPoll drain: %v", err) }
	if len(fp.registerCalls) != 2 { t.Fatalf("registerCalls=%d, want 2 (f1,f2)", len(fp.registerCalls)) }
	if len(fp.deleteCalls) != 1 { t.Fatalf("deleteCalls=%d, want 1 (f3 removed)", len(fp.deleteCalls)) }
	if fp.deleteCalls[0].cloudID != "f3" { t.Fatalf("deleted wrong cloudID: %q", fp.deleteCalls[0].cloudID) }
	st, _ := s.loadStatus(pp.ID())
	if st.ChangesPageToken != "tok-after-drain" { t.Fatalf("token not advanced: got %q", st.ChangesPageToken) }
	if st.ChangesIndexedTotal != 2 || st.ChangesRemovedTotal != 1 {
		t.Fatalf("counters: indexed=%d removed=%d, want 2/1", st.ChangesIndexedTotal, st.ChangesRemovedTotal)
	}
}

// Providers without CloudChangesPoller (e.g. mega/local) are skipped silently — returns nil, no error.
type plainProvider struct{ id string }
func (p *plainProvider) ID() string                               { return p.id }
func (p *plainProvider) Upload(path string, data []byte) error    { return nil }
func (p *plainProvider) Download(path string) ([]byte, error)     { return nil, nil }
func (p *plainProvider) Delete(path string) error                 { return nil }
func (p *plainProvider) Available() bool                          { return true }

func TestIncrementalPoll_SkipsProvidersWithoutPoller(t *testing.T) {
	fp := &fakePipeline{}
	pp := &plainProvider{id: "mega:test"}
	s, err := New(fp, makeProviderFn(pp), t.TempDir())
	if err != nil { t.Fatalf("scanner.New: %v", err) }
	if err := s.IncrementalPoll(pp.ID()); err != nil { t.Fatalf("expected nil err, got %v", err) }
	if len(fp.registerCalls) != 0 { t.Fatalf("plain provider shouldn't call Register, got %d", len(fp.registerCalls)) }
	// Status file should NOT be created for skipped providers.
	if _, err := s.loadStatus(pp.ID()); err == nil {
		t.Fatalf("loadStatus on skipped provider should fail (no file)")
	}
	_ = filepath.Join // silence unused import in some Go versions
}
