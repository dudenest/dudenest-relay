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
	knownMaps       []*types.FileMap // returned by ListFiles — drives the scan dedup set
}

type registerCall struct{ providerID, cloudID, name, path string; size int64; mtime time.Time }
type deleteCall struct{ providerID, cloudID string }

func (f *fakePipeline) ListFiles() ([]*types.FileMap, error) { return f.knownMaps, nil }
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

// fakeFullLister adds CloudFullLister capability to a poller for bootstrap testing.
type fakeFullLister struct {
	*fakePoller
	pages [][]types.Entry
}
func (f *fakeFullLister) ListAll(perPage func(entries []types.Entry) bool) error {
	for _, page := range f.pages {
		if !perPage(page) { return nil }
	}
	return nil
}

// BootstrapWholeDrive registers every file via RegisterForeign, sets WholeDriveBootstrapped flag,
// and is idempotent — second call is a no-op until ResetWholeDriveBootstrap clears the flag.
func TestBootstrapWholeDrive_IndexesAllPagesIdempotent(t *testing.T) {
	fp := &fakePipeline{}
	now := time.Now().UTC()
	fl := &fakeFullLister{
		fakePoller: &fakePoller{id: "gdrive:wholedrive@example.com"},
		pages: [][]types.Entry{
			{
				{CloudID: "a", Name: "outside1.jpg", Path: "outside1.jpg", Size: 100, MTime: now},
				{CloudID: "b", Name: "outside2.pdf", Path: "outside2.pdf", Size: 200, MTime: now},
			},
			{
				{CloudID: "c", Name: "outside3.mp4", Path: "outside3.mp4", Size: 999, MTime: now},
			},
		},
	}
	s, err := New(fp, makeProviderFn(fl), t.TempDir())
	if err != nil { t.Fatalf("scanner.New: %v", err) }
	if err := s.BootstrapWholeDrive(fl.ID()); err != nil { t.Fatalf("BootstrapWholeDrive: %v", err) }
	if len(fp.registerCalls) != 3 { t.Fatalf("want 3 RegisterForeign, got %d", len(fp.registerCalls)) }
	st, _ := s.loadStatus(fl.ID())
	if !st.WholeDriveBootstrapped { t.Fatalf("flag not set after success") }
	if st.WholeDriveBootstrapIndexed != 3 { t.Fatalf("WholeDriveBootstrapIndexed=%d, want 3", st.WholeDriveBootstrapIndexed) }
	// Second call must NO-OP (no new RegisterForeign).
	if err := s.BootstrapWholeDrive(fl.ID()); err != nil { t.Fatalf("re-run: %v", err) }
	if len(fp.registerCalls) != 3 { t.Fatalf("re-run added register calls: want 3, got %d", len(fp.registerCalls)) }
	// After reset, third call should re-index.
	if err := s.ResetWholeDriveBootstrap(fl.ID()); err != nil { t.Fatalf("reset: %v", err) }
	if err := s.BootstrapWholeDrive(fl.ID()); err != nil { t.Fatalf("post-reset: %v", err) }
	if len(fp.registerCalls) != 6 { t.Fatalf("post-reset: want 6 total (fake pipeline doesn't dedup), got %d", len(fp.registerCalls)) }
}

// Bootstrap must NOT re-register a file the relay already tracks (upload FileMap with that CloudID),
// or the file shows twice — the foreign copy misfiled under Files. Regression for the demo bug.
func TestBootstrapWholeDrive_SkipsKnownCloudIDs(t *testing.T) {
	now := time.Now().UTC()
	fp := &fakePipeline{knownMaps: []*types.FileMap{{
		FileID:   "upload-1",
		Replicas: []types.Replica{{CloudID: "a", Location: "gdrive:x@y.com:photos/2026/07/known.jpg"}},
	}}}
	fl := &fakeFullLister{
		fakePoller: &fakePoller{id: "gdrive:x@y.com"},
		pages: [][]types.Entry{{
			{CloudID: "a", Name: "known.jpg", Path: "photos/2026/07/known.jpg", Size: 100, MTime: now}, // already tracked → skip
			{CloudID: "b", Name: "direct.pdf", Path: "direct.pdf", Size: 200, MTime: now},               // genuinely foreign → register
		}},
	}
	s, err := New(fp, makeProviderFn(fl), t.TempDir())
	if err != nil { t.Fatalf("scanner.New: %v", err) }
	if err := s.BootstrapWholeDrive(fl.ID()); err != nil { t.Fatalf("bootstrap: %v", err) }
	if len(fp.registerCalls) != 1 { t.Fatalf("want 1 RegisterForeign (skip known CloudID a), got %d", len(fp.registerCalls)) }
	if fp.registerCalls[0].cloudID != "b" { t.Fatalf("registered wrong file: got %q, want b", fp.registerCalls[0].cloudID) }
}

// Providers without CloudFullLister (only CloudChangesPoller, or none) skip bootstrap silently.
func TestBootstrapWholeDrive_SkipsProvidersWithoutFullLister(t *testing.T) {
	fp := &fakePipeline{}
	pp := &fakePoller{id: "gdrive:onlypoller@example.com"} // has poller but not full lister
	s, err := New(fp, makeProviderFn(pp), t.TempDir())
	if err != nil { t.Fatalf("scanner.New: %v", err) }
	if err := s.BootstrapWholeDrive(pp.ID()); err != nil { t.Fatalf("expected nil err, got %v", err) }
	if len(fp.registerCalls) != 0 { t.Fatalf("should skip silently, got %d Register calls", len(fp.registerCalls)) }
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
