// Package scan implements the P5c background scan engine — discovers files on cloud providers
// and registers them in the local blockmap as Strategy=Foreign entries (pointing at the
// existing cloud locations via CloudID, never re-uploading).
//
// Triggers:
//   1. `auth_done` WebSocket event from browser auth flow — newly authorized provider triggers
//      an initial scan automatically (user just connected a Google Drive, scanner picks up).
//   2. 24h auto-rescan timer (configurable in <configDir>/scan/config.json, default ENABLED) —
//      periodically discovers files added directly to the cloud outside of dudenest uploads.
//   3. Manual: POST /admin/scan/start — Flutter Settings button.
//
// State per provider lives at <configDir>/scan/<provider_id>.json. Each provider scans
// independently in its own goroutine. Pause/Resume granularity: per-file via cancel chan
// (per user decision 2026-05-20) — drops in-progress entry, persists state at folder boundary
// for clean resume.
//
// Dedup by CloudID: scanner walks all existing FileMaps once at scan start, builds an in-memory
// set of known CloudIDs. Skips any Entry whose CloudID is already known. Idempotent rescan.
//
// Throttling (rate limit avoidance): caller-side cooperative; this V1 doesn't implement
// adaptive throttle (P6 — separate session). Drive API native pagination (PageSize=1000) keeps
// raw call rate low enough for typical drives without throttling.
package scan

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dudenest/dudenest-relay/pkg/types"
)

// State enumerates per-provider scan lifecycle.
type State string

const (
	StateIdle    State = "idle"    // not started or finished cleanly
	StateRunning State = "running" // walker goroutine active
	StatePausing State = "pausing" // cancel signaled, waiting for in-flight List/blockmap to finish
	StatePaused  State = "paused"  // halted at last folder boundary, resumable via Start
	StateError   State = "error"   // fatal error; user must manually re-trigger via Start
)

// Status is the JSON response shape for GET /admin/scan/status.
type Status struct {
	ProviderID        string    `json:"provider_id"`
	State             State     `json:"state"`
	StartedAt         time.Time `json:"started_at,omitempty"`
	LastFinishedAt    time.Time `json:"last_finished_at,omitempty"`
	CurrentFolder     string    `json:"current_folder,omitempty"` // last folder walker descended into (resume point)
	FilesDiscovered   int       `json:"files_discovered"`         // total entries seen during this run (including dups)
	FilesNewlyIndexed int       `json:"files_newly_indexed"`      // CloudID was not in blockmap — added as Foreign FileMap
	FilesSkipped      int       `json:"files_skipped"`            // CloudID already known (dedup hit)
	Errors            int       `json:"errors"`
	LastError         string    `json:"last_error,omitempty"`
}

// Config governs auto-rescan behavior across all providers.
// Persisted at <configDir>/scan/config.json. Defaults applied by Scanner.LoadConfig on missing file.
type Config struct {
	AutoRescanEnabled       bool `json:"auto_rescan_enabled"`         // default true (user decision 2026-05-20)
	AutoRescanIntervalHours int  `json:"auto_rescan_interval_hours"`  // default 24
	SkipFilesAboveBytes     int64 `json:"skip_files_above_bytes,omitempty"` // 0 = no limit (user decision 2026-05-20: scan everything)
}

// Pipeliner is what the scanner needs from the pipeline package. Narrow interface so tests
// can inject a fake without dragging the whole pipeline.New chain in.
type Pipeliner interface {
	ListFiles() ([]*types.FileMap, error)
	RegisterForeign(providerID, cloudID, name, path string, size int64, mtime time.Time) error
}

// Scanner owns all per-provider goroutines + state files. One Scanner per relay process.
type Scanner struct {
	pipeline    Pipeliner
	providersFn func() []types.CloudProvider // late-bound: providers may be added at runtime
	stateDir    string                       // <configDir>/scan/
	cfg         Config
	cfgMu       sync.RWMutex

	mu       sync.Mutex
	running  map[string]*scanRun // keyed by provider ID; nil entry = not running
	statuses map[string]*Status  // last known status per provider; survives between runs
}

type scanRun struct {
	cancel  chan struct{}
	done    chan struct{}
	status  *Status
	startMu sync.Mutex
}

// New constructs a Scanner. providersFn is called each time a scan starts so the scanner
// always sees the current set of cloud providers (handles hot-add after auth_done events).
func New(pipeline Pipeliner, providersFn func() []types.CloudProvider, stateDir string) (*Scanner, error) {
	if err := os.MkdirAll(stateDir, 0o755); err != nil { return nil, fmt.Errorf("mkdir state dir: %w", err) }
	s := &Scanner{
		pipeline:    pipeline,
		providersFn: providersFn,
		stateDir:    stateDir,
		running:     make(map[string]*scanRun),
		statuses:    make(map[string]*Status),
	}
	s.cfg = s.loadConfigOrDefault()
	// Pre-populate statuses from persisted state files so /admin/scan/status returns history immediately on cold start.
	files, _ := os.ReadDir(stateDir)
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".json") || f.Name() == "config.json" { continue }
		pid := strings.TrimSuffix(f.Name(), ".json")
		if st, err := s.loadStatus(pid); err == nil { s.statuses[pid] = st }
	}
	return s, nil
}

// loadConfigOrDefault reads <stateDir>/config.json. Missing file → defaults applied + written.
func (s *Scanner) loadConfigOrDefault() Config {
	def := Config{AutoRescanEnabled: true, AutoRescanIntervalHours: 24, SkipFilesAboveBytes: 0}
	p := filepath.Join(s.stateDir, "config.json")
	data, err := os.ReadFile(p)
	if err != nil { _ = s.saveConfig(def); return def }
	var c Config
	if err := json.Unmarshal(data, &c); err != nil { return def }
	if c.AutoRescanIntervalHours == 0 { c.AutoRescanIntervalHours = 24 }
	return c
}

func (s *Scanner) saveConfig(c Config) error {
	p := filepath.Join(s.stateDir, "config.json")
	data, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(p, data, 0o644)
}

// GetConfig + SetConfig are called by /admin/scan/config endpoints.
func (s *Scanner) GetConfig() Config { s.cfgMu.RLock(); defer s.cfgMu.RUnlock(); return s.cfg }
func (s *Scanner) SetConfig(c Config) error {
	s.cfgMu.Lock(); defer s.cfgMu.Unlock()
	s.cfg = c
	return s.saveConfig(c)
}

func (s *Scanner) statusPath(providerID string) string {
	// Provider IDs contain ':' which is fine on Linux fs but ugly. Replace for safety.
	safe := strings.ReplaceAll(providerID, ":", "_")
	return filepath.Join(s.stateDir, safe+".json")
}

func (s *Scanner) loadStatus(providerID string) (*Status, error) {
	data, err := os.ReadFile(s.statusPath(providerID))
	if err != nil { return nil, err }
	var st Status
	if err := json.Unmarshal(data, &st); err != nil { return nil, err }
	return &st, nil
}

func (s *Scanner) saveStatus(st *Status) error {
	data, _ := json.MarshalIndent(st, "", "  ")
	return os.WriteFile(s.statusPath(st.ProviderID), data, 0o644)
}

// Start kicks off (or resumes) a scan for the given provider. Idempotent: if already running,
// returns immediately. Returns the status snapshot at start time so the caller can show progress.
func (s *Scanner) Start(providerID string) (*Status, error) {
	s.mu.Lock()
	if r, ok := s.running[providerID]; ok && r != nil {
		s.mu.Unlock()
		return r.status, nil // already running
	}
	prov := s.findProvider(providerID)
	if prov == nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("provider %q not currently loaded", providerID)
	}
	lister, ok := prov.(types.CloudLister)
	if !ok {
		s.mu.Unlock()
		return nil, fmt.Errorf("provider %q does not support listing (no CloudLister interface)", providerID)
	}
	st := &Status{ProviderID: providerID, State: StateRunning, StartedAt: time.Now().UTC()}
	if prev := s.statuses[providerID]; prev != nil {
		// Preserve cumulative counters across runs if resuming from paused; reset otherwise.
		if prev.State == StatePaused {
			st = prev
			st.State = StateRunning
		}
	}
	s.statuses[providerID] = st
	r := &scanRun{cancel: make(chan struct{}), done: make(chan struct{}), status: st}
	s.running[providerID] = r
	s.mu.Unlock()
	_ = s.saveStatus(st)
	go s.runScan(providerID, prov, lister, r)
	return st, nil
}

// Pause requests the running scan to stop at the next checkpoint (per-file granularity).
// Returns immediately; actual transition to StatePaused happens within seconds.
func (s *Scanner) Pause(providerID string) error {
	s.mu.Lock()
	r, ok := s.running[providerID]
	s.mu.Unlock()
	if !ok || r == nil { return fmt.Errorf("not running") }
	select {
	case <-r.cancel:
		// already cancelled
	default:
		close(r.cancel)
	}
	r.status.State = StatePausing
	_ = s.saveStatus(r.status)
	return nil
}

// StatusAll returns a snapshot of every known provider's status (running + idle history).
func (s *Scanner) StatusAll() map[string]*Status {
	s.mu.Lock(); defer s.mu.Unlock()
	out := make(map[string]*Status, len(s.statuses))
	for k, v := range s.statuses { vv := *v; out[k] = &vv }
	return out
}

// AutoRescanLoop is intended to run as a single relay-wide goroutine (started from serve.go).
// Every 5 minutes it checks each provider's last_finished_at + interval; triggers Start if due.
// Cheap (just os.Stat + math); safe to leave running for the relay lifetime.
func (s *Scanner) AutoRescanLoop(stop <-chan struct{}) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-stop: return
		case <-t.C:
			cfg := s.GetConfig()
			if !cfg.AutoRescanEnabled { continue }
			interval := time.Duration(cfg.AutoRescanIntervalHours) * time.Hour
			for _, prov := range s.providersFn() {
				st, _ := s.loadStatus(prov.ID())
				if st == nil || st.LastFinishedAt.IsZero() || time.Since(st.LastFinishedAt) >= interval {
					if _, err := s.Start(prov.ID()); err != nil { log.Printf("auto-rescan start %s: %v", prov.ID(), err) }
				}
			}
		}
	}
}

func (s *Scanner) findProvider(providerID string) types.CloudProvider {
	for _, p := range s.providersFn() { if p.ID() == providerID { return p } }
	return nil
}

// runScan is the walker goroutine. Calls itself recursively via walkFolder. Each folder
// represents a checkpoint; pause settles within one folder's worth of work.
func (s *Scanner) runScan(providerID string, prov types.CloudProvider, lister types.CloudLister, r *scanRun) {
	defer func() {
		close(r.done)
		s.mu.Lock()
		s.running[providerID] = nil
		s.mu.Unlock()
	}()
	// Build dedup set: all CloudIDs already present in our blockmap.
	maps, _ := s.pipeline.ListFiles()
	known := make(map[string]bool, 1024)
	for _, fm := range maps {
		for _, r := range fm.Replicas {
			if r.CloudID != "" { known[r.CloudID] = true }
		}
	}
	// Start at the configured base folder root (prefix="").
	startFolder := ""
	if r.status.State == StatePaused && r.status.CurrentFolder != "" { startFolder = r.status.CurrentFolder }
	r.status.State = StateRunning
	_ = s.saveStatus(r.status)
	if err := s.walkFolder(providerID, lister, startFolder, known, r); err != nil {
		if err == errCancelled {
			r.status.State = StatePaused
		} else {
			r.status.State = StateError
			r.status.LastError = err.Error()
			r.status.Errors++
		}
		_ = s.saveStatus(r.status)
		return
	}
	r.status.State = StateIdle
	r.status.LastFinishedAt = time.Now().UTC()
	r.status.CurrentFolder = ""
	_ = s.saveStatus(r.status)
	log.Printf("✅ scan complete provider=%s discovered=%d newly_indexed=%d skipped=%d errors=%d", providerID, r.status.FilesDiscovered, r.status.FilesNewlyIndexed, r.status.FilesSkipped, r.status.Errors)
}

var errCancelled = fmt.Errorf("scan cancelled")

// walkFolder recursively walks one folder. Returns errCancelled if r.cancel fires; otherwise
// nil (success) or other errors. Per-folder checkpointing: status.CurrentFolder is updated
// before each List call so a pause is restartable.
func (s *Scanner) walkFolder(providerID string, lister types.CloudLister, prefix string, known map[string]bool, r *scanRun) error {
	select {
	case <-r.cancel: return errCancelled
	default:
	}
	r.status.CurrentFolder = prefix
	_ = s.saveStatus(r.status)
	entries, err := lister.List(prefix)
	if err != nil { return fmt.Errorf("list %q: %w", prefix, err) }
	for _, e := range entries {
		select {
		case <-r.cancel: return errCancelled
		default:
		}
		if e.IsDir {
			if err := s.walkFolder(providerID, lister, e.Path, known, r); err != nil { return err }
			continue
		}
		r.status.FilesDiscovered++
		if e.CloudID == "" || known[e.CloudID] {
			r.status.FilesSkipped++
			continue
		}
		cfg := s.GetConfig()
		if cfg.SkipFilesAboveBytes > 0 && e.Size > cfg.SkipFilesAboveBytes {
			r.status.FilesSkipped++
			continue
		}
		if err := s.pipeline.RegisterForeign(providerID, e.CloudID, e.Name, e.Path, e.Size, e.MTime); err != nil {
			r.status.Errors++
			r.status.LastError = err.Error()
			continue
		}
		known[e.CloudID] = true
		r.status.FilesNewlyIndexed++
	}
	return nil
}
