// Phase γ — Drain workflow. When the user removes an account via DELETE /admin/accounts/{id},
// admin_accounts.go transitions the account to Role=Drain (instead of immediate hard-delete).
// This file implements the background worker that walks all FileMaps, finds replicas living on
// the draining account, copies each one to one of the other still-active accounts (chosen via the
// same SelectReplicas algorithm — minus the drainee), updates Location, and finally — once
// every replica has been migrated — transitions the account to Status=Removed.
//
// Design intent:
//   - Idempotent: re-running mid-migration picks up where it left off (each replica is checked
//     individually; already-migrated ones skipped via prefix match).
//   - Throttled: honors cfg.DrainMaxConcurrentMigrations + cfg.DrainBandwidthLimitMBPerSec.
//   - Resumable: persistent state lives in FileMap.Location updates — no separate migration log.
//   - Safe under upload pressure: new uploads continue going to non-draining accounts thanks to
//     SelectReplicas excluding Role=Drain. So we never race "upload to draining account" while
//     drain is in progress.
//
// Out of scope: cross-provider migration semantics (drain a Drive account by copying replicas to
// a MEGA account). Currently best-effort — we use SelectReplicas without diversity override, so
// if user has only one Drive and one MEGA, draining the Drive may pick MEGA as target (correct
// behavior) or fail if MEGA is over its file-size cap (logged + retried next pass).
package account

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dudenest/dudenest-relay/pkg/types"
)

// PipelineDrainer is the minimal Pipeline surface the drain worker needs. Defined here so the
// account package doesn't import internal/pipeline directly (which would be a cycle: pipeline →
// account → pipeline). The relay startup wires the real *pipeline.Pipeline implementation in.
type PipelineDrainer interface {
	// ListFiles returns all known FileMaps so the worker can iterate.
	ListFiles() ([]*types.FileMap, error)
	// GetFileMap returns a specific FileMap (used after we mutate to re-read).
	GetFileMap(fileID string) (*types.FileMap, error)
	// SaveFileMap persists the updated FileMap (with new Location entries).
	SaveFileMap(fm *types.FileMap) error
	// CloudByID looks up a CloudProvider by its CloudProvider.ID(), e.g. "gdrive:user@x.com".
	// Returns nil if the provider is not loaded. The drain worker uses this to: (a) download
	// replica data from the draining account, (b) upload to the chosen target account.
	CloudByID(providerID string) types.CloudProvider
}

// DrainProgress tracks per-account state so the admin endpoint can show progress in UI.
// Lives in-memory only — restart resumes from where Location pointers stand.
// Exported so /admin/accounts/{id}/drain-progress can return it as JSON via DrainState.Snapshot.
type DrainProgress struct {
	StartedAt         time.Time `json:"started_at"`
	FileMapsScanned   int       `json:"file_maps_scanned"`
	ReplicasToMigrate int       `json:"replicas_to_migrate"`
	ReplicasMigrated  int       `json:"replicas_migrated"`
	ReplicasFailed    int       `json:"replicas_failed"`
	LastErr           string    `json:"last_err,omitempty"`
}

// DrainState exposes per-account progress for /admin/accounts/{id} GET. Thread-safe.
type DrainState struct {
	mu   sync.RWMutex
	byID map[int64]*DrainProgress
}

// NewDrainState returns an empty tracker. Created once in serve.go and passed to StartDrainLoop.
func NewDrainState() *DrainState {
	return &DrainState{byID: map[int64]*DrainProgress{}}
}

// Snapshot returns a copy of the current progress for an account (for /admin/accounts/{id}).
func (s *DrainState) Snapshot(id int64) *DrainProgress {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.byID[id]
	if !ok { return nil }
	cp := *p
	return &cp
}

// StartDrainLoop runs a sweep every interval and drains every Role=Drain account it finds.
// Idempotent — if a previous run was interrupted, the next pass picks up remaining replicas
// (those whose Location still references the draining account).
//
// One pass blocks until all draining accounts are processed; intervals between passes give
// the relay time for normal operation. Goroutine exits when ctx cancels.
func (m *Manager) StartDrainLoop(ctx context.Context, drainer PipelineDrainer, state *DrainState, interval time.Duration) {
	if interval <= 0 { interval = 2 * time.Minute }
	go func() {
		// Initial delay: 1 minute after start, so quota poll + reconcile run first and we don't
		// race with bootstrap. Subsequent passes use the full interval.
		select {
		case <-ctx.Done(): return
		case <-time.After(time.Minute):
		}
		for {
			drained := m.drainOnePass(drainer, state)
			if drained > 0 {
				log.Printf("drain: completed pass — %d accounts had replicas remaining", drained)
			}
			select {
			case <-ctx.Done(): return
			case <-time.After(interval):
			}
		}
	}()
}

// drainOnePass walks all accounts with Role=Drain and migrates their replicas. Returns the
// number of accounts touched (with at least one replica remaining at the start of the pass).
func (m *Manager) drainOnePass(drainer PipelineDrainer, state *DrainState) int {
	cfg := m.Policy()
	drains := []*types.CloudAccount{}
	for _, a := range m.ActiveAccounts() {
		if a.Role == types.RoleDrain {
			drains = append(drains, a)
		}
	}
	if len(drains) == 0 { return 0 }
	for _, d := range drains {
		m.drainOneAccount(d, drainer, state, cfg)
	}
	return len(drains)
}

// drainOneAccount migrates every replica belonging to one draining account. Implementation:
//  1. Build the "draining" provider ID string ("<provider>:<email>") used as Location prefix.
//  2. ListFiles, then for each FileMap walk Replicas looking for ones whose Location starts with that prefix.
//  3. For each match: download data from draining provider, choose a new target via SelectReplicas
//     (with current account temporarily removed from consideration), upload, rewrite Location +
//     CloudID in place, persist FileMap.
//  4. When zero matches remain across all FileMaps → transition account to Status=Removed.
func (m *Manager) drainOneAccount(d *types.CloudAccount, drainer PipelineDrainer, state *DrainState, cfg types.AccountPolicyConfig) {
	state.mu.Lock()
	prog, ok := state.byID[d.ID]
	if !ok {
		prog = &DrainProgress{StartedAt: time.Now()}
		state.byID[d.ID] = prog
	}
	state.mu.Unlock()

	drainProviderID := d.Provider + ":" + d.Email
	files, err := drainer.ListFiles()
	if err != nil {
		log.Printf("drain ID%03d: list files: %v", d.ID, err)
		state.mu.Lock(); prog.LastErr = err.Error(); state.mu.Unlock()
		return
	}
	prog.FileMapsScanned = len(files)

	// Build pool of candidate accounts (all active, NOT this one).
	otherAccounts := []*types.CloudAccount{}
	for _, a := range m.ActiveAccounts() {
		if a.ID != d.ID && a.Role != types.RoleDrain {
			otherAccounts = append(otherAccounts, a)
		}
	}
	if len(otherAccounts) == 0 {
		// No targets to migrate to — log + skip. User must add another account first.
		log.Printf("drain ID%03d: no other active accounts available — pause until user adds one", d.ID)
		state.mu.Lock(); prog.LastErr = "no migration target accounts"; state.mu.Unlock()
		return
	}

	// Throttle: concurrent migrations per draining account.
	sem := make(chan struct{}, max1(cfg.DrainMaxConcurrentMigrations))
	var wg sync.WaitGroup
	var muProg sync.Mutex
	remainingAfter := 0

	for _, fm := range files {
		fm := fm
		for ri := range fm.Replicas {
			r := &fm.Replicas[ri]
			if !strings.HasPrefix(r.Location, drainProviderID+":") {
				continue // replica not on the draining account
			}
			remainingAfter++
			wg.Add(1)
			sem <- struct{}{}
			go func(fm *types.FileMap, ri int) {
				defer wg.Done()
				defer func() { <-sem }()
				if err := m.migrateOneReplica(fm, ri, d, otherAccounts, drainer, cfg); err != nil {
					log.Printf("drain ID%03d: migrate %s replica %d: %v", d.ID, fm.FileID, ri, err)
					muProg.Lock(); prog.ReplicasFailed++; prog.LastErr = err.Error(); muProg.Unlock()
					return
				}
				muProg.Lock(); prog.ReplicasMigrated++; muProg.Unlock()
			}(fm, ri)
		}
	}
	prog.ReplicasToMigrate = remainingAfter
	wg.Wait()

	// After this pass, if no failures + nothing left → transition to Removed.
	if prog.ReplicasFailed == 0 {
		// Re-scan to confirm — guards against TOCTOU between counting + Wait.
		files2, err := drainer.ListFiles()
		if err == nil {
			stillThere := 0
			for _, fm := range files2 {
				for _, r := range fm.Replicas {
					if strings.HasPrefix(r.Location, drainProviderID+":") { stillThere++ }
				}
			}
			if stillThere == 0 {
				now := time.Now().UTC()
				m.mu.Lock()
				for _, a := range m.accounts {
					if a.ID == d.ID {
						a.Status = types.StatusRemoved
						a.Role = types.RoleReadOnly // role becomes irrelevant once Removed, but ReadOnly is a sensible terminal
						a.RemovedAt = &now
						break
					}
				}
				_ = m.savelocked()
				m.mu.Unlock()
				log.Printf("✅ drain ID%03d done: %d replicas migrated, account marked Removed (audit-retained)", d.ID, prog.ReplicasMigrated)
			}
		}
	}
}

// migrateOneReplica performs the actual download+upload+rewrite for a single replica.
// Honors bandwidth throttling via cfg.DrainBandwidthLimitMBPerSec (if > 0, sleep proportional
// to bytes transferred before completing — keeps each migration atomic but caps overall throughput).
func (m *Manager) migrateOneReplica(
	fm *types.FileMap, ri int,
	d *types.CloudAccount, otherAccounts []*types.CloudAccount,
	drainer PipelineDrainer, cfg types.AccountPolicyConfig,
) error {
	r := &fm.Replicas[ri]
	// Source provider lookup
	srcID := d.Provider + ":" + d.Email
	src := drainer.CloudByID(srcID)
	if src == nil {
		return fmt.Errorf("source provider %s not loaded", srcID)
	}
	// Path = everything after "<provider>:<email>:"
	parts := strings.SplitN(r.Location, ":", 3)
	if len(parts) != 3 {
		return fmt.Errorf("malformed Location %q", r.Location)
	}
	srcPath := parts[2]

	// Download. Prefer CloudIDDownloader if we have an ID — survives renames on cloud side.
	var data []byte
	var err error
	if r.CloudID != "" {
		if idd, ok := src.(types.CloudIDDownloader); ok {
			data, err = idd.DownloadByID(r.CloudID)
		}
	}
	if data == nil {
		data, err = src.Download(srcPath)
	}
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}

	// Pick target via SelectReplicas with file size + content type from path inference.
	contentType := types.FilesFolder
	if strings.Contains(srcPath, "/"+types.PhotosFolder+"/") || strings.Contains(srcPath, ":"+types.PhotosFolder+"/") {
		contentType = types.PhotosFolder
	}
	chosen, err := SelectReplicas(FileMeta{Size: int64(len(data)), ContentType: contentType}, otherAccounts, cfg)
	if err != nil {
		return fmt.Errorf("select target: %w", err)
	}
	// Use the highest-priority chosen as the single migration target — we're replacing one replica, not creating multiple.
	target := chosen[0]
	dst := drainer.CloudByID(target.Provider + ":" + target.Email)
	if dst == nil {
		return fmt.Errorf("target provider %s:%s not loaded", target.Provider, target.Email)
	}

	// Build dest path: keep filename + use same folder layout as the source for now.
	// (Future: re-bucket if PathScheme changed since original upload.)
	destPath := srcPath
	var newCloudID string
	if u, ok := dst.(types.CloudIDUploader); ok {
		newCloudID, err = u.UploadAndReturnID(destPath, data)
	} else {
		err = dst.Upload(destPath, data)
	}
	if err != nil {
		return fmt.Errorf("upload to target: %w", err)
	}

	// Rewrite replica Location + CloudID, persist FileMap.
	newLocation := fmt.Sprintf("%s:%s", dst.ID(), destPath)
	// Re-load FileMap before saving to merge with any concurrent meta edits.
	fresh, gerr := drainer.GetFileMap(fm.FileID)
	if gerr == nil {
		fm = fresh
		if ri < len(fm.Replicas) {
			r = &fm.Replicas[ri]
			if !strings.HasPrefix(r.Location, srcID+":") {
				// Concurrent update already migrated this replica — bail.
				return nil
			}
		}
	}
	r.Location = newLocation
	if newCloudID != "" { r.CloudID = newCloudID }
	r.Created = time.Now().UTC()
	if err := drainer.SaveFileMap(fm); err != nil {
		return fmt.Errorf("save updated filemap: %w", err)
	}

	// Best-effort: remove the source copy from the draining account. Failure here is non-fatal —
	// the data has been replicated successfully; orphan cleanup happens via the scan engine.
	if r.CloudID != "" {
		if idd, ok := src.(types.CloudIDDownloader); ok {
			_ = idd.DeleteByID(r.CloudID)
		}
	}
	_ = src.Delete(srcPath)

	// Bandwidth throttle: sleep proportional to bytes if limit set.
	if cfg.DrainBandwidthLimitMBPerSec > 0 {
		bytesPerSec := int64(cfg.DrainBandwidthLimitMBPerSec) * 1024 * 1024
		expectedDuration := time.Duration(int64(len(data)) * int64(time.Second) / bytesPerSec)
		if expectedDuration > 0 {
			time.Sleep(expectedDuration)
		}
	}
	return nil
}

func max1(n int) int { if n < 1 { return 1 }; return n }

// _filepath_keepImported is a stub to keep "path/filepath" import meaningful if we ever need it.
// Removed in trim — left as a comment to remind future maintainers that drain paths are RELATIVE
// (no filesystem ops here — everything is provider-API).
var _ = filepath.Separator
var _ = os.Getenv
