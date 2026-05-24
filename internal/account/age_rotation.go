// Package account: age-based rotation worker (Phase γ continue, s319).
// Periodically scans FileMaps for files older than cfg.AgeRotationDays and migrates replicas
// living on non-ColdArchive accounts to ColdArchive accounts. Disabled by default — operator
// opts in via cfg.AgeBasedRotation=true + at least one Role=ColdArchive account.
//
// Reuses migrateOneReplica from drain.go (same download/upload/rewrite/save pattern). Difference:
// source isn't a draining account — it's any account currently holding a replica older than the cutoff.
// Target pool = only ColdArchive accounts (vs drain's "all-other-active" pool).
//
// Idempotent — after migration the replica.s Location prefix points to the ColdArchive account,
// so subsequent passes invisibly skip it (HasPrefix check on the source list excludes ColdArchive).
package account

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/dudenest/dudenest-relay/pkg/types"
)

// StartAgeRotationLoop runs a sweep every interval and migrates aged replicas to ColdArchive accounts.
// Disabled unless cfg.AgeBasedRotation=true AND at least one Role=ColdArchive account exists.
// Default interval 24h. First sweep delayed 5 min after start so other loops (quota/reconcile/drain)
// run first and don't compete on the same FileMaps.
// Safe to call without ColdArchive accounts — worker loops but does nothing until one is added.
func (m *Manager) StartAgeRotationLoop(ctx context.Context, drainer PipelineDrainer, interval time.Duration) {
	if interval <= 0 { interval = 24 * time.Hour }
	go func() {
		select { case <-ctx.Done(): return; case <-time.After(5 * time.Minute): } // initial delay
		for {
			cfg := m.Policy()
			if cfg.AgeBasedRotation {
				if n := m.ageRotateOnePass(drainer, cfg); n > 0 {
					log.Printf("age-rotation: completed pass — %d replicas migrated to ColdArchive", n)
				}
			}
			select { case <-ctx.Done(): return; case <-time.After(interval): }
		}
	}()
}

// ageRotateOnePass walks all FileMaps, finds replicas older than cfg.AgeRotationDays sitting on
// non-ColdArchive accounts, and migrates each to a ColdArchive target via SelectReplicas.
// Returns total replicas migrated this pass (logged for ops visibility).
// Idempotent: subsequent passes skip replicas already on ColdArchive (excluded from source set).
func (m *Manager) ageRotateOnePass(drainer PipelineDrainer, cfg types.AccountPolicyConfig) int {
	coldTargets := []*types.CloudAccount{}
	activeByProviderEmail := map[string]*types.CloudAccount{}
	for _, a := range m.ActiveAccounts() {
		activeByProviderEmail[a.Provider+":"+a.Email] = a
		if a.Role == types.RoleColdArchive {
			// Skip targets without quota headroom (HardCap reached) — would just fail upload + waste cycle
			if a.QuotaTotalBytes > 0 {
				hardCap := cfg.HardCapDefaultPct
				if a.HardCapPct != nil { hardCap = *a.HardCapPct }
				if a.UsedPercent() >= hardCap { continue }
			}
			coldTargets = append(coldTargets, a)
		}
	}
	if len(coldTargets) == 0 { return 0 } // no targets — silently skip (logged once at config check)
	files, err := drainer.ListFiles()
	if err != nil { log.Printf("age-rotation: ListFiles: %v", err); return 0 }
	cutoff := time.Now().Add(-time.Duration(cfg.AgeRotationDays) * 24 * time.Hour)
	var migrated int
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, max1(cfg.DrainMaxConcurrentMigrations)) // shared concurrency budget w/ drain
	for _, fm := range files {
		if fm.Modified.IsZero() || fm.Modified.After(cutoff) { continue } // not old enough or no timestamp
		for ri := range fm.Replicas {
			r := &fm.Replicas[ri]
			parts := strings.SplitN(r.Location, ":", 3)
			if len(parts) != 3 { continue } // malformed Location, skip silently
			src, ok := activeByProviderEmail[parts[0]+":"+parts[1]]
			if !ok || src.Role == types.RoleColdArchive { continue } // unknown source OR already cold
			wg.Add(1); sem <- struct{}{}
			fmCopy, riCopy, srcCopy := fm, ri, src
			go func() {
				fm, ri, src := fmCopy, riCopy, srcCopy
				defer wg.Done(); defer func() { <-sem }()
				if err := m.migrateOneReplica(fm, ri, src, coldTargets, drainer, cfg); err != nil {
					log.Printf("age-rotation: %s replica %d → ColdArchive: %v", fm.FileID, ri, err)
					return
				}
				mu.Lock(); migrated++; mu.Unlock()
			}()
		}
	}
	wg.Wait()
	return migrated
}
