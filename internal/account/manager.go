// Package account holds the in-memory + on-disk state of the user's cloud accounts
// and the pure selection algorithm used by the upload pipeline (Phase α of
// CLOUD-ACCOUNT-POLICY-PLAN). All values come from accounts.json + account_policy.json;
// nothing is hardcoded — the only "defaults" are seed values in types.DefaultPolicy().
package account

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/dudenest/dudenest-relay/pkg/types"
)

// File names inside configDir. Documented here so the rest of the code can ref these constants
// instead of stringly-typed paths.
const (
	AccountsFileName = "accounts.json"
	PolicyFileName   = "account_policy.json"
)

// Manager is the relay-side owner of CloudAccount state. Created once at startup,
// passed by reference into the pipeline. All exported methods are goroutine-safe.
type Manager struct {
	configDir string
	mu        sync.RWMutex
	accounts  []*types.CloudAccount
	policy    types.AccountPolicyConfig
}

// New loads accounts.json + account_policy.json from configDir. Missing files are silently
// initialized to empty/default — that's the path for fresh installs and for first run on
// existing relays that pre-date Phase α.
func New(configDir string) (*Manager, error) {
	m := &Manager{configDir: configDir}
	if err := m.loadPolicy(); err != nil {
		return nil, fmt.Errorf("load policy: %w", err)
	}
	if err := m.loadAccounts(); err != nil {
		return nil, fmt.Errorf("load accounts: %w", err)
	}
	return m, nil
}

func (m *Manager) loadPolicy() error {
	path := filepath.Join(m.configDir, PolicyFileName)
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		m.policy = types.DefaultPolicy()
		return nil
	}
	if err != nil {
		return err
	}
	p, err := types.UnmarshalPolicy(data)
	if err != nil {
		return fmt.Errorf("decode policy: %w", err)
	}
	m.policy = p
	return nil
}

func (m *Manager) loadAccounts() error {
	path := filepath.Join(m.configDir, AccountsFileName)
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		m.accounts = nil
		return nil
	}
	if err != nil {
		return err
	}
	a, err := types.UnmarshalAccounts(data)
	if err != nil {
		return fmt.Errorf("decode accounts: %w", err)
	}
	m.accounts = a
	return nil
}

// SaveAccounts persists the current account list. Atomically replaces accounts.json via tmp+rename.
func (m *Manager) SaveAccounts() error {
	m.mu.RLock()
	data, err := json.MarshalIndent(m.accounts, "", "  ")
	m.mu.RUnlock()
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(m.configDir, AccountsFileName), data)
}

// SavePolicy persists current policy. Same atomic-replace pattern.
func (m *Manager) SavePolicy() error {
	m.mu.RLock()
	data, err := json.MarshalIndent(m.policy, "", "  ")
	m.mu.RUnlock()
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(m.configDir, PolicyFileName), data)
}

// Policy returns a copy (safe to read concurrently). Edit via UpdatePolicy.
func (m *Manager) Policy() types.AccountPolicyConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.policy
}

// UpdatePolicy replaces the policy + persists. Returns error from disk write.
func (m *Manager) UpdatePolicy(p types.AccountPolicyConfig) error {
	m.mu.Lock()
	m.policy = p
	m.mu.Unlock()
	return m.SavePolicy()
}

// Accounts returns a snapshot copy of all accounts (active + removed). Caller must not mutate.
// For mutations use the typed methods (AddAccount, Reorder, SetRole, …).
func (m *Manager) Accounts() []*types.CloudAccount {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*types.CloudAccount, len(m.accounts))
	for i, a := range m.accounts {
		copy := *a
		out[i] = &copy
	}
	return out
}

// ActiveAccounts returns only accounts with Status != Removed (i.e. those the algorithm
// considers for selection + that the UI shows as live entries).
func (m *Manager) ActiveAccounts() []*types.CloudAccount {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*types.CloudAccount
	for _, a := range m.accounts {
		if a.Status != types.StatusRemoved {
			copy := *a
			out = append(out, &copy)
		}
	}
	return out
}

// NextID returns the next monotonic ID. IDs are NEVER reused, including after Drain+Remove,
// so we scan all records (including Removed) for the max.
func (m *Manager) NextID() int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var max int64
	for _, a := range m.accounts {
		if a.ID > max {
			max = a.ID
		}
	}
	return max + 1
}

// AddAccount inserts a fresh CloudAccount with auto-assigned ID + Role + Priority based on the
// rules in CLOUD-ACCOUNT-POLICY-PLAN §11 #4 (account #1 → PrimaryWrite; #2+ → ReplicaWrite by
// default, can be promoted later). Returns the new account (with assigned ID etc.) for UI display.
//
// The caller passes a partial record (Provider + Email + RemovedAt are caller-controlled).
// Status is forced to Active, AddedAt set to now, Priority set to current max+1.
func (m *Manager) AddAccount(provider, email string) (*types.CloudAccount, error) {
	if provider == "" || email == "" {
		return nil, errors.New("provider and email required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	// Detect re-add of a previously-Removed account with same (provider, email).
	// Per-policy decision (OnReAddSameEmail) — for Phase α we just return the existing record
	// so the caller (UI) can prompt the user. Phase β implements the auto-restore logic.
	for _, a := range m.accounts {
		if a.Provider == provider && a.Email == email {
			return a, errReAddDetected
		}
	}

	id := int64(1)
	for _, a := range m.accounts {
		if a.ID >= id {
			id = a.ID + 1
		}
	}
	maxPri := -1
	activeCount := 0
	for _, a := range m.accounts {
		if a.Status == types.StatusRemoved {
			continue
		}
		activeCount++
		if a.Priority > maxPri {
			maxPri = a.Priority
		}
	}

	// First active account → PrimaryWrite; subsequent → ReplicaWrite (user can promote later).
	// Decision from user 2026-05-22 §11 #4: default for accounts #5+ is ReplicaWrite, not ColdArchive.
	role := types.RoleReplicaWrite
	if activeCount == 0 {
		role = types.RolePrimaryWrite
	}

	a := &types.CloudAccount{
		ID:       id,
		Provider: provider,
		Email:    email,
		AddedAt:  time.Now().UTC(),
		Role:     role,
		Priority: maxPri + 1,
		Status:   types.StatusActive,
	}
	m.accounts = append(m.accounts, a)
	if err := m.savelocked(); err != nil {
		return nil, err
	}
	return a, nil
}

// ErrReAddDetected returned by AddAccount when (provider, email) matches an existing record
// (even Status=Removed). UI should prompt user per cfg.OnReAddSameEmail.
var errReAddDetected = errors.New("account with this provider+email already exists (possibly Removed); see policy.OnReAddSameEmail")

// IsReAddError tells callers if AddAccount failed because of re-add semantics.
func IsReAddError(err error) bool { return errors.Is(err, errReAddDetected) }

// Reorder applies a new priority sequence given a list of IDs in desired order. IDs not in
// the slice keep their existing priority appended at the end (so a partial reorder doesn't
// silently drop accounts). Persisted on success.
func (m *Manager) Reorder(ids []int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	byID := map[int64]*types.CloudAccount{}
	for _, a := range m.accounts {
		byID[a.ID] = a
	}
	priority := 0
	seen := map[int64]bool{}
	for _, id := range ids {
		a, ok := byID[id]
		if !ok {
			return fmt.Errorf("unknown account id: %d", id)
		}
		a.Priority = priority
		priority++
		seen[id] = true
	}
	// Accounts not in the reorder list go to the back, preserving their relative order.
	for _, a := range m.accounts {
		if !seen[a.ID] && a.Status != types.StatusRemoved {
			a.Priority = priority
			priority++
		}
	}
	return m.savelocked()
}

// SetRole flips a single account's role + persists. Used by ReconcileRoles loop and by UI.
func (m *Manager) SetRole(id int64, role types.Role) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.accounts {
		if a.ID == id {
			a.Role = role
			return m.savelocked()
		}
	}
	return fmt.Errorf("account %d not found", id)
}

// savelocked persists accounts.json while holding m.mu.
func (m *Manager) savelocked() error {
	data, err := json.MarshalIndent(m.accounts, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(m.configDir, AccountsFileName), data)
}

// --- Selection algorithm — pure function, no I/O, fully unit-testable ---

// Errors returned by SelectReplicas. Callers (upload pipeline) translate to HTTP/log.
var (
	ErrNoEligibleAccounts   = errors.New("no eligible cloud accounts (all Removed/Quarantine, or none added)")
	ErrInsufficientReplicas = errors.New("fewer eligible accounts than replication_factor and AllowSingleReplicaWithWarning=false")
)

// FileMeta is the minimal information SelectReplicas needs about a pending upload.
// Kept separate from types.FileMap so the algorithm doesn't pull in the full FileMap surface.
type FileMeta struct {
	Size        int64
	ContentType string // "photos" | "files" — matches CloudAccount.AcceptsContentTypes
}

// SelectReplicas decides which CloudAccounts should receive a new upload. Implementation of
// the algorithm in CLOUD-ACCOUNT-POLICY-PLAN §4.1.
//
// Steps:
//  1. Filter to writable + active + quota-OK + size-OK + content-type-OK candidates.
//  2. Stable-sort by (Priority ASC, FreeBytes DESC, AddedAt ASC).
//  3. Take up to cfg.ReplicationFactor entries, honoring diversity constraints.
//  4. If fewer than RF chosen → return error (or partial + warning, depending on policy).
//
// Pure function — does not touch disk or network. The returned slice references the same
// account pointers passed in (no copy).
func SelectReplicas(file FileMeta, accounts []*types.CloudAccount, cfg types.AccountPolicyConfig) ([]*types.CloudAccount, error) {
	if len(accounts) == 0 {
		return nil, ErrNoEligibleAccounts
	}
	if cfg.ReplicationFactor < 1 {
		return nil, fmt.Errorf("invalid replication_factor=%d (must be >= 1)", cfg.ReplicationFactor)
	}

	// Step 1: filter
	candidates := make([]*types.CloudAccount, 0, len(accounts))
	for _, a := range accounts {
		if a == nil {
			continue
		}
		if a.Status != types.StatusActive {
			continue
		}
		if a.Role != types.RolePrimaryWrite && a.Role != types.RoleReplicaWrite {
			// Drain / ReadOnly / ColdArchive / Quarantine are not selectable for direct new upload.
			// ColdArchive receives content via age-rotation worker, not direct upload.
			continue
		}

		hardCap := derefInt(a.HardCapPct, cfg.HardCapDefaultPct)
		if a.UsedPercent() >= hardCap {
			continue // over hard cap — never write
		}

		maxFile := derefInt64(a.MaxFileSizeBytes, cfg.MaxFileSizeDefaultMB*1024*1024)
		if file.Size > maxFile {
			continue
		}

		if !a.AcceptsContentType(file.ContentType) {
			continue
		}

		candidates = append(candidates, a)
	}

	if len(candidates) == 0 {
		return nil, ErrNoEligibleAccounts
	}

	// Step 2: stable sort by Priority, then free-space DESC, then AddedAt ASC.
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Priority != candidates[j].Priority {
			return candidates[i].Priority < candidates[j].Priority
		}
		fi, fj := candidates[i].FreeBytes(), candidates[j].FreeBytes()
		if fi != fj {
			return fi > fj
		}
		return candidates[i].AddedAt.Before(candidates[j].AddedAt)
	})

	// Step 3: pick up to RF respecting diversity constraints.
	chosen := make([]*types.CloudAccount, 0, cfg.ReplicationFactor)
	seenProviders := map[string]bool{}
	seenRegions := map[string]bool{}
	for _, c := range candidates {
		if cfg.DiversityRequired && seenProviders[c.Provider] {
			continue
		}
		if cfg.DiversityRegionRequired && c.Region != "" && seenRegions[c.Region] {
			continue
		}
		chosen = append(chosen, c)
		seenProviders[c.Provider] = true
		if c.Region != "" {
			seenRegions[c.Region] = true
		}
		if len(chosen) >= cfg.ReplicationFactor {
			break
		}
	}

	// Step 4: insufficient-replicas decision.
	if len(chosen) < cfg.ReplicationFactor {
		if !cfg.AllowSingleReplicaWithWarning {
			return nil, ErrInsufficientReplicas
		}
		// else: caller logs a warning + UI shows a degraded-redundancy badge.
		// We still need at least one replica — if zero, we already returned ErrNoEligibleAccounts above.
	}

	return chosen, nil
}

// --- helpers ---

func derefInt(p *int, def int) int {
	if p == nil {
		return def
	}
	return *p
}

func derefInt64(p *int64, def int64) int64 {
	if p == nil {
		return def
	}
	return *p
}

// ReplaceAll swaps the in-memory account list with the provided slice and persists.
// Used by admin endpoints (PATCH /admin/accounts/{id}) when the handler builds up an edited
// view via Accounts() copies and needs to commit the result. Caller is responsible for not
// removing accounts (IDs are not reused — to soft-delete use SetRole(id, RoleDrain)).
func (m *Manager) ReplaceAll(accounts []*types.CloudAccount) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.accounts = accounts
	return m.savelocked()
}

// --- Phase β: quota polling + ReconcileRoles ---

// ProviderLookup resolves a CloudAccount to its CloudProvider. The relay supplies this at
// StartQuotaPollLoop time so the manager package doesn't need to import internal/cloudconn.
// Return nil if no provider is loaded for that account — the loop logs and skips.
type ProviderLookup func(a *types.CloudAccount) types.CloudProvider

// RefreshQuota calls provider.Quota() (if the provider implements QuotaReporter) and updates
// the account's QuotaUsedBytes/QuotaTotalBytes/QuotaCheckedAt. Returns nil for accounts whose
// provider doesn't report quota (caller treats nil as "skip silently"). Persists on success.
//
// Errors during the API call transition the account to StatusQuarantineUntil = now+5min
// (or the next ReconcileRoles tick clears the quarantine if a subsequent call succeeds).
func (m *Manager) RefreshQuota(id int64, lookup ProviderLookup) error {
	m.mu.Lock()
	var acc *types.CloudAccount
	for _, a := range m.accounts {
		if a.ID == id { acc = a; break }
	}
	m.mu.Unlock()
	if acc == nil { return fmt.Errorf("account %d not found", id) }
	prov := lookup(acc)
	if prov == nil { return nil } // provider not loaded (e.g. token revoked) — leave quota stale
	qr, ok := prov.(types.QuotaReporter)
	if !ok { return nil } // provider doesn't support Quota (e.g. local fs)
	used, total, err := qr.Quota()
	if err != nil {
		m.mu.Lock()
		acc.Status = types.StatusError
		acc.LastError = "quota refresh: " + err.Error()
		until := time.Now().Add(5 * time.Minute)
		acc.QuarantineUntil = &until
		_ = m.savelocked()
		m.mu.Unlock()
		return err
	}
	m.mu.Lock()
	acc.QuotaUsedBytes = used
	acc.QuotaTotalBytes = total
	acc.QuotaCheckedAt = time.Now().UTC()
	acc.LastSeenAt = acc.QuotaCheckedAt
	if acc.Status == types.StatusError { // clear previous error if we now succeed
		acc.Status = types.StatusActive
		acc.LastError = ""
		acc.QuarantineUntil = nil
	}
	err = m.savelocked()
	m.mu.Unlock()
	return err
}

// StartQuotaPollLoop spawns a background goroutine that refreshes quotas for all active accounts
// every cfg.QuotaCheckIntervalMin minutes. Pure dispatch — actual ReconcileRoles fires from a separate
// loop (see StartReconcileLoop) so quota refresh failures don't block role transitions.
// Safe to call once at startup. Goroutine exits when ctx cancels.
func (m *Manager) StartQuotaPollLoop(ctx context.Context, lookup ProviderLookup) {
	go func() {
		interval := time.Duration(m.Policy().QuotaCheckIntervalMin) * time.Minute
		if interval < time.Minute { interval = 30 * time.Minute }
		// First poll: small delay so the relay can fully initialize providers + answer first Flutter requests
		// before we start hitting Drive API.
		select {
		case <-ctx.Done(): return
		case <-time.After(30 * time.Second):
		}
		for {
			active := m.ActiveAccounts()
			for _, a := range active {
				if a.QuarantineUntil != nil && time.Now().Before(*a.QuarantineUntil) { continue }
				if err := m.RefreshQuota(a.ID, lookup); err != nil {
					// Already logged into account.LastError via RefreshQuota; here we just emit one line.
					fmt.Printf("quota poll: %s (id=%d): %v\n", a.Email, a.ID, err)
				}
			}
			select {
			case <-ctx.Done(): return
			case <-time.After(interval):
			}
		}
	}()
}

// ReconcileRoles enforces auto-demote/auto-promote rules based on current quota + policy.
// Pure-ish: reads from manager state, may mutate via SetRole — does NOT touch network.
// Designed for batched calls (e.g. from StartReconcileLoop) but safe to call ad-hoc.
//
// Algorithm:
//  1. For each account with Role=PrimaryWrite and !Pinned: if UsedPercent >= softCap → demote to ReplicaWrite.
//  2. Per cfg.PromoteStrategy, pick the best ReplicaWrite candidate and promote to PrimaryWrite
//     when there is no PrimaryWrite left or when the strategy says the current set should rotate.
//
// Returns counts of demotions + promotions for logging.
func (m *Manager) ReconcileRoles() (demoted, promoted int) {
	if !m.Policy().AutoDemoteOnSoftCap && !m.Policy().AutoPromoteOnSpace { return 0, 0 }
	cfg := m.Policy()
	active := m.ActiveAccounts()
	// Step 1: demote
	if cfg.AutoDemoteOnSoftCap {
		for _, a := range active {
			if a.Role != types.RolePrimaryWrite || a.Pinned { continue }
			softCap := cfg.SoftCapDefaultPct
			if a.SoftCapPct != nil { softCap = *a.SoftCapPct }
			if a.QuotaTotalBytes > 0 && a.UsedPercent() >= softCap {
				_ = m.SetRole(a.ID, types.RoleReplicaWrite)
				demoted++
			}
		}
	}
	// Step 2: promote if no PrimaryWrite candidates exist + we have a ReplicaWrite below SoftCap.
	// Critical: exclude candidates that are over SoftCap — otherwise Step 1 demote + Step 2 re-promote
	// loops every tick (any over-cap account demoted by Step 1 would be re-promoted by Step 2).
	if cfg.AutoPromoteOnSpace {
		active = m.ActiveAccounts() // re-load after demotions
		hasPrimary := false
		var candidates []*types.CloudAccount
		for _, a := range active {
			if a.Pinned { continue }
			if a.Role == types.RolePrimaryWrite { hasPrimary = true }
			if a.Role == types.RoleReplicaWrite {
				softCap := cfg.SoftCapDefaultPct
				if a.SoftCapPct != nil { softCap = *a.SoftCapPct }
				if a.QuotaTotalBytes > 0 && a.UsedPercent() >= softCap { continue } // skip over-cap (would loop)
				candidates = append(candidates, a)
			}
		}
		if !hasPrimary && len(candidates) > 0 {
			// Pick the candidate by configured strategy.
			best := pickPromoteCandidate(candidates, cfg.PromoteStrategy)
			if best != nil {
				_ = m.SetRole(best.ID, types.RolePrimaryWrite)
				promoted++
			}
		}
	}
	return demoted, promoted
}

// pickPromoteCandidate selects the best account to promote from ReplicaWrite to PrimaryWrite.
// Strategies (all configurable via cfg.PromoteStrategy):
//   - "by_priority"        : lowest Priority value (typical default)
//   - "by_free_pct"        : highest free percentage (load-balance fresh accounts)
//   - "by_age_oldest_first": oldest AddedAt (rotate stable accounts to the front)
//   - "round_robin"        : pick by ID modulo current minute (cheap pseudo-random)
//   - anything else        : fall back to by_priority
func pickPromoteCandidate(candidates []*types.CloudAccount, strategy string) *types.CloudAccount {
	if len(candidates) == 0 { return nil }
	switch strategy {
	case "by_free_pct":
		best := candidates[0]
		for _, c := range candidates[1:] { if 100-c.UsedPercent() > 100-best.UsedPercent() { best = c } }
		return best
	case "by_age_oldest_first":
		best := candidates[0]
		for _, c := range candidates[1:] { if c.AddedAt.Before(best.AddedAt) { best = c } }
		return best
	case "round_robin":
		min := int64(time.Now().Minute()) % int64(len(candidates))
		return candidates[min]
	case "by_priority":
		fallthrough
	default:
		best := candidates[0]
		for _, c := range candidates[1:] { if c.Priority < best.Priority { best = c } }
		return best
	}
}

// StartReconcileLoop runs ReconcileRoles every 1 minute. Cheap (no network) — fine to run often
// so promotions surface within a minute of a quota refresh detecting SoftCap.
func (m *Manager) StartReconcileLoop(ctx context.Context) {
	go func() {
		t := time.NewTicker(1 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done(): return
			case <-t.C:
				if d, p := m.ReconcileRoles(); d+p > 0 {
					fmt.Printf("reconcile: demoted=%d promoted=%d\n", d, p)
				}
			}
		}
	}()
}

// BootstrapFromProviders auto-creates CloudAccount entries for each existing CloudProvider
// when accounts.json is empty. Runs once on first relay start after Phase α deploy — for
// existing relays (poc1, poc2) with providers/*.json but no accounts.json yet.
//
// Each provider's ID is parsed as "<provider>:<email>" (e.g. "gdrive:darek@gmail.com").
// The first such provider in the slice → PrimaryWrite/Priority 0; rest → ReplicaWrite/Priority N.
// Returns the number of accounts created (0 if accounts.json was already populated).
//
// Per user decision 2026-05-22 §11 #3: existing relays may be reset; this bootstrap is the
// auto path — UI can then let the user drag-reorder priorities.
func (m *Manager) BootstrapFromProviders(providerIDs []string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.accounts) > 0 {
		return 0, nil // already bootstrapped
	}
	added := 0
	for i, pid := range providerIDs {
		// Split "provider:email" — defensive parse for malformed IDs.
		var provider, email string
		for j := 0; j < len(pid); j++ {
			if pid[j] == ':' {
				provider = pid[:j]
				email = pid[j+1:]
				break
			}
		}
		if provider == "" || email == "" {
			continue // skip malformed; not fatal — operator can re-add via UI
		}
		role := types.RoleReplicaWrite
		if added == 0 {
			role = types.RolePrimaryWrite
		}
		m.accounts = append(m.accounts, &types.CloudAccount{
			ID:       int64(i + 1),
			Provider: provider,
			Email:    email,
			AddedAt:  time.Now().UTC(),
			Role:     role,
			Priority: i,
			Status:   types.StatusActive,
		})
		added++
	}
	if added > 0 {
		if err := m.savelocked(); err != nil {
			return 0, err
		}
	}
	return added, nil
}

// atomicWrite writes data to a temp file in the same directory then renames into place —
// classic POSIX atomic-replace pattern, safe against crash mid-write.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op if the rename below succeeds
	if _, err := tmp.Write(data); err != nil {
		tmp.Close() //nolint:errcheck
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
