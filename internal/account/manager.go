// Package account holds the in-memory + on-disk state of the user's cloud accounts
// and the pure selection algorithm used by the upload pipeline (Phase α of
// CLOUD-ACCOUNT-POLICY-PLAN). All values come from accounts.json + account_policy.json;
// nothing is hardcoded — the only "defaults" are seed values in types.DefaultPolicy().
package account

import (
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
