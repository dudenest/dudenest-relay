package account

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dudenest/dudenest-relay/pkg/types"
)

// ----- SelectReplicas (the pure algorithm) — α-1..α-8 from CLOUD-ACCOUNT-POLICY-PLAN §10 -----

// α-1: zero accounts → ErrNoEligibleAccounts. No selector should ever silently fail upload.
func TestSelectReplicas_NoAccounts(t *testing.T) {
	_, err := SelectReplicas(FileMeta{Size: 1024}, nil, types.DefaultPolicy())
	if err != ErrNoEligibleAccounts {
		t.Errorf("expected ErrNoEligibleAccounts, got %v", err)
	}
}

// α-2: single account + RF=2 + AllowSingleReplicaWithWarning=true → 1 chosen, no error.
// This is the "user just added first account" path — they should be able to upload,
// just with a warning visible in UI.
func TestSelectReplicas_SingleAccountWithWarningAllowed(t *testing.T) {
	cfg := types.DefaultPolicy() // AllowSingleReplicaWithWarning=true by default
	a := mkAccount(1, "gdrive", "a@x.com", types.RolePrimaryWrite, 0)
	chosen, err := SelectReplicas(FileMeta{Size: 1024, ContentType: "photos"}, []*types.CloudAccount{a}, cfg)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(chosen) != 1 {
		t.Errorf("expected 1 replica, got %d", len(chosen))
	}
}

// α-3: single account + RF=2 + AllowSingleReplicaWithWarning=false → ErrInsufficientReplicas.
// Strict mode for compliance / enterprise where partial redundancy is unacceptable.
func TestSelectReplicas_SingleAccountStrictFailsClosed(t *testing.T) {
	cfg := types.DefaultPolicy()
	cfg.AllowSingleReplicaWithWarning = false
	a := mkAccount(1, "gdrive", "a@x.com", types.RolePrimaryWrite, 0)
	_, err := SelectReplicas(FileMeta{Size: 1024}, []*types.CloudAccount{a}, cfg)
	if err != ErrInsufficientReplicas {
		t.Errorf("expected ErrInsufficientReplicas, got %v", err)
	}
}

// α-4: three accounts, RF=2 → first two by Priority chosen.
// Ensures the algorithm does not silently waste a 3rd account.
func TestSelectReplicas_PicksFirstTwoByPriority(t *testing.T) {
	cfg := types.DefaultPolicy() // RF=2
	accs := []*types.CloudAccount{
		mkAccount(1, "gdrive", "a@x.com", types.RolePrimaryWrite, 0),
		mkAccount(2, "gdrive", "b@x.com", types.RoleReplicaWrite, 1),
		mkAccount(3, "gdrive", "c@x.com", types.RoleReplicaWrite, 2),
	}
	chosen, err := SelectReplicas(FileMeta{Size: 1024}, accs, cfg)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(chosen) != 2 {
		t.Fatalf("expected 2 replicas, got %d", len(chosen))
	}
	if chosen[0].ID != 1 || chosen[1].ID != 2 {
		t.Errorf("expected ID 1 then 2 (by Priority), got %d, %d", chosen[0].ID, chosen[1].ID)
	}
}

// α-5: tie on Priority → tie-break by FreeBytes DESC.
// Without this the algorithm could repeatedly hammer the fullest account.
func TestSelectReplicas_TieBreakByFreeSpace(t *testing.T) {
	cfg := types.DefaultPolicy()
	cfg.ReplicationFactor = 1
	full := mkAccount(1, "gdrive", "full@x.com", types.RolePrimaryWrite, 1)
	full.QuotaTotalBytes = 100
	full.QuotaUsedBytes = 80 // 20 free
	empty := mkAccount(2, "gdrive", "empty@x.com", types.RolePrimaryWrite, 1)
	empty.QuotaTotalBytes = 100
	empty.QuotaUsedBytes = 10 // 90 free
	chosen, err := SelectReplicas(FileMeta{Size: 1}, []*types.CloudAccount{full, empty}, cfg)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if chosen[0].ID != 2 {
		t.Errorf("expected ID 2 (more free space), got %d", chosen[0].ID)
	}
}

// α-6: account over HardCap → excluded entirely.
// Critical safety — a write to an over-cap account just fails round-trip and wastes the user's time.
func TestSelectReplicas_OverHardCapExcluded(t *testing.T) {
	cfg := types.DefaultPolicy()
	cfg.HardCapDefaultPct = 95
	cfg.ReplicationFactor = 1
	a := mkAccount(1, "gdrive", "full@x.com", types.RolePrimaryWrite, 0)
	a.QuotaTotalBytes = 100
	a.QuotaUsedBytes = 96 // 96% used > 95%
	_, err := SelectReplicas(FileMeta{Size: 1}, []*types.CloudAccount{a}, cfg)
	if err != ErrNoEligibleAccounts {
		t.Errorf("expected ErrNoEligibleAccounts (all over cap), got %v", err)
	}
}

// α-7: diversity required → cannot pick two replicas on the same Provider type.
// Validates the F4 multi-region foundation also works for the Provider dimension.
func TestSelectReplicas_DiversityRequired(t *testing.T) {
	cfg := types.DefaultPolicy()
	cfg.DiversityRequired = true
	cfg.ReplicationFactor = 2
	accs := []*types.CloudAccount{
		mkAccount(1, "gdrive", "a@x.com", types.RolePrimaryWrite, 0),
		mkAccount(2, "gdrive", "b@x.com", types.RoleReplicaWrite, 1), // same provider — skipped under diversity
		mkAccount(3, "mega", "c@m.com", types.RoleReplicaWrite, 2),
	}
	chosen, err := SelectReplicas(FileMeta{Size: 1024}, accs, cfg)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(chosen) != 2 {
		t.Fatalf("expected 2 replicas (one per provider type), got %d", len(chosen))
	}
	if chosen[0].Provider == chosen[1].Provider {
		t.Errorf("diversity violated: %s == %s", chosen[0].Provider, chosen[1].Provider)
	}
}

// α-8: AcceptsContentTypes per-account override → photo-only account is skipped for "files".
func TestSelectReplicas_ContentTypeFilter(t *testing.T) {
	cfg := types.DefaultPolicy()
	cfg.ReplicationFactor = 1
	photosOnly := mkAccount(1, "mega", "ph@x.com", types.RolePrimaryWrite, 0)
	allowed := []string{"photos"}
	photosOnly.AcceptsContentTypes = &allowed
	general := mkAccount(2, "gdrive", "g@x.com", types.RolePrimaryWrite, 1)

	// Upload "files" — must skip photos-only account.
	chosen, err := SelectReplicas(FileMeta{Size: 1024, ContentType: "files"}, []*types.CloudAccount{photosOnly, general}, cfg)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if chosen[0].ID != 2 {
		t.Errorf("expected ID 2 (general), got %d", chosen[0].ID)
	}
}

// ----- Manager state ops -----

// AddAccount: first account gets PrimaryWrite + Priority 0; second+ ReplicaWrite + dense Priority.
// This is the path the install/setup wizard hits when the user adds their first cloud.
func TestAddAccount_FirstIsPrimarySubsequentIsReplica(t *testing.T) {
	m, _ := mkManager(t)
	a1, err := m.AddAccount("gdrive", "first@x.com")
	if err != nil {
		t.Fatalf("add 1: %v", err)
	}
	if a1.Role != types.RolePrimaryWrite || a1.Priority != 0 || a1.ID != 1 {
		t.Errorf("first account wrong: role=%s pri=%d id=%d", a1.Role, a1.Priority, a1.ID)
	}
	a2, err := m.AddAccount("gdrive", "second@x.com")
	if err != nil {
		t.Fatalf("add 2: %v", err)
	}
	if a2.Role != types.RoleReplicaWrite || a2.Priority != 1 || a2.ID != 2 {
		t.Errorf("second account wrong: role=%s pri=%d id=%d", a2.Role, a2.Priority, a2.ID)
	}
}

// IDs never reused: after Removed account, NextID still continues monotonic.
// Critical for audit + log integrity.
func TestNextID_MonotonicAcrossRemoved(t *testing.T) {
	m, _ := mkManager(t)
	a1, _ := m.AddAccount("gdrive", "a@x.com")
	a2, _ := m.AddAccount("gdrive", "b@x.com")
	_ = a2
	a1.Status = types.StatusRemoved // simulate Drain completed
	if got := m.NextID(); got != 3 {
		t.Errorf("expected NextID=3 (max=2, +1, ignoring Removed), got %d", got)
	}
}

// Reorder: dense priorities after a manual UI drag-drop.
func TestReorder_Dense(t *testing.T) {
	m, _ := mkManager(t)
	a1, _ := m.AddAccount("gdrive", "a@x.com")
	a2, _ := m.AddAccount("gdrive", "b@x.com")
	a3, _ := m.AddAccount("gdrive", "c@x.com")
	// User dragged: [a3, a1, a2]
	if err := m.Reorder([]int64{a3.ID, a1.ID, a2.ID}); err != nil {
		t.Fatalf("reorder: %v", err)
	}
	accs := m.Accounts()
	byID := map[int64]int{}
	for _, a := range accs {
		byID[a.ID] = a.Priority
	}
	if byID[a3.ID] != 0 || byID[a1.ID] != 1 || byID[a2.ID] != 2 {
		t.Errorf("priorities after reorder wrong: a3=%d a1=%d a2=%d", byID[a3.ID], byID[a1.ID], byID[a2.ID])
	}
}

// DisplayID padding: <1000 → 3 digits zero-padded; >=1000 → no padding (still readable).
func TestDisplayID_PaddingRules(t *testing.T) {
	cases := []struct {
		id   int64
		want string
	}{
		{1, "ID001"},
		{42, "ID042"},
		{999, "ID999"},
		{1000, "ID1000"},
		{12345, "ID12345"},
	}
	for _, tc := range cases {
		a := &types.CloudAccount{ID: tc.id}
		if got := a.DisplayID(); got != tc.want {
			t.Errorf("DisplayID(%d) = %q, want %q", tc.id, got, tc.want)
		}
	}
}

// PathFor: default scheme is year_month per user decision §11 #5. Unknown scheme also
// falls back to year_month to be safe.
func TestPathFor_DefaultsToYearMonth(t *testing.T) {
	cfg := types.DefaultPolicy()
	when := time.Date(2026, 5, 22, 14, 30, 0, 0, time.UTC)
	got := cfg.PathFor("photos", "IMG_001.jpg", when)
	want := "dudenest/photos/2026/05/IMG_001.jpg"
	if got != want {
		t.Errorf("PathFor default: got %q, want %q", got, want)
	}
	cfg.PathScheme = "year_month_day"
	got = cfg.PathFor("photos", "IMG_001.jpg", when)
	want = "dudenest/photos/2026/05/22/IMG_001.jpg"
	if got != want {
		t.Errorf("PathFor day scheme: got %q, want %q", got, want)
	}
}

// Round-trip serialization — what gets written to accounts.json must come back identical.
func TestAccountsRoundTrip(t *testing.T) {
	in := []*types.CloudAccount{mkAccount(1, "gdrive", "a@x.com", types.RolePrimaryWrite, 0)}
	b, err := types.MarshalAccounts(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out, err := types.UnmarshalAccounts(b)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out) != 1 || out[0].ID != 1 || out[0].Role != types.RolePrimaryWrite {
		t.Errorf("round-trip lost data: %+v", out[0])
	}
}

// Policy round-trip — same guarantee, plus we ensure DefaultPolicy is self-consistent JSON.
func TestPolicyRoundTrip(t *testing.T) {
	cfg := types.DefaultPolicy()
	b, err := types.MarshalPolicy(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := types.UnmarshalPolicy(b)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.ReplicationFactor != cfg.ReplicationFactor || got.PathScheme != cfg.PathScheme {
		t.Errorf("round-trip lost fields: got %+v", got)
	}
}

// On-disk persistence: write account, re-open Manager, see same account.
// This is the path that proves no data is lost across relay restart.
func TestManagerPersistence(t *testing.T) {
	m, dir := mkManager(t)
	if _, err := m.AddAccount("gdrive", "persist@x.com"); err != nil {
		t.Fatalf("add: %v", err)
	}
	// New Manager instance pointed at same dir — should load from disk.
	m2, err := New(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	accs := m2.Accounts()
	if len(accs) != 1 || accs[0].Email != "persist@x.com" {
		t.Errorf("persistence failed; got %+v", accs)
	}
	// Verify the file is actually JSON we can independently parse (no hidden encoding).
	data, _ := os.ReadFile(filepath.Join(dir, AccountsFileName))
	var raw []map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("file not valid JSON: %v", err)
	}
	if raw[0]["email"] != "persist@x.com" {
		t.Errorf("on-disk email wrong: %v", raw[0]["email"])
	}
}

// ----- Phase β: ReconcileRoles + promote/demote logic -----

// β-1: account hits SoftCap → auto-demote PrimaryWrite → ReplicaWrite, persisted.
func TestReconcileRoles_AutoDemoteOnSoftCap(t *testing.T) {
	m, _ := mkManager(t)
	cfg := m.Policy()
	cfg.SoftCapDefaultPct = 90
	cfg.AutoDemoteOnSoftCap = true
	_ = m.UpdatePolicy(cfg)
	a, _ := m.AddAccount("gdrive", "full@x.com")
	// Mutate quota in place — Manager.Accounts() returns copies so we need to use ReplaceAll.
	live := m.Accounts()
	live[0].QuotaTotalBytes = 100
	live[0].QuotaUsedBytes = 95 // 95% > 90% soft
	_ = m.ReplaceAll(live)
	d, p := m.ReconcileRoles()
	if d != 1 { t.Errorf("expected 1 demotion, got %d", d) }
	if p != 0 { t.Errorf("expected 0 promotions (no replicas available), got %d", p) }
	// Re-read
	for _, acc := range m.Accounts() {
		if acc.ID == a.ID && acc.Role != types.RoleReplicaWrite {
			t.Errorf("expected ID%d demoted to replica_write, got %s", acc.ID, acc.Role)
		}
	}
}

// β-2: when PrimaryWrite gets demoted and there's a ReplicaWrite candidate, promote it.
// Validates "no PrimaryWrite left → auto-promote" path in ReconcileRoles step 2.
func TestReconcileRoles_AutoPromoteWhenNoPrimary(t *testing.T) {
	m, _ := mkManager(t)
	cfg := m.Policy()
	cfg.AutoDemoteOnSoftCap = true
	cfg.AutoPromoteOnSpace = true
	cfg.SoftCapDefaultPct = 90
	cfg.PromoteStrategy = "by_priority"
	_ = m.UpdatePolicy(cfg)
	full, _ := m.AddAccount("gdrive", "full@x.com") // becomes PrimaryWrite
	other, _ := m.AddAccount("gdrive", "other@x.com") // becomes ReplicaWrite
	live := m.Accounts()
	for _, a := range live {
		if a.ID == full.ID { a.QuotaTotalBytes = 100; a.QuotaUsedBytes = 95 } // over soft cap
		if a.ID == other.ID { a.QuotaTotalBytes = 100; a.QuotaUsedBytes = 5 }
	}
	_ = m.ReplaceAll(live)
	d, p := m.ReconcileRoles()
	if d != 1 || p != 1 { t.Errorf("expected demoted=1 promoted=1, got demoted=%d promoted=%d", d, p) }
	for _, a := range m.Accounts() {
		if a.ID == other.ID && a.Role != types.RolePrimaryWrite {
			t.Errorf("expected ID%d promoted to primary_write, got %s", a.ID, a.Role)
		}
	}
}

// β-3: Pinned accounts are never auto-demoted, even when over soft cap.
// Validates the user-override escape hatch.
func TestReconcileRoles_RespectsPinned(t *testing.T) {
	m, _ := mkManager(t)
	cfg := m.Policy()
	cfg.AutoDemoteOnSoftCap = true
	cfg.SoftCapDefaultPct = 90
	_ = m.UpdatePolicy(cfg)
	a, _ := m.AddAccount("gdrive", "pinned@x.com")
	live := m.Accounts()
	live[0].QuotaTotalBytes = 100
	live[0].QuotaUsedBytes = 99 // very over cap
	live[0].Pinned = true
	_ = m.ReplaceAll(live)
	d, _ := m.ReconcileRoles()
	if d != 0 { t.Errorf("pinned account must not be demoted, got %d demotions", d) }
	for _, acc := range m.Accounts() {
		if acc.ID == a.ID && acc.Role != types.RolePrimaryWrite {
			t.Errorf("pinned account changed role from PrimaryWrite to %s", acc.Role)
		}
	}
}

// β-4: pickPromoteCandidate strategies pick distinct winners on the same input.
func TestPickPromoteCandidate_Strategies(t *testing.T) {
	// Three candidates: A oldest+high prio, B free%-leader, C lowest prio.
	a := &types.CloudAccount{ID: 1, Priority: 5, AddedAt: time.Unix(1700, 0), QuotaTotalBytes: 100, QuotaUsedBytes: 80}
	b := &types.CloudAccount{ID: 2, Priority: 3, AddedAt: time.Unix(2000, 0), QuotaTotalBytes: 100, QuotaUsedBytes: 10}
	c := &types.CloudAccount{ID: 3, Priority: 1, AddedAt: time.Unix(1900, 0), QuotaTotalBytes: 100, QuotaUsedBytes: 50}
	cands := []*types.CloudAccount{a, b, c}
	if pickPromoteCandidate(cands, "by_priority").ID != 3 { t.Errorf("by_priority: expected ID 3 (lowest prio)") }
	if pickPromoteCandidate(cands, "by_free_pct").ID != 2 { t.Errorf("by_free_pct: expected ID 2 (90%% free)") }
	if pickPromoteCandidate(cands, "by_age_oldest_first").ID != 1 { t.Errorf("by_age: expected ID 1 (oldest)") }
	// round_robin is deterministic-per-minute; just assert it returns a valid candidate.
	got := pickPromoteCandidate(cands, "round_robin")
	if got != a && got != b && got != c { t.Errorf("round_robin returned unexpected account") }
	// Unknown strategy falls back to by_priority.
	if pickPromoteCandidate(cands, "unknown").ID != 3 { t.Errorf("unknown strategy: should fall back to by_priority") }
}

// β-5: ReplaceAll persists changes — re-load Manager and verify.
func TestReplaceAll_Persistence(t *testing.T) {
	m, dir := mkManager(t)
	_, _ = m.AddAccount("gdrive", "a@x.com")
	_, _ = m.AddAccount("gdrive", "b@x.com")
	live := m.Accounts()
	live[0].Priority = 99 // change something
	live[1].Pinned = true
	if err := m.ReplaceAll(live); err != nil { t.Fatalf("ReplaceAll: %v", err) }
	m2, err := New(dir)
	if err != nil { t.Fatalf("reload: %v", err) }
	accs := m2.Accounts()
	if len(accs) != 2 { t.Fatalf("expected 2 accounts after reload, got %d", len(accs)) }
	if accs[0].Priority != 99 || !accs[1].Pinned { t.Errorf("changes did not persist: %+v %+v", accs[0], accs[1]) }
}

// ----- Phase γ drain: minimal test (rest exercised end-to-end on production) -----

// γ-1: NewDrainState returns nil snapshot for unknown account.
// Defensive — UI should treat nil as "drain not in progress" and render normally.
func TestDrainState_NilSnapshotForUnknown(t *testing.T) {
	st := NewDrainState()
	if st.Snapshot(999) != nil { t.Error("expected nil snapshot for unknown id, got non-nil") }
}

// γ-2: drainOnePass with no Drain accounts is a no-op and returns 0.
// Validates the early-exit + ensures we don't accidentally drain ReplicaWrite/PrimaryWrite accounts.
func TestDrain_NoOpWhenNoDrainAccounts(t *testing.T) {
	m, _ := mkManager(t)
	_, _ = m.AddAccount("gdrive", "a@x.com")
	_, _ = m.AddAccount("gdrive", "b@x.com")
	st := NewDrainState()
	n := m.drainOnePass(&noopDrainer{}, st)
	if n != 0 { t.Errorf("expected 0 (no drain accounts), got %d", n) }
}

// γ-3: when a Drain account exists but no other accounts are available, drainOneAccount
// logs warning + leaves account untouched (NOT marked Removed). This is the "user removed
// their only account" edge case — safe behavior is to refuse rather than data-loss.
func TestDrain_RefusesWhenNoOtherAccounts(t *testing.T) {
	m, _ := mkManager(t)
	only, _ := m.AddAccount("gdrive", "only@x.com")
	// Manually transition to Drain (in production happens via DELETE /admin/accounts/{id})
	live := m.Accounts()
	for _, a := range live { if a.ID == only.ID { a.Role = types.RoleDrain } }
	_ = m.ReplaceAll(live)
	st := NewDrainState()
	n := m.drainOnePass(&noopDrainer{}, st)
	if n != 1 { t.Errorf("expected 1 (one account touched), got %d", n) }
	// Account must still be present, Status not Removed.
	for _, a := range m.Accounts() {
		if a.ID == only.ID {
			if a.Status == types.StatusRemoved { t.Error("account incorrectly marked Removed despite no migration target") }
		}
	}
	prog := st.Snapshot(only.ID)
	if prog == nil || prog.LastErr == "" { t.Error("expected LastErr to record 'no migration target'") }
}

// γ-4: DrainState.Snapshot returns a defensive copy — mutating the returned struct doesn't leak back.
// This guards against the /admin/accounts/{id}/drain-progress endpoint accidentally exposing internal state.
func TestDrainState_SnapshotIsCopy(t *testing.T) {
	st := NewDrainState()
	// Force a progress entry via direct map insert (bypasses needing full drainOneAccount setup).
	st.mu.Lock()
	st.byID[42] = &DrainProgress{ShardsToMigrate: 100, ShardsMigrated: 30}
	st.mu.Unlock()
	snap := st.Snapshot(42)
	if snap == nil { t.Fatal("expected snapshot") }
	if snap.ShardsToMigrate != 100 || snap.ShardsMigrated != 30 { t.Errorf("snapshot mismatch: %+v", snap) }
	snap.ShardsMigrated = 999 // mutate copy
	again := st.Snapshot(42)
	if again.ShardsMigrated != 30 { t.Errorf("internal state leaked: got %d, want 30", again.ShardsMigrated) }
}

// noopDrainer is a stub PipelineDrainer for unit tests — no files, no providers.
type noopDrainer struct{}

func (*noopDrainer) ListFiles() ([]*types.FileMap, error)              { return nil, nil }
func (*noopDrainer) GetFileMap(string) (*types.FileMap, error)         { return nil, nil }
func (*noopDrainer) SaveFileMap(*types.FileMap) error                  { return nil }
func (*noopDrainer) CloudByID(string) types.CloudProvider              { return nil }

// ----- test helpers -----

func mkAccount(id int64, provider, email string, role types.Role, priority int) *types.CloudAccount {
	return &types.CloudAccount{
		ID: id, Provider: provider, Email: email,
		Role: role, Priority: priority,
		Status: types.StatusActive, AddedAt: time.Unix(1700000000+id, 0).UTC(),
	}
}

func mkManager(t *testing.T) (*Manager, string) {
	t.Helper()
	dir := t.TempDir()
	m, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m, dir
}
