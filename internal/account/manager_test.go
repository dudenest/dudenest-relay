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
