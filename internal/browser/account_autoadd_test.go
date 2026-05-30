// account_autoadd_test.go pins the s329 #B systemic fix: every successful SaveToken in
// browser/api.go (3 OAuth callsites — handleExchange / handleSession noVNC / handleAutoLogin)
// MUST also call autoAddAccount so the new provider lands in account.Manager state (accounts.json),
// not just the providers/<id>.json token store.
//
// Pre-fix empirical observation (production 2026-05-30 prcznsk@gmail.com):
//   - User OAuthed 4th account (stratumos re-auth) and 5th account (getechnics.com@gmail.com)
//   - Token files appeared in ~/.config/dudenest/providers/gdrive_*.json ✅
//   - /providers (legacy) returned the new accounts ✅
//   - /admin/accounts (Phase α/β) returned ONLY the bootstrapped 3 ❌
//   - Flutter UI: new tiles rendered without admin badge / Priority chip / popup menu / drag handle ❌
//   - Scan IncrementalPoll loop iterates mgr.Accounts() → never picked up new providers ❌
//   - User-visible symptom: "last scan 5 min ago · whole-Drive: 0 files" — bootstrap never triggered ❌
//
// This test verifies the helper handles all three lifecycle paths idempotently.
package browser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dudenest/dudenest-relay/internal/account"
	"github.com/dudenest/dudenest-relay/pkg/types"
)

func TestAutoAddAccount_FreshAccount_RegistersInManager(t *testing.T) {
	dir := t.TempDir()
	mgr, err := account.New(dir)
	if err != nil { t.Fatalf("account.New: %v", err) }
	srv := &Server{accountMgr: mgr}

	srv.autoAddAccount("gdrive", "newuser@gmail.com")

	got := mgr.Accounts()
	if len(got) != 1 {
		t.Fatalf("expected 1 account after auto-add, got %d", len(got))
	}
	a := got[0]
	if a.Provider != "gdrive" { t.Errorf("Provider = %q, want gdrive", a.Provider) }
	if a.Email != "newuser@gmail.com" { t.Errorf("Email = %q, want newuser@gmail.com", a.Email) }
	if a.Status != types.StatusActive { t.Errorf("Status = %q, want active", a.Status) }
	// First account → PrimaryWrite per Manager.AddAccount rule
	if a.Role != types.RolePrimaryWrite { t.Errorf("first account Role = %q, want primary_write", a.Role) }
	if a.Priority != 0 { t.Errorf("first account Priority = %d, want 0", a.Priority) }
}

func TestAutoAddAccount_SecondAccount_AssignsNextPriorityAndReplica(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := account.New(dir)
	srv := &Server{accountMgr: mgr}

	srv.autoAddAccount("gdrive", "first@gmail.com")
	srv.autoAddAccount("gdrive", "second@gmail.com")

	got := mgr.Accounts()
	if len(got) != 2 { t.Fatalf("expected 2 accounts, got %d", len(got)) }
	// Second account → ReplicaWrite, Priority 1
	var second *types.CloudAccount
	for _, a := range got { if a.Email == "second@gmail.com" { second = a } }
	if second == nil { t.Fatal("second@gmail.com not found in accounts") }
	if second.Role != types.RoleReplicaWrite { t.Errorf("2nd account Role = %q, want replica_write", second.Role) }
	if second.Priority != 1 { t.Errorf("2nd account Priority = %d, want 1", second.Priority) }
}

func TestAutoAddAccount_ReAuth_IsIdempotent(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := account.New(dir)
	srv := &Server{accountMgr: mgr}

	srv.autoAddAccount("gdrive", "user@gmail.com")
	srv.autoAddAccount("gdrive", "user@gmail.com") // re-auth same email — must not duplicate

	got := mgr.Accounts()
	if len(got) != 1 {
		t.Fatalf("re-auth should be idempotent (no duplicate). Got %d accounts: %+v", len(got), got)
	}
}

func TestAutoAddAccount_NilManager_IsNoop(t *testing.T) {
	srv := &Server{accountMgr: nil} // legacy mode (CLI auth, etc.)
	// Must not panic; must not error. Just silently skip.
	srv.autoAddAccount("gdrive", "user@gmail.com")
}

func TestAutoAddAccount_EmptyArgs_IsNoop(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := account.New(dir)
	srv := &Server{accountMgr: mgr}

	srv.autoAddAccount("", "user@gmail.com")
	srv.autoAddAccount("gdrive", "")

	if len(mgr.Accounts()) != 0 {
		t.Fatalf("empty args should not create accounts, got %d", len(mgr.Accounts()))
	}
}

// s329 #B regression pin: verify accounts.json is persisted to disk after auto-add (not just
// in-memory) — otherwise a relay restart would lose the auto-added account.
func TestAutoAddAccount_PersistsToAccountsJson(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := account.New(dir)
	srv := &Server{accountMgr: mgr}

	srv.autoAddAccount("gdrive", "persist-me@gmail.com")

	// Re-open the manager from disk — fresh instance should see the added account.
	mgr2, err := account.New(dir)
	if err != nil { t.Fatalf("re-open account.Manager: %v", err) }
	got := mgr2.Accounts()
	if len(got) != 1 {
		t.Fatalf("expected 1 persisted account after relay restart sim, got %d", len(got))
	}
	if got[0].Email != "persist-me@gmail.com" {
		t.Errorf("persisted Email = %q, want persist-me@gmail.com", got[0].Email)
	}

	// And accounts.json must exist on disk
	if _, statErr := readFile(filepath.Join(dir, account.AccountsFileName)); statErr != nil {
		t.Errorf("expected %s on disk after auto-add: %v", account.AccountsFileName, statErr)
	}
}

// readFile is a tiny assertion wrapper for the persistence test.
func readFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil { return "", err }
	if len(b) == 0 || !strings.Contains(string(b), "[") {
		return "", &simpleErr{msg: "accounts.json present but does not look like a JSON array"}
	}
	return string(b), nil
}

type simpleErr struct{ msg string }
func (e *simpleErr) Error() string { return e.msg }
