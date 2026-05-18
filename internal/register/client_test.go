// client_test.go — covers fleet-wide OAuth credential persistence in WriteBootstrapCreds.
// Critical guard: real Google OAuth client JSON ("installed" or "web" format — Dudenest uses "installed"
// today on relay-poc) must NEVER be overwritten by hub-delivered placeholder or by a re-register cycle.
// shouldReplaceOAuth() encodes that contract; these tests pin it.
package register

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestShouldReplaceOAuth_Placeholder verifies the v0.8.x placeholder marker is detected as replaceable.
func TestShouldReplaceOAuth_Placeholder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gdrive_client_secret.json")
	if err := os.WriteFile(path, []byte(`{"installed":{"client_id":"placeholder"}}`), 0o600); err != nil { t.Fatal(err) }
	if !shouldReplaceOAuth(path) { t.Error("v0.8.x placeholder should be replaceable") }
}

// TestShouldReplaceOAuth_ServiceAccount verifies the older `service_account` marker is detected.
func TestShouldReplaceOAuth_ServiceAccount(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gdrive_client_secret.json")
	if err := os.WriteFile(path, []byte(`{"type":"service_account","client_email":"x@y"}`), 0o600); err != nil { t.Fatal(err) }
	if !shouldReplaceOAuth(path) { t.Error("service_account placeholder should be replaceable") }
}

// TestShouldReplaceOAuth_Missing verifies a missing file is replaceable (fresh-VM bootstrap path).
func TestShouldReplaceOAuth_Missing(t *testing.T) {
	if !shouldReplaceOAuth(filepath.Join(t.TempDir(), "nope.json")) { t.Error("missing file should be replaceable") }
}

// TestShouldReplaceOAuth_RealCredentials is the most important guard: relay-poc's hand-configured
// real OAuth client JSON ("installed" format — what relay-poc actually carries today; or "web" — both supported
// by oauth2.ConfigFromJSON) must NEVER be replaced; overwriting it would break OAuth for every user paired
// with that relay until the operator manually restored the file.
func TestShouldReplaceOAuth_RealCredentials(t *testing.T) {
	dir := t.TempDir()
	pathWeb := filepath.Join(dir, "web.json")
	realWeb := `{"web":{"client_id":"932297984145-real.apps.googleusercontent.com","project_id":"dudenest-prod","client_secret":"GOCSPX-realsecret"}}`
	if err := os.WriteFile(pathWeb, []byte(realWeb), 0o600); err != nil { t.Fatal(err) }
	if shouldReplaceOAuth(pathWeb) { t.Error("real web-format OAuth JSON must be preserved") }
	pathInstalled := filepath.Join(dir, "installed.json")
	realInstalled := `{"installed":{"client_id":"932297984145-real.apps.googleusercontent.com","project_id":"dudenest-prod","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://oauth2.googleapis.com/token","client_secret":"GOCSPX-realsecret"}}`
	if err := os.WriteFile(pathInstalled, []byte(realInstalled), 0o600); err != nil { t.Fatal(err) }
	if shouldReplaceOAuth(pathInstalled) { t.Error("real installed-format OAuth JSON (what relay-poc carries) must be preserved") }
}

// TestWriteBootstrapCreds_WritesGDriveOnFirstBoot covers the fresh-VM path:
// configDir has no gdrive_client_secret.json yet → hub-delivered payload is persisted verbatim.
func TestWriteBootstrapCreds_WritesGDriveOnFirstBoot(t *testing.T) {
	dir := t.TempDir()
	hubOAuth := `{"web":{"client_id":"932297984145-hub.apps.googleusercontent.com","client_secret":"GOCSPX-hub"}}`
	p := &BootstrapPayload{RelayID: "r-1", RelaySecret: "s-1", JWTSecret: "jwt-1", RelayURL: "https://relay-1.example.com", GdriveClientSecret: hubOAuth}
	if _, err := WriteBootstrapCreds(dir, p); err != nil { t.Fatalf("WriteBootstrapCreds: %v", err) }
	got, err := os.ReadFile(filepath.Join(dir, "gdrive_client_secret.json"))
	if err != nil { t.Fatalf("read written file: %v", err) }
	if string(got) != hubOAuth { t.Errorf("written content mismatch:\nwant %q\ngot  %q", hubOAuth, string(got)) }
}

// TestWriteBootstrapCreds_PreservesRealCredentialsOnReRegister covers the legacy-relay path:
// relay-poc already has real OAuth client JSON ("installed" format today). A re-register cycle must NOT overwrite it,
// even if the hub returns different credentials (e.g. during rollout when the hub hasn't been seeded yet).
func TestWriteBootstrapCreds_PreservesRealCredentialsOnReRegister(t *testing.T) {
	dir := t.TempDir()
	realOnDisk := `{"web":{"client_id":"932297984145-real.apps.googleusercontent.com","client_secret":"GOCSPX-real"}}`
	path := filepath.Join(dir, "gdrive_client_secret.json")
	if err := os.WriteFile(path, []byte(realOnDisk), 0o600); err != nil { t.Fatal(err) }
	hubDifferent := `{"web":{"client_id":"DIFFERENT-from-hub","client_secret":"DIFFERENT"}}`
	p := &BootstrapPayload{RelayID: "r-2", RelaySecret: "s-2", GdriveClientSecret: hubDifferent}
	if _, err := WriteBootstrapCreds(dir, p); err != nil { t.Fatalf("WriteBootstrapCreds: %v", err) }
	got, err := os.ReadFile(path)
	if err != nil { t.Fatalf("read file: %v", err) }
	if string(got) != realOnDisk { t.Errorf("real on-disk credentials were overwritten — guard failed.\nwant %q\ngot  %q", realOnDisk, string(got)) }
}

// TestWriteBootstrapCreds_EmptyHubPayloadIsNoop covers the backward-compat path:
// when the backend is older and doesn't serve the new field, payload.GdriveClientSecret is "".
// Relay must NOT create or truncate the on-disk file in that case.
func TestWriteBootstrapCreds_EmptyHubPayloadIsNoop(t *testing.T) {
	dir := t.TempDir()
	p := &BootstrapPayload{RelayID: "r-3", RelaySecret: "s-3", GdriveClientSecret: ""}
	if _, err := WriteBootstrapCreds(dir, p); err != nil { t.Fatalf("WriteBootstrapCreds: %v", err) }
	if _, err := os.Stat(filepath.Join(dir, "gdrive_client_secret.json")); !os.IsNotExist(err) {
		t.Error("empty payload should not create gdrive_client_secret.json (backward compat with older backend)")
	}
}

// TestWriteBootstrapCreds_ReplacesPlaceholderEndToEnd: install.sh wrote the placeholder, first /relay/bootstrap
// arrives — the placeholder must be replaced with the hub's real credentials. This is the path that fires
// on every fresh-VM bootstrap once the fleet-wide auto-distribution is enabled in production.
func TestWriteBootstrapCreds_ReplacesPlaceholderEndToEnd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gdrive_client_secret.json")
	if err := os.WriteFile(path, []byte(`{"installed":{"client_id":"placeholder"}}`), 0o600); err != nil { t.Fatal(err) }
	hubReal := `{"web":{"client_id":"932297984145-real.apps.googleusercontent.com","client_secret":"GOCSPX-real"}}`
	p := &BootstrapPayload{RelayID: "r-4", RelaySecret: "s-4", GdriveClientSecret: hubReal}
	if _, err := WriteBootstrapCreds(dir, p); err != nil { t.Fatalf("WriteBootstrapCreds: %v", err) }
	got, err := os.ReadFile(path)
	if err != nil { t.Fatalf("read file: %v", err) }
	if string(got) != hubReal { t.Errorf("placeholder not replaced:\nwant %q\ngot  %q", hubReal, string(got)) }
	if strings.Contains(string(got), "placeholder") { t.Error("placeholder marker still present after WriteBootstrapCreds") }
}
