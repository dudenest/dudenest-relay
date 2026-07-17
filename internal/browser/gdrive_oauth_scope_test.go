// gdrive_oauth_scope_test.go pins the OAuth scope to drive.file (user decision 2026-07-15:
// "na tym etapie produkt nie potrzebuje widzieć innych plików których sam nie stworzył").
//
// Why this test exists — the scope silently flipped once and nobody noticed for ~6 weeks:
//   - s329 (2026-05-30, commit 2398007) changed drive.file → drive (full) to make whole-Drive
//     bootstrap work. It was a deliberate change, but it silently put the project on a RESTRICTED
//     scope: unverified + restricted = hard 100-user lifetime cap + "Google hasn't verified this
//     app" consent screen. Both block a store launch.
//   - The Google Cloud Console kept DECLARING drive.file while the code REQUESTED drive — so the
//     console actively misled anyone who checked there instead of reading the code.
//   - Empirical cost/benefit, measured on relay-poc 2026-07-15: 943 FileMaps indexed, 0 with
//     Strategy=Foreign. The restricted scope had bought exactly nothing.
//
// If a future change needs whole-Drive adoption, flipping these constants is NOT sufficient —
// it also requires a funded CASA assessment ($500-4500/yr, re-audited every 12 months). This test
// failing is the reminder to make that a decision rather than an accident.
package browser

import (
	"testing"

	"google.golang.org/api/drive/v3"
)

const wantScope = drive.DriveFileScope // https://www.googleapis.com/auth/drive.file — non-sensitive, no CASA

func TestBuildOAuthConfig_RequestsDriveFileScopeOnly(t *testing.T) {
	cs := &GDriveClientSecret{}
	cs.Installed.ClientID = "test-client-id"
	cs.Installed.ClientSecret = "test-client-secret"
	got := BuildOAuthConfig(cs, "http://localhost:1/callback")
	assertScope(t, "BuildOAuthConfig", got.Scopes)
}

func TestBuildWebOAuthConfig_RequestsDriveFileScopeOnly(t *testing.T) {
	got := BuildWebOAuthConfig("web-id", "web-secret", "https://example.test/callback")
	assertScope(t, "BuildWebOAuthConfig", got.Scopes)
}

// assertScope fails on both halves of the contract: drive.file must be present, and no restricted
// scope may sneak in alongside it (Google grants the union of requested scopes, so an extra entry
// re-triggers the 100-user cap even if drive.file is also listed).
func assertScope(t *testing.T, who string, scopes []string) {
	t.Helper()
	if len(scopes) != 1 {
		t.Fatalf("%s: want exactly 1 scope, got %d: %v", who, len(scopes), scopes)
	}
	if scopes[0] != wantScope {
		t.Errorf("%s: scope = %q, want %q — see #scope in gdrive_oauth.go before changing this", who, scopes[0], wantScope)
	}
	for _, s := range scopes {
		if s == drive.DriveScope || s == drive.DriveReadonlyScope || s == drive.DriveMetadataScope {
			t.Errorf("%s: RESTRICTED scope %q requested — needs CASA audit + 100-user cap applies", who, s)
		}
	}
}
