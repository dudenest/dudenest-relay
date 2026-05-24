package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dudenest/dudenest-relay/internal/account"
)

// TestRefreshQuotaAll_RoutingViaTrailingSlashMux pins the s320 hotfix: Go ServeMux dispatches
// /admin/accounts/refresh-quota to the trailing-slash entry ("/admin/accounts/") because the
// exact-match entry ("/admin/accounts") only matches the literal path. handleByID must early-return
// to handleRefreshQuotaAll BEFORE parseInt — otherwise user sees "id must be integer" 400.
func TestRefreshQuotaAll_RoutingViaTrailingSlashMux(t *testing.T) {
	mgr, err := account.New(t.TempDir())
	if err != nil { t.Fatalf("account.New: %v", err) }
	a := &accountAdmin{mgr: mgr} // provLookup nil → handler returns 503 (still proves routing worked)
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/accounts", a.handleListOrReorder)
	mux.HandleFunc("/admin/accounts/", a.handleByID)
	req := httptest.NewRequest(http.MethodPost, "/admin/accounts/refresh-quota", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code == http.StatusBadRequest && strings.Contains(rr.Body.String(), "id must be integer") {
		t.Fatalf("regression: refresh-quota path treated as account id (s320 hotfix broken). body=%s", rr.Body.String())
	}
	// Accept 503 (no provLookup wired in test) or 202 (would-be success) — both prove handler reached.
	if rr.Code != http.StatusServiceUnavailable && rr.Code != http.StatusAccepted {
		t.Fatalf("unexpected status=%d body=%s", rr.Code, rr.Body.String())
	}
}
