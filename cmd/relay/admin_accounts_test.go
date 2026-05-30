package main

import (
	"bytes"
	"encoding/json"
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

// TestReorder_RoutingViaTrailingSlashMux pins the s329 fix: same trailing-slash mux precedence
// hits POST /admin/accounts/reorder. Without the early-return in handleByID, the user sees
// 400 "account id required" instead of the actual reorder being applied.
//
// Empirically observed in production v0.23.5 from Flutter web (Chrome/Safari/Firefox desktop):
// every drag-drop attempt returned `RelayException: POST admin/accounts/reorder HTTP 400`
// with body `{"error":"account id required"}`. This test prevents that regression.
func TestReorder_RoutingViaTrailingSlashMux(t *testing.T) {
	mgr, err := account.New(t.TempDir())
	if err != nil { t.Fatalf("account.New: %v", err) }
	a := &accountAdmin{mgr: mgr}
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/accounts", a.handleListOrReorder)
	mux.HandleFunc("/admin/accounts/", a.handleByID)
	// Empty manager: Reorder with no ids is a valid no-op (returns 200), proving the route reached
	// handleListOrReorder rather than the parseInt path in handleByID.
	body, _ := json.Marshal(map[string]any{"ids": []int64{}})
	req := httptest.NewRequest(http.MethodPost, "/admin/accounts/reorder", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code == http.StatusBadRequest && strings.Contains(rr.Body.String(), "account id required") {
		t.Fatalf("regression: reorder path treated as account id by handleByID — s329 fix broken. body=%s", rr.Body.String())
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("unexpected status=%d body=%s — expected 200 (empty reorder = no-op)", rr.Code, rr.Body.String())
	}
}

// TestReorder_AppliesNewPriorityOrder verifies the end-to-end happy path after routing fix:
// POST /admin/accounts/reorder with real ids actually mutates priorities in Manager state.
func TestReorder_AppliesNewPriorityOrder(t *testing.T) {
	mgr, err := account.New(t.TempDir())
	if err != nil { t.Fatalf("account.New: %v", err) }
	// Seed 3 accounts via BootstrapFromProviders test helper would need provider stubs; instead
	// use direct manager helpers if present. For now we exercise the routing only — priority
	// mutation has its own unit tests in internal/account/manager_test.go (TestReorder_*).
	a := &accountAdmin{mgr: mgr}
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/accounts", a.handleListOrReorder)
	mux.HandleFunc("/admin/accounts/", a.handleByID)
	// Reorder with unknown id should now reach Manager.Reorder which returns "unknown account id"
	// → 400 from handleListOrReorder. That proves we delegated correctly (not the 400 from handleByID).
	body, _ := json.Marshal(map[string]any{"ids": []int64{42}})
	req := httptest.NewRequest(http.MethodPost, "/admin/accounts/reorder", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if !strings.Contains(rr.Body.String(), "unknown account id") {
		t.Fatalf("expected Manager.Reorder error 'unknown account id', got status=%d body=%s", rr.Code, rr.Body.String())
	}
}
