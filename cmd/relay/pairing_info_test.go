package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPairingInfoPublicSafeUnclaimedAndClaimed(t *testing.T) {
	dir := t.TempDir()
	rr := httptest.NewRecorder()
	makePairingInfoHandler(dir, "https://relay.example.test").ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/pairing/info", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("unclaimed status=%d body=%s", rr.Code, rr.Body.String())
	}
	var got map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("json: %v", err)
	}
	if got["status"] != "unclaimed" || got["pairing_mode"] != "local" || got["path"] != "/pairing/info" {
		t.Fatalf("unexpected unclaimed payload: %#v", got)
	}
	for _, forbidden := range []string{"relay_secret", "jwt_secret", "providers", "tokens", "backup", "files"} {
		if strings.Contains(rr.Body.String(), forbidden) {
			t.Fatalf("secret/metadata field leaked: %s in %s", forbidden, rr.Body.String())
		}
	}
	os.WriteFile(filepath.Join(dir, "relay_creds.json"), []byte(`{"relay_id":"rel-1","relay_secret":"secret-1","user_id":"owner-1"}`), 0o600) //nolint:errcheck
	rr = httptest.NewRecorder()
	makePairingInfoHandler(dir, "https://relay.example.test").ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/pairing/info", nil))
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("json claimed: %v", err)
	}
	if got["status"] != "claimed" || got["relay_id"] != "rel-1" {
		t.Fatalf("unexpected claimed payload: %#v", got)
	}
	if strings.Contains(rr.Body.String(), "secret-1") || strings.Contains(rr.Body.String(), "owner-1") {
		t.Fatalf("sensitive value leaked: %s", rr.Body.String())
	}
}

func TestPairingInfoRejectsNonGET(t *testing.T) {
	rr := httptest.NewRecorder()
	makePairingInfoHandler(t.TempDir(), "").ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/pairing/info", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d want 405", rr.Code)
	}
}
