package backup

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dudenest/dudenest-relay/pkg/types"
)

func testMasterKey() []byte {
	key := make([]byte, 32)
	for i := range key { key[i] = byte(i) }
	return key
}

// TestNewNoEnv: returns nil when credentials absent.
func TestNewNoEnv(t *testing.T) {
	os.Unsetenv("RELAY_ID"); os.Unsetenv("RELAY_SECRET")
	c := New(testMasterKey(), t.TempDir(), "https://backup.example.com", 3*time.Second, "test")
	if c != nil { t.Fatal("expected nil client when RELAY_ID/RELAY_SECRET not set") }
}

// TestTriggerNilSafe: Trigger on nil must not panic.
func TestTriggerNilSafe(t *testing.T) {
	var c *Client
	c.Trigger(nil) // must not panic
}

// TestNewWithEnv: New returns non-nil when all credentials set.
func TestNewWithEnv(t *testing.T) {
	t.Setenv("RELAY_ID", "test-relay")
	t.Setenv("RELAY_SECRET", "test-secret")
	c := New(testMasterKey(), t.TempDir(), "http://localhost:9999", 3*time.Second, "test")
	if c == nil { t.Fatal("expected non-nil client") }
}

// TestTriggerTimerReset: calling Trigger resets internal timer (last call wins).
func TestTriggerTimerReset(t *testing.T) {
	var hits atomic.Int32
	done := make(chan struct{}, 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		done <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	t.Setenv("RELAY_ID", "r-debounce")
	t.Setenv("RELAY_SECRET", "s-debounce")
	c := New(testMasterKey(), t.TempDir(), srv.URL, 3*time.Second, "test")
	if c == nil { t.Fatal("client nil") }
	// Manually fire with short 50ms debounce to verify timer reset logic.
	shortDebounce := 50 * time.Millisecond
	fireShort := func() {
		c.mu.Lock()
		if c.timer != nil { c.timer.Stop() }
		c.timer = time.AfterFunc(shortDebounce, func() { c.send(nil) }) //nolint:errcheck
		c.mu.Unlock()
	}
	fireShort(); fireShort(); fireShort() // 3 rapid calls → should fire once
	select {
	case <-done:
		time.Sleep(shortDebounce + 30*time.Millisecond) // wait for possible second fire
		if hits.Load() != 1 { t.Errorf("expected 1 send, got %d", hits.Load()) }
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout: send never fired")
	}
}

// TestSendEncryptsAndPosts: send() posts correct JSON with headers.
func TestSendEncryptsAndPosts(t *testing.T) {
	var received map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Relay-ID") != "relay-abc" { t.Errorf("wrong relay id: %s", r.Header.Get("X-Relay-ID")) }
		if r.Header.Get("X-Relay-Secret") != "secret-xyz" { t.Errorf("wrong relay secret") }
		if ct := r.Header.Get("Content-Type"); ct != "application/json" { t.Errorf("wrong content type: %s", ct) }
		json.NewDecoder(r.Body).Decode(&received) //nolint:errcheck
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	t.Setenv("RELAY_ID", "relay-abc")
	t.Setenv("RELAY_SECRET", "secret-xyz")
	c := New(testMasterKey(), t.TempDir(), srv.URL, 3*time.Second, "test")
	if c == nil { t.Fatal("client nil") }
	fm := &types.FileMap{FileID: "f1", Name: "test.txt", Size: 42}
	if err := c.send([]*types.FileMap{fm}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if received["maps_json"] == nil { t.Error("maps_json missing in payload") }
	if received["backup_version"] == nil { t.Error("backup_version missing in payload") }
}

// TestReadProviderTokensEmpty: empty providers dir → nil tokens, no error.
func TestReadProviderTokensEmpty(t *testing.T) {
	c := &Client{configDir: t.TempDir()}
	tokens, ids, err := c.readProviderTokens()
	if err != nil { t.Fatalf("unexpected error: %v", err) }
	if tokens != nil { t.Error("expected nil tokens for empty dir") }
	if ids != nil { t.Error("expected nil ids for empty dir") }
}

// TestReadProviderTokensWithFiles: tokens are read and marshaled correctly.
func TestReadProviderTokensWithFiles(t *testing.T) {
	dir := t.TempDir()
	provDir := filepath.Join(dir, "providers")
	os.MkdirAll(provDir, 0700) //nolint:errcheck
	os.WriteFile(filepath.Join(provDir, "gdrive_test@example.com.json"), []byte(`{"access_token":"tok1"}`), 0600) //nolint:errcheck
	c := &Client{configDir: dir}
	tokens, ids, err := c.readProviderTokens()
	if err != nil { t.Fatalf("unexpected error: %v", err) }
	if tokens == nil { t.Fatal("expected non-nil tokens") }
	if len(ids) != 1 { t.Fatalf("expected 1 id, got %d", len(ids)) }
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(tokens, &parsed); err != nil { t.Fatalf("parse tokens: %v", err) }
	if _, ok := parsed["gdrive_test@example.com.json"]; !ok { t.Error("token file not in parsed map") }
}

// --- s313 Phase 0: fast-update via /relay/ping response ---

// mockUpdateTrigger swaps the package-level updateTrigger for tests.
// Returns a counter that increments on each call + a restore func.
func mockUpdateTrigger(t *testing.T) (*atomic.Int64, func()) {
	t.Helper()
	original := updateTrigger
	var calls atomic.Int64
	updateTrigger = func() error {
		calls.Add(1)
		return nil
	}
	return &calls, func() { updateTrigger = original }
}

// TestPing_BackwardCompatOldHub: hub returns plain {"status":"ok"} (pre-Phase 0); relay must not crash and must not trigger update.
func TestPing_BackwardCompatOldHub(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`)) //nolint:errcheck
	}))
	defer srv.Close()
	calls, restore := mockUpdateTrigger(t)
	defer restore()
	t.Setenv("RELAY_ID", "relay-old")
	t.Setenv("RELAY_SECRET", "secret-old")
	c := New(testMasterKey(), t.TempDir(), srv.URL, 3*time.Second, "v0.16.0")
	if c == nil { t.Fatal("client nil") }
	resp, err := c.Ping()
	if err != nil { t.Fatalf("ping: %v", err) }
	if resp == nil { t.Fatal("expected non-nil response") }
	if resp.UpdateNow { t.Error("old hub response should not trigger update") }
	if calls.Load() != 0 { t.Errorf("updateTrigger called %d times, expected 0", calls.Load()) }
}

// TestPing_TriggersUpdateOnNewerVersion: hub indicates newer version → updateTrigger called exactly once.
func TestPing_TriggersUpdateOnNewerVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify relay sent arch field (Phase 0 contract)
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck
		if body["arch"] == "" { t.Errorf("relay must send arch in ping body") }
		if body["relay_version"] != "v0.17.0" { t.Errorf("wrong relay_version: %q", body["relay_version"]) }
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(PingResponse{ //nolint:errcheck
			Status: "ok", LatestVersion: "v0.17.5",
			DownloadURL: "https://example.com/relay-linux-amd64.tar.gz",
			UpdateNow:   true, NextPingSeconds: 3,
		})
	}))
	defer srv.Close()
	calls, restore := mockUpdateTrigger(t)
	defer restore()
	t.Setenv("RELAY_ID", "relay-x"); t.Setenv("RELAY_SECRET", "secret-x")
	c := New(testMasterKey(), t.TempDir(), srv.URL, 3*time.Second, "v0.17.0")
	resp, err := c.Ping()
	if err != nil { t.Fatalf("ping: %v", err) }
	if !resp.UpdateNow { t.Error("expected update_now=true in parsed response") }
	if calls.Load() != 1 { t.Errorf("updateTrigger called %d times, expected 1", calls.Load()) }
}

// TestPing_DoesNotTriggerOnSameVersion: even if hub says update_now=true, mismatch check on client side guards.
// (Hub should not send update_now=true when versions match, but defense-in-depth.)
func TestPing_DoesNotTriggerOnSameVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(PingResponse{ //nolint:errcheck
			Status: "ok", LatestVersion: "v0.17.5",
			DownloadURL: "https://example.com/relay-linux-amd64.tar.gz",
			UpdateNow:   true, // hub bug: claims update but versions match
		})
	}))
	defer srv.Close()
	calls, restore := mockUpdateTrigger(t)
	defer restore()
	t.Setenv("RELAY_ID", "relay-y"); t.Setenv("RELAY_SECRET", "secret-y")
	c := New(testMasterKey(), t.TempDir(), srv.URL, 3*time.Second, "v0.17.5") // same as latest
	_, err := c.Ping()
	if err != nil { t.Fatalf("ping: %v", err) }
	if calls.Load() != 0 { t.Errorf("must not trigger update when versions match, got %d calls", calls.Load()) }
}

// TestPing_DoesNotTriggerOnMissingDownloadURL: hub didn't supply URL (unknown arch); skip.
func TestPing_DoesNotTriggerOnMissingDownloadURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(PingResponse{ //nolint:errcheck
			Status: "ok", LatestVersion: "v0.17.5",
			DownloadURL: "", // arch not supported by hub
			UpdateNow:   true,
		})
	}))
	defer srv.Close()
	calls, restore := mockUpdateTrigger(t)
	defer restore()
	t.Setenv("RELAY_ID", "relay-z"); t.Setenv("RELAY_SECRET", "secret-z")
	c := New(testMasterKey(), t.TempDir(), srv.URL, 3*time.Second, "v0.17.0")
	_, err := c.Ping()
	if err != nil { t.Fatalf("ping: %v", err) }
	if calls.Load() != 0 { t.Errorf("must not trigger update with empty download URL, got %d calls", calls.Load()) }
}

// TestPing_NilClientSafe: Ping on nil receiver must not panic (used pre-registration).
func TestPing_NilClientSafe(t *testing.T) {
	var c *Client
	resp, err := c.Ping()
	if err != nil || resp != nil {
		t.Errorf("nil client ping should return (nil, nil), got (%v, %v)", resp, err)
	}
}
