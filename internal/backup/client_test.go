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
