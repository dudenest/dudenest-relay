package remotehand

import (
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// sidecarScript returns the path to rh_sidecar.py relative to this test file.
func sidecarScript() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "remotehand", "rh_sidecar.py")
}

// requireSidecar skips the test unless python3 + pynacl are available.
func requireSidecar(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	if err := exec.Command("python3", "-c", "import nacl").Run(); err != nil {
		t.Skip("pynacl not installed")
	}
}

// TestBridgeTransportE2E spawns the REAL Python sidecar in fake mode and verifies
// the full stdio round-trip: rh_hello + rh_prompt(email) out, rh_input in, and
// rh_state(success) out — proving the Go relay ↔ Python sidecar process boundary.
func TestBridgeTransportE2E(t *testing.T) {
	requireSidecar(t)
	lines := make(chan map[string]any, 64)
	send := func(b []byte) {
		var m map[string]any
		if json.Unmarshal(b, &m) == nil {
			lines <- m
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	b := New(sidecarScript(), ":0", "sess-test", send,
		"RH_FAKE=1", "RH_STATES=email,password,success")
	if err := b.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer b.Close()

	// 1) sidecar greets with rh_hello carrying an ephemeral pubkey
	m := waitFor(t, lines, func(m map[string]any) bool { return m["type"] == "rh_hello" })
	if pk, _ := m["relay_pubkey"].(string); len(pk) != 44 {
		t.Fatalf("rh_hello pubkey wrong length: %q", m["relay_pubkey"])
	}
	// 2) sidecar observes EMAIL and prompts
	waitFor(t, lines, func(m map[string]any) bool {
		return m["type"] == "rh_prompt" && m["step"] == "email"
	})
	// 3) Flutter answers (plaintext transport; crypto path covered by Python tests)
	in, _ := json.Marshal(map[string]any{
		"type": "rh_input", "session_id": "sess-test", "step": "email",
		"values": map[string]string{"login": "a@b.c", "password": "pw"},
	})
	if err := b.SendInput(in); err != nil {
		t.Fatalf("send input: %v", err)
	}
	// 4) sidecar drives to success
	waitFor(t, lines, func(m map[string]any) bool {
		return m["type"] == "rh_state" && m["state"] == "success"
	})
}

func waitFor(t *testing.T, lines <-chan map[string]any, pred func(map[string]any) bool) map[string]any {
	t.Helper()
	deadline := time.After(12 * time.Second)
	for {
		select {
		case m := <-lines:
			if pred(m) {
				return m
			}
		case <-deadline:
			t.Fatal("timeout waiting for expected sidecar message")
			return nil
		}
	}
}

// TestBridgeDoubleStart guards the lifecycle contract.
func TestBridgeDoubleStart(t *testing.T) {
	requireSidecar(t)
	b := New(sidecarScript(), ":0", "s", func([]byte) {}, "RH_FAKE=1")
	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer b.Close()
	if err := b.Start(context.Background()); err == nil {
		t.Fatal("second Start should fail")
	}
}

// TestSendInputBeforeStart must error, not panic.
func TestSendInputBeforeStart(t *testing.T) {
	b := New(sidecarScript(), ":0", "s", func([]byte) {})
	if err := b.SendInput([]byte("{}")); err == nil {
		t.Fatal("SendInput before Start should error")
	}
}
