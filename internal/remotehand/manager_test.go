package remotehand

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/dudenest/dudenest-relay/internal/ws"
)

// Compile-time proof that the real ws.Hub satisfies the Broadcaster contract.
var _ Broadcaster = (*ws.Hub)(nil)

// fakeHub records BroadcastRaw output and captures the inbound handler.
type fakeHub struct {
	mu      sync.Mutex
	out     chan map[string]any
	onInput func([]byte)
}

func newFakeHub() *fakeHub { return &fakeHub{out: make(chan map[string]any, 64)} }

func (f *fakeHub) BroadcastRaw(b []byte) {
	var m map[string]any
	if json.Unmarshal(b, &m) == nil {
		f.out <- m
	}
}
func (f *fakeHub) SetOnClientMessage(fn func([]byte)) {
	f.mu.Lock(); f.onInput = fn; f.mu.Unlock()
}
func (f *fakeHub) input(v any) {
	f.mu.Lock(); fn := f.onInput; f.mu.Unlock()
	b, _ := json.Marshal(v)
	fn(b)
}

// TestAttachWiresHubToSidecar proves the full hub↔sidecar wiring via Attach:
// sidecar output reaches BroadcastRaw and Flutter input reaches the sidecar.
func TestAttachWiresHubToSidecar(t *testing.T) {
	requireSidecar(t)
	hub := newFakeHub()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	b, err := Attach(ctx, hub, sidecarScript(), ":0", "sess-attach",
		"RH_FAKE=1", "RH_STATES=email,password,success")
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	defer b.Close()

	waitFor(t, hub.out, func(m map[string]any) bool { return m["type"] == "rh_hello" })
	waitFor(t, hub.out, func(m map[string]any) bool {
		return m["type"] == "rh_prompt" && m["step"] == "email"
	})
	hub.input(map[string]any{"type": "rh_input", "step": "email",
		"values": map[string]string{"login": "a@b.c", "password": "pw"}})
	waitFor(t, hub.out, func(m map[string]any) bool {
		return m["type"] == "rh_state" && m["state"] == "success"
	})
}

// TestManagerRoutesBySessionAndReleasesDisplay proves the multi-session path:
// Start spawns a sidecar on an allocated display, inbound frames route by
// session_id, and End releases the display.
func TestManagerRoutesBySessionAndReleasesDisplay(t *testing.T) {
	requireSidecar(t)
	hub := newFakeHub()
	pool := NewDisplayPool(":0")
	m := NewManager(hub, pool, sidecarScript(), 20*time.Second,
		"RH_FAKE=1", "RH_STATES=email,password,success")

	sid, err := m.Start("https://accounts.google.com/o/oauth2/v2/auth?fake")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if pool.Available() != 0 || m.Active() != 1 {
		t.Fatalf("display not allocated / session not tracked (avail=%d active=%d)",
			pool.Available(), m.Active())
	}
	// rh_hello must carry this session's id
	hello := waitFor(t, hub.out, func(x map[string]any) bool { return x["type"] == "rh_hello" })
	if hello["session_id"] != sid {
		t.Fatalf("rh_hello session_id=%v, want %s", hello["session_id"], sid)
	}
	waitFor(t, hub.out, func(x map[string]any) bool {
		return x["type"] == "rh_prompt" && x["step"] == "email"
	})
	// input WITHOUT session_id must be dropped by the router (no crash, no delivery)
	hub.input(map[string]any{"type": "rh_input", "step": "email",
		"values": map[string]string{"login": "x"}})
	// correctly-addressed input drives to success
	hub.input(map[string]any{"type": "rh_input", "session_id": sid, "step": "email",
		"values": map[string]string{"login": "a@b.c", "password": "pw"}})
	waitFor(t, hub.out, func(x map[string]any) bool {
		return x["type"] == "rh_state" && x["state"] == "success"
	})

	m.End(sid)
	if m.Active() != 0 || pool.Available() != 1 {
		t.Fatalf("End should free session+display (active=%d avail=%d)", m.Active(), pool.Available())
	}
	m.End(sid) // idempotent
}

// TestManagerPoolExhaustion: Start fails cleanly when no display is free.
func TestManagerPoolExhaustion(t *testing.T) {
	requireSidecar(t)
	hub := newFakeHub()
	m := NewManager(hub, NewDisplayPool(":0"), sidecarScript(), 20*time.Second,
		"RH_FAKE=1", "RH_STATES=email,success")
	sid, err := m.Start("u")
	if err != nil {
		t.Fatalf("first start: %v", err)
	}
	defer m.End(sid)
	if _, err := m.Start("u"); err != ErrNoDisplay {
		t.Fatalf("want ErrNoDisplay on exhausted pool, got %v", err)
	}
}
