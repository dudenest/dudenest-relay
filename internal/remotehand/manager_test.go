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
