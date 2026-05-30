// hub.go — WebSocket hub for relay↔Flutter bidirectional communication.
// Flutter connects to /ws and receives auth_request messages from relay.
// Flutter responds by doing OAuth on user's device (user's IP) and sending code to /auth/exchange.
package ws

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"sync"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

// Message is the JSON envelope for all relay↔Flutter WebSocket messages.
type Message struct {
	Type      string `json:"type"`                 // "auth_request"|"auth_done"|"auth_error"|"ping"
	Provider  string `json:"provider,omitempty"`   // "gdrive"|"mega"|"onedrive"
	RequestID string `json:"request_id,omitempty"` // correlates request↔response
	Email     string `json:"email,omitempty"`      // set on auth_done
	Error     string `json:"error,omitempty"`      // set on auth_error
}

// Hub manages connected Flutter clients and broadcasts messages to them.
type Hub struct {
	mu         sync.Mutex
	clients    map[net.Conn]bool
	onAuthDone func() // optional callback invoked when an auth_done Broadcast fires — used by serve.go to trigger pipeline reinit out of standby mode
}

// NewHub returns a ready-to-use WebSocket hub.
func NewHub() *Hub {
	return &Hub{clients: make(map[net.Conn]bool)}
}

// SetOnAuthDone registers a callback fired (non-blocking) every time a Broadcast
// with Type=="auth_done" is sent. Set by serve.go in standby mode so the pipeline
// can be re-initialized as soon as a new cloud provider token lands on disk.
func (h *Hub) SetOnAuthDone(fn func()) {
	h.mu.Lock(); defer h.mu.Unlock()
	h.onAuthDone = fn
}

// ServeHTTP upgrades HTTP connection to WebSocket and tracks it for broadcasting.
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, _, _, err := ws.UpgradeHTTP(r, w)
	if err != nil { return }
	h.mu.Lock(); h.clients[conn] = true; h.mu.Unlock()
	defer func() { h.mu.Lock(); delete(h.clients, conn); h.mu.Unlock(); conn.Close() }()
	for { // read loop: keep-alive + detect client disconnect
		if _, _, err := wsutil.ReadClientData(conn); err != nil { break }
	}
}

// Broadcast sends msg to all connected Flutter clients (best-effort, ignores errors).
// If msg.Type=="auth_done" and an OnAuthDone callback is registered, it is invoked
// in a goroutine after the broadcast so the standby loop in serve.go can reload the pipeline.
func (h *Hub) Broadcast(msg Message) {
	data, _ := json.Marshal(msg)
	h.mu.Lock()
	n := len(h.clients) // s329 #I: capture under lock for diagnostic log
	for conn := range h.clients {
		wsutil.WriteServerMessage(conn, ws.OpText, data) //nolint:errcheck
	}
	cb := h.onAuthDone
	h.mu.Unlock()
	log.Printf("ws Broadcast: type=%s email=%s clients=%d", msg.Type, msg.Email, n) // s329 #I: diagnose Flutter "Waiting for authentication" hang — was n=0 the cause?
	if msg.Type == "auth_done" && cb != nil { go cb() }
}

// SendAuthRequest asks Flutter to start an OAuth flow for the given provider.
// Flutter responds by calling POST /auth/exchange with the matching request_id.
func (h *Hub) SendAuthRequest(provider, requestID string) {
	h.Broadcast(Message{Type: "auth_request", Provider: provider, RequestID: requestID})
}

// ClientCount returns the number of currently connected Flutter clients.
func (h *Hub) ClientCount() int {
	h.mu.Lock(); defer h.mu.Unlock()
	return len(h.clients)
}
