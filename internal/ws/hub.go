// hub.go — WebSocket hub for relay↔Flutter bidirectional communication.
// Flutter connects to /ws and receives auth_request messages from relay.
// Flutter responds by doing OAuth on user's device (user's IP) and sending code to /auth/exchange.
package ws

import (
	"encoding/json"
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
	mu      sync.Mutex
	clients map[net.Conn]bool
}

// NewHub returns a ready-to-use WebSocket hub.
func NewHub() *Hub {
	return &Hub{clients: make(map[net.Conn]bool)}
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
func (h *Hub) Broadcast(msg Message) {
	data, _ := json.Marshal(msg)
	h.mu.Lock(); defer h.mu.Unlock()
	for conn := range h.clients {
		wsutil.WriteServerMessage(conn, ws.OpText, data) //nolint:errcheck
	}
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
