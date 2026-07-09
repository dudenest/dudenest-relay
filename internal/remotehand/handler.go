package remotehand

import (
	"encoding/json"
	"net/http"
)

// StartHandler begins a method-3 session for a provider's OAuth URL.
//
//	POST {"oauth_url":"https://accounts.google.com/o/oauth2/..."}
//	 200 {"session_id":"rh-..."}   503 when at capacity (no free display)
//
// Mount behind the relay's auth middleware in serve.go/api.go when the user picks
// "Relay assisted (method 3)". After this returns, Flutter opens the ws and drives
// the dynamic form; the OAuth token is captured server-side by the existing relay
// callback (same as method 2) once the login succeeds.
func (m *Manager) StartHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			OAuthURL string `json:"oauth_url"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.OAuthURL == "" {
			http.Error(w, "oauth_url required", http.StatusBadRequest)
			return
		}
		sid, err := m.Start(req.OAuthURL)
		if err == ErrNoDisplay {
			http.Error(w, "no free relay display", http.StatusServiceUnavailable)
			return
		}
		if err != nil {
			http.Error(w, "failed to start session", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"session_id": sid})
	}
}

// EndHandler tears down a session (user cancelled / flow finished).
//
//	POST {"session_id":"rh-..."} -> 204
func (m *Manager) EndHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			SessionID string `json:"session_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SessionID == "" {
			http.Error(w, "session_id required", http.StatusBadRequest)
			return
		}
		m.End(req.SessionID)
		w.WriteHeader(http.StatusNoContent)
	}
}
