package remotehand

import (
	"encoding/json"
	"net/http"
)

// StartHandler begins a method-3 session.
//
//	POST {"provider":"gdrive"}    → relay builds the OAuth URL server-side and
//	                                arms token capture (production path)
//	POST {"oauth_url":"https://…"} → explicit URL (tests/advanced)
//	 200 {"session_id":"rh-..."}   503 at capacity   400 bad request
//
// Mounted behind the relay's auth middleware in serve.go. After this returns,
// Flutter opens the ws and drives the dynamic form; the OAuth token is captured
// server-side (browser.Server.StartAssistedCapture, same helpers as method 2).
func (m *Manager) StartHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Provider string `json:"provider"`
			OAuthURL string `json:"oauth_url"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		oauthURL := req.OAuthURL
		if oauthURL == "" && req.Provider != "" {
			m.mu.Lock()
			prep := m.prepareSession
			m.mu.Unlock()
			if prep == nil {
				http.Error(w, "provider sessions not configured", http.StatusBadRequest)
				return
			}
			built, perr := prep(req.Provider)
			if perr != nil {
				http.Error(w, perr.Error(), http.StatusBadRequest)
				return
			}
			oauthURL = built
		}
		if oauthURL == "" {
			http.Error(w, "provider or oauth_url required", http.StatusBadRequest)
			return
		}
		sid, err := m.Start(oauthURL)
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
