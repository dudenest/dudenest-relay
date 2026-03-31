// api.go — HTTP REST API server for browser auth sessions (used by Flutter UI).
package browser

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/dudenest/dudenest-relay/internal/browser/providers"
)

// Server exposes browser auth sessions over HTTP for Flutter to consume.
type Server struct {
	mgr        *Manager
	listenAddr string
	oauthURL   string // Google OAuth2 authorization URL (built from client_id)
}

// NewServer creates an API server. display e.g. ":99", listenAddr e.g. "0.0.0.0:8086".
func NewServer(display, listenAddr, oauthURL string) *Server {
	return &Server{mgr: NewManager(display), listenAddr: listenAddr, oauthURL: oauthURL}
}

// Run starts the HTTP server (blocking).
func (srv *Server) Run() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/session", srv.handleSession)    // POST: create session
	mux.HandleFunc("/auth/input", srv.handleInput)        // POST: send text to field
	mux.HandleFunc("/auth/click", srv.handleClick)        // POST: click element
	mux.HandleFunc("/auth/status/", srv.handleStatus)     // GET:  session status
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	fmt.Printf("browser-auth API listening on %s\n", srv.listenAddr)
	return http.ListenAndServe(srv.listenAddr, mux)
}

// --- Request / Response types ---

type sessionReq struct {
	Provider string `json:"provider"` // "gdrive"
}

type inputReq struct {
	SessionID string `json:"session_id"`
	Selector  string `json:"selector"`
	Text      string `json:"text"`
}

type clickReq struct {
	SessionID string `json:"session_id"`
	Selector  string `json:"selector"`
}

type stepResp struct {
	SessionID     string              `json:"session_id,omitempty"`
	Status        string              `json:"status"`
	Fields        []providers.Field   `json:"fields,omitempty"`
	ScreenshotB64 string              `json:"screenshot_b64,omitempty"`
	Error         string              `json:"error,omitempty"`
}

// --- Handlers ---

func (srv *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req sessionReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON: "+err.Error(), 400)
		return
	}
	if req.Provider != "gdrive" {
		jsonError(w, "unsupported provider: "+req.Provider, 400)
		return
	}
	sid, err := srv.mgr.Create()
	if err != nil {
		jsonError(w, "browser start failed: "+err.Error(), 500)
		return
	}
	s, _ := srv.mgr.Get(sid)
	step, err := providers.GDriveStartFlow(s, srv.oauthURL)
	if err != nil {
		srv.mgr.Close(sid)
		jsonError(w, "gdrive flow start: "+err.Error(), 500)
		return
	}
	jsonOK(w, stepResp{SessionID: sid, Status: step.Status, Fields: step.Fields, ScreenshotB64: step.ScreenshotB64})
}

func (srv *Server) handleInput(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req inputReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON: "+err.Error(), 400)
		return
	}
	s, err := srv.mgr.Get(req.SessionID)
	if err != nil {
		jsonError(w, err.Error(), 404)
		return
	}
	// Determine current step by selector type
	var step *providers.GDriveStep
	switch {
	case strings.Contains(req.Selector, "email") || req.Selector == providers.SelectorEmail:
		step, err = providers.GDriveSubmitEmail(s, req.Text)
	case strings.Contains(req.Selector, "password") || req.Selector == providers.SelectorPassword:
		step, err = providers.GDriveSubmitPassword(s, req.Text, srv.oauthURL)
	case strings.Contains(req.Selector, "totp") || strings.Contains(req.Selector, "tel"):
		step, err = providers.GDriveSubmit2FA(s, req.Text, srv.oauthURL)
	default:
		if err2 := s.SendKeys(req.Selector, req.Text); err2 != nil {
			jsonError(w, "sendkeys: "+err2.Error(), 500)
			return
		}
		step = &providers.GDriveStep{Status: "ok"}
	}
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	if step.Status == "done" {
		srv.mgr.Close(req.SessionID)
	}
	jsonOK(w, stepResp{Status: step.Status, Fields: step.Fields, ScreenshotB64: step.ScreenshotB64})
}

func (srv *Server) handleClick(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req clickReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON: "+err.Error(), 400)
		return
	}
	s, err := srv.mgr.Get(req.SessionID)
	if err != nil {
		jsonError(w, err.Error(), 404)
		return
	}
	if err := s.Click(req.Selector); err != nil {
		jsonError(w, "click: "+err.Error(), 500)
		return
	}
	jsonOK(w, stepResp{Status: "clicked"})
}

func (srv *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	sid := strings.TrimPrefix(r.URL.Path, "/auth/status/")
	_, err := srv.mgr.Get(sid)
	if err != nil {
		jsonOK(w, stepResp{Status: "not_found"})
		return
	}
	jsonOK(w, stepResp{Status: "active"})
}

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(stepResp{Status: "error", Error: msg})
}
