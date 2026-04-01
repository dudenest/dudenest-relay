// api.go — HTTP REST API server for browser auth sessions (used by Flutter UI).
package browser

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// Server exposes browser auth sessions over HTTP for Flutter to consume.
type Server struct {
	mgr        *Manager
	listenAddr string
	oauthURL   string        // Google OAuth2 authorization URL (built from client_id)
	oauthCfg   *oauth2.Config // for token exchange after consent
	configDir  string        // where to save tokens (~/.config/dudenest)
}

// NewServer creates an API server. display e.g. ":99", listenAddr e.g. "0.0.0.0:8086".
func NewServer(display, listenAddr, oauthURL string, oauthCfg *oauth2.Config, configDir string) *Server {
	return &Server{mgr: NewManager(display), listenAddr: listenAddr, oauthURL: oauthURL, oauthCfg: oauthCfg, configDir: configDir}
}

// Run starts the HTTP server (blocking).
func (srv *Server) Run() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/session", srv.handleSession)
	mux.HandleFunc("/auth/input", srv.handleInput)
	mux.HandleFunc("/auth/click", srv.handleClick)
	mux.HandleFunc("/auth/status/", srv.handleStatus)
	mux.HandleFunc("/auth/close/", srv.handleClose)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	fmt.Printf("browser-auth API listening on %s\n", srv.listenAddr)
	return http.ListenAndServe(srv.listenAddr, mux)
}

// --- Request / Response types ---

type sessionReq struct{ Provider string `json:"provider"` }
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
	SessionID     string  `json:"session_id,omitempty"`
	Status        string  `json:"status"`
	Fields        []Field `json:"fields,omitempty"`
	ScreenshotB64 string  `json:"screenshot_b64,omitempty"`
	Error         string  `json:"error,omitempty"`
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
	fmt.Println("handleSession: creating browser session...")
	sid, err := srv.mgr.Create()
	if err != nil {
		fmt.Printf("handleSession: browser start failed: %v\n", err)
		jsonError(w, "browser start failed: "+err.Error(), 500)
		return
	}
	fmt.Printf("handleSession: session created: %s\n", sid)
	s, _ := srv.mgr.Get(sid)
	fmt.Println("handleSession: starting gdrive flow...")
	step, err := GDriveStartFlow(s, srv.oauthURL)
	if err != nil {
		fmt.Printf("handleSession: gdrive flow error: %v\n", err)
		srv.mgr.Close(sid)
		jsonError(w, "gdrive flow start: "+err.Error(), 500)
		return
	}
	fmt.Printf("handleSession: flow step=%s screenshot=%d bytes\n", step.Status, len(step.ScreenshotB64))
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
	var step *GDriveStep
	switch {
	case strings.Contains(req.Selector, "email"):
		step, err = GDriveSubmitEmail(s, req.Text)
	case strings.Contains(req.Selector, "password"):
		step, err = GDriveSubmitPassword(s, req.Text, srv.oauthURL)
	case strings.Contains(req.Selector, "phone_number"):
		step, err = GDriveSubmitPhone(s, req.Text, srv.oauthURL)
	case strings.Contains(req.Selector, "device_approval"):
		step, err = GDriveApproveDevice(s, srv.oauthURL)
	case strings.Contains(req.Selector, "sms"):
		step, err = GDriveSubmitSMSCode(s, req.Text, srv.oauthURL)
	case strings.Contains(req.Selector, "tel") || strings.Contains(req.Selector, "totp"):
		step, err = GDriveSubmit2FA(s, req.Text, srv.oauthURL)
	default:
		if err2 := s.SendKeys(req.Selector, req.Text); err2 != nil {
			jsonError(w, "sendkeys: "+err2.Error(), 500)
			return
		}
		step = &GDriveStep{Status: "ok"}
	}
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	// NOTE: session NOT closed on "done" — browser stays visible on :99 for visual inspection (auto-closes after 5min)
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
	// Consent click: full OAuth flow — click + wait for callback + exchange code + save token
	if strings.Contains(req.Selector, "submit_approve_access") {
		callbackURL, err := GDriveApproveConsent(s)
		if err != nil {
			jsonError(w, "consent: "+err.Error(), 500)
			return
		}
		parsed, err := url.Parse(callbackURL)
		if err != nil {
			jsonError(w, "parse callback URL: "+err.Error(), 500)
			return
		}
		code := parsed.Query().Get("code")
		if code == "" {
			jsonError(w, "no code in callback URL: "+callbackURL, 500)
			return
		}
		token, err := ExchangeCode(srv.oauthCfg, code)
		if err != nil {
			jsonError(w, "token exchange: "+err.Error(), 500)
			return
		}
		email, err := GetEmailFromToken(srv.oauthCfg, token)
		if err != nil {
			email = "unknown@gmail.com" // non-fatal: token works even without email
		}
		gt := &GDriveToken{
			AccessToken:  token.AccessToken,
			TokenType:    token.TokenType,
			RefreshToken: token.RefreshToken,
			Expiry:       token.Expiry,
			Email:        email,
			ProviderID:   "gdrive_" + fmt.Sprintf("%d", time.Now().UnixMilli()),
		}
		if err := SaveToken(srv.configDir, gt.ProviderID, gt); err != nil {
			jsonError(w, "save token: "+err.Error(), 500)
			return
		}
		// Navigate to Drive so :99 shows logged-in state for visual inspection; session auto-closes after 5min
		_ = s.Navigate("https://drive.google.com")
		jsonOK(w, stepResp{Status: "done", Fields: []Field{{ID: "email", Label: email}}})
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

func (srv *Server) handleClose(w http.ResponseWriter, r *http.Request) {
	sid := strings.TrimPrefix(r.URL.Path, "/auth/close/")
	srv.mgr.Close(sid)
	jsonOK(w, stepResp{Status: "closed"})
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
