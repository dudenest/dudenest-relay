// api.go — HTTP REST API server for browser auth sessions (used by Flutter UI).
// Auth methods supported:
//   A. Flutter-side OAuth  — GET /auth/url → Flutter opens browser (user IP ✅) → POST /auth/exchange
//   B. Browser automation  — POST /auth/session → chromedp on relay (self-hosted only)
//   C. WebSocket requests  — relay sends auth_request to Flutter via /ws
package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/dudenest/dudenest-relay/internal/ws"
)

// Server exposes browser auth sessions over HTTP for Flutter to consume.
type Server struct {
	mgr           *Manager
	listenAddr    string
	oauthURL      string         // Google OAuth2 authorization URL (built from client_id)
	oauthCfg      *oauth2.Config // desktop/mobile client (redirect: http://localhost or custom scheme)
	webOAuthCfg   *oauth2.Config // web client (redirect: https://dudenest.com/auth); nil = unsupported
	configDir     string         // where to save tokens (~/.config/dudenest)
	wsHub         *ws.Hub        // optional — broadcasts auth_request to Flutter (nil = disabled)
}

// NewServer creates an API server. display e.g. ":99", listenAddr e.g. "0.0.0.0:8086".
// webOAuthCfg may be nil (web OAuth disabled). wsHub may be nil (WebSocket disabled).
func NewServer(display, listenAddr, oauthURL string, oauthCfg, webOAuthCfg *oauth2.Config, configDir string, wsHub *ws.Hub) *Server {
	return &Server{mgr: NewManager(display), listenAddr: listenAddr, oauthURL: oauthURL, oauthCfg: oauthCfg, webOAuthCfg: webOAuthCfg, configDir: configDir, wsHub: wsHub}
}

// selectOAuthCfg returns the appropriate OAuth config based on the callback URI.
// HTTPS callbacks (Flutter web) use the web client; all others use the desktop client.
func (srv *Server) selectOAuthCfg(callbackURI string) *oauth2.Config {
	if strings.HasPrefix(callbackURI, "https://") && srv.webOAuthCfg != nil {
		return srv.webOAuthCfg
	}
	return srv.oauthCfg
}

// RegisterRoutes adds all browser-auth and provider routes to mux.
func (srv *Server) RegisterRoutes(mux *http.ServeMux) {
	// Method A: Flutter-side OAuth (user's IP for login ✅)
	mux.HandleFunc("/auth/url", srv.handleAuthURL)
	mux.HandleFunc("/auth/exchange", srv.handleExchange)
	// Method B: Browser automation (chromedp on relay, self-hosted only)
	mux.HandleFunc("/auth/session", srv.handleSession)
	mux.HandleFunc("/auth/input", srv.handleInput)
	mux.HandleFunc("/auth/click", srv.handleClick)
	mux.HandleFunc("/auth/status/", srv.handleStatus)
	mux.HandleFunc("/auth/close/", srv.handleClose)
	// Providers list
	mux.HandleFunc("/providers", srv.handleProviders)
}

// Run starts the HTTP server (blocking).
func (srv *Server) Run() error {
	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	fmt.Printf("browser-auth API listening on %s\n", srv.listenAddr)
	return http.ListenAndServe(srv.listenAddr, mux)
}

// --- Method A: Flutter-side OAuth handlers ---

// handleAuthURL returns an OAuth2 authorization URL for Flutter to open in a system browser.
// Flutter specifies its own callback URI so the auth code returns to the user's device (user's IP ✅).
// GET /auth/url?provider=gdrive&callback=com.dudenest.app://oauth/callback
func (srv *Server) handleAuthURL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet { http.Error(w, "GET only", http.StatusMethodNotAllowed); return }
	provider := r.URL.Query().Get("provider")
	callbackURI := r.URL.Query().Get("callback")
	if provider == "" { provider = "gdrive" }
	if provider != "gdrive" { jsonError(w, "unsupported provider: "+provider, 400); return }
	cfg := *srv.selectOAuthCfg(callbackURI) // copy — web vs desktop client based on callback URI
	if callbackURI != "" { cfg.RedirectURL = callbackURI }
	authURL := cfg.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	jsonOK(w, map[string]string{"url": authURL, "provider": provider, "redirect_uri": cfg.RedirectURL})
}

// handleExchange exchanges an OAuth2 code (received by Flutter) for a token, stores it on relay.
// The code was obtained on user's device (user's IP) — relay only does the token exchange (acceptable).
// POST /auth/exchange {provider, code, redirect_uri, request_id?}
func (srv *Server) handleExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "POST only", http.StatusMethodNotAllowed); return }
	var req struct {
		Provider    string `json:"provider"`
		Code        string `json:"code"`
		RedirectURI string `json:"redirect_uri"`
		RequestID   string `json:"request_id,omitempty"` // correlates with ws auth_request
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil { jsonError(w, "invalid JSON: "+err.Error(), 400); return }
	if req.Provider == "" { req.Provider = "gdrive" }
	if req.Provider != "gdrive" { jsonError(w, "unsupported provider: "+req.Provider, 400); return }
	if req.Code == "" { jsonError(w, "code required", 400); return }
	cfg := *srv.selectOAuthCfg(req.RedirectURI) // must use same client as handleAuthURL used
	if req.RedirectURI != "" { cfg.RedirectURL = req.RedirectURI }
	token, err := ExchangeCode(&cfg, req.Code)
	if err != nil { jsonError(w, "token exchange: "+err.Error(), 500); return }
	email, err := GetEmailFromToken(&cfg, token)
	if err != nil { email = "unknown@gmail.com" } // non-fatal
	gt := &GDriveToken{
		AccessToken:  token.AccessToken,
		TokenType:    token.TokenType,
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry,
		Email:        email,
		ProviderID:   upsertProviderID(srv.configDir, email), // reuse existing ID if email known
	}
	if err := SaveToken(srv.configDir, gt.ProviderID, gt); err != nil { jsonError(w, "save token: "+err.Error(), 500); return }
	// Notify Flutter via WebSocket if this was a relay-initiated auth request
	if req.RequestID != "" && srv.wsHub != nil {
		srv.wsHub.Broadcast(ws.Message{Type: "auth_done", RequestID: req.RequestID, Provider: req.Provider, Email: email})
	}
	fmt.Printf("handleExchange: provider saved — %s (%s)\n", email, gt.ProviderID)
	jsonOK(w, map[string]string{"status": "ok", "email": email, "provider_id": gt.ProviderID})
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
		// Bind :8085 synchronously BEFORE clicking — eliminates race where browser redirects before server is ready.
		// defer cancel() ensures port is freed when this handler returns (success or error).
		type codeRes struct{ code string; err error }
		codeCh := make(chan codeRes, 1)
		cbCtx, cancelCallback := context.WithCancel(r.Context())
		defer cancelCallback() // frees :8085 immediately when handler returns
		waitForCode, cbErr := StartCallbackServer(cbCtx, 40*time.Second)
		if cbErr != nil {
			jsonError(w, "callback server bind: "+cbErr.Error(), 500)
			return
		}
		go func() { code, err := waitForCode(); codeCh <- codeRes{code, err} }()
		callbackURL, challenge, err := GDriveApproveConsent(s)
		if err != nil {
			jsonError(w, "consent: "+err.Error(), 500)
			return
		}
		if challenge != nil { // intermediate challenge (phone/sms) — return to client
			jsonOK(w, stepResp{Status: challenge.Status, Fields: challenge.Fields, ScreenshotB64: challenge.ScreenshotB64})
			return
		}
		// Get code — prefer callback server (handles ERR_CONNECTION_REFUSED case), fallback to URL
		var code string
		select {
		case res := <-codeCh:
			if res.err != nil {
				jsonError(w, "callback server: "+res.err.Error(), 500)
				return
			}
			code = res.code
		default: // callback server not yet received — try URL
			parsed, err := url.Parse(callbackURL)
			if err != nil {
				jsonError(w, "parse callback URL: "+err.Error(), 500)
				return
			}
			code = parsed.Query().Get("code")
		}
		if code == "" { // wait for callback server as last resort
			res := <-codeCh
			if res.err != nil {
				jsonError(w, "callback: "+res.err.Error(), 500)
				return
			}
			code = res.code
		}
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
			ProviderID:   upsertProviderID(srv.configDir, email), // reuse existing ID if email known
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

type providerInfo struct {
	ID         string  `json:"id"`
	Type       string  `json:"type"`
	Email      string  `json:"email"`
	QuotaTotal float64 `json:"quota_total_gb"`
	QuotaUsed  float64 `json:"quota_used_gb"`
	Available  bool    `json:"available"`
	LastError  string  `json:"last_error,omitempty"` // reason when available=false
}
type providersResp struct{ Providers []providerInfo `json:"providers"` }

func (srv *Server) handleProviders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	dir := filepath.Join(srv.configDir, "providers")
	entries, _ := os.ReadDir(dir)
	seen := map[string]bool{} // deduplicate by email
	providers := []providerInfo{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		tokenPath := filepath.Join(dir, e.Name())
		t, err := LoadToken(tokenPath)
		if err != nil {
			fmt.Printf("handleProviders: skip %s: %v\n", e.Name(), err)
			continue
		}
		if seen[t.Email] { // skip duplicate (same email, multiple files)
			fmt.Printf("handleProviders: skip duplicate %s (%s)\n", t.Email, e.Name())
			continue
		}
		seen[t.Email] = true
		pi := providerInfo{ID: t.ProviderID, Type: "gdrive", Email: t.Email}
		newTok, total, used, quotaErr := GetDriveQuotaRefreshing(srv.oauthCfg, t)
		if quotaErr == nil {
			pi.QuotaTotal = float64(total) / 1e9
			pi.QuotaUsed = float64(used) / 1e9
			pi.Available = true
			if newTok != nil && newTok.AccessToken != t.AccessToken { // token was refreshed — save to disk
				t.AccessToken = newTok.AccessToken
				t.Expiry = newTok.Expiry
				if newTok.RefreshToken != "" { t.RefreshToken = newTok.RefreshToken }
				if saveErr := overwriteToken(tokenPath, t); saveErr != nil {
					fmt.Printf("handleProviders: save refreshed token %s: %v\n", t.Email, saveErr)
				} else {
					fmt.Printf("handleProviders: refreshed token saved for %s\n", t.Email)
				}
			}
		} else {
			pi.LastError = classifyTokenError(quotaErr)
			fmt.Printf("handleProviders: %s (%s) unavailable: %v → %s\n", t.Email, t.ProviderID, quotaErr, pi.LastError)
		}
		providers = append(providers, pi)
	}
	jsonOK(w, providersResp{Providers: providers})
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
