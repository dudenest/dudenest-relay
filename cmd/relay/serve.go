// serve.go — combined HTTP server: file API + browser auth API.
// relay serve --key <key> --provider gdrive --gdrive-token <path> --listen 0.0.0.0:8086
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/oauth2"

	"github.com/dudenest/dudenest-relay/internal/auth"
	"github.com/dudenest/dudenest-relay/internal/backup"
	"github.com/dudenest/dudenest-relay/internal/blockmap"
	"github.com/dudenest/dudenest-relay/internal/browser"
	"github.com/dudenest/dudenest-relay/internal/config"
	"github.com/dudenest/dudenest-relay/internal/register"
	"github.com/dudenest/dudenest-relay/internal/thumbnail"
	"github.com/dudenest/dudenest-relay/internal/ws"
	"github.com/dudenest/dudenest-relay/pkg/types"
)

var (
	serveListen      string
	relayConfigPath  string
)

func serveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start combined HTTP server: file API + browser auth API",
		RunE:  runServe,
	}
	home, _ := os.UserHomeDir()
	cmd.Flags().StringVar(&serveListen, "listen", "", "HTTP listen address (overrides config; default: 0.0.0.0:8086)")
	cmd.Flags().StringVar(&authClientSecret, "client-secret", filepath.Join(home, ".config/dudenest/gdrive_client_secret.json"), "Path to Google OAuth2 client_secret.json")
	cmd.Flags().StringVar(&authConfigDir, "config-dir", filepath.Join(home, ".config/dudenest"), "Path to dudenest config directory")
	cmd.Flags().StringVar(&authDisplay, "display", "", "X display for Chromium (TigerVNC); overrides config")
	return cmd
}

// degradedServerWithAuth runs in standby: /files returns 503, but /auth/* and /ws stay active
// so users can re-authorize cloud providers without restarting the relay.
// /health returns 200 (degraded) so HAProxy keeps the node in rotation.
// tryReg is called on /files requests even in standby so JWT-based registration fires regardless of cloud auth state.
func degradedServerWithAuth(listen, reason string, authSrv interface{ RegisterRoutes(*http.ServeMux) }, wsHub http.Handler, tryReg func(string)) error {
	log.Printf("⚠️  relay: entering standby mode — %s", reason)
	log.Printf("⚠️  relay: /files=503, /auth active — re-authorize via Flutter app")
	ticker := time.NewTicker(5 * time.Minute)
	go func() { // periodic reminder, no cloud retries
		for range ticker.C {
			log.Printf("⚠️  relay: STANDBY (%s) — use /auth/url to re-authorize", reason)
		}
	}()
	standbyFile := func(w http.ResponseWriter, r *http.Request) { // validate JWT + trigger registration even in standby
		if tryReg != nil { tryReg(r.Header.Get("Authorization")) }
		jsonErr(w, "relay in standby: "+reason, http.StatusServiceUnavailable)
	}
	mux := http.NewServeMux()
	authSrv.RegisterRoutes(mux) // /auth/* active even in standby — user can add/re-auth providers
	mux.Handle("/ws", wsHub)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "degraded", "reason": reason}) //nolint:errcheck
	})
	mux.HandleFunc("/files", standbyFile)
	mux.HandleFunc("/files/", standbyFile)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { jsonErr(w, "relay in standby: "+reason, http.StatusServiceUnavailable) })
	log.Printf("⚠️  relay: standby server with auth listening on %s", listen)
	return http.ListenAndServe(listen, corsMiddleware(mux))
}

func runServe(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(relayConfigPath) // load config first — CLI flags override below
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if serveListen != "" { cfg.Server.Listen = serveListen }         // --listen overrides config
	if authDisplay != "" { cfg.Server.Display = authDisplay }        // --display overrides config
	cs, err := browser.LoadClientSecret(authClientSecret) // load auth config before pipeline — needed for standby mode too
	if err != nil {
		return fmt.Errorf("load client_secret: %w", err)
	}
	cfg2 := browser.BuildOAuthConfig(cs, browser.CallbackURL(cfg.OAuth.CallbackPort))
	var webCfg *oauth2.Config // web client for cfg.OAuth.WebRedirectURL callbacks (Flutter web)
	if id, secret := os.Getenv("GDRIVE_WEB_CLIENT_ID"), os.Getenv("GDRIVE_WEB_CLIENT_SECRET"); id != "" && secret != "" {
		webCfg = browser.BuildWebOAuthConfig(id, secret, cfg.OAuth.WebRedirectURL)
		fmt.Println("relay serve: web OAuth client loaded (GDRIVE_WEB_CLIENT_ID)")
	}
	wsHub := ws.NewHub()
	bm := blockmap.New(storePath) // blockmap for file_count in /auth/providers
	authSrv := browser.NewServer(cfg.Server.Display, cfg.Server.Listen, browser.BuildAuthURL(cfg2), cfg2, webCfg, authConfigDir, wsHub, bm, cfg.OAuth.CallbackPort, cfg.NoVNC.BackendAddr, cfg.SessionTimeout())
	// tryReg: JWT-based registration trigger, created before getPipeline() so it fires even in standby.
	// Validates Bearer token, extracts user_id from claims, registers relay with backup (saves relay_creds.json).
	// Does not need pipeline/fileServer — only configDir + backupURL.
	var standbyRegOnce sync.Once
	tryReg := func(authHeader string) {
		if !strings.HasPrefix(authHeader, "Bearer ") { return }
		token := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := auth.ValidateJWT(token)
		if err != nil || claims == nil || claims.Sub == "" { return }
		go standbyRegOnce.Do(func() {
			if _, err2 := register.RegisterOnceWithUserID(authConfigDir, claims.Sub, cfg.Backup.URL); err2 != nil {
				log.Printf("⚠️  standby register: %v", err2)
			} else {
				log.Printf("✅ standby register: relay registered with backup (user=%s)", claims.Sub)
			}
		})
	}
	p, err := getPipeline()
	if err != nil {
		if isCredentialError(err) { // OAuth expired/revoked or no providers yet → standby with auth routes active
			return degradedServerWithAuth(cfg.Server.Listen, fmt.Sprintf("pipeline init: %v", err), authSrv, wsHub, tryReg)
		}
		return fmt.Errorf("pipeline init: %w", err)
	}
	tc, err := thumbnail.NewCache(authConfigDir)
	if err != nil {
		return fmt.Errorf("thumbnail cache: %w", err)
	}
	key, _ := getKey() // key already validated in getPipeline(), safe to ignore error here
	if creds, err2 := register.EnsureRegistered(authConfigDir, cfg.Backup.URL); err2 != nil { // auto-register with backup on first start
		log.Printf("⚠️  register: %v (backup disabled)", err2)
	} else if creds != nil {
		os.Setenv("RELAY_ID", creds.RelayID)         //nolint:errcheck
		os.Setenv("RELAY_SECRET", creds.RelaySecret) //nolint:errcheck
	}
	bc := backup.New(key, authConfigDir, cfg.Backup.URL, cfg.Debounce()) // nil if URL/RELAY_ID/RELAY_SECRET not set
	if bc != nil { bc.StartPingLoop(5 * time.Minute) } // keep last_seen_at current
	if maps, err2 := p.ListFiles(); err2 == nil && len(maps) == 0 { // startup recovery: restore if no local files
		if restored, err3 := bc.Restore(); err3 != nil {
			log.Printf("⚠️  startup restore: %v", err3)
		} else if restored {
			log.Printf("✅ startup restore: file maps + provider tokens restored from backup")
		}
	}
	mux := http.NewServeMux()
	authSrv.RegisterRoutes(mux)
	mux.Handle("/ws", wsHub) // WebSocket: Flutter connects for relay→Flutter auth requests
	fs := &fileServer{p: p, thumbCache: tc, backupClient: bc, maxUploadBytes: cfg.MaxUploadBytes()}
	lr := &lazyRegistrar{configDir: authConfigDir, masterKey: key, fs: fs, backupURL: cfg.Backup.URL, debounce: cfg.Debounce()}
	mux.HandleFunc("/files", requireAuthWithReg(lr, fs.handleList))
	mux.HandleFunc("/files/", requireAuthWithReg(lr, fs.handleFile))
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }) //nolint:errcheck
	fmt.Printf("relay serve listening on %s (provider: %s, ws: /ws)\n", cfg.Server.Listen, provider)
	return http.ListenAndServe(cfg.Server.Listen, corsMiddleware(mux))
}

// fileServer handles /files/* endpoints using the pipeline.
type fileServer struct {
	p interface {
		Upload(filePath string, strategy string) (*types.FileMap, error)
		Download(fileID, outputPath string) error
		ListFiles() ([]*types.FileMap, error)
		GetFileMap(fileID string) (*types.FileMap, error)
		DeleteFile(fileID string) error
	}
	thumbCache     *thumbnail.Cache
	backupMu       sync.RWMutex
	backupClient   *backup.Client // nil = backup disabled; may be set lazily after JWT registration
	maxUploadBytes int64          // max multipart upload size (from config)
}

func (fs *fileServer) backup() *backup.Client {
	fs.backupMu.RLock()
	defer fs.backupMu.RUnlock()
	return fs.backupClient
}
func (fs *fileServer) setBackup(bc *backup.Client) {
	fs.backupMu.Lock()
	fs.backupClient = bc
	fs.backupMu.Unlock()
}

// lazyRegistrar triggers relay registration on first valid JWT request.
// Eliminates the need for RELAY_USER_ID env var — user ID is extracted from JWT claims.
type lazyRegistrar struct {
	once      sync.Once
	configDir string
	masterKey []byte
	fs        *fileServer
	backupURL string        // from config — used for registration and backup client init
	debounce  time.Duration // from config — used for backup client init
}

func (lr *lazyRegistrar) tryRegister(userID string) {
	lr.once.Do(func() {
		creds, err := register.RegisterOnceWithUserID(lr.configDir, userID, lr.backupURL)
		if err != nil {
			log.Printf("⚠️  lazy register: %v (backup disabled)", err)
			return
		}
		if creds == nil {
			return
		}
		os.Setenv("RELAY_ID", creds.RelayID)         //nolint:errcheck
		os.Setenv("RELAY_SECRET", creds.RelaySecret) //nolint:errcheck
		bc := backup.New(lr.masterKey, lr.configDir, lr.backupURL, lr.debounce)
		if bc != nil {
			lr.fs.setBackup(bc)
			log.Printf("✅ lazy register: backup enabled (relay_id=%s)", creds.RelayID)
			if maps, err2 := lr.fs.p.ListFiles(); err2 == nil { bc.Trigger(maps) } // initial snapshot
			bc.StartPingLoop(5 * time.Minute)
		}
	})
}

// handleList handles GET /files — returns list of uploaded FileMaps.
func (fs *fileServer) handleList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	maps, err := fs.p.ListFiles()
	if err != nil {
		jsonErr(w, "list files: "+err.Error(), 500)
		return
	}
	type fileSummary struct {
		FileID  string    `json:"file_id"`
		Name    string    `json:"name"`
		Size    int64     `json:"size"`
		Hash    string    `json:"hash"`
		Created time.Time `json:"created"`
	}
	summaries := make([]fileSummary, 0, len(maps))
	for _, fm := range maps {
		summaries = append(summaries, fileSummary{FileID: fm.FileID, Name: fm.Name, Size: fm.Size, Hash: fm.Hash, Created: fm.Created})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"files": summaries}) //nolint:errcheck
}

// handleFile dispatches /files/{id}, /files/{id}/thumbnail, and /files/upload.
func (fs *fileServer) handleFile(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/files/")
	switch {
	case path == "upload" && r.Method == http.MethodPost:
		fs.handleUpload(w, r)
	case strings.HasSuffix(path, "/thumbnail") && r.Method == http.MethodGet:
		fs.handleThumbnail(w, r, strings.TrimSuffix(path, "/thumbnail"))
	case strings.HasSuffix(path, "/map") && r.Method == http.MethodGet:
		fs.handleGetMap(w, r, strings.TrimSuffix(path, "/map"))
	case path != "" && r.Method == http.MethodGet:
		fs.handleDownload(w, r, path)
	case path != "" && r.Method == http.MethodDelete:
		fs.handleDelete(w, r, path)
	default:
		http.NotFound(w, r)
	}
}

func (fs *fileServer) handleGetMap(w http.ResponseWriter, r *http.Request, fileID string) {
	fm, err := fs.p.GetFileMap(fileID)
	if err != nil {
		jsonErr(w, "get map: "+err.Error(), 404)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(fm) //nolint:errcheck
}
// handleUpload accepts multipart/form-data with field "file", uploads via pipeline.
func (fs *fileServer) handleUpload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(fs.maxUploadBytes); err != nil {
		jsonErr(w, "parse form: "+err.Error(), 400)
		return
	}
	f, header, err := r.FormFile("file")
	if err != nil {
		jsonErr(w, "form field 'file' required: "+err.Error(), 400)
		return
	}
	defer f.Close()
	tmpDir, err := os.MkdirTemp("", "relay-upload-*") // unique dir → file named as original
	if err != nil {
		jsonErr(w, "tmp dir: "+err.Error(), 500)
		return
	}
	defer os.RemoveAll(tmpDir)
	tmpPath := filepath.Join(tmpDir, header.Filename)
	tmp, err := os.Create(tmpPath)
	if err != nil {
		jsonErr(w, "tmp file: "+err.Error(), 500)
		return
	}
	if _, err := io.Copy(tmp, f); err != nil {
		tmp.Close()
		jsonErr(w, "write tmp: "+err.Error(), 500)
		return
	}
	tmp.Close()
	strategy := r.FormValue("strategy")
	if strategy == "" { strategy = types.StrategyReplica } // default: replica (full file, no encryption)
	fm, err := fs.p.Upload(tmpPath, strategy)
	if err != nil {
		jsonErr(w, "upload: "+err.Error(), 500)
		return
	}
	if fs.thumbCache != nil { // generate thumbnail while local file still exists
		thumbnail.Generate(tmpPath, fs.thumbCache.Path(fm.FileID)) //nolint:errcheck
	}
	if maps, err2 := fs.p.ListFiles(); err2 == nil { // trigger backup after successful upload
		fs.backup().Trigger(maps)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"file_id":  fm.FileID,
		"name":     header.Filename,
		"size":     fm.Size,
		"hash":     fm.Hash,
		"strategy": fm.Strategy,
		"chunks":   len(fm.Chunks),
	})
}

// handleDownload assembles a file and streams it back with Range support.
func (fs *fileServer) handleDownload(w http.ResponseWriter, r *http.Request, fileID string) {
	tmp, err := os.CreateTemp("", "relay-download-*")
	if err != nil {
		jsonErr(w, "tmp file: "+err.Error(), 500)
		return
	}
	tmp.Close()
	defer os.Remove(tmp.Name())
	if err := fs.p.Download(fileID, tmp.Name()); err != nil {
		jsonErr(w, "download: "+err.Error(), 500)
		return
	}
	f, err := os.Open(tmp.Name())
	if err != nil {
		jsonErr(w, "open: "+err.Error(), 500)
		return
	}
	defer f.Close()
	fm, _ := fs.p.GetFileMap(fileID)
	name := fileID
	var modTime time.Time
	if fm != nil {
		name = fm.Name
		modTime = fm.Modified
	}
	http.ServeContent(w, r, name, modTime, f) // handles Range, Content-Type, ETag
}

// handleThumbnail serves a cached 200×200 JPEG thumbnail; lazy-generates on first request.
func (fs *fileServer) handleThumbnail(w http.ResponseWriter, r *http.Request, fileID string) {
	if fileID == "" {
		http.NotFound(w, r)
		return
	}
	thumbPath := fs.thumbCache.Path(fileID)
	if !fs.thumbCache.Exists(fileID) { // lazy-generate: download full file once, then cache
		tmp, err := os.CreateTemp("", "relay-thumb-*")
		if err != nil {
			jsonErr(w, "tmp file: "+err.Error(), 500)
			return
		}
		tmp.Close()
		defer os.Remove(tmp.Name())
		if err := fs.p.Download(fileID, tmp.Name()); err != nil {
			jsonErr(w, "download for thumbnail: "+err.Error(), 500)
			return
		}
		if err := thumbnail.Generate(tmp.Name(), thumbPath); err != nil {
			jsonErr(w, "generate thumbnail: "+err.Error(), 500)
			return
		}
	}
	data, err := os.ReadFile(thumbPath)
	if err != nil {
		jsonErr(w, "read thumbnail: "+err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(data) //nolint:errcheck
}

// handleDelete removes a file from cloud storage.
func (fs *fileServer) handleDelete(w http.ResponseWriter, r *http.Request, fileID string) {
	if err := fs.p.DeleteFile(fileID); err != nil {
		jsonErr(w, "delete: "+err.Error(), 500)
		return
	}
	if maps, err := fs.p.ListFiles(); err == nil { // trigger backup after successful delete
		fs.backup().Trigger(maps)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted", "file_id": fileID}) //nolint:errcheck
}

// requireAuthWithReg validates JWT Bearer token and triggers lazy relay registration on first valid request.
// lr may be nil (disables lazy registration, e.g. if backup already configured at startup).
func requireAuthWithReg(lr *lazyRegistrar, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			jsonErr(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := auth.ValidateJWT(token)
		if err != nil {
			jsonErr(w, "invalid token: "+err.Error(), http.StatusUnauthorized)
			return
		}
		if lr != nil && claims != nil && claims.Sub != "" {
			go lr.tryRegister(claims.Sub) // non-blocking; sync.Once ensures runs exactly once
		}
		next.ServeHTTP(w, r)
	}
}
// corsMiddleware adds CORS headers for Flutter web clients.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
// isCredentialError detects OAuth token errors that should not trigger a crash loop.
// These errors are permanent until credentials are refreshed — retrying is wasteful.
// "no cloud providers available" = fresh install, no users authenticated yet → standby.
func isCredentialError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "invalid_grant") ||
		strings.Contains(s, "Token has been expired or revoked") ||
		strings.Contains(s, "oauth2: cannot fetch token") ||
		strings.Contains(s, "no cloud providers available")
}

func jsonErr(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg}) //nolint:errcheck
}
