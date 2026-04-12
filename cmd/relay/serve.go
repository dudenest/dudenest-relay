// serve.go — combined HTTP server: file API + browser auth API.
// relay serve --key <key> --provider gdrive --gdrive-token <path> --listen 0.0.0.0:8086
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/oauth2"

	"github.com/dudenest/dudenest-relay/internal/auth"
	"github.com/dudenest/dudenest-relay/internal/browser"

	"github.com/dudenest/dudenest-relay/internal/thumbnail"
	"github.com/dudenest/dudenest-relay/internal/ws"
	"github.com/dudenest/dudenest-relay/internal/pipeline"
	"github.com/dudenest/dudenest-relay/pkg/types"
)

var serveListen string

func serveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start combined HTTP server: file API + browser auth API",
		RunE:  runServe,
	}
	home, _ := os.UserHomeDir()
	cmd.Flags().StringVar(&serveListen, "listen", "0.0.0.0:8086", "HTTP listen address")
	cmd.Flags().StringVar(&authClientSecret, "client-secret", filepath.Join(home, ".config/dudenest/gdrive_client_secret.json"), "Path to Google OAuth2 client_secret.json")
	cmd.Flags().StringVar(&authConfigDir, "config-dir", filepath.Join(home, ".config/dudenest"), "Path to dudenest config directory")
	cmd.Flags().StringVar(&authDisplay, "display", ":99", "X display for Chromium (TigerVNC)")
	return cmd
}

func runServe(cmd *cobra.Command, args []string) error {
	p, err := getPipeline()
	if err != nil {
		return fmt.Errorf("pipeline init: %w", err)
	}
	cs, err := browser.LoadClientSecret(authClientSecret)
	if err != nil {
		return fmt.Errorf("load client_secret: %w", err)
	}
	cfg := browser.BuildOAuthConfig(cs)
	var webCfg *oauth2.Config // web client for https://dudenest.com/auth callbacks (Flutter web)
	if id, secret := os.Getenv("GDRIVE_WEB_CLIENT_ID"), os.Getenv("GDRIVE_WEB_CLIENT_SECRET"); id != "" && secret != "" {
		webCfg = browser.BuildWebOAuthConfig(id, secret)
		fmt.Println("relay serve: web OAuth client loaded (GDRIVE_WEB_CLIENT_ID)")
	}
	wsHub := ws.NewHub() // WebSocket hub: Flutter connects here, relay sends auth_request messages
	authSrv := browser.NewServer(authDisplay, serveListen, browser.BuildAuthURL(cfg), cfg, webCfg, authConfigDir, wsHub)
	tc, err := thumbnail.NewCache(authConfigDir)
	if err != nil {
		return fmt.Errorf("thumbnail cache: %w", err)
	}
	mux := http.NewServeMux()
	authSrv.RegisterRoutes(mux)
	mux.Handle("/ws", wsHub) // WebSocket: Flutter connects for relay→Flutter auth requests
	fs := &fileServer{p: p, thumbCache: tc}
	mux.HandleFunc("/files", requireAuth(fs.handleList))
	mux.HandleFunc("/files/", requireAuth(fs.handleFile))
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }) //nolint:errcheck

	fmt.Printf("relay serve listening on %s (provider: %s, ws: /ws)\n", serveListen, provider)
	return http.ListenAndServe(serveListen, corsMiddleware(mux))
}

// fileServer handles /files/* endpoints using the pipeline.
type fileServer struct {
	p interface {
		Upload(filePath string, strategy string) (*types.FileMap, error)
		Download(fileID, outputPath string) error
		ListFiles() ([]*types.FileMap, error)
		DeleteFile(fileID string) error
	}
	thumbCache *thumbnail.Cache
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
	fm, err := fs.p.(*pipeline.Pipeline).ListFiles() // This is a bit inefficient, but Pipeline doesn't have Load() exposed in interface yet
	if err != nil {
		jsonErr(w, "list maps: "+err.Error(), 500)
		return
	}
	var found *types.FileMap
	for _, m := range fm {
		if m.FileID == fileID {
			found = m
			break
		}
	}
	if found == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(found) //nolint:errcheck
}
// handleUpload accepts multipart/form-data with field "file", uploads via pipeline.
func (fs *fileServer) handleUpload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(32 << 20); err != nil { // 32MB memory buffer
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
	if strategy == "" { strategy = types.StrategyChunking }
	fm, err := fs.p.Upload(tmpPath, strategy)
	if err != nil {
		jsonErr(w, "upload: "+err.Error(), 500)
		return
	}
	if fs.thumbCache != nil { // generate thumbnail while local file still exists
		thumbnail.Generate(tmpPath, fs.thumbCache.Path(fm.FileID)) //nolint:errcheck
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"file_id": fm.FileID,
		"name":    header.Filename,
		"size":    fm.Size,
		"hash":    fm.Hash,
		"strategy": fm.Strategy,
		"chunks":  len(fm.Chunks),
	})
}

// handleDownload reassembles a file and streams it back.
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
	data, err := os.ReadFile(tmp.Name())
	if err != nil {
		jsonErr(w, "read tmp: "+err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment")
	w.Write(data) //nolint:errcheck
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
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted", "file_id": fileID}) //nolint:errcheck
	}

	// requireAuth validates JWT Bearer token from dudenest-backend.
	func requireAuth(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				jsonErr(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			token := strings.TrimPrefix(authHeader, "Bearer ")
			_, err := auth.ValidateJWT(token)
			if err != nil {
				jsonErr(w, "invalid token: "+err.Error(), http.StatusUnauthorized)
				return
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
func jsonErr(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg}) //nolint:errcheck
}
