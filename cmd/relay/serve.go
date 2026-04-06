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

	"github.com/dudenest/dudenest-relay/internal/browser"
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
	authSrv := browser.NewServer(authDisplay, serveListen, browser.BuildAuthURL(cfg), cfg, authConfigDir)
	mux := http.NewServeMux()
	authSrv.RegisterRoutes(mux)
	fs := &fileServer{p: p}
	mux.HandleFunc("/files", fs.handleList)
	mux.HandleFunc("/files/", fs.handleFile)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }) //nolint:errcheck
	fmt.Printf("relay serve listening on %s (provider: %s)\n", serveListen, provider)
	return http.ListenAndServe(serveListen, mux)
}

// fileServer handles /files/* endpoints using the pipeline.
type fileServer struct{ p interface {
	Upload(filePath string) (*types.FileMap, error)
	Download(fileID, outputPath string) error
	ListFiles() ([]*types.FileMap, error)
	DeleteFile(fileID string) error
} }

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

// handleFile dispatches /files/{id} and /files/upload.
func (fs *fileServer) handleFile(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/files/")
	switch {
	case path == "upload" && r.Method == http.MethodPost:
		fs.handleUpload(w, r)
	case path != "" && r.Method == http.MethodGet:
		fs.handleDownload(w, r, path)
	case path != "" && r.Method == http.MethodDelete:
		fs.handleDelete(w, r, path)
	default:
		http.NotFound(w, r)
	}
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
	tmp, err := os.CreateTemp("", "relay-upload-*-"+header.Filename)
	if err != nil {
		jsonErr(w, "tmp file: "+err.Error(), 500)
		return
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, f); err != nil {
		tmp.Close()
		jsonErr(w, "write tmp: "+err.Error(), 500)
		return
	}
	tmp.Close()
	fm, err := fs.p.Upload(tmp.Name())
	if err != nil {
		jsonErr(w, "upload: "+err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"file_id": fm.FileID,
		"name":    header.Filename,
		"size":    fm.Size,
		"hash":    fm.Hash,
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

// handleDelete removes a file from cloud storage.
func (fs *fileServer) handleDelete(w http.ResponseWriter, r *http.Request, fileID string) {
	if err := fs.p.DeleteFile(fileID); err != nil {
		jsonErr(w, "delete: "+err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted", "file_id": fileID}) //nolint:errcheck
}

func jsonErr(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg}) //nolint:errcheck
}
