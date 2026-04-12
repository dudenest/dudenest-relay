// Package gdrive implements CloudProvider backed by Google Drive.
// Uses oauth2 refresh token from ~/.config/dudenest/providers/gdrive_<id>.json.
package gdrive

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/drive/v3"
	"google.golang.org/api/option"
)

// tokenFile mirrors the JSON structure written by browser.SaveToken.
type tokenFile struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	RefreshToken string    `json:"refresh_token"`
	Expiry       time.Time `json:"expiry"`
}

// Provider stores blocks on Google Drive in a dedicated app folder tree.
// Thread-safe: folderCache protected by mu (parallel shard uploads use same Provider).
type Provider struct {
	id           string
	svc          *drive.Service
	baseFolderID string
	folderCache  map[string]string
	mu           sync.Mutex // serializes ensurePath — prevents duplicate folder TOCTOU race
}

// New creates a Provider. tokenPath = gdrive_<id>.json, clientSecretPath = client_secret.json.
// basePath is the folder name created under Drive root (e.g. "dudenest-relay").
func New(id, tokenPath, clientSecretPath, basePath string) (*Provider, error) {
	tok, err := loadToken(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("load token: %w", err)
	}
	secretData, err := os.ReadFile(clientSecretPath)
	if err != nil {
		return nil, fmt.Errorf("read client_secret: %w", err)
	}
	cfg, err := google.ConfigFromJSON(secretData, drive.DriveFileScope)
	if err != nil {
		return nil, fmt.Errorf("parse client_secret: %w", err)
	}
	ctx := context.Background()
	client := cfg.Client(ctx, tok) // auto-refreshes via refresh_token
	svc, err := drive.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, fmt.Errorf("drive service: %w", err)
	}
	p := &Provider{id: id, svc: svc, folderCache: make(map[string]string)}
	p.baseFolderID, err = p.ensureFolder(basePath, "root")
	if err != nil {
		return nil, fmt.Errorf("ensure base folder %q: %w", basePath, err)
	}
	return p, nil
}

func (p *Provider) ID() string { return p.id }

// Upload creates or overwrites a file at path under the base folder.
func (p *Provider) Upload(path string, data []byte) error {
	dir, name := filepath.Dir(path), filepath.Base(path)
	parentID, err := p.ensurePath(dir)
	if err != nil {
		return fmt.Errorf("ensure dir %s: %w", dir, err)
	}
	// Check if file already exists — update instead of create (avoid duplicates).
	existingID, _ := p.findFile(name, parentID)
	meta := &drive.File{Name: name}
	body := bytes.NewReader(data)
	if existingID != "" {
		_, err = p.svc.Files.Update(existingID, meta).Media(body).Do()
	} else {
		meta.Parents = []string{parentID}
		_, err = p.svc.Files.Create(meta).Media(body).Do()
	}
	return err
}

// Download retrieves file content at path.
func (p *Provider) Download(path string) ([]byte, error) {
	dir, name := filepath.Dir(path), filepath.Base(path)
	parentID, err := p.ensurePath(dir)
	if err != nil {
		return nil, fmt.Errorf("find dir %s: %w", dir, err)
	}
	fileID, err := p.findFile(name, parentID)
	if err != nil {
		return nil, fmt.Errorf("find file %s: %w", name, err)
	}
	resp, err := p.svc.Files.Get(fileID).Download()
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", path, err)
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(resp.Body)
	return buf.Bytes(), err
}

// Delete removes the file at path.
func (p *Provider) Delete(path string) error {
	dir, name := filepath.Dir(path), filepath.Base(path)
	parentID, err := p.ensurePath(dir)
	if err != nil {
		return fmt.Errorf("find dir %s: %w", dir, err)
	}
	fileID, err := p.findFile(name, parentID)
	if err != nil {
		return fmt.Errorf("find file %s: %w", name, err)
	}
	return p.svc.Files.Delete(fileID).Do()
}

// Available checks Drive connectivity by calling About.Get.
func (p *Provider) Available() bool {
	_, err := p.svc.About.Get().Fields("user").Do()
	return err == nil
}

// ensurePath resolves dir (relative to base folder) creating folders as needed.
// Serialized via write lock for entire traversal — prevents TOCTOU race where
// concurrent goroutines all miss cache and create duplicate GDrive folders.
func (p *Provider) ensurePath(dir string) (string, error) {
	if dir == "" || dir == "." {
		return p.baseFolderID, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if id, ok := p.folderCache[dir]; ok { // fast path: full path cached
		return id, nil
	}
	parts := strings.Split(strings.Trim(dir, "/"), "/")
	parentID := p.baseFolderID
	accumulated := ""
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if accumulated != "" {
			accumulated += "/" + part
		} else {
			accumulated = part
		}
		if id, ok := p.folderCache[accumulated]; ok { // partial path cached
			parentID = id
			continue
		}
		id, err := p.ensureFolder(part, parentID)
		if err != nil {
			return "", fmt.Errorf("folder %s: %w", accumulated, err)
		}
		p.folderCache[accumulated] = id
		parentID = id
	}
	return parentID, nil
}

// ensureFolder returns the Drive folder ID for name under parentID, creating it if absent.
func (p *Provider) ensureFolder(name, parentID string) (string, error) {
	q := fmt.Sprintf("name=%q and mimeType='application/vnd.google-apps.folder' and %q in parents and trashed=false", name, parentID)
	list, err := p.svc.Files.List().Q(q).Fields("files(id)").Do()
	if err != nil {
		return "", fmt.Errorf("list folders: %w", err)
	}
	if len(list.Files) > 0 {
		return list.Files[0].Id, nil
	}
	f := &drive.File{
		Name:     name,
		MimeType: "application/vnd.google-apps.folder",
		Parents:  []string{parentID},
	}
	created, err := p.svc.Files.Create(f).Fields("id").Do()
	if err != nil {
		return "", fmt.Errorf("create folder %s: %w", name, err)
	}
	return created.Id, nil
}

// findFile returns the Drive file ID for name in parentID, error if not found.
func (p *Provider) findFile(name, parentID string) (string, error) {
	q := fmt.Sprintf("name=%q and %q in parents and trashed=false and mimeType!='application/vnd.google-apps.folder'", name, parentID)
	list, err := p.svc.Files.List().Q(q).Fields("files(id)").Do()
	if err != nil {
		return "", fmt.Errorf("list files: %w", err)
	}
	if len(list.Files) == 0 {
		return "", fmt.Errorf("not found: %s", name)
	}
	return list.Files[0].Id, nil
}

// loadToken reads a gdrive_<id>.json and converts it to an oauth2.Token.
func loadToken(path string) (*oauth2.Token, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var tf tokenFile
	if err := json.Unmarshal(data, &tf); err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}
	return &oauth2.Token{
		AccessToken:  tf.AccessToken,
		TokenType:    tf.TokenType,
		RefreshToken: tf.RefreshToken,
		Expiry:       tf.Expiry,
	}, nil
}
