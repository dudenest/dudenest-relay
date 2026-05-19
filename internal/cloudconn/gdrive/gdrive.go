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

// legacyBasePath is the v0.6.x..v0.9.x folder name used before the v0.10.0 rename to "dudenest".
// Provider looks it up at startup (without creating it) and uses it as a read-only fallback for
// Download/Delete so existing files on relay-poc (uploaded before v0.10.0) keep working without migration.
// See PHOTOS-FILES-REDESIGN.md §3.1 (option B — read-alias forever).
const legacyBasePath = "dudenest-relay"

// Provider stores blocks on Google Drive in a dedicated app folder tree.
// Thread-safe: folderCache protected by mu (parallel shard uploads use same Provider).
// folderCache keys are prefixed "P:" (primary base) or "L:" (legacy base) so the two trees never collide.
type Provider struct {
	id                 string
	svc                *drive.Service
	baseFolderID       string // primary base — current basePath (default "dudenest"). All Upload goes here.
	legacyBaseFolderID string // optional — set if a "dudenest-relay" folder exists at Drive root from pre-v0.10.0 installs. "" means no legacy content.
	folderCache        map[string]string
	mu                 sync.Mutex // serializes ensurePath — prevents duplicate folder TOCTOU race
}

// New creates a Provider. tokenPath = gdrive_<id>.json, clientSecretPath = client_secret.json.
// basePath is the folder name created under Drive root (e.g. "dudenest" since v0.10.0).
// If a legacy "dudenest-relay" folder exists from older installs, its ID is captured for read-only fallback.
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
	if basePath != legacyBasePath { // only worth checking when current basePath differs from legacy (avoid pointless API call on first install)
		p.legacyBaseFolderID, _ = p.findFolder(legacyBasePath, "root") // best-effort; "" means none — read-alias becomes no-op
	}
	return p, nil
}

func (p *Provider) ID() string { return p.id }

// Upload creates or overwrites a file at path under the PRIMARY base folder.
// New uploads NEVER land in the legacy "dudenest-relay" tree — the rename is forward-only.
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

// Download retrieves file content at path. Searches primary base first; on miss, falls back to
// the legacy "dudenest-relay" base (if it exists) so pre-v0.10.0 uploaded files keep resolving.
func (p *Provider) Download(path string) ([]byte, error) {
	fileID, _, err := p.resolveFile(path)
	if err != nil {
		return nil, err
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

// Delete removes the file at path. Same primary→legacy fallback as Download so deletes of pre-v0.10.0
// files work too (e.g. user removes a photo that lives at the old layout from the Flutter app).
func (p *Provider) Delete(path string) error {
	fileID, _, err := p.resolveFile(path)
	if err != nil {
		return err
	}
	return p.svc.Files.Delete(fileID).Do()
}

// resolveFile finds a file's Drive ID by relative path, trying the primary base first
// then the legacy base (if present). Returns (fileID, baseUsed, error) — baseUsed is
// "primary" or "legacy", useful for logging/telemetry.
func (p *Provider) resolveFile(path string) (string, string, error) {
	dir, name := filepath.Dir(path), filepath.Base(path)
	// Primary base — look up dir without creating new folders (a Download/Delete for a missing path should NOT silently provision an empty tree on every miss).
	if parentID, err := p.findPath(dir, p.baseFolderID, "P"); err == nil {
		if fileID, err := p.findFile(name, parentID); err == nil {
			return fileID, "primary", nil
		}
	}
	// Legacy fallback — only if a "dudenest-relay" folder was found at startup.
	if p.legacyBaseFolderID != "" {
		if parentID, err := p.findPath(dir, p.legacyBaseFolderID, "L"); err == nil {
			if fileID, err := p.findFile(name, parentID); err == nil {
				return fileID, "legacy", nil
			}
		}
	}
	return "", "", fmt.Errorf("not found in primary or legacy base: %s", path)
}

// Available checks Drive connectivity by calling About.Get.
func (p *Provider) Available() bool {
	_, err := p.svc.About.Get().Fields("user").Do()
	return err == nil
}

// ensurePath resolves dir (relative to PRIMARY base folder), creating folders as needed.
// Used by Upload only — Download/Delete go through findPath (read-only).
// Serialized via write lock for entire traversal — prevents TOCTOU race where
// concurrent goroutines all miss cache and create duplicate GDrive folders.
// Cache keys are prefixed "P:" to avoid collisions with legacy-base lookups.
func (p *Provider) ensurePath(dir string) (string, error) {
	if dir == "" || dir == "." {
		return p.baseFolderID, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	cacheKey := "P:" + dir
	if id, ok := p.folderCache[cacheKey]; ok { return id, nil } // fast path: full path cached
	parts := strings.Split(strings.Trim(dir, "/"), "/")
	parentID := p.baseFolderID
	accumulated := ""
	for _, part := range parts {
		if part == "" || part == "." { continue }
		if accumulated != "" { accumulated += "/" + part } else { accumulated = part }
		partialKey := "P:" + accumulated
		if id, ok := p.folderCache[partialKey]; ok { // partial path cached
			parentID = id
			continue
		}
		id, err := p.ensureFolder(part, parentID)
		if err != nil { return "", fmt.Errorf("folder %s: %w", accumulated, err) }
		p.folderCache[partialKey] = id
		parentID = id
	}
	return parentID, nil
}

// findPath is the read-only counterpart of ensurePath: walks dir under the given base folder
// without creating anything. Returns an error if any intermediate folder doesn't exist,
// signalling a miss the caller can then retry against another base (legacy fallback).
// cachePrefix differentiates primary ("P") vs legacy ("L") cached results.
func (p *Provider) findPath(dir, baseID, cachePrefix string) (string, error) {
	if dir == "" || dir == "." { return baseID, nil }
	p.mu.Lock()
	defer p.mu.Unlock()
	cacheKey := cachePrefix + ":" + dir
	if id, ok := p.folderCache[cacheKey]; ok { return id, nil }
	parts := strings.Split(strings.Trim(dir, "/"), "/")
	parentID := baseID
	accumulated := ""
	for _, part := range parts {
		if part == "" || part == "." { continue }
		if accumulated != "" { accumulated += "/" + part } else { accumulated = part }
		partialKey := cachePrefix + ":" + accumulated
		if id, ok := p.folderCache[partialKey]; ok {
			parentID = id
			continue
		}
		id, err := p.findFolder(part, parentID)
		if err != nil { return "", fmt.Errorf("find folder %s: %w", accumulated, err) }
		p.folderCache[partialKey] = id
		parentID = id
	}
	return parentID, nil
}

// findFolder returns the Drive folder ID for name under parentID, error if not found (NEVER creates).
// Read-only counterpart of ensureFolder; used by legacy-base lookups and startup probing.
func (p *Provider) findFolder(name, parentID string) (string, error) {
	q := fmt.Sprintf("name=%q and mimeType='application/vnd.google-apps.folder' and %q in parents and trashed=false", name, parentID)
	list, err := p.svc.Files.List().Q(q).Fields("files(id)").Do()
	if err != nil { return "", fmt.Errorf("list folders: %w", err) }
	if len(list.Files) == 0 { return "", fmt.Errorf("folder not found: %s", name) }
	return list.Files[0].Id, nil
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
