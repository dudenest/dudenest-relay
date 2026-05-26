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

	"github.com/dudenest/dudenest-relay/pkg/types"
)

// tokenFile mirrors the JSON structure written by browser.SaveToken.
type tokenFile struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	RefreshToken string    `json:"refresh_token"`
	Expiry       time.Time `json:"expiry"`
}

const legacyBasePath = "dudenest-relay"

// Provider stores files on Google Drive under a single base folder (default "dudenest" since v0.10.0).
// Thread-safe: folderCache protected by mu (parallel replica uploads use same Provider).
// Legacy "dudenest-relay" base is read-only fallback for old FileMaps; new writes stay under baseFolderID.
type Provider struct {
	id           string
	svc          *drive.Service
	baseFolderID string            // single base — basePath as passed to New (default "dudenest")
	folderCache  map[string]string // populated lazily by ensurePath / findPath
	mu           sync.Mutex        // serializes ensurePath — prevents duplicate folder TOCTOU race
}

// New creates a Provider. tokenPath = gdrive_<id>.json, clientSecretPath = client_secret.json.
// basePath is the folder name created under Drive root (e.g. "dudenest" since v0.10.0). Single base only.
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

// Upload creates or overwrites a file at path under the base folder. CloudProvider interface
// requirement — for new code that wants the CloudID, use UploadAndReturnID (P5a additive).
func (p *Provider) Upload(path string, data []byte) error {
	_, err := p.UploadAndReturnID(path, data)
	return err
}

// UploadAndReturnID is the CloudIDUploader sub-interface: same as Upload but returns the
// permanent Drive file ID so the pipeline can persist it in the FileMap (no extra
// path-to-ID lookup at Download time).
//
// Behavior with name collisions: when a file with the same name already exists at the same
// parent folder, we UPDATE in place (preserves the existing CloudID — same ID before/after).
// This matches Drive's "overwrite" semantics and avoids creating duplicate entries for
// re-uploads of the same logical file. For date-bucketed uploads (P5b) two different photos
// named IMG_0001.JPG taken in the same month will land in the same folder; the second
// upload would overwrite the first if names collide. The pipeline-side caller is responsible
// for ensuring filenames are unique within their bucket if it wants both kept (e.g. by
// prefixing with a short content hash) — gdrive doesn't second-guess the caller's intent.
func (p *Provider) UploadAndReturnID(path string, data []byte) (string, error) {
	dir, name := filepath.Dir(path), filepath.Base(path)
	parentID, err := p.ensurePath(dir)
	if err != nil {
		return "", fmt.Errorf("ensure dir %s: %w", dir, err)
	}
	existingID, _ := p.findFile(name, parentID)
	meta := &drive.File{Name: name}
	body := bytes.NewReader(data)
	if existingID != "" {
		f, err := p.svc.Files.Update(existingID, meta).Media(body).Fields("id").Do()
		if err != nil {
			return "", err
		}
		return f.Id, nil
	}
	meta.Parents = []string{parentID}
	f, err := p.svc.Files.Create(meta).Media(body).Fields("id").Do()
	if err != nil {
		return "", err
	}
	return f.Id, nil
}

// Download retrieves file content at path. Uses read-only findPath (does not create folders on miss
// — pre-v0.10.0 this method called ensurePath which silently provisioned empty trees for every missing
// FileMap, leaking folders on Drive).
func (p *Provider) Download(path string) ([]byte, error) {
	fileID, err := p.resolveFilePath(path, true)
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

// Delete removes the file at path. Same read-only findPath as Download — never creates folders.
func (p *Provider) Delete(path string) error {
	fileID, err := p.resolveFilePath(path, false)
	if err != nil {
		return err
	}
	return p.svc.Files.Delete(fileID).Do()
}

// ---- P5a CloudID-based ops (implements CloudIDDownloader / CloudIDUploader / CloudIDResolver / CloudMover) ----

// DownloadByID is one Drive API call (no path → ID lookup needed). Preferred path for FileMaps
// that already have CloudID populated. Survives user-side renames/moves in Drive UI — the ID
// stays valid even if the path our blockmap remembers is stale.
func (p *Provider) DownloadByID(cloudID string) ([]byte, error) {
	resp, err := p.svc.Files.Get(cloudID).Download()
	if err != nil {
		return nil, fmt.Errorf("download id %s: %w", cloudID, err)
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(resp.Body)
	return buf.Bytes(), err
}

// DeleteByID is one Drive API call. Same robustness benefit as DownloadByID.
func (p *Provider) DeleteByID(cloudID string) error {
	return p.svc.Files.Delete(cloudID).Do()
}

// ResolvePathToID is used by the proactive backfill loop at relay startup to migrate
// pre-CloudID FileMaps. Performs the same path walk as findPath + findFile but returns
// the Drive file ID without touching content. Cheap (1-2 Drive API calls per file).
func (p *Provider) ResolvePathToID(path string) (string, error) {
	return p.resolveFilePath(path, false)
}

func (p *Provider) resolveFilePath(path string, allowNameFallback bool) (string, error) {
	dir, name := filepath.Dir(path), filepath.Base(path)
	parentID, err := p.findPath(dir)
	if err == nil {
		if id, ferr := p.findFile(name, parentID); ferr == nil {
			return id, nil
		} else {
			err = fmt.Errorf("find file %s: %w", name, ferr)
		}
	} else {
		err = fmt.Errorf("find dir %s: %w", dir, err)
	}
	legacyParentID, legacyErr := p.findRootPath(dir)
	if legacyErr == nil {
		id, findErr := p.findFile(name, legacyParentID)
		if findErr == nil {
			return id, nil
		}
		legacyErr = fmt.Errorf("find file %s: %w", name, findErr)
	}
	legacyBaseParentID, legacyBaseErr := p.findLegacyBasePath(dir)
	if legacyBaseErr != nil {
		return "", fmt.Errorf("%w; legacy root fallback: %w; legacy base fallback: find dir %s: %w", err, legacyErr, dir, legacyBaseErr)
	}
	id, legacyBaseErr := p.findFile(name, legacyBaseParentID)
	if legacyBaseErr != nil {
		if allowNameFallback {
			if anyID, anyErr := p.findFileAnywhere(name); anyErr == nil {
				return anyID, nil
			}
		}
		return "", fmt.Errorf("%w; legacy root fallback: %w; legacy base fallback: find file %s: %w", err, legacyErr, name, legacyBaseErr)
	}
	return id, nil
}

// MoveByID moves a file from its current parent(s) to the folder identified by newPath
// (creating intermediate folders if missing). The file's CloudID stays the same — only its
// addressable path changes. Used by P5b editable-date logic: when user changes a file's
// effective date, we re-bucket it into <folder>/<YYYY>/<MM>/ without re-uploading content.
//
// Drive's files.update natively supports parent reparenting via addParents + removeParents.
// We:
//  1. ensurePath(newPath) → resolves/creates target folder, returns its ID
//  2. Get current file metadata (specifically the parents field)
//  3. files.update(id, addParents=newParent, removeParents=oldParents)
//
// All in 3 API calls. No data transfer.
func (p *Provider) MoveByID(cloudID, newPath string) error {
	newParentID, err := p.ensurePath(newPath)
	if err != nil {
		return fmt.Errorf("ensure dest %s: %w", newPath, err)
	}
	cur, err := p.svc.Files.Get(cloudID).Fields("parents").Do()
	if err != nil {
		return fmt.Errorf("get parents %s: %w", cloudID, err)
	}
	addParents := newParentID
	removeParents := strings.Join(cur.Parents, ",")
	if removeParents == newParentID {
		return nil
	} // already there — no-op
	_, err = p.svc.Files.Update(cloudID, &drive.File{}).
		AddParents(addParents).
		RemoveParents(removeParents).
		Fields("id, parents").Do()
	return err
}

// Compile-time assertions: Provider implements all four CloudID sub-interfaces in P5a.
var (
	_ types.CloudLister       = (*Provider)(nil)
	_ types.CloudIDDownloader = (*Provider)(nil)
	_ types.CloudIDUploader   = (*Provider)(nil)
	_ types.CloudIDResolver   = (*Provider)(nil)
	_ types.CloudMover        = (*Provider)(nil)
)

// Available checks Drive connectivity by calling About.Get.
func (p *Provider) Available() bool {
	_, err := p.svc.About.Get().Fields("user").Do()
	return err == nil
}

// List implements types.CloudLister — enumerates first-level children of `prefix` under the base folder.
// prefix=="" lists the base folder itself. Caller walks recursively by re-invoking List on each
// returned Entry where IsDir==true. Pagination across Drive API's nextPageToken is handled
// internally; the returned slice contains every entry under prefix (up to several thousand).
//
// Folder vs file distinction: Drive marks folders with mimeType=='application/vnd.google-apps.folder'.
// Returned Entry.Size is 0 for folders and parsed from drive.File.Size for files.
// Entry.MTime sources from drive.File.ModifiedTime (RFC3339).
// Entry.Path is `<prefix>/<name>` (or just `<name>` for prefix=="").
//
// Drive API rate limit is 1000 queries/100s default; a typical first-level listing is 1-2 calls
// even for thousands of files because PageSize=1000. Recursive walking is the caller's responsibility
// and must throttle (P6 user-aware scan-engine throttling).
func (p *Provider) List(prefix string) ([]types.Entry, error) {
	parentID, err := p.findPath(prefix)
	if err != nil {
		return nil, fmt.Errorf("find prefix %q: %w", prefix, err)
	}
	q := fmt.Sprintf("%q in parents and trashed=false", parentID)
	out := make([]types.Entry, 0, 64)
	pageToken := ""
	for {
		call := p.svc.Files.List().Q(q).PageSize(1000).Fields("nextPageToken, files(id, name, mimeType, size, modifiedTime)")
		if pageToken != "" {
			call = call.PageToken(pageToken)
		}
		resp, lerr := call.Do()
		if lerr != nil {
			return nil, fmt.Errorf("list under %q: %w", prefix, lerr)
		}
		for _, f := range resp.Files {
			isDir := f.MimeType == "application/vnd.google-apps.folder"
			childPath := f.Name
			if prefix != "" && prefix != "." {
				childPath = strings.TrimRight(prefix, "/") + "/" + f.Name
			}
			mt, _ := time.Parse(time.RFC3339, f.ModifiedTime) // empty/parse-failure → zero time, callers treat as "unknown"
			out = append(out, types.Entry{
				Path: childPath, Name: f.Name, Size: f.Size, MTime: mt, IsDir: isDir,
				CloudID: f.Id, // P5a: capture permanent Drive file ID for scan engine + backfill use
			})
		}
		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}
	return out, nil
}

// (CloudLister + other compile-time assertions consolidated in P5a `var ( … )` block above.)

// ensurePath resolves dir (relative to base folder), creating folders as needed.
// Used by Upload only — Download/Delete go through findPath (read-only).
// Serialized via write lock for entire traversal — prevents TOCTOU race where
// concurrent goroutines all miss cache and create duplicate GDrive folders.
func (p *Provider) ensurePath(dir string) (string, error) {
	if dir == "" || dir == "." {
		return p.baseFolderID, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if id, ok := p.folderCache[dir]; ok {
		return id, nil
	} // fast path: full path cached
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

// findPath is the read-only counterpart of ensurePath: walks dir under the base folder without
// creating anything. Returns an error if any intermediate folder doesn't exist — callers (Download
// and Delete) propagate this as a clean miss rather than silently creating empty folder trees.
func (p *Provider) findPath(dir string) (string, error) {
	return p.findPathFrom(dir, p.baseFolderID, "")
}

func (p *Provider) findRootPath(dir string) (string, error) {
	return p.findPathFrom(dir, "root", "root:")
}

func (p *Provider) findLegacyBasePath(dir string) (string, error) {
	legacyBaseID, err := p.findFolder(legacyBasePath, "root")
	if err != nil {
		return "", err
	}
	return p.findPathFrom(dir, legacyBaseID, legacyBasePath+":")
}

func (p *Provider) findPathFrom(dir, startID, cachePrefix string) (string, error) {
	if dir == "" || dir == "." {
		return startID, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	cacheKey := cachePrefix + dir
	if id, ok := p.folderCache[cacheKey]; ok {
		return id, nil
	}
	parts := strings.Split(strings.Trim(dir, "/"), "/")
	parentID := startID
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
		key := cachePrefix + accumulated
		if id, ok := p.folderCache[key]; ok {
			parentID = id
			continue
		}
		id, err := p.findFolder(part, parentID)
		if err != nil {
			return "", fmt.Errorf("find folder %s: %w", accumulated, err)
		}
		p.folderCache[key] = id
		parentID = id
	}
	return parentID, nil
}

// findFolder returns the Drive folder ID for name under parentID, error if not found (NEVER creates).
// Read-only counterpart of ensureFolder; used by legacy-base lookups and startup probing.
func (p *Provider) findFolder(name, parentID string) (string, error) {
	q := fmt.Sprintf("name=%q and mimeType='application/vnd.google-apps.folder' and %q in parents and trashed=false", name, parentID)
	list, err := p.svc.Files.List().Q(q).Fields("files(id)").Do()
	if err != nil {
		return "", fmt.Errorf("list folders: %w", err)
	}
	if len(list.Files) == 0 {
		return "", fmt.Errorf("folder not found: %s", name)
	}
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

func (p *Provider) findFileAnywhere(name string) (string, error) {
	q := fmt.Sprintf("name=%q and trashed=false and mimeType!='application/vnd.google-apps.folder'", name)
	list, err := p.svc.Files.List().Q(q).PageSize(10).Fields("files(id)").Do()
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

// Quota implements types.QuotaReporter. Uses Drive's About endpoint to fetch storageQuota.
// Returns (used, total, nil) on success. Drive's "unlimited" quota (Workspace) reports
// limit=0 in the API — we translate that to total=0 (which CloudAccount.FreeBytes()
// defensively treats as "unknown" so SelectReplicas doesn't favor this account blindly).
// Single Drive API call per invocation — safe to call frequently.
func (p *Provider) Quota() (used, total int64, err error) {
	about, err := p.svc.About.Get().Fields("storageQuota").Do()
	if err != nil {
		return 0, 0, fmt.Errorf("about.get: %w", err)
	}
	if about.StorageQuota == nil {
		return 0, 0, nil
	}
	return about.StorageQuota.Usage, about.StorageQuota.Limit, nil
}

// Compile-time assertion that Provider satisfies QuotaReporter — catches signature drift at build.
var _ types.QuotaReporter = (*Provider)(nil)
