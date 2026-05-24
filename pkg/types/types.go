// Package types defines core data structures for the dudenest relay.
//
// Storage model (since v0.21.0 cleanup): exactly one strategy — "1 file + N replicas".
// Every uploaded file is stored as a whole (not split) on N independent cloud accounts.
// FileMap.Replicas lists where each copy lives. Download fetches from the first available
// replica; integrity is verified by FileMap.Hash (SHA-256 of the whole plaintext file).
//
// Historical note: pre-v0.21.0 the codebase carried legacy structures from an earlier split-file
// design (Reed-Solomon erasure-encoding). That strategy was abandoned long before public release;
// v0.21.0 removes every remaining trace (types, code paths, terminology, docs) and migrates
// persisted FileMaps to the new schema on first load. The only place where legacy JSON field names
// still appear is `internal/blockmap/legacy_v1_migration.go` (out of necessity — to Unmarshal the
// old wire format). Everywhere else the vocabulary is exclusively "1 file + N replicas".
package types

import "time"

const (
	// Cloud-side folder names under the provider's base folder (default base "dudenest" since v0.10.0).
	// Replica uploads route media → PhotosFolder, everything else → FilesFolder.
	PhotosFolder = "photos" // image/* + video/* MIME types (and ext-fallback for HEIC/MOV/RAW)
	FilesFolder  = "files"  // PDF, archives, documents, anything DetectContentType doesn't classify as media

	// StrategyForeign marks files that the user (or another relay) put on the cloud directly —
	// dudenest indexes them and serves them via CloudID/stream-on-demand without ever owning the bytes.
	// All other files use the implicit replica strategy (FileMap.Replicas is the source of truth).
	StrategyForeign = "Foreign"
)

// Replica represents one copy of a file on one cloud account.
// FileMap.Replicas is a slice of these — one entry per account holding the file.
type Replica struct {
	ID         string    `json:"id"`                 // unique ID for this replica record (e.g. "<file_id>.r0")
	ReplicaIdx int       `json:"replica_idx"`        // 0-based position in FileMap.Replicas (matches slice index at write time; preserved through migrations)
	Size       int64     `json:"size"`               // bytes uploaded to this account (== FileMap.Size in practice; field kept for symmetry + future per-replica compression)
	Location   string    `json:"location"`           // "<provider>:<email>:<relative_path>" — kept for UI/back-compat + as fallback addressing when CloudID is empty
	CloudID    string    `json:"cloud_id,omitempty"` // provider's permanent file ID (Drive file.id, etc.); primary addressing key for Download/Delete/Move when present
	Created    time.Time `json:"created"`
}

// FileMap is the per-file metadata record: identity (FileID, Name, Hash) + list of replicas.
// Persisted as JSON in <configDir>/maps/<file_id>.json. The hub keeps an encrypted backup blob.
type FileMap struct {
	Version      int       `json:"version"`                 // schema version; v0.21.0+ writes Version=2 (Replicas), older relays wrote Version=1 (legacy split format — migrated on load)
	FileID       string    `json:"file_id"`                 // UUID assigned at upload
	Name         string    `json:"name"`                    // original filename
	Size         int64     `json:"size"`                    // original file size in bytes
	Hash         string    `json:"hash"`                    // SHA-256 of entire plaintext file — also the F1 dedup key
	Replicas     []Replica `json:"replicas"`                // copies on N accounts; empty when LogicalAlias != ""
	Created      time.Time `json:"created"`
	Modified     time.Time `json:"modified"`
	LogicalAlias string    `json:"logical_alias,omitempty"` // F1 dedup: if non-empty, this FileMap is a pointer to another FileID (target holds Replicas)
}

// GDriveToken is persisted to ~/.config/dudenest/providers/gdrive_<id>.json.
type GDriveToken struct {
	AccessToken   string    `json:"access_token"`
	TokenType     string    `json:"token_type"`
	RefreshToken  string    `json:"refresh_token"`
	Expiry        time.Time `json:"expiry"`
	Email         string    `json:"email"`
	ProviderID    string    `json:"provider_id"`
	ClientID      string    `json:"client_id,omitempty"`       // which OAuth client issued this token
	LastError     string    `json:"last_error,omitempty"`      // persisted error state (e.g. invalid_grant)
	LastFileCount int64     `json:"last_file_count,omitempty"` // last known file count on this provider (cached for offline display)
}

// CloudProvider interface — implemented by gdrive, mega, onedrive, etc.
type CloudProvider interface {
	ID() string // unique account identifier (e.g. "gdrive:piowin00@gmail.com")
	Upload(path string, data []byte) error
	Download(path string) ([]byte, error)
	Delete(path string) error
	Available() bool // checks quota and connectivity
}

// QuotaReporter is an OPTIONAL sub-interface for providers that can report storage usage.
// Used by Phase β quota polling loop (internal/account.Manager) to keep CloudAccount.QuotaUsedBytes/
// QuotaTotalBytes fresh. Providers that can't report (e.g. local filesystem) just don't implement it;
// the polling loop type-asserts and skips them, leaving quota at 0/0 (which SelectReplicas treats as
// "free space unknown" via the defensive FreeBytes()==0 return).
type QuotaReporter interface {
	Quota() (usedBytes, totalBytes int64, err error)
}

// CloudLister is an OPTIONAL sub-interface for providers that can enumerate their contents.
// Go-idiomatic pattern (like io.ReadSeeker on top of io.Reader): scan engine type-asserts
// (`l, ok := provider.(CloudLister)`) and skips providers that don't support it.
// Implemented by gdrive (P4); mega + local are not implementers today.
// First-level listing only — caller walks recursively by calling List on each IsDir==true Entry.
// The provider handles Drive-API/MEGA-API pagination internally; the returned slice contains all entries under prefix.
type CloudLister interface {
	List(prefix string) ([]Entry, error)
}

// CloudIDDownloader is an OPTIONAL sub-interface for providers that can address files by a
// permanent provider-side ID instead of mutable path. Download/Delete via CloudID survives
// user renames/moves on the cloud side (the same Drive file ID stays valid even if the user
// moves the file in Drive UI). gdrive implements this; other providers add later.
type CloudIDDownloader interface {
	DownloadByID(cloudID string) ([]byte, error)
	DeleteByID(cloudID string) error
}

// CloudIDUploader is an OPTIONAL sub-interface — same as Upload but returns the provider's
// permanent file ID so the pipeline can persist it in the FileMap immediately (no extra path
// lookup later). gdrive returns Drive's file.id from files.create.
type CloudIDUploader interface {
	UploadAndReturnID(path string, data []byte) (cloudID string, err error)
}

// CloudIDResolver is an OPTIONAL sub-interface for lazy/proactive backfill: given a relative
// path, return the provider's permanent file ID. Used to migrate pre-CloudID FileMaps without
// re-uploading data — the file already lives on the cloud, we just need to record its ID.
type CloudIDResolver interface {
	ResolvePathToID(path string) (cloudID string, err error)
}

// CloudMover is an OPTIONAL sub-interface for providers that can move a file between folders
// by ID without re-uploading the data. Used by editable-date logic: when user changes a
// file's date in the meta sheet, dudenest-relay moves the file to the new YYYY/MM date bucket
// without touching the file contents. Drive supports this via files.update(addParents, removeParents).
type CloudMover interface {
	MoveByID(cloudID, newPath string) error
}

// Entry describes a single child of a folder returned by CloudLister.List.
// Path is relative to the provider's base folder (e.g. "photos/abc123" or "photos/abc123/photo.jpg").
// Empty prefix lists the base folder itself; entries returned then have Path == "<name>".
type Entry struct {
	Path    string    `json:"path"`               // relative to provider base; folder children appear as "<prefix>/<name>"
	Name    string    `json:"name"`               // leaf name (the part after the last "/")
	Size    int64     `json:"size"`               // bytes; 0 for folders
	MTime   time.Time `json:"mtime"`              // last-modified at the provider
	IsDir   bool      `json:"is_dir"`             // true for folders (recurse with List(entry.Path))
	CloudID string    `json:"cloud_id,omitempty"` // provider's permanent file ID; Drive uses 28-44 char alphanum; empty for providers that don't expose IDs
}
