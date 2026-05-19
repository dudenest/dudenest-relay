// Package types defines core data structures for the dudenest relay.
package types

import "time"

const (
	ChunkSize    = 8 * 1024 * 1024 // 8MB — optimal for cloud APIs
	DataShards   = 6                // Reed-Solomon data shards
	ParityShards = 3                // Reed-Solomon parity shards (survive 3 cloud failures)
	TotalShards  = DataShards + ParityShards

	StrategyChunking = "Chunking"
	StrategyReplica  = "Replica"
	StrategyForeign  = "Foreign" // P5c: file is indexed but lives on the cloud where the user (or another relay) put it; we never uploaded it, we just point at it via CloudID and stream-on-demand

	// Cloud-side folder names under the provider's base folder (default base "dudenest" since v0.10.0).
	// P2 of Photos/Files redesign: replica uploads route media → PhotosFolder, everything else → FilesFolder.
	// Chunked uploads (legacy) keep using "blocks/..." regardless of content type (see uploadChunking).
	PhotosFolder = "photos" // image/* + video/* MIME types (and ext-fallback for HEIC/MOV/RAW)
	FilesFolder  = "files"  // PDF, archives, documents, anything DetectContentType doesn't classify as media
)

// Block represents a single encrypted+erasure-coded chunk stored in the cloud.
type Block struct {
	ID       string    `json:"id"`                  // SHA-256 of original plaintext chunk
	ShardIdx int       `json:"shard"`               // 0-8 (0-5 data, 6-8 parity) or 0-2 for Replica
	Size     int64     `json:"size"`                // encrypted shard size in bytes
	Location string    `json:"location"`            // cloud provider + path (e.g. "gdrive:abc@gmail.com:photos/2026/05/IMG.jpg") — kept for back-compat + UI display; with CloudID set, addressing prefers the ID and Location is informational
	CloudID  string    `json:"cloud_id,omitempty"`  // P5a: provider's permanent file ID; primary addressing key for Download/Delete/Move when available
	Created  time.Time `json:"created"`
}

// ChunkMeta describes one logical chunk of the original file.
type ChunkMeta struct {
	Index  int     `json:"index"`   // 0-based chunk number
	Offset int64   `json:"offset"`  // byte offset in original file
	Size   int64   `json:"size"`    // original plaintext size
	Hash   string  `json:"hash"`    // SHA-256 of plaintext chunk
	Shards []Block `json:"shards"`  // 9 shards per chunk (6+3) OR 3 replicas
}

// FileMap is the complete block map for a file — stored encrypted on cloud.
type FileMap struct {
	Version   int         `json:"version"`   // schema version
	FileID    string      `json:"file_id"`   // UUID assigned at upload
	Strategy  string      `json:"strategy"`  // Chunking or Replica
	Name      string      `json:"name"`      // original filename
	Size      int64       `json:"size"`      // original file size in bytes
	Hash      string      `json:"hash"`      // SHA-256 of entire file
	ChunkSize int         `json:"chunk_size"` // bytes per chunk
	Chunks    []ChunkMeta `json:"chunks"`
	Created   time.Time   `json:"created"`
	Modified  time.Time   `json:"modified"`
}
// GDriveToken is persisted to ~/.config/dudenest/providers/gdrive_<id>.json.
type GDriveToken struct {
	AccessToken   string    `json:"access_token"`
	TokenType     string    `json:"token_type"`
	RefreshToken  string    `json:"refresh_token"`
	Expiry        time.Time `json:"expiry"`
	Email         string    `json:"email"`
	ProviderID    string    `json:"provider_id"`
	ClientID      string    `json:"client_id,omitempty"`      // which OAuth client issued this token
	LastError     string    `json:"last_error,omitempty"`     // persisted error state (e.g. invalid_grant)
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
// moves the file in Drive UI). gdrive implements this in P5; other providers add later.
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
// by ID without re-uploading the data. Used by P5b editable-date logic: when user changes a
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
	CloudID string    `json:"cloud_id,omitempty"` // P5: provider's permanent file ID; Drive uses 28-44 char alphanum; empty for providers that don't expose IDs
}

// EncryptedBlock is the wire format stored on the cloud provider.
// Layout: [12B nonce][ciphertext][16B GCM tag]
type EncryptedBlock struct {
	Nonce      []byte // 12 bytes, random per block
	Ciphertext []byte // shard data + GCM tag
}
