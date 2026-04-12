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
)

// Block represents a single encrypted+erasure-coded chunk stored in the cloud.
type Block struct {
	ID       string    `json:"id"`       // SHA-256 of original plaintext chunk
	ShardIdx int       `json:"shard"`    // 0-8 (0-5 data, 6-8 parity) or 0-2 for Replica
	Size     int64     `json:"size"`     // encrypted shard size in bytes
	Location string    `json:"location"` // cloud provider + path (e.g. "gdrive:/blocks/abc123.0")
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
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	RefreshToken string    `json:"refresh_token"`
	Expiry       time.Time `json:"expiry"`
	Email        string    `json:"email"`
	ProviderID   string    `json:"provider_id"`
	ClientID     string    `json:"client_id,omitempty"` // which OAuth client issued this token
}

// CloudProvider interface — implemented by gdrive, mega, onedrive, etc.
type CloudProvider interface {
	ID() string // unique account identifier (e.g. "gdrive:piowin00@gmail.com")
	Upload(path string, data []byte) error
	Download(path string) ([]byte, error)
	Delete(path string) error
	Available() bool // checks quota and connectivity
}

// EncryptedBlock is the wire format stored on the cloud provider.
// Layout: [12B nonce][ciphertext][16B GCM tag]
type EncryptedBlock struct {
	Nonce      []byte // 12 bytes, random per block
	Ciphertext []byte // shard data + GCM tag
}
