// Package pipeline orchestrates chunk → encrypt → erasure-code → upload and reverse.
package pipeline

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/dudenest/dudenest-relay/internal/blockmap"
	"github.com/dudenest/dudenest-relay/internal/blockstore"
	"github.com/dudenest/dudenest-relay/internal/crypto"
	"github.com/dudenest/dudenest-relay/internal/erasure"
	"github.com/dudenest/dudenest-relay/pkg/types"
)

// Pipeline ties together all relay components.
type Pipeline struct {
	enc      *crypto.Encryptor
	rs       *erasure.Encoder
	bm       *blockmap.Manager
	cloud    types.CloudProvider
	chunkSz  int
}

// New creates a pipeline with a master key and cloud provider.
func New(masterKey []byte, cloud types.CloudProvider, mapStorePath string) (*Pipeline, error) {
	enc, err := crypto.New(masterKey)
	if err != nil {
		return nil, fmt.Errorf("crypto init: %w", err)
	}
	rs, err := erasure.New()
	if err != nil {
		return nil, fmt.Errorf("erasure init: %w", err)
	}
	return &Pipeline{
		enc:     enc,
		rs:      rs,
		bm:      blockmap.New(mapStorePath),
		cloud:   cloud,
		chunkSz: types.ChunkSize,
	}, nil
}

// Upload chunks, encrypts, erasure-codes and uploads a file. Returns FileMap.
// Shards within each chunk are uploaded in parallel (goroutines).
func (p *Pipeline) Upload(filePath string) (*types.FileMap, error) {
	fm, err := blockmap.NewFileMap(filePath)
	if err != nil {
		return nil, fmt.Errorf("new filemap: %w", err)
	}
	metas, chunks, err := blockstore.ChunkFile(filePath, p.chunkSz)
	if err != nil {
		return nil, fmt.Errorf("chunk: %w", err)
	}
	for i, chunk := range chunks {
		shards, err := p.rs.Split(chunk)
		if err != nil {
			return nil, fmt.Errorf("chunk %d split: %w", i, err)
		}
		meta := &metas[i]
		blocks := make([]types.Block, len(shards)) // pre-allocated, index-safe for goroutines
		errs := make([]error, len(shards))
		var wg sync.WaitGroup
		for j, shard := range shards {
			wg.Add(1)
			go func(j int, shard []byte) {
				defer wg.Done()
				blockID := fmt.Sprintf("%s.%d.%d", fm.FileID, i, j)
				encrypted, encErr := p.enc.Encrypt(blockID, shard)
				if encErr != nil {
					errs[j] = fmt.Errorf("encrypt chunk %d shard %d: %w", i, j, encErr)
					return
				}
				cloudPath := fmt.Sprintf("blocks/%s/%d/%d", meta.Hash[:8], i, j)
				if upErr := p.cloud.Upload(cloudPath, encrypted); upErr != nil {
					errs[j] = fmt.Errorf("upload chunk %d shard %d: %w", i, j, upErr)
					return
				}
				blocks[j] = types.Block{
					ID:       blockID,
					ShardIdx: j,
					Size:     int64(len(encrypted)),
					Location: fmt.Sprintf("%s:%s", p.cloud.Name(), cloudPath),
					Created:  time.Now().UTC(),
				}
			}(j, shard)
		}
		wg.Wait()
		for j, e := range errs {
			if e != nil {
				return nil, fmt.Errorf("chunk %d shard %d: %w", i, j, e)
			}
		}
		meta.Shards = blocks
		fm.Chunks = append(fm.Chunks, metas[i])
	}
	if err := p.bm.Save(fm); err != nil {
		return nil, fmt.Errorf("save filemap: %w", err)
	}
	return fm, nil
}

// Download retrieves, decrypts, and reassembles a file from its FileMap.
// Shards within each chunk are downloaded in parallel (goroutines).
func (p *Pipeline) Download(fileID, outputPath string) error {
	fm, err := p.bm.Load(fileID)
	if err != nil {
		return fmt.Errorf("load filemap: %w", err)
	}
	var allChunks [][]byte
	for _, meta := range fm.Chunks {
		shards := make([][]byte, types.TotalShards) // index-safe, each goroutine writes distinct idx
		var mu sync.Mutex                           // protects nothing critical — shards[idx] distinct
		var wg sync.WaitGroup
		for _, block := range meta.Shards {
			wg.Add(1)
			go func(block types.Block) {
				defer wg.Done()
				cloudPath := parseCloudPath(block.Location)
				data, dlErr := p.cloud.Download(cloudPath)
				if dlErr != nil {
					return // shard unavailable — RS reconstructs from remaining
				}
				plainShard, decErr := p.enc.Decrypt(block.ID, data)
				if decErr != nil {
					return // corrupted shard — RS handles
				}
				_ = mu // suppress unused warning; shards[idx] writes are non-overlapping
				shards[block.ShardIdx] = plainShard
			}(block)
		}
		wg.Wait()
		chunk, err := p.rs.Join(shards, int(meta.Size))
		if err != nil {
			return fmt.Errorf("reconstruct chunk %d: %w", meta.Index, err)
		}
		allChunks = append(allChunks, chunk)
	}
	if err := blockstore.ReassembleFile(outputPath, allChunks); err != nil {
		return fmt.Errorf("reassemble: %w", err)
	}
	if err := blockmap.Verify(outputPath, fm); err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	return nil
}

// ListFiles returns all uploaded FileMaps from local storage.
func (p *Pipeline) ListFiles() ([]*types.FileMap, error) {
	return p.bm.List()
}

// DeleteFile removes all cloud blocks for a file and its local FileMap.
func (p *Pipeline) DeleteFile(fileID string) error {
	fm, err := p.bm.Load(fileID)
	if err != nil {
		return fmt.Errorf("load filemap: %w", err)
	}
	var firstErr error
	for _, meta := range fm.Chunks {
		for _, block := range meta.Shards {
			cloudPath := parseCloudPath(block.Location)
			if err := p.cloud.Delete(cloudPath); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("delete shard %s: %w", block.ID, err)
			}
		}
	}
	mapPath := fmt.Sprintf("%s/%s.json", p.bm.StorePath(), fileID)
	os.Remove(mapPath) //nolint:errcheck
	return firstErr
}

func parseCloudPath(location string) string {
	for i, c := range location {
		if c == ':' {
			return location[i+1:]
		}
	}
	return location
}
