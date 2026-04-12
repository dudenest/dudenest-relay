// Package pipeline orchestrates chunk → encrypt → erasure-code → upload and reverse.
package pipeline

import (
	"fmt"
	"strings"
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
	enc     *crypto.Encryptor
	rs      *erasure.Encoder
	bm      *blockmap.Manager
	clouds  []types.CloudProvider // multiple providers for Replica strategy
	chunkSz int
}

// New creates a pipeline with a master key and cloud providers.
func New(masterKey []byte, clouds []types.CloudProvider, mapStorePath string) (*Pipeline, error) {
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
		clouds:  clouds,
		chunkSz: types.ChunkSize,
	}, nil
}

// Upload chunks, encrypts and stores a file using selected strategy.
func (p *Pipeline) Upload(filePath string, strategy string) (*types.FileMap, error) {
	fm, err := blockmap.NewFileMap(filePath)
	if err != nil {
		return nil, fmt.Errorf("new filemap: %w", err)
	}
	fm.Strategy = strategy
	if strategy == types.StrategyReplica {
		return p.uploadReplica(fm, filePath)
	}
	return p.uploadChunking(fm, filePath)
}

func (p *Pipeline) uploadChunking(fm *types.FileMap, filePath string) (*types.FileMap, error) {
	metas, chunks, err := blockstore.ChunkFile(filePath, p.chunkSz)
	if err != nil {
		return nil, fmt.Errorf("chunk: %w", err)
	}
	cloud := p.clouds[0] // Default to first cloud for legacy chunking
	for i, chunk := range chunks {
		shards, err := p.rs.Split(chunk)
		if err != nil {
			return nil, fmt.Errorf("chunk %d split: %w", i, err)
		}
		meta := &metas[i]
		blocks := make([]types.Block, len(shards))
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
				if upErr := cloud.Upload(cloudPath, encrypted); upErr != nil {
					errs[j] = fmt.Errorf("upload chunk %d shard %d: %w", i, j, upErr)
					return
				}
				blocks[j] = types.Block{
					ID: blockID, ShardIdx: j, Size: int64(len(encrypted)),
					Location: fmt.Sprintf("%s:%s", cloud.ID(), cloudPath), Created: time.Now().UTC(),
				}
			}(j, shard)
		}
		wg.Wait()
		for _, e := range errs {
			if e != nil {
				return nil, e
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

func (p *Pipeline) uploadReplica(fm *types.FileMap, filePath string) (*types.FileMap, error) {
	metas, chunks, err := blockstore.ChunkFile(filePath, p.chunkSz)
	if err != nil {
		return nil, fmt.Errorf("chunk: %w", err)
	}
	if len(p.clouds) < 3 {
		return nil, fmt.Errorf("replica strategy requires at least 3 cloud providers, got %d", len(p.clouds))
	}
	for i, chunk := range chunks {
		meta := &metas[i]
		blocks := make([]types.Block, 3) // 1 main + 2 backups
		errs := make([]error, 3)
		var wg sync.WaitGroup
		for j := 0; j < 3; j++ {
			wg.Add(1)
			go func(j int) {
				defer wg.Done()
				cloud := p.clouds[j]
				blockID := fmt.Sprintf("%s.%d.r%d", fm.FileID, i, j)
				encrypted, encErr := p.enc.Encrypt(blockID, chunk)
				if encErr != nil {
					errs[j] = encErr
					return
				}
				cloudPath := fmt.Sprintf("replicas/%s/%d/r%d", meta.Hash[:8], i, j)
				if upErr := cloud.Upload(cloudPath, encrypted); upErr != nil {
					errs[j] = upErr
					return
				}
				blocks[j] = types.Block{
					ID: blockID, ShardIdx: j, Size: int64(len(encrypted)),
					Location: fmt.Sprintf("%s:%s", cloud.ID(), cloudPath), Created: time.Now().UTC(),
				}
			}(j)
		}
		wg.Wait()
		for _, e := range errs {
			if e != nil {
				return nil, e
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
func (p *Pipeline) Download(fileID, outputPath string) error {
	fm, err := p.bm.Load(fileID)
	if err != nil {
		return fmt.Errorf("load filemap: %w", err)
	}
	var allChunks [][]byte
	for _, meta := range fm.Chunks {
		var chunk []byte
		if fm.Strategy == types.StrategyReplica {
			chunk, err = p.downloadReplica(meta)
		} else {
			chunk, err = p.downloadChunking(meta)
		}
		if err != nil {
			return fmt.Errorf("chunk %d: %w", meta.Index, err)
		}
		allChunks = append(allChunks, chunk)
	}
	if err := blockstore.ReassembleFile(outputPath, allChunks); err != nil {
		return fmt.Errorf("reassemble: %w", err)
	}
	return blockmap.Verify(outputPath, fm)
}

func (p *Pipeline) downloadChunking(meta types.ChunkMeta) ([]byte, error) {
	shards := make([][]byte, types.TotalShards)
	var wg sync.WaitGroup
	for _, block := range meta.Shards {
		wg.Add(1)
		go func(block types.Block) {
			defer wg.Done()
			cloud := p.getCloudByName(block.Location)
			if cloud == nil {
				return
			}
			data, dlErr := cloud.Download(parseCloudPath(block.Location))
			if dlErr != nil {
				return
			}
			plain, decErr := p.enc.Decrypt(block.ID, data)
			if decErr == nil {
				shards[block.ShardIdx] = plain
			}
		}(block)
	}
	wg.Wait()
	return p.rs.Join(shards, int(meta.Size))
}

func (p *Pipeline) downloadReplica(meta types.ChunkMeta) ([]byte, error) {
	var lastErr error
	for _, block := range meta.Shards { // Replicas are stored in meta.Shards
		cloud := p.getCloudByName(block.Location)
		if cloud == nil {
			continue
		}
		data, dlErr := cloud.Download(parseCloudPath(block.Location))
		if dlErr != nil {
			lastErr = dlErr
			continue
		}
		plain, decErr := p.enc.Decrypt(block.ID, data)
		if decErr != nil {
			lastErr = decErr
			continue
		}
		return plain, nil // Success — return first available replica
	}
	return nil, fmt.Errorf("all replicas unavailable: %v", lastErr)
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
			cloud := p.getCloudByName(block.Location)
			if cloud == nil {
				continue
			}
			if err := cloud.Delete(parseCloudPath(block.Location)); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("delete block %s: %w", block.ID, err)
			}
		}
	}
	return firstErr
}

func (p *Pipeline) getCloudByName(location string) types.CloudProvider {
	parts := strings.Split(location, ":")
	if len(parts) < 2 {
		return nil
	}
	id := parts[0] + ":" + parts[1] // e.g. "gdrive:piowin00@gmail.com"
	for _, c := range p.clouds {
		if c.ID() == id {
			return c
		}
	}
	// Fallback for legacy "local" or "mega" without email in ID
	for _, c := range p.clouds {
		if c.ID() == parts[0] {
			return c
		}
	}
	return nil
}

func parseCloudPath(location string) string {
	parts := strings.Split(location, ":")
	if len(parts) > 2 {
		return parts[2]
	}
	if len(parts) == 2 {
		return parts[1]
	}
	return location
}
