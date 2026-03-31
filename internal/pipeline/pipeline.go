// Package pipeline orchestrates chunk → encrypt → erasure-code → upload and reverse.
package pipeline

import (
	"fmt"
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
		for j, shard := range shards {
			blockID := fmt.Sprintf("%s.%d.%d", fm.FileID, i, j)
			encrypted, err := p.enc.Encrypt(blockID, shard)
			if err != nil {
				return nil, fmt.Errorf("encrypt chunk %d shard %d: %w", i, j, err)
			}
			cloudPath := fmt.Sprintf("blocks/%s/%d/%d", meta.Hash[:8], i, j)
			if err := p.cloud.Upload(cloudPath, encrypted); err != nil {
				return nil, fmt.Errorf("upload chunk %d shard %d: %w", i, j, err)
			}
			meta.Shards = append(meta.Shards, types.Block{
				ID:       blockID,
				ShardIdx: j,
				Size:     int64(len(encrypted)),
				Location: fmt.Sprintf("%s:%s", p.cloud.Name(), cloudPath),
				Created:  time.Now().UTC(),
			})
		}
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
		shards := make([][]byte, types.TotalShards)
		for _, block := range meta.Shards {
			// Parse location: "provider:cloudPath"
			cloudPath := parseCloudPath(block.Location)
			data, err := p.cloud.Download(cloudPath)
			if err != nil {
				// shard unavailable — leave nil (RS will reconstruct)
				continue
			}
			plainShard, err := p.enc.Decrypt(block.ID, data)
			if err != nil {
				continue // corrupted shard — RS will handle
			}
			shards[block.ShardIdx] = plainShard
		}
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

func parseCloudPath(location string) string {
	for i, c := range location {
		if c == ':' {
			return location[i+1:]
		}
	}
	return location
}
