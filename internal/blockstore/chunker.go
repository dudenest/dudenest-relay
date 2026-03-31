// Package blockstore handles file chunking and reassembly.
package blockstore

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/dudenest/dudenest-relay/pkg/types"
)

// ChunkFile splits a file into fixed-size chunks and returns their metadata.
// Does NOT encrypt or upload — returns raw chunk bytes for the pipeline.
func ChunkFile(path string, chunkSize int) ([]types.ChunkMeta, [][]byte, error) {
	if chunkSize <= 0 {
		chunkSize = types.ChunkSize
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	var metas []types.ChunkMeta
	var chunks [][]byte
	buf := make([]byte, chunkSize)
	offset := int64(0)
	idx := 0
	for {
		n, err := io.ReadFull(f, buf)
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			h := sha256.Sum256(data)
			metas = append(metas, types.ChunkMeta{
				Index:  idx,
				Offset: offset,
				Size:   int64(n),
				Hash:   hex.EncodeToString(h[:]),
			})
			chunks = append(chunks, data)
			offset += int64(n)
			idx++
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("read chunk %d: %w", idx, err)
		}
	}
	return metas, chunks, nil
}

// ReassembleFile writes chunks to an output file in order.
func ReassembleFile(path string, chunks [][]byte) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()
	for i, chunk := range chunks {
		if _, err := f.Write(chunk); err != nil {
			return fmt.Errorf("write chunk %d: %w", i, err)
		}
	}
	return nil
}

// HashFile returns SHA-256 hex hash of a file.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
