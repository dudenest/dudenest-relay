// Package erasure implements Reed-Solomon 6+3 erasure coding for relay blocks.
// A single 8MB chunk is split into 6 data shards + 3 parity shards (9 total).
// Any 6 shards can reconstruct the original data (tolerates 3 cloud failures).
package erasure

import (
	"errors"
	"fmt"

	"github.com/klauspost/reedsolomon"
	"github.com/dudenest/dudenest-relay/pkg/types"
)

// Encoder wraps klauspost/reedsolomon for 6+3 configuration.
type Encoder struct {
	enc reedsolomon.Encoder
}

// New creates a 6+3 Reed-Solomon encoder.
func New() (*Encoder, error) {
	enc, err := reedsolomon.New(types.DataShards, types.ParityShards)
	if err != nil {
		return nil, fmt.Errorf("create RS encoder: %w", err)
	}
	return &Encoder{enc: enc}, nil
}

// Split splits a data chunk into 9 shards (6 data + 3 parity).
// Returns shards of equal size (data is zero-padded to fit if needed).
func (e *Encoder) Split(data []byte) ([][]byte, error) {
	shards, err := e.enc.Split(data)
	if err != nil {
		return nil, fmt.Errorf("split: %w", err)
	}
	if err := e.enc.Encode(shards); err != nil {
		return nil, fmt.Errorf("encode parity: %w", err)
	}
	return shards, nil
}

// Join reconstructs original data from available shards (nil = missing shard).
// originalSize is needed to trim zero-padding added during Split.
func (e *Encoder) Join(shards [][]byte, originalSize int) ([]byte, error) {
	if len(shards) != types.TotalShards {
		return nil, fmt.Errorf("expected %d shards, got %d", types.TotalShards, len(shards))
	}
	// Count available shards
	available := 0
	for _, s := range shards {
		if s != nil {
			available++
		}
	}
	if available < types.DataShards {
		return nil, errors.New("insufficient shards: need at least 6")
	}
	// Reconstruct missing shards
	if err := e.enc.Reconstruct(shards); err != nil {
		return nil, fmt.Errorf("reconstruct: %w", err)
	}
	// Verify integrity
	ok, err := e.enc.Verify(shards)
	if err != nil {
		return nil, fmt.Errorf("verify: %w", err)
	}
	if !ok {
		return nil, errors.New("shard verification failed after reconstruction")
	}
	// Join data shards and trim to originalSize
	result := make([]byte, 0, originalSize)
	for i := 0; i < types.DataShards; i++ {
		result = append(result, shards[i]...)
	}
	if len(result) < originalSize {
		return nil, fmt.Errorf("reconstructed size %d < expected %d", len(result), originalSize)
	}
	return result[:originalSize], nil
}

// ShardSize returns the size of each shard for a given data length.
func ShardSize(dataLen int) int {
	enc, _ := reedsolomon.New(types.DataShards, types.ParityShards)
	shards, _ := enc.Split(make([]byte, dataLen))
	if len(shards) == 0 {
		return 0
	}
	return len(shards[0])
}
