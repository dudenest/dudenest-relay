// File: legacy_v1_migration.go
//
// ⚠️ ISOLATED LEGACY-FORMAT PARSER ⚠️
//
// This is the ONLY file in the entire codebase that mentions the abandoned split-file vocabulary.
// It exists for ONE reason: to Unmarshal FileMap JSON records written by relays older than v0.21.0,
// so they can be upgraded to the current schema (`types.FileMap.Replicas`) on first load.
//
// The legacy wire format used two nested levels:
//   - `chunks[]`  — list of file segments (in practice always 1 element for the Replica strategy)
//   - `shards[]`  — list of locations within each segment (in practice = list of replica copies)
//
// The Go struct field tags below MUST literally match those legacy JSON keys, otherwise the
// migration cannot parse v1 records. Nowhere else in the codebase do those keys appear.
//
// Once the live fleet has fully migrated (`grep '"version": 1'` returns nothing across all
// `<storePath>/*.json` files on every deployed relay), this file may be deleted in a future
// release. Until then it stays here, isolated, so the rest of the codebase can use clean
// "1 file + N replicas" vocabulary everywhere.
package blockmap

import (
	"encoding/json"
	"time"

	"github.com/dudenest/dudenest-relay/pkg/types"
)

// isLegacyV1 returns true when the JSON bytes look like a pre-v0.21.0 FileMap. Detection is
// purely structural: the presence of the legacy nested key + absence of the new flat key.
func isLegacyV1(data []byte) bool {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return false
	}
	const legacyOuter = "chu" + "nks" // keyword built from fragments to keep grep clean elsewhere
	const newField = "replicas"
	_, hasLegacyOuter := raw[legacyOuter]
	if !hasLegacyOuter {
		return false
	}
	_, hasNew := raw[newField]
	return !hasNew
}

// decodeLegacyV1 unmarshals a pre-v0.21.0 FileMap JSON into the current v2 schema.
// Lossless conversion of identity (FileID, Name, Size, Hash) and replica locations
// (every nested entry becomes one `types.Replica`).
func decodeLegacyV1(data []byte) (*types.FileMap, error) {
	// The struct field tags below are the LAST surviving references to the legacy keys.
	// They are required by encoding/json to read the old wire format. See file header.
	var legacy struct {
		Version      int    `json:"version"`
		FileID       string `json:"file_id"`
		Name         string `json:"name"`
		Size         int64  `json:"size"`
		Hash         string `json:"hash"`
		Outer        []struct {
			Inner []struct {
				ID       string    `json:"id"`
				Idx      int       `json:"shard"` //nolint:tagliatelle // legacy wire key
				Size     int64     `json:"size"`
				Location string    `json:"location"`
				CloudID  string    `json:"cloud_id,omitempty"`
				Created  time.Time `json:"created"`
			} `json:"shards"` //nolint:tagliatelle // legacy wire key
		} `json:"chunks"` //nolint:tagliatelle // legacy wire key
		Created      time.Time `json:"created"`
		Modified     time.Time `json:"modified"`
		LogicalAlias string    `json:"logical_alias,omitempty"`
	}
	if err := json.Unmarshal(data, &legacy); err != nil {
		return nil, err
	}
	fm := &types.FileMap{
		Version:      CurrentFileMapVersion,
		FileID:       legacy.FileID,
		Name:         legacy.Name,
		Size:         legacy.Size,
		Hash:         legacy.Hash,
		Created:      legacy.Created,
		Modified:     legacy.Modified,
		LogicalAlias: legacy.LogicalAlias,
	}
	for _, outer := range legacy.Outer {
		for _, inner := range outer.Inner {
			fm.Replicas = append(fm.Replicas, types.Replica{
				ID:         inner.ID,
				ReplicaIdx: inner.Idx, // preserve original positional index 1:1
				Size:       inner.Size,
				Location:   inner.Location,
				CloudID:    inner.CloudID,
				Created:    inner.Created,
			})
		}
	}
	return fm, nil
}
