package main

import (
	"testing"

	"github.com/dudenest/dudenest-relay/pkg/types"
)

// TestFolderFromFileMap regresses the Phase α (v0.17.2) classification bug where the
// PathRoot prefix (default "dudenest/") caused new uploads to be misclassified as Files
// in the Flutter UI even though their cloud-side path was dudenest/photos/2026/05/foo.jpg.
//
// The Location format produced by uploadReplica is:
//
//	"<provider_id>:<path>"
//
// where <provider_id> contains a colon ("gdrive:darek@x.com"), so the full string is
// "gdrive:darek@x.com:dudenest/photos/2026/05/foo.jpg".
//
// Three formats exist depending on the writer version — the classifier must handle all.
func TestFolderFromFileMap(t *testing.T) {
	cases := []struct {
		name     string
		location string
		want     string
	}{
		{
			name:     "Phase α format (v0.17.2+) with PathRoot — photo",
			location: "gdrive:darek@x.com:dudenest/photos/2026/05/IMG_001.jpg",
			want:     types.PhotosFolder,
		},
		{
			name:     "Phase α format (v0.17.2+) with PathRoot — file",
			location: "gdrive:darek@x.com:dudenest/files/2026/05/report.pdf",
			want:     types.FilesFolder,
		},
		{
			name:     "v0.11.0..v0.17.1 format (no PathRoot) — photo",
			location: "gdrive:darek@x.com:photos/2026/05/IMG_001.jpg",
			want:     types.PhotosFolder,
		},
		{
			name:     "v0.11.0..v0.17.1 format (no PathRoot) — file",
			location: "gdrive:darek@x.com:files/2026/05/report.pdf",
			want:     types.FilesFolder,
		},
		{
			name:     "pre-v0.11.0 legacy hash-based — always files",
			location: "gdrive:darek@x.com:files/c0759f6b/0/0",
			want:     types.FilesFolder,
		},
		{
			name:     "MEGA provider with PathRoot",
			location: "mega:me@mega.nz:dudenest/photos/2026/05/IMG.jpg",
			want:     types.PhotosFolder,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fm := &types.FileMap{
				Chunks: []types.ChunkMeta{{
					Shards: []types.Block{{Location: tc.location}},
				}},
			}
			if got := folderFromFileMap(fm); got != tc.want {
				t.Errorf("location=%q: got %q, want %q", tc.location, got, tc.want)
			}
		})
	}
}

// TestFolderFromFileMap_EmptyOrInvalid: defensive cases that must default to Files
// (the pre-v0.11.0 behavior when nothing better is known).
func TestFolderFromFileMap_EmptyOrInvalid(t *testing.T) {
	cases := []struct {
		name string
		fm   *types.FileMap
	}{
		{"no chunks", &types.FileMap{}},
		{"chunks without shards", &types.FileMap{Chunks: []types.ChunkMeta{{}}}},
		{"empty location", &types.FileMap{Chunks: []types.ChunkMeta{{Shards: []types.Block{{Location: ""}}}}}},
		{"non-recognizable", &types.FileMap{Chunks: []types.ChunkMeta{{Shards: []types.Block{{Location: "weird-format-no-colons-no-slashes"}}}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := folderFromFileMap(tc.fm); got != types.FilesFolder {
				t.Errorf("expected default FilesFolder, got %q", got)
			}
		})
	}
}
