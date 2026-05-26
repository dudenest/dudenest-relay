package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/dudenest/dudenest-relay/internal/account"
	"github.com/dudenest/dudenest-relay/internal/thumbnail"
	"github.com/dudenest/dudenest-relay/pkg/types"
)

type manifestPipeline struct{ files []*types.FileMap }

func (p *manifestPipeline) Upload(string) (*types.FileMap, error)     { return nil, nil }
func (p *manifestPipeline) Download(string, string) error             { return nil }
func (p *manifestPipeline) ListFiles() ([]*types.FileMap, error)      { return p.files, nil }
func (p *manifestPipeline) GetFileMap(string) (*types.FileMap, error) { return nil, nil }
func (p *manifestPipeline) DeleteFile(string) error                   { return nil }
func (p *manifestPipeline) MoveFile(string, string) error             { return nil }
func (p *manifestPipeline) AccountManager() *account.Manager          { return nil }

func TestHandleManifestRevisionAndUnchanged(t *testing.T) {
	tc, err := thumbnail.NewCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fs := &fileServer{p: &manifestPipeline{files: []*types.FileMap{{
		FileID: "f1", Name: "photo.jpg", Size: 123, Hash: "h1", Created: time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC),
		Replicas: []types.Replica{{Location: "gdrive:a@b:dudenest/photos/2026/05/photo.jpg"}},
	}}}, thumbCache: tc, metaDir: filepath.Join(t.TempDir(), "meta")}

	req := httptest.NewRequest(http.MethodGet, "/files/manifest", nil)
	rec := httptest.NewRecorder()
	fs.handleManifest(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var first map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	rev, _ := first["revision"].(string)
	if rev == "" {
		t.Fatal("revision missing")
	}
	if first["unchanged"] == true {
		t.Fatal("first response must include files")
	}
	if got := len(first["files"].([]any)); got != 1 {
		t.Fatalf("files=%d", got)
	}

	req = httptest.NewRequest(http.MethodGet, "/files/manifest?since="+rev, nil)
	rec = httptest.NewRecorder()
	fs.handleManifest(rec, req)
	var second map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &second); err != nil {
		t.Fatal(err)
	}
	if second["unchanged"] != true {
		t.Fatalf("want unchanged=true, got %#v", second["unchanged"])
	}
	if got := len(second["files"].([]any)); got != 0 {
		t.Fatalf("files=%d", got)
	}
}
