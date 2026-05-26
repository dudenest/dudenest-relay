package pipeline

import (
	"bytes"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/dudenest/dudenest-relay/pkg/types"
)

// MockCloud implements types.CloudProvider for testing.
type MockCloud struct {
	name      string
	storage   map[string][]byte
	available bool
}

func NewMockCloud(name string) *MockCloud {
	return &MockCloud{name: name, storage: make(map[string][]byte), available: true}
}

func (m *MockCloud) ID() string                            { return m.name }
func (m *MockCloud) Upload(path string, data []byte) error { m.storage[path] = data; return nil }
func (m *MockCloud) Download(path string) ([]byte, error) {
	if !m.available {
		return nil, fmt.Errorf("cloud %s is offline", m.name)
	}
	data, ok := m.storage[path]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return data, nil
}
func (m *MockCloud) Delete(path string) error { delete(m.storage, path); return nil }
func (m *MockCloud) Available() bool          { return m.available }

func TestReplicaStrategy(t *testing.T) {
	// Setup: 3 clouds, but only 2 replicas are created (limit = 2)
	c1 := NewMockCloud("cloud1")
	c2 := NewMockCloud("cloud2")
	c3 := NewMockCloud("cloud3")
	clouds := []types.CloudProvider{c1, c2, c3}

	key := make([]byte, 32)
	p, _ := New(key, clouds, t.TempDir(), nil)

	content := []byte("secret dudenest data for replica test")
	tmpFile := t.TempDir() + "/test-replica.txt"
	os.WriteFile(tmpFile, content, 0600) //nolint:errcheck

	fm, err := p.Upload(tmpFile)
	if err != nil {
		t.Fatalf("Upload failed: %v", err)
	}

	// max 2 replicas: c1 and c2 should have data, c3 should not
	if len(c1.storage) == 0 || len(c2.storage) == 0 {
		t.Errorf("Data not replicated to first 2 clouds")
	}
	if len(c3.storage) != 0 {
		t.Errorf("Expected c3 to be empty (only 2 replicas)")
	}

	// Simulate failure of primary (c1) — should failover to c2
	c1.available = false
	outPath := t.TempDir() + "/test-replica-out.txt"
	err = p.Download(fm.FileID, outPath)
	if err != nil {
		t.Fatalf("Download failed after c1 failover: %v", err)
	}
	outContent, _ := os.ReadFile(outPath)
	if !bytes.Equal(content, outContent) {
		t.Errorf("Content mismatch: expected %s, got %s", content, outContent)
	}
	fmt.Println("✅ Replica failover test passed (2 replicas, c1 fail → c2 ok)")
}

// TestReplicaRoutesByContentType pins the P2 behavior: image content lands under PhotosFolder,
// non-media under FilesFolder. Both uploads should round-trip via Download (path resolution from
// FileMap.Location must match what Upload wrote). Regression net: if uploadReplica ever stops
// calling mediaFolder() or hard-codes "files/" again, this test fails on the Photos assertion.
func TestReplicaRoutesByContentType(t *testing.T) {
	tmp := t.TempDir()
	c := NewMockCloud("c1")
	key := make([]byte, 32)
	p, _ := New(key, []types.CloudProvider{c}, t.TempDir(), nil)
	// Image upload — PNG magic bytes — must land under "photos/<hash>/..." in MockCloud.storage
	imgPath := tmp + "/photo.png"
	os.WriteFile(imgPath, append(pngHeader, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05), 0o600) //nolint:errcheck
	imgFM, err := p.Upload(imgPath)
	if err != nil {
		t.Fatalf("image Upload: %v", err)
	}
	foundImgPath := ""
	for k := range c.storage {
		if bytes.HasPrefix([]byte(k), []byte("photos/")) {
			foundImgPath = k
			break
		}
	}
	if foundImgPath == "" {
		t.Errorf("image was not stored under photos/ — got keys: %v", keysOf(c.storage))
	}
	// And Download must resolve via the stored Location
	outImg := tmp + "/photo-out.png"
	if err := p.Download(imgFM.FileID, outImg); err != nil {
		t.Fatalf("image Download: %v", err)
	}
	// Non-media upload — text — must land under "files/<hash>/..."
	docPath := tmp + "/note.txt"
	os.WriteFile(docPath, []byte("just text"), 0o600) //nolint:errcheck
	if _, err := p.Upload(docPath); err != nil {
		t.Fatalf("text Upload: %v", err)
	}
	foundDocPath := ""
	for k := range c.storage {
		if bytes.HasPrefix([]byte(k), []byte("files/")) {
			foundDocPath = k
			break
		}
	}
	if foundDocPath == "" {
		t.Errorf("text was not stored under files/ — got keys: %v", keysOf(c.storage))
	}
}

// keysOf is a small helper used by TestReplicaRoutesByContentType for error messages.
func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestReplicaSingleProvider(t *testing.T) {
	// Edge case: only 1 provider available — should still work
	c1 := NewMockCloud("cloud1")
	key := make([]byte, 32)
	p, _ := New(key, []types.CloudProvider{c1}, t.TempDir(), nil)

	content := []byte("single provider test")
	tmpFile := t.TempDir() + "/single.txt"
	os.WriteFile(tmpFile, content, 0600) //nolint:errcheck

	fm, err := p.Upload(tmpFile)
	if err != nil {
		t.Fatalf("Upload with 1 provider failed: %v", err)
	}
	outPath := t.TempDir() + "/single-out.txt"
	if err := p.Download(fm.FileID, outPath); err != nil {
		t.Fatalf("Download with 1 provider failed: %v", err)
	}
	got, _ := os.ReadFile(outPath)
	if !bytes.Equal(content, got) {
		t.Errorf("Content mismatch")
	}
	fmt.Println("✅ Single provider replica test passed")
}

func TestDownloadForeignFileWithoutHash(t *testing.T) {
	c := NewMockCloud("cloud1")
	content := []byte("foreign cloud file")
	c.storage["files/report.txt"] = content
	p, _ := New(make([]byte, 32), []types.CloudProvider{c}, t.TempDir(), nil)
	if err := p.RegisterForeign("cloud1", "cloud-id-1", "report.txt", "files/report.txt", int64(len(content)), time.Now().UTC()); err != nil {
		t.Fatalf("RegisterForeign: %v", err)
	}
	out := t.TempDir() + "/report.txt"
	if err := p.Download("foreign-cloud-id-1", out); err != nil {
		t.Fatalf("Download foreign without hash: %v", err)
	}
	got, _ := os.ReadFile(out)
	if !bytes.Equal(got, content) {
		t.Fatalf("content mismatch: %q", got)
	}
}
