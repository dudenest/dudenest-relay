package pipeline

import (
	"bytes"
	"fmt"
	"os"
	"testing"

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

func (m *MockCloud) ID() string                             { return m.name }
func (m *MockCloud) Upload(path string, data []byte) error  { m.storage[path] = data; return nil }
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
	p, _ := New(key, clouds, t.TempDir())

	content := []byte("secret dudenest data for replica test")
	tmpFile := t.TempDir() + "/test-replica.txt"
	os.WriteFile(tmpFile, content, 0600) //nolint:errcheck

	fm, err := p.Upload(tmpFile, types.StrategyReplica)
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

func TestReplicaSingleProvider(t *testing.T) {
	// Edge case: only 1 provider available — should still work
	c1 := NewMockCloud("cloud1")
	key := make([]byte, 32)
	p, _ := New(key, []types.CloudProvider{c1}, t.TempDir())

	content := []byte("single provider test")
	tmpFile := t.TempDir() + "/single.txt"
	os.WriteFile(tmpFile, content, 0600) //nolint:errcheck

	fm, err := p.Upload(tmpFile, types.StrategyReplica)
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
