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
	// 1. Setup 3 mock clouds
	c1 := NewMockCloud("cloud1")
	c2 := NewMockCloud("cloud2")
	c3 := NewMockCloud("cloud3")
	clouds := []types.CloudProvider{c1, c2, c3}

	// 2. Setup pipeline
	key := make([]byte, 32)
	p, _ := New(key, clouds, "/tmp/dudenest-test-maps")
	defer os.RemoveAll("/tmp/dudenest-test-maps")

	// 3. Create dummy file
	content := []byte("secret dudenest data for replica test")
	tmpFile := "/tmp/test-replica.txt"
	os.WriteFile(tmpFile, content, 0600)
	defer os.Remove(tmpFile)

	// 4. Upload using Replica strategy
	fm, err := p.Upload(tmpFile, types.StrategyReplica)
	if err != nil {
		t.Fatalf("Upload failed: %v", err)
	}

	// 5. Verify it's on all 3 clouds
	if len(c1.storage) == 0 || len(c2.storage) == 0 || len(c3.storage) == 0 {
		t.Errorf("Data not replicated across all clouds")
	}

	// 6. Simulate failure of Cloud 1 and Cloud 2
	c1.available = false
	c2.available = false

	// 7. Download and verify it still works (should failover to Cloud 3)
	outPath := "/tmp/test-replica-out.txt"
	err = p.Download(fm.FileID, outPath)
	if err != nil {
		t.Fatalf("Download failed after failover: %v", err)
	}
	defer os.Remove(outPath)

	outContent, _ := os.ReadFile(outPath)
	if !bytes.Equal(content, outContent) {
		t.Errorf("Content mismatch: expected %s, got %s", content, outContent)
	}
	
	fmt.Println("✅ Replica failover test passed")
}
