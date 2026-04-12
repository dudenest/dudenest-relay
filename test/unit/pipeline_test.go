package unit

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/dudenest/dudenest-relay/internal/cloudconn/local"
	"github.com/dudenest/dudenest-relay/internal/crypto"
	"github.com/dudenest/dudenest-relay/internal/erasure"
	"github.com/dudenest/dudenest-relay/internal/pipeline"
	"github.com/dudenest/dudenest-relay/pkg/types"
)

func TestCrypto(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key) //nolint:errcheck
	enc, err := crypto.New(key)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("hello dudenest relay — AES-256-GCM test")
	cipher, err := enc.Encrypt("block-001", plaintext)
	if err != nil {
		t.Fatal("encrypt:", err)
	}
	decoded, err := enc.Decrypt("block-001", cipher)
	if err != nil {
		t.Fatal("decrypt:", err)
	}
	if string(decoded) != string(plaintext) {
		t.Fatalf("got %q, want %q", decoded, plaintext)
	}
}

func TestErasure(t *testing.T) {
	enc, err := erasure.New()
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 1*1024*1024) // 1MB test
	rand.Read(data)                    //nolint:errcheck
	shards, err := enc.Split(data)
	if err != nil {
		t.Fatal("split:", err)
	}
	if len(shards) != 9 {
		t.Fatalf("expected 9 shards, got %d", len(shards))
	}
	// Simulate losing 3 shards (max tolerable)
	shards[1] = nil
	shards[4] = nil
	shards[7] = nil
	recovered, err := enc.Join(shards, len(data))
	if err != nil {
		t.Fatal("join:", err)
	}
	if len(recovered) != len(data) {
		t.Fatalf("size mismatch: got %d, want %d", len(recovered), len(data))
	}
	for i := range data {
		if recovered[i] != data[i] {
			t.Fatalf("data mismatch at byte %d", i)
		}
	}
}

func TestPipeline(t *testing.T) {
	tmp := t.TempDir()
	// Create test file (16MB — 2 chunks of 8MB)
	testFile := filepath.Join(tmp, "testdata.bin")
	testData := make([]byte, 16*1024*1024)
	rand.Read(testData) //nolint:errcheck
	if err := os.WriteFile(testFile, testData, 0600); err != nil {
		t.Fatal(err)
	}
	key := crypto.DeriveKeyFromPassword("test-password", "test-salt")
	cloud := local.New(filepath.Join(tmp, "cloud"))
	p, err := pipeline.New(key, []types.CloudProvider{cloud}, filepath.Join(tmp, "maps"))
	if err != nil {
		t.Fatal(err)
	}
	fm, err := p.Upload(testFile, types.StrategyChunking)
	if err != nil {
		t.Fatal("upload:", err)
	}
	if len(fm.Chunks) != 2 {
		t.Fatalf("expected 2 chunks, got %d", len(fm.Chunks))
	}
	outputFile := filepath.Join(tmp, "recovered.bin")
	if err := p.Download(fm.FileID, outputFile); err != nil {
		t.Fatal("download:", err)
	}
	recovered, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(recovered) != len(testData) {
		t.Fatalf("size mismatch: got %d, want %d", len(recovered), len(testData))
	}
	for i := range testData {
		if recovered[i] != testData[i] {
			t.Fatalf("data mismatch at byte %d", i)
		}
	}
	t.Logf("✅ Pipeline test passed: 16MB file, 2 chunks, 18 shards, upload+download+verify OK")
}
