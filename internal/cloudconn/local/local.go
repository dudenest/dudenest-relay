// Package local implements CloudProvider for local filesystem storage.
// Used for PoC testing without real cloud credentials.
package local

import (
	"fmt"
	"os"
	"path/filepath"
)

// Provider stores blocks on the local filesystem (PoC/testing only).
type Provider struct {
	basePath string
}

func New(basePath string) *Provider {
	os.MkdirAll(basePath, 0700) //nolint:errcheck
	return &Provider{basePath: basePath}
}

func (p *Provider) ID() string { return "local" }

func (p *Provider) Upload(path string, data []byte) error {
	full := filepath.Join(p.basePath, path)
	if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	return os.WriteFile(full, data, 0600)
}

func (p *Provider) Download(path string) ([]byte, error) {
	return os.ReadFile(filepath.Join(p.basePath, path))
}

func (p *Provider) Delete(path string) error {
	return os.Remove(filepath.Join(p.basePath, path))
}

func (p *Provider) Available() bool {
	_, err := os.Stat(p.basePath)
	return err == nil
}
