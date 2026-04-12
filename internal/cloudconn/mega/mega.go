// Package mega implements CloudProvider for MEGA.nz (free 20GB).
package mega

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	gm "github.com/t3rm1n4l/go-mega"
)

// Provider stores blocks on MEGA.nz.
type Provider struct {
	email        string
	client   *gm.Mega
	root     *gm.Node
	basePath string
}

// New authenticates with MEGA and returns a Provider.
func New(email, password, basePath string) (*Provider, error) {
	m := gm.New()
	if err := m.Login(email, password); err != nil {
		return nil, fmt.Errorf("mega login: %w", err)
	}
	p := &Provider{email: email, client: m, root: m.FS.GetRoot(), basePath: basePath}
	if err := p.ensureDir(basePath); err != nil {
		return nil, fmt.Errorf("mega mkdir base: %w", err)
	}
	return p, nil
}

func (p *Provider) ID() string { return "mega:" + p.email }

func (p *Provider) Upload(path string, data []byte) error {
	dir := filepath.Dir(filepath.Join(p.basePath, path))
	if err := p.ensureDir(dir); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	parent, err := p.getNode(dir)
	if err != nil {
		return fmt.Errorf("parent node %s: %w", dir, err)
	}
	// MEGA API requires a local file path — write to temp
	tmp, err := os.CreateTemp("", "relay-mega-*.shard")
	if err != nil {
		return fmt.Errorf("tempfile: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	tmp.Close()
	filename := filepath.Base(path)
	_, err = p.client.UploadFile(tmp.Name(), parent, filename, nil)
	return err
}

func (p *Provider) Download(path string) ([]byte, error) {
	node, err := p.getNode(filepath.Join(p.basePath, path))
	if err != nil {
		return nil, fmt.Errorf("node %s: %w", path, err)
	}
	tmp, err := os.CreateTemp("", "relay-mega-dl-*.shard")
	if err != nil {
		return nil, fmt.Errorf("tempfile: %w", err)
	}
	tmpPath := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpPath)
	if err := p.client.DownloadFile(node, tmpPath, nil); err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	return os.ReadFile(tmpPath)
}

func (p *Provider) Delete(path string) error {
	node, err := p.getNode(filepath.Join(p.basePath, path))
	if err != nil {
		return fmt.Errorf("node %s: %w", path, err)
	}
	return p.client.Delete(node, false)
}

func (p *Provider) Available() bool {
	_, err := p.getNode(p.basePath)
	return err == nil
}

// ensureDir creates the directory path recursively.
func (p *Provider) ensureDir(path string) error {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	current := p.root
	for _, part := range parts {
		if part == "" {
			continue
		}
		children, err := p.client.FS.GetChildren(current)
		if err != nil {
			return fmt.Errorf("children: %w", err)
		}
		found := false
		for _, child := range children {
			if child.GetName() == part && child.GetType() == gm.FOLDER {
				current = child
				found = true
				break
			}
		}
		if !found {
			created, err := p.client.CreateDir(part, current)
			if err != nil {
				return fmt.Errorf("mkdir %s: %w", part, err)
			}
			current = created
		}
	}
	return nil
}

// getNode resolves a path string to a MEGA node.
func (p *Provider) getNode(path string) (*gm.Node, error) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	current := p.root
	for _, part := range parts {
		if part == "" {
			continue
		}
		children, err := p.client.FS.GetChildren(current)
		if err != nil {
			return nil, fmt.Errorf("children: %w", err)
		}
		found := false
		for _, child := range children {
			if child.GetName() == part {
				current = child
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("not found: %s", part)
		}
	}
	return current, nil
}
