// Package mega implements CloudProvider for MEGA.nz (free 20GB).
package mega

import (
	"fmt"
	"path/filepath"
	"strings"

	gm "github.com/t3rm1n4l/go-mega"
)

// Provider stores blocks on MEGA.nz.
type Provider struct {
	client   *gm.Mega
	rootNode *gm.Node
	basePath string
	email    string
}

// New authenticates with MEGA and returns a Provider.
func New(email, password, basePath string) (*Provider, error) {
	m := gm.New()
	if err := m.Login(email, password); err != nil {
		return nil, fmt.Errorf("mega login: %w", err)
	}
	root, err := m.FS.HashLookup(m.FS.GetRoot())
	if err != nil {
		return nil, fmt.Errorf("mega root: %w", err)
	}
	p := &Provider{client: m, rootNode: root, basePath: basePath, email: email}
	if err := p.ensureDir(basePath); err != nil {
		return nil, fmt.Errorf("mega mkdir base: %w", err)
	}
	return p, nil
}

func (p *Provider) Name() string { return "mega" }

func (p *Provider) Upload(path string, data []byte) error {
	dir := filepath.Dir(filepath.Join(p.basePath, path))
	if err := p.ensureDir(dir); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	parent, err := p.getNode(dir)
	if err != nil {
		return fmt.Errorf("parent node %s: %w", dir, err)
	}
	filename := filepath.Base(path)
	_, err = p.client.UploadFile("", data, filename, parent, nil)
	return err
}

func (p *Provider) Download(path string) ([]byte, error) {
	node, err := p.getNode(filepath.Join(p.basePath, path))
	if err != nil {
		return nil, fmt.Errorf("node %s: %w", path, err)
	}
	return p.client.DownloadFile(node, "")
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

// ensureDir creates the directory path recursively if it doesn't exist.
func (p *Provider) ensureDir(path string) error {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	current := p.rootNode
	for _, part := range parts {
		if part == "" {
			continue
		}
		found := false
		for _, child := range p.client.FS.GetChildren(current) {
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
	current := p.rootNode
	for _, part := range parts {
		if part == "" {
			continue
		}
		found := false
		for _, child := range p.client.FS.GetChildren(current) {
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
