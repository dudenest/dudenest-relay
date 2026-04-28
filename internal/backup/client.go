// Package backup sends relay state snapshots to dudenest-backup service.
// Triggered after every upload/delete; client-side debounce: 3s.
// Server-side debounce: 5s (backup service). Silent no-op if env not set.
package backup

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dudenest/dudenest-relay/internal/crypto"
	"github.com/dudenest/dudenest-relay/pkg/types"
)

// Client sends encrypted relay state to dudenest-backup.
type Client struct {
	url       string
	relayID   string
	secret    string
	enc       *crypto.Encryptor
	configDir string
	mu        sync.Mutex
	timer     *time.Timer
}

// New creates a backup client from env vars (BACKUP_URL, RELAY_ID, RELAY_SECRET).
// Returns nil if any var is missing — backup silently disabled.
func New(masterKey []byte, configDir string) *Client {
	url := os.Getenv("BACKUP_URL")
	relayID := os.Getenv("RELAY_ID")
	secret := os.Getenv("RELAY_SECRET")
	if url == "" || relayID == "" || secret == "" {
		log.Println("backup: BACKUP_URL/RELAY_ID/RELAY_SECRET not set — backup disabled")
		return nil
	}
	enc, err := crypto.New(masterKey)
	if err != nil {
		log.Printf("backup: crypto init: %v — backup disabled", err)
		return nil
	}
	log.Printf("backup: client ready → %s (relay_id=%s)", url, relayID)
	return &Client{url: url, relayID: relayID, secret: secret, enc: enc, configDir: configDir}
}

// Trigger schedules a backup with 3s client-side debounce.
// Safe to call on nil (backup disabled). Resets timer on each call.
func (c *Client) Trigger(maps []*types.FileMap) {
	if c == nil {
		return
	}
	mapsCopy := make([]*types.FileMap, len(maps))
	copy(mapsCopy, maps)
	c.mu.Lock()
	if c.timer != nil {
		c.timer.Stop()
	}
	c.timer = time.AfterFunc(3*time.Second, func() {
		if err := c.send(mapsCopy); err != nil {
			log.Printf("backup: send failed: %v", err)
		}
	})
	c.mu.Unlock()
}

// backupRequest matches dudenest-backup POST /relay/backup body.
type backupRequest struct {
	MapsJSON      string   `json:"maps_json"`
	ProvidersEnc  []byte   `json:"providers_enc"`
	ProviderIDs   []string `json:"provider_ids"`
	BackupVersion int64    `json:"backup_version"`
}

func (c *Client) send(maps []*types.FileMap) error {
	mapsJSON, err := json.Marshal(maps)
	if err != nil {
		return fmt.Errorf("marshal maps: %w", err)
	}
	provTokens, providerIDs, err := c.readProviderTokens()
	if err != nil {
		log.Printf("backup: read tokens: %v (continuing without encrypted tokens)", err)
	}
	var providersEnc []byte
	if len(provTokens) > 0 {
		if providersEnc, err = c.enc.Encrypt("relay-providers-v1", provTokens); err != nil {
			return fmt.Errorf("encrypt tokens: %w", err)
		}
	}
	body, err := json.Marshal(backupRequest{
		MapsJSON:      string(mapsJSON),
		ProvidersEnc:  providersEnc,
		ProviderIDs:   providerIDs,
		BackupVersion: time.Now().UnixMilli(),
	})
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, c.url+"/relay/backup", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Relay-ID", c.relayID)
	req.Header.Set("X-Relay-Secret", c.secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("http post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("unexpected status %d from backup service", resp.StatusCode)
	}
	log.Printf("backup: snapshot sent (%d maps, %d providers) → HTTP %d", len(maps), len(providerIDs), resp.StatusCode)
	return nil
}

// readProviderTokens reads all gdrive_*.json token files from configDir/providers.
// Returns (tokensJSON, providerIDs, error). tokensJSON is nil if no tokens found.
func (c *Client) readProviderTokens() ([]byte, []string, error) {
	dir := filepath.Join(c.configDir, "providers")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	tokens := map[string]json.RawMessage{}
	var ids []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			log.Printf("backup: skip token %s: %v", e.Name(), err)
			continue
		}
		tokens[e.Name()] = data
		ids = append(ids, strings.TrimSuffix(e.Name(), ".json")) // gdrive_email@... → display id
	}
	if len(tokens) == 0 {
		return nil, nil, nil
	}
	b, err := json.Marshal(tokens)
	return b, ids, err
}
