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
	debounce  time.Duration // client-side debounce before sending snapshot
	mu        sync.Mutex
	timer     *time.Timer
}

// New creates a backup client.
// backupURL: base URL of dudenest-backup (e.g. "https://backup.dudenest.com").
// debounce: client-side delay before sending snapshot (e.g. 3*time.Second).
// RELAY_ID and RELAY_SECRET are still read from env — set by relay registration.
// Returns nil if backupURL or credentials are missing — backup silently disabled.
func New(masterKey []byte, configDir, backupURL string, debounce time.Duration) *Client {
	relayID := os.Getenv("RELAY_ID")
	secret := os.Getenv("RELAY_SECRET")
	if backupURL == "" || relayID == "" || secret == "" {
		log.Println("backup: backupURL/RELAY_ID/RELAY_SECRET not set — backup disabled")
		return nil
	}
	enc, err := crypto.New(masterKey)
	if err != nil {
		log.Printf("backup: crypto init: %v — backup disabled", err)
		return nil
	}
	log.Printf("backup: client ready → %s (relay_id=%s)", backupURL, relayID)
	return &Client{url: backupURL, relayID: relayID, secret: secret, enc: enc, configDir: configDir, debounce: debounce}
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
	c.timer = time.AfterFunc(c.debounce, func() {
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

// restoreResponse matches the GET /relay/restore response from dudenest-backup.
type restoreResponse struct {
	RelayID       string  `json:"relay_id"`
	MapsJSON      string  `json:"maps_json"`
	ProvidersEnc  []byte  `json:"providers_enc"`
	ProviderIDs   []string `json:"provider_ids"`
	BackupVersion int64   `json:"backup_version"`
	CreatedAt     string  `json:"created_at"`
}

// Restore fetches the latest backup from dudenest-backup and writes maps + provider tokens to configDir.
// Safe to call on nil. Returns (restored=true, nil) if backup was found and applied.
func (c *Client) Restore() (bool, error) {
	if c == nil { return false, nil }
	req, err := http.NewRequest(http.MethodGet, c.url+"/relay/restore", nil)
	if err != nil { return false, fmt.Errorf("restore: new request: %w", err) }
	req.Header.Set("X-Relay-ID", c.relayID)
	req.Header.Set("X-Relay-Secret", c.secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { return false, fmt.Errorf("restore: http get: %w", err) }
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound { return false, nil } // no backup yet — normal
	if resp.StatusCode != http.StatusOK { return false, fmt.Errorf("restore: backup returned %d", resp.StatusCode) }
	var r restoreResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil { return false, fmt.Errorf("restore: decode: %w", err) }
	if r.MapsJSON == "" { return false, nil }
	// Write maps.json to configDir (pipeline reads from this location)
	mapsPath := filepath.Join(c.configDir, "maps.json")
	if err := os.WriteFile(mapsPath, []byte(r.MapsJSON), 0o600); err != nil {
		return false, fmt.Errorf("restore: write maps: %w", err)
	}
	// Decrypt and restore provider tokens if present
	if len(r.ProvidersEnc) > 0 && c.enc != nil {
		provJSON, err := c.enc.Decrypt("relay-providers-v1", r.ProvidersEnc)
		if err != nil { log.Printf("restore: decrypt providers failed: %v (skipping token restore)", err) } else {
			var tokens map[string]json.RawMessage
			if err := json.Unmarshal(provJSON, &tokens); err == nil {
				provDir := filepath.Join(c.configDir, "providers")
				if err := os.MkdirAll(provDir, 0o700); err == nil {
					for name, data := range tokens {
						if err := os.WriteFile(filepath.Join(provDir, name), data, 0o600); err != nil {
							log.Printf("restore: write token %s: %v", name, err)
						}
					}
				}
			}
		}
	}
	log.Printf("restore: ✅ restored backup v%d (%s) — %d providers", r.BackupVersion, r.CreatedAt, len(r.ProviderIDs))
	return true, nil
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
