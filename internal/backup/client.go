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
	"os/exec"
	"path/filepath"
	"runtime"
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
	version   string // relay binary version, reported in every ping
	enc       *crypto.Encryptor
	configDir string
	debounce  time.Duration // client-side debounce before sending snapshot
	mu        sync.Mutex
	timer     *time.Timer
}

// New creates a backup client.
// backupURL: base URL of dudenest-backup (e.g. "https://backup.dudenest.com").
// debounce: client-side delay before sending snapshot (e.g. 3*time.Second).
// version: relay binary version string reported in every ping (e.g. "v0.5.9").
// RELAY_ID and RELAY_SECRET are still read from env — set by relay registration.
// Returns nil if backupURL or credentials are missing — backup silently disabled.
func New(masterKey []byte, configDir, backupURL string, debounce time.Duration, version string) *Client {
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
	log.Printf("backup: client ready → %s (relay_id=%s version=%s)", backupURL, relayID, version)
	return &Client{url: backupURL, relayID: relayID, secret: secret, version: version, enc: enc, configDir: configDir, debounce: debounce}
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

// UpdateURL updates relay_url in CRDB for this relay. Safe to call on nil.
// Called at startup when relay already has credentials — ensures relay_url stays current
// without re-registration (relay_id and backup history are preserved).
func (c *Client) UpdateURL(publicURL string) error {
	if c == nil || publicURL == "" { return nil }
	body, _ := json.Marshal(map[string]string{"relay_url": publicURL})
	req, err := http.NewRequest(http.MethodPost, c.url+"/relay/update-url", bytes.NewReader(body))
	if err != nil { return fmt.Errorf("update-url: new request: %w", err) }
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Relay-ID", c.relayID)
	req.Header.Set("X-Relay-Secret", c.secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { return fmt.Errorf("update-url: http post: %w", err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK { return fmt.Errorf("update-url: status %d", resp.StatusCode) }
	log.Printf("backup: relay_url updated in CRDB → %s", publicURL)
	return nil
}

// UpdateUserID sets user_id in CRDB for this relay. Called on first JWT request for old relays. Safe to call on nil.
func (c *Client) UpdateUserID(userID string) error {
	if c == nil || userID == "" { return nil }
	body, _ := json.Marshal(map[string]string{"user_id": userID})
	req, err := http.NewRequest(http.MethodPost, c.url+"/relay/update-user-id", bytes.NewReader(body))
	if err != nil { return fmt.Errorf("update-user-id: new request: %w", err) }
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Relay-ID", c.relayID)
	req.Header.Set("X-Relay-Secret", c.secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { return fmt.Errorf("update-user-id: http post: %w", err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK { return fmt.Errorf("update-user-id: status %d", resp.StatusCode) }
	log.Printf("backup: user_id updated in CRDB → %s", userID)
	return nil
}

// PingResponse — extended in s313 Phase 0 to carry latest-release info from hub.
// Older hub instances respond with {"status":"ok"} only; unknown fields default to zero values
// (no update push, no interval change) so the relay stays put.
type PingResponse struct {
	Status          string `json:"status"`
	LatestVersion   string `json:"latest_version,omitempty"`
	DownloadURL     string `json:"download_url,omitempty"`
	UpdateNow       bool   `json:"update_now"`
	NextPingSeconds int    `json:"next_ping_seconds,omitempty"`
}

// triggerUpdate runs systemctl start dudenest-relay-update.service in the background.
// Fire-and-forget — the service downloads the new binary and restarts the relay, which
// kills this process. We don't want to block the ping loop on it.
// Overridable for tests via the package-level updateTrigger var.
var updateTrigger = func() error {
	cmd := exec.Command("systemctl", "start", "dudenest-relay-update.service")
	return cmd.Start() // Start, not Run — don't wait for the service to finish (it restarts us mid-flight)
}

// Ping POSTs /relay/ping to the hub and acts on the response:
//   - If hub indicates a newer version + matching arch download URL → fires systemctl update service.
//   - If hub instructs a new next_ping_seconds → caller (StartPingLoop) adjusts interval.
//
// Safe to call on nil.
func (c *Client) Ping() (*PingResponse, error) {
	if c == nil { return nil, nil }
	body, _ := json.Marshal(map[string]string{
		"relay_version": c.version,
		"arch":          runtime.GOOS + "-" + runtime.GOARCH, // e.g. "linux-amd64" — hub uses this to pick the right download URL
	})
	req, err := http.NewRequest(http.MethodPost, c.url+"/relay/ping", bytes.NewReader(body))
	if err != nil { return nil, fmt.Errorf("ping: new request: %w", err) }
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Relay-ID", c.relayID)
	req.Header.Set("X-Relay-Secret", c.secret)
	httpResp, err := http.DefaultClient.Do(req)
	if err != nil { return nil, fmt.Errorf("ping: http post: %w", err) }
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusOK { return nil, fmt.Errorf("ping: status %d", httpResp.StatusCode) }
	var resp PingResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		// Older hub may return plain {"status":"ok"} which still decodes fine; only true JSON errors land here.
		return nil, fmt.Errorf("ping: decode: %w", err)
	}
	log.Printf("backup: ping ok (relay_id=%s version=%s, latest=%s, update_now=%v, next_ping=%ds)",
		c.relayID, c.version, resp.LatestVersion, resp.UpdateNow, resp.NextPingSeconds)
	if resp.UpdateNow && resp.LatestVersion != "" && resp.LatestVersion != c.version && resp.DownloadURL != "" {
		log.Printf("backup: fast-update: hub says newer version %s available, triggering systemd update unit", resp.LatestVersion)
		if err := updateTrigger(); err != nil {
			log.Printf("backup: fast-update: failed to trigger systemctl: %v (will retry next ping)", err)
		}
	}
	return &resp, nil
}

// StartPingLoop sends POST /relay/ping at an adaptive interval starting at `initial`.
// If the hub returns next_ping_seconds > 0 in the response, the loop adopts that interval
// for the next tick — this is how the burst-then-relax cadence is driven from the hub side
// (see ~/.AI/dudenest-application/FAST-UPDATE-PLAN.md "Phase 0").
//
// Bounds enforced on hub-suggested interval: [1s, 5min]. Anything outside is clamped — defends
// against hub bug/typo from accidentally hammering or stalling the whole fleet.
// Safe to call on nil.
func (c *Client) StartPingLoop(initial time.Duration) {
	if c == nil { return }
	const (
		minInterval = 1 * time.Second
		maxInterval = 5 * time.Minute
	)
	go func() {
		interval := initial
		for {
			time.Sleep(interval)
			resp, err := c.Ping()
			if err != nil {
				log.Printf("backup: ping failed: %v", err)
				continue
			}
			if resp != nil && resp.NextPingSeconds > 0 {
				newInterval := time.Duration(resp.NextPingSeconds) * time.Second
				if newInterval < minInterval { newInterval = minInterval }
				if newInterval > maxInterval { newInterval = maxInterval }
				if newInterval != interval {
					log.Printf("backup: ping interval %s → %s (hub-driven)", interval, newInterval)
					interval = newInterval
				}
			}
		}
	}()
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
