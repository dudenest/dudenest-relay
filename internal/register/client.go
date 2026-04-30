// register/client.go — auto-registers relay with dudenest-backup on first start.
// Reads BACKUP_URL + RELAY_USER_ID env vars; saves credentials to configDir/relay_creds.json.
// Idempotent: if relay_creds.json exists, reads and returns saved credentials.
package register

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
)

type Credentials struct {
	RelayID     string `json:"relay_id"`
	RelaySecret string `json:"relay_secret"`
}

const credsFile = "relay_creds.json"

// EnsureRegistered auto-registers with BACKUP_URL on first start.
// Returns nil credentials (and no error) if BACKUP_URL or RELAY_USER_ID not set.
// Credentials are saved to configDir/relay_creds.json for subsequent starts.
func EnsureRegistered(configDir string) (*Credentials, error) {
	backupURL := os.Getenv("BACKUP_URL")
	userID := os.Getenv("RELAY_USER_ID")
	if backupURL == "" || userID == "" {
		return nil, nil // backup registration disabled — not an error
	}
	credsPath := filepath.Join(configDir, credsFile)
	if data, err := os.ReadFile(credsPath); err == nil { // already registered
		var creds Credentials
		if err2 := json.Unmarshal(data, &creds); err2 == nil && creds.RelayID != "" {
			log.Printf("register: loaded existing credentials (relay_id=%s)", creds.RelayID)
			return &creds, nil
		}
	}
	version := relayVersion()
	body, _ := json.Marshal(map[string]string{"user_id": userID, "relay_version": version})
	resp, err := http.Post(backupURL+"/relay/register", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("register: POST %s/relay/register: %w", backupURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("register: backup returned %d", resp.StatusCode)
	}
	var creds Credentials
	if err := json.NewDecoder(resp.Body).Decode(&creds); err != nil {
		return nil, fmt.Errorf("register: decode response: %w", err)
	}
	if creds.RelayID == "" || creds.RelaySecret == "" {
		return nil, fmt.Errorf("register: empty credentials in response")
	}
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return nil, fmt.Errorf("register: mkdir configDir: %w", err)
	}
	data, _ := json.Marshal(creds)
	if err := os.WriteFile(credsPath, data, 0o600); err != nil {
		return nil, fmt.Errorf("register: save creds: %w", err)
	}
	log.Printf("register: ✅ registered with backup (relay_id=%s)", creds.RelayID)
	return &creds, nil
}

func relayVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		return info.Main.Version
	}
	return "unknown"
}
