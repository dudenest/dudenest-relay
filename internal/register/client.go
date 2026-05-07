// register/client.go — auto-registers relay with dudenest-backup on first start.
// Saves credentials to configDir/relay_creds.json (idempotent — skips if file exists).
// Two entry points: EnsureRegistered (env-var based, startup) and RegisterOnceWithUserID (JWT-based, lazy).
//
// relay_url (added 2026-05-07): the relay sends its public HTTPS URL during registration.
// dudenest-backup stores it in CRDB. Flutter clients read it via GET /api/v1/relays and use
// it as the relay baseURL — enabling automatic per-user relay routing without manual configuration.
// Set via RELAY_PUBLIC_URL env var in relay.env (e.g. "https://relay.dudenest.com").
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

// EnsureRegistered loads existing relay_creds.json (from prior JWT registration or prior start),
// then falls back to backupURL + RELAY_USER_ID env-var registration.
// relayPublicURL is the public HTTPS URL of this relay (from config, e.g. "https://relay.dudenest.com").
// Returns nil credentials (no error) if no existing creds and RELAY_USER_ID env var not set.
func EnsureRegistered(configDir, backupURL, relayPublicURL string) (*Credentials, error) {
	if creds, err := loadExisting(configDir); err == nil && creds != nil {
		return creds, nil // already registered (e.g. from lazy JWT registration)
	}
	userID := os.Getenv("RELAY_USER_ID")
	if backupURL == "" || userID == "" {
		return nil, nil // backup registration disabled — not an error
	}
	return registerCore(configDir, backupURL, userID, relayPublicURL)
}

// RegisterOnceWithUserID registers relay using userID from JWT claims.
// relayPublicURL is the public HTTPS URL of this relay (from config). Idempotent: returns saved creds if already registered.
func RegisterOnceWithUserID(configDir, userID, backupURL, relayPublicURL string) (*Credentials, error) {
	if creds, err := loadExisting(configDir); err == nil && creds != nil {
		return creds, nil
	}
	return registerCore(configDir, backupURL, userID, relayPublicURL)
}

// loadExisting reads relay_creds.json if it exists and has a non-empty relay_id.
func loadExisting(configDir string) (*Credentials, error) {
	data, err := os.ReadFile(filepath.Join(configDir, credsFile))
	if err != nil {
		return nil, err
	}
	var creds Credentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, err
	}
	if creds.RelayID == "" {
		return nil, fmt.Errorf("empty relay_id in saved credentials")
	}
	log.Printf("register: loaded existing credentials (relay_id=%s)", creds.RelayID)
	return &creds, nil
}

// registerCore calls /relay/register on backupURL and saves returned credentials.
// relayPublicURL is included in the registration request and stored in CRDB for Flutter routing.
func registerCore(configDir, backupURL, userID, relayPublicURL string) (*Credentials, error) {
	version := relayVersion()
	body, _ := json.Marshal(map[string]string{
		"user_id":       userID,
		"relay_version": version,
		"relay_url":     relayPublicURL, // public URL stored in CRDB, returned to Flutter via GET /user/relays
	})
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
	if err := os.WriteFile(filepath.Join(configDir, credsFile), data, 0o600); err != nil {
		return nil, fmt.Errorf("register: save creds: %w", err)
	}
	log.Printf("register: ✅ registered with backup (relay_id=%s relay_url=%s)", creds.RelayID, relayPublicURL)
	return &creds, nil
}

func relayVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		return info.Main.Version
	}
	return "unknown"
}
