// Package config loads relay configuration from JSON file with env-var overrides.
// Priority: CLI flag > env var > JSON config file > built-in defaults.
// Default config path: ~/.config/dudenest/relay.json (or $RELAY_CONFIG env var).
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Config holds all relay runtime configuration.
type Config struct {
	Server  ServerConfig  `json:"server"`
	OAuth   OAuthConfig   `json:"oauth"`
	Browser BrowserConfig `json:"browser"`
	Backup  BackupConfig  `json:"backup"`
	NoVNC   NoVNCConfig   `json:"novnc"`
	Upload  UploadConfig  `json:"upload"`
	Cache   CacheConfig   `json:"cache"`
}
type ServerConfig struct {
	Listen  string `json:"listen"`  // HTTP listen address
	Display string `json:"display"` // X display for Chromium (TigerVNC)
}
type OAuthConfig struct {
	CallbackPort   int    `json:"callback_port"`    // local port for OAuth2 redirect
	WebRedirectURL string `json:"web_redirect_url"` // redirect URL for web (Flutter web) OAuth client
}
type BrowserConfig struct {
	SessionTimeoutHours int `json:"session_timeout_hours"` // browser session auto-expiry
}
type BackupConfig struct {
	URL             string  `json:"url"`              // dudenest-backup service base URL
	PublicURL       string  `json:"public_url"`       // public HTTPS URL of this relay (e.g. "https://relay.dudenest.com") — sent during registration, returned to Flutter for per-user routing
	DebounceSeconds float64 `json:"debounce_seconds"` // client-side debounce before sending snapshot
}
type NoVNCConfig struct {
	BackendAddr string `json:"backend_addr"` // noVNC/websockify backend address
}
type UploadConfig struct {
	MaxSizeMB int `json:"max_size_mb"` // maximum single file upload size
}
type CacheConfig struct {
	ManifestMaxFiles int `json:"manifest_max_files"` // 0 = no server-side cap
}

// Defaults returns the hardcoded production defaults.
func Defaults() *Config {
	return &Config{
		Server:  ServerConfig{Listen: "0.0.0.0:8086", Display: ":99"},
		OAuth:   OAuthConfig{CallbackPort: 8085, WebRedirectURL: "https://dudenest.com/auth"},
		Browser: BrowserConfig{SessionTimeoutHours: 4},
		Backup:  BackupConfig{URL: "https://backup.dudenest.com", DebounceSeconds: 3},
		NoVNC:   NoVNCConfig{BackendAddr: "127.0.0.1:6080"},
		Upload:  UploadConfig{MaxSizeMB: 32},
		Cache:   CacheConfig{ManifestMaxFiles: 0},
	}
}

// Load reads a JSON config file, overlays it on Defaults(), and applies env overrides.
// If path is empty, uses $RELAY_CONFIG env var or ~/.config/dudenest/relay.json.
// Missing config file is not an error — defaults are returned.
func Load(path string) (*Config, error) {
	cfg := Defaults()
	if path == "" {
		if v := os.Getenv("RELAY_CONFIG"); v != "" {
			path = v
		} else {
			home, _ := os.UserHomeDir()
			path = filepath.Join(home, ".config/dudenest/relay.json")
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil // no config file — use defaults; not an error
		}
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	applyEnvOverrides(cfg)
	return cfg, nil
}

// applyEnvOverrides applies environment variable overrides on top of file config.
// Only non-sensitive values are overridable via env; secrets stay in CI/CD vars.
func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("BACKUP_URL"); v != "" {
		cfg.Backup.URL = v
	}
	if v := os.Getenv("RELAY_PUBLIC_URL"); v != "" {
		cfg.Backup.PublicURL = v
	} // public URL of this relay — set per-deployment in relay.env
	if v := os.Getenv("RELAY_LISTEN"); v != "" {
		cfg.Server.Listen = v
	}
	if v := os.Getenv("RELAY_DISPLAY"); v != "" {
		cfg.Server.Display = v
	}
}

// SessionTimeout returns browser session expiry duration.
func (c *Config) SessionTimeout() time.Duration {
	return time.Duration(c.Browser.SessionTimeoutHours) * time.Hour
}

// Debounce returns the backup client-side debounce duration.
func (c *Config) Debounce() time.Duration {
	return time.Duration(float64(time.Second) * c.Backup.DebounceSeconds)
}

// MaxUploadBytes returns max allowed upload size in bytes.
func (c *Config) MaxUploadBytes() int64 { return int64(c.Upload.MaxSizeMB) << 20 }
