// register/client.go — auto-registers relay with dudenest-backup on first start.
// Saves credentials to configDir/relay_creds.json (idempotent — skips if file exists).
// Two entry points: EnsureRegistered (env-var based, startup) and RegisterOnceWithUserID (JWT-based, lazy).
//
// relay_url (added 2026-05-07): the relay sends its public HTTPS URL during registration.
// dudenest-backup stores it in CRDB. Flutter clients read it via GET /api/v1/relays and use
// it as the relay baseURL — enabling automatic per-user relay routing without manual configuration.
// Set via RELAY_PUBLIC_URL env var in relay.env (e.g. "https://relay.dudenest.com").
//
// ZT auto-provisioning (added 2026-05-11): Announce() + BootstrapPayload for no-domain relay setup.
// Flow: relay → POST /relay/announce → relay-provisioner authorizes ZT → POST /relay/bootstrap → relay has creds.
// jwt_secret persistence (added 2026-05-14): PollBootstrap writes jwt_secret.txt; LoadJWTSecret reads it at startup.
package register

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/dudenest/dudenest-relay/internal/auth"
)

type Credentials struct {
	RelayID     string `json:"relay_id"`
	RelaySecret string `json:"relay_secret"`
	UserID      string `json:"user_id,omitempty"` // owner's JWT sub — set at registration; used for Layer 2 owner check
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
// ZT pairing: if relay_creds.json exists but user_id is empty (ZT-bootstrapped relay), calls POST /relay/update-user-id
// to pair the relay with the authenticated user in CRDB, then persists user_id to relay_creds.json.
func RegisterOnceWithUserID(configDir, userID, backupURL, relayPublicURL string) (*Credentials, error) {
	if creds, err := loadExisting(configDir); err == nil && creds != nil {
		if creds.UserID == "" && userID != "" && backupURL != "" { // ZT relay: pair with user on first JWT request
			return pairUserID(configDir, creds, userID, backupURL)
		}
		return creds, nil
	}
	return registerCore(configDir, backupURL, userID, relayPublicURL)
}

// pairUserID calls POST /relay/update-user-id on hub to pair an existing relay (ZT-bootstrapped, no user_id) with a user.
// Updates relay_creds.json with user_id on success. Returns updated creds.
func pairUserID(configDir string, creds *Credentials, userID, backupURL string) (*Credentials, error) {
	body, _ := json.Marshal(map[string]string{"user_id": userID})
	req, err := http.NewRequest(http.MethodPost, backupURL+"/relay/update-user-id", bytes.NewReader(body))
	if err != nil { return creds, fmt.Errorf("pair: build request: %w", err) }
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Relay-ID", creds.RelayID)
	req.Header.Set("X-Relay-Secret", creds.RelaySecret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { return creds, fmt.Errorf("pair: POST update-user-id: %w", err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK { return creds, fmt.Errorf("pair: hub returned %d", resp.StatusCode) }
	creds.UserID = userID
	if data, err2 := json.Marshal(creds); err2 == nil {
		os.WriteFile(filepath.Join(configDir, credsFile), data, 0o600) //nolint:errcheck
	}
	log.Printf("register: ✅ paired relay_id=%s with user_id=%s", creds.RelayID, userID)
	return creds, nil
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
	creds.UserID = userID // persist owner's user_id for Layer 2 owner check on subsequent startups
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return nil, fmt.Errorf("register: mkdir configDir: %w", err)
	}
	data, _ := json.Marshal(creds)
	if err := os.WriteFile(filepath.Join(configDir, credsFile), data, 0o600); err != nil {
		return nil, fmt.Errorf("register: save creds: %w", err)
	}
	log.Printf("register: ✅ registered with backup (relay_id=%s user_id=%s relay_url=%s)", creds.RelayID, userID, relayPublicURL)
	return &creds, nil
}

func relayVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		return info.Main.Version
	}
	return "unknown"
}

// ── ZT Auto-Provisioning (added 2026-05-11) ──────────────────────────────────

const announceTokenFile = "announce_token.tmp"

// BootstrapPayload is delivered by relay-provisioner via POST /relay/bootstrap (ZT-only endpoint).
type BootstrapPayload struct {
	JWTSecret          string `json:"jwt_secret"`            // delivered once — write to relay.env
	RelayID            string `json:"relay_id"`              // permanent relay identity
	RelaySecret        string `json:"relay_secret"`          // HMAC key for relay→backup auth
	RelayURL           string `json:"relay_url"`             // assigned subdomain (relay-XXXX.dudenest.com)
	BackupURL          string `json:"backup_url"`            // dudenest-backup base URL
	GdriveClientSecret string `json:"gdrive_client_secret"`  // fleet-wide Google OAuth client JSON ("installed" or "web" format — oauth2.ConfigFromJSON handles both); written to <configDir>/gdrive_client_secret.json if file missing or contains placeholder
}

// Announce generates a one-time token, POSTs to hub /relay/announce, and saves token to disk.
// Gets ZT node ID from zerotier-cli and public IP from api.ipify.org.
// Returns announce_token for later bootstrap validation.
func Announce(configDir, hubURL string) (string, error) {
	ztID, err := getZerotierID()
	if err != nil { return "", fmt.Errorf("zerotier-cli: %w", err) }
	publicIP, err := getPublicIP()
	if err != nil { return "", fmt.Errorf("public ip: %w", err) }
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil { return "", fmt.Errorf("rand: %w", err) }
	token := hex.EncodeToString(tokenBytes)
	if err := os.WriteFile(filepath.Join(configDir, announceTokenFile), []byte(token), 0o600); err != nil {
		return "", fmt.Errorf("save token: %w", err)
	}
	body, _ := json.Marshal(map[string]string{"zt_id": ztID, "public_ip": publicIP, "announce_token": token, "version": relayVersion()})
	resp, err := http.Post(hubURL+"/relay/announce", "application/json", bytes.NewReader(body))
	if err != nil { return "", fmt.Errorf("announce POST: %w", err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK { return "", fmt.Errorf("announce: hub returned %d", resp.StatusCode) }
	log.Printf("register: ✅ announced to hub (zt_id=%s public_ip=%s)", ztID, publicIP)
	return token, nil
}

// LoadAnnounceToken reads the saved announce_token from disk (for bootstrap validation).
func LoadAnnounceToken(configDir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(configDir, announceTokenFile))
	if err != nil { return "", err }
	return strings.TrimSpace(string(data)), nil
}

// ClearAnnounceToken removes the announce_token temp file after successful bootstrap.
func ClearAnnounceToken(configDir string) { os.Remove(filepath.Join(configDir, announceTokenFile)) } //nolint:errcheck

const jwtSecretFile = "jwt_secret.txt"
const gdriveClientSecretFile = "gdrive_client_secret.json"

// WriteBootstrapCreds writes relay_creds.json, jwt_secret.txt, and gdrive_client_secret.json from bootstrap payload.
// jwt_secret.txt is read at startup via LoadJWTSecret to restore the signing key across restarts.
// gdrive_client_secret.json is written ONLY when the on-disk file is missing OR contains a placeholder
// — never overwrites real Google OAuth client credentials (in either "installed" or "web" format) that an operator may have configured by hand.
func WriteBootstrapCreds(configDir string, p *BootstrapPayload) (*Credentials, error) {
	creds := &Credentials{RelayID: p.RelayID, RelaySecret: p.RelaySecret}
	data, _ := json.Marshal(creds)
	if err := os.MkdirAll(configDir, 0o700); err != nil { return nil, fmt.Errorf("mkdir: %w", err) }
	if err := os.WriteFile(filepath.Join(configDir, credsFile), data, 0o600); err != nil {
		return nil, fmt.Errorf("write creds: %w", err)
	}
	if p.JWTSecret != "" { // persist jwt_secret for next restart
		if err := os.WriteFile(filepath.Join(configDir, jwtSecretFile), []byte(p.JWTSecret), 0o600); err != nil {
			log.Printf("register: ⚠️  failed to write jwt_secret.txt: %v", err)
		}
	}
	if p.GdriveClientSecret != "" { // fleet-wide OAuth credentials delivered by hub
		gdrivePath := filepath.Join(configDir, gdriveClientSecretFile)
		if shouldReplaceOAuth(gdrivePath) {
			if err := os.WriteFile(gdrivePath, []byte(p.GdriveClientSecret), 0o600); err != nil {
				log.Printf("register: ⚠️  failed to write %s: %v", gdriveClientSecretFile, err)
			} else {
				log.Printf("register: ✅ %s updated from hub", gdriveClientSecretFile)
			}
		} else {
			log.Printf("register: %s contains real credentials — kept on-disk file, ignored hub value", gdriveClientSecretFile)
		}
	}
	log.Printf("register: ✅ bootstrap complete (relay_id=%s relay_url=%s)", p.RelayID, p.RelayURL)
	return creds, nil
}

// shouldReplaceOAuth returns true if gdrive_client_secret.json is missing or contains a known placeholder marker.
// Markers: `"placeholder"` from install.sh v0.8.x, `"service_account"` from older bootstraps.
// Real Google OAuth client JSON (Dudenest uses "installed" format today on relay-poc — `"installed":{"client_id":"..."}`;
// the "web" format `"web":{"client_id":"..."}` is also valid and accepted by oauth2.ConfigFromJSON) carries neither
// placeholder marker, so this guard preserves hand-configured credentials on legacy relays (e.g. relay-poc).
func shouldReplaceOAuth(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil { return true } // missing or unreadable — safe to write
	s := string(data)
	return strings.Contains(s, `"placeholder"`) || strings.Contains(s, `"service_account"`)
}

// LoadJWTSecret reads jwt_secret.txt and updates the auth package signing key.
// Call at startup after configDir is known, before any JWT validation occurs.
func LoadJWTSecret(configDir string) {
	data, err := os.ReadFile(filepath.Join(configDir, jwtSecretFile))
	if err != nil { return } // file missing = not yet bootstrapped, use env var (dev-secret or JWT_SECRET)
	s := strings.TrimSpace(string(data))
	if s == "" { return }
	auth.SetJWTSecret(s)
	log.Printf("register: jwt_secret loaded from %s", jwtSecretFile)
}

// PollBootstrap polls hub GET /relay/bootstrap?announce_token=<token> until credentials arrive (relay-pull arch).
// Runs in a goroutine; writes relay_creds.json + jwt_secret.txt, updates signing key immediately on success.
func PollBootstrap(configDir, hubURL, announceToken string) {
	url := hubURL + "/relay/bootstrap?announce_token=" + announceToken
	deadline := time.Now().Add(10 * time.Minute)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err != nil { log.Printf("register: bootstrap poll: %v — retry in 10s", err); time.Sleep(10 * time.Second); continue }
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusOK:
			var p BootstrapPayload
			if err := json.Unmarshal(body, &p); err != nil { log.Printf("register: bootstrap decode: %v", err); return }
			if _, err := WriteBootstrapCreds(configDir, &p); err != nil { log.Printf("register: bootstrap write: %v", err); return }
			os.Setenv("RELAY_ID", p.RelayID)         //nolint:errcheck
			os.Setenv("RELAY_SECRET", p.RelaySecret) //nolint:errcheck
			os.Setenv("JWT_SECRET", p.JWTSecret)     //nolint:errcheck
			if p.BackupURL != "" { os.Setenv("BACKUP_URL", p.BackupURL) } //nolint:errcheck
			if p.JWTSecret != "" { auth.SetJWTSecret(p.JWTSecret) } // update signing key immediately (no restart needed)
			ClearAnnounceToken(configDir)
			log.Printf("register: ✅ bootstrapped (relay_id=%s relay_url=%s)", p.RelayID, p.RelayURL)
			return
		case http.StatusAccepted:  // 202 — provisioner not yet done
			log.Printf("register: bootstrap pending — retry in 10s")
			time.Sleep(10 * time.Second)
		case http.StatusGone:     // 410 — token already used
			log.Printf("register: bootstrap token already consumed"); return
		case http.StatusNotFound: // 404 — token invalid or expired
			log.Printf("register: bootstrap token invalid or expired"); return
		default:
			log.Printf("register: bootstrap unexpected %d — retry in 10s", resp.StatusCode)
			time.Sleep(10 * time.Second)
		}
	}
	log.Printf("register: ⚠️  bootstrap timed out after 10 minutes")
}

// getZerotierID runs zerotier-cli info and extracts the 10-char node ID.
func getZerotierID() (string, error) {
	out, err := exec.Command("zerotier-cli", "info").Output()
	if err != nil { return "", err }
	// Output: "200 info <nodeID> <version> <status>"
	parts := strings.Fields(string(out))
	if len(parts) < 3 { return "", fmt.Errorf("unexpected zerotier-cli output: %q", string(out)) }
	return parts[2], nil
}

// getPublicIP fetches public WAN IP from ipify.org (simple plaintext endpoint).
func getPublicIP() (string, error) {
	resp, err := http.Get("https://api.ipify.org")
	if err != nil { return "", err }
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil { return "", err }
	ip := strings.TrimSpace(string(body))
	if ip == "" { return "", fmt.Errorf("empty response from ipify.org") }
	return ip, nil
}
