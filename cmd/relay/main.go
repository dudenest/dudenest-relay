// cmd/relay — Dudenest Relay binary (ZT auto-provisioning mode + HTTP server)
// Usage: relay serve --key <hex> --listen :8086 --config-dir /etc/dudenest --map-store /var/lib/dudenest/maps
// ZT provisioning: set ZT_ANNOUNCE=true; hub URL from BACKUP_URL env var.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

const version = "0.1.0"

// relayCreds is persisted to relay_creds.json after bootstrap.
type relayCreds struct {
	RelayID     string `json:"relay_id"`
	RelaySecret string `json:"relay_secret"`
	RelayURL    string `json:"relay_url"`
	JwtSecret   string `json:"jwt_secret"`
	BackupURL   string `json:"backup_url"`
}

func main() {
	log.SetFlags(log.Ltime | log.Lshortfile)
	root := &cobra.Command{Use: "relay", Version: version, SilenceUsage: true}
	root.AddCommand(serveCmd(), versionCmd())
	if err := root.Execute(); err != nil { os.Exit(1) }
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use: "version", Short: "Print version",
		Run: func(_ *cobra.Command, _ []string) { fmt.Println(version) },
	}
}

func serveCmd() *cobra.Command {
	var key, listen, configDir, mapStore string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start relay HTTP server",
		RunE: func(_ *cobra.Command, _ []string) error {
			return serve(key, listen, configDir, mapStore)
		},
	}
	cmd.Flags().StringVar(&key, "key", os.Getenv("RELAY_KEY"), "AES-256 encryption key (hex)")
	cmd.Flags().StringVar(&listen, "listen", "0.0.0.0:8086", "HTTP listen address")
	cmd.Flags().StringVar(&configDir, "config-dir", "/etc/dudenest", "Config directory (relay_creds.json location)")
	cmd.Flags().StringVar(&mapStore, "map-store", "/var/lib/dudenest/maps", "File map store directory")
	return cmd
}

func serve(key, listen, configDir, _ string) error {
	if key == "" { return fmt.Errorf("--key or RELAY_KEY required") }
	if err := os.MkdirAll(configDir, 0700); err != nil { return fmt.Errorf("mkdir config-dir: %w", err) }
	credsPath := filepath.Join(configDir, "relay_creds.json")
	var creds *relayCreds

	if _, err := os.Stat(credsPath); os.IsNotExist(err) {
		if os.Getenv("ZT_ANNOUNCE") != "true" {
			return fmt.Errorf("relay_creds.json not found and ZT_ANNOUNCE != true — provision relay first")
		}
		backupURL := os.Getenv("BACKUP_URL")
		if backupURL == "" { backupURL = "https://backup.dudenest.com" }
		log.Printf("ZT_ANNOUNCE=true — starting provisioning flow via %s", backupURL)
		var err error
		creds, err = ztProvision(backupURL, credsPath)
		if err != nil { return fmt.Errorf("ZT provisioning failed: %w", err) }
	} else {
		c, err := loadCreds(credsPath)
		if err != nil { return fmt.Errorf("load creds: %w", err) }
		creds = c
		log.Printf("relay credentials loaded: relay_id=%s relay_url=%s", creds.RelayID, creds.RelayURL)
	}
	return runHTTP(listen, creds)
}

// ── ZT provisioning flow ──────────────────────────────────────────────────────

func ztProvision(backupURL, credsPath string) (*relayCreds, error) {
	ztID, err := getZtNodeID()
	if err != nil { return nil, fmt.Errorf("get ZT node ID: %w", err) }
	log.Printf("ZT node ID: %s", ztID)

	publicIP, err := getPublicIP()
	if err != nil { return nil, fmt.Errorf("get public IP: %w", err) }
	log.Printf("public IP: %s", publicIP)

	announceToken := uuid.New().String()
	if err := postAnnounce(backupURL, ztID, publicIP, announceToken); err != nil {
		return nil, fmt.Errorf("announce: %w", err)
	}
	log.Printf("announced to hub — waiting for ZeroTier authorization and provisioning ...")

	creds, err := pollBootstrap(backupURL, announceToken)
	if err != nil { return nil, fmt.Errorf("bootstrap: %w", err) }

	data, _ := json.MarshalIndent(creds, "", "  ")
	if err := os.WriteFile(credsPath, data, 0600); err != nil {
		return nil, fmt.Errorf("write relay_creds.json: %w", err)
	}
	log.Printf("relay_creds.json written: relay_id=%s relay_url=%s", creds.RelayID, creds.RelayURL)
	return creds, nil
}

func getZtNodeID() (string, error) {  // zerotier-cli info -> "200 info <nodeID> <ver> <status>"
	out, err := exec.Command("zerotier-cli", "info").Output()
	if err != nil { return "", err }
	parts := strings.Fields(strings.TrimSpace(string(out)))
	if len(parts) < 3 { return "", fmt.Errorf("unexpected zerotier-cli output: %q", string(out)) }
	return parts[2], nil
}

func getPublicIP() (string, error) {
	resp, err := http.Get("https://api.ipify.org")
	if err != nil { return "", err }
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	ip := strings.TrimSpace(string(b))
	if ip == "" { return "", fmt.Errorf("empty response from ipify") }
	return ip, nil
}

func postAnnounce(backupURL, ztID, publicIP, announceToken string) error {
	body, _ := json.Marshal(map[string]string{
		"zt_id":          ztID,
		"public_ip":      publicIP,
		"announce_token": announceToken,
		"version":        version,
	})
	resp, err := http.Post(backupURL+"/relay/announce", "application/json", bytes.NewReader(body))
	if err != nil { return err }
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("hub announce: %s %s", resp.Status, b)
	}
	return nil
}

func pollBootstrap(backupURL, announceToken string) (*relayCreds, error) {
	url := backupURL + "/relay/bootstrap?announce_token=" + announceToken
	deadline := time.Now().Add(10 * time.Minute)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err != nil { log.Printf("bootstrap poll: %v — retry in 10s", err); time.Sleep(10 * time.Second); continue }
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusOK:
			var creds relayCreds
			if err := json.Unmarshal(body, &creds); err != nil { return nil, fmt.Errorf("decode creds: %w", err) }
			return &creds, nil
		case http.StatusAccepted:  // 202 — provisioner not yet done
			log.Printf("bootstrap: pending — retry in 10s")
			time.Sleep(10 * time.Second)
		case http.StatusGone:  // 410 — token already used
			return nil, fmt.Errorf("announce_token already consumed")
		case http.StatusNotFound:
			return nil, fmt.Errorf("announce_token invalid or expired")
		default:
			log.Printf("bootstrap: unexpected %d — retry in 10s", resp.StatusCode)
			time.Sleep(10 * time.Second)
		}
	}
	return nil, fmt.Errorf("bootstrap timed out after 10 minutes")
}

// ── HTTP server ───────────────────────────────────────────────────────────────

func runHTTP(listen string, creds *relayCreds) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
			"status":    "ok",
			"relay_id":  creds.RelayID,
			"relay_url": creds.RelayURL,
		})
	})
	log.Printf("relay HTTP listening on %s (relay_id=%s relay_url=%s)", listen, creds.RelayID, creds.RelayURL)
	return http.ListenAndServe(listen, mux)
}

func loadCreds(path string) (*relayCreds, error) {
	data, err := os.ReadFile(path)
	if err != nil { return nil, err }
	var c relayCreds
	return &c, json.Unmarshal(data, &c)
}
