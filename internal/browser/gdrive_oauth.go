// gdrive_oauth.go — OAuth2 token exchange and storage for Google Drive.
package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/drive/v3"

	"github.com/dudenest/dudenest-relay/pkg/types"
)

// GDriveClientSecret matches the structure of client_secret.json (Desktop App type).
type GDriveClientSecret struct {
	Installed struct {
		ClientID     string   `json:"client_id"`
		ClientSecret string   `json:"client_secret"`
		AuthURI      string   `json:"auth_uri"`
		TokenURI     string   `json:"token_uri"`
		RedirectURIs []string `json:"redirect_uris"`
	} `json:"installed"`
}

// LoadClientSecret reads and parses client_secret.json.
func LoadClientSecret(path string) (*GDriveClientSecret, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read client_secret: %w", err)
	}
	var cs GDriveClientSecret
	if err := json.Unmarshal(data, &cs); err != nil {
		return nil, fmt.Errorf("parse client_secret: %w", err)
	}
	return &cs, nil
}

// BuildOAuthConfig creates an oauth2.Config from client_secret.json.
// redirectURL is the full callback URI (e.g. from config.CallbackURL(port)).
//
// #scope: drive.DriveFileScope (per-file — only files this OAuth client created, or that the user
// opened with it). Reverts the drive.DriveScope (full-access) upgrade made in s329 (2026-05-30).
//
// Why back to drive.file — user decision 2026-07-15 ("na tym etapie produkt nie potrzebuje widzieć
// innych plików których sam nie stworzył"):
//   - drive / drive.readonly are RESTRICTED scopes → Google requires a CASA security assessment
//     ($500-4500/yr, re-audited every 12 months). Unverified + restricted = hard 100-user lifetime
//     cap + "Google hasn't verified this app" consent screen. Both block a store launch.
//   - Measured on relay-poc 2026-07-15: 943 FileMaps indexed, 0 with Strategy=Foreign — the full
//     scope had bought nothing; BootstrapWholeDrive produced zero entries in ~6 weeks of running.
//   - client_secret is shared fleet-wide (entrypoint.sh), so every relay shares one client_id →
//     files uploaded by ANY relay stay visible to EVERY relay under drive.file. Only files the user
//     placed on Drive outside dudenest become invisible — that is the accepted trade.
//
// Consequence: BootstrapWholeDrive / CloudFullLister.ListAll now see only app-created files (already
// in the blockmap) → effectively inert. Kept rather than deleted: re-upgrading is this one constant
// plus a Reconnect, if whole-Drive adoption ever becomes a funded product goal (CASA).
//
// Existing tokens keep whatever scope was granted at consent time; user must Reconnect each tile in
// Settings → Cloud Accounts to move an account onto drive.file.
func BuildOAuthConfig(cs *GDriveClientSecret, redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     cs.Installed.ClientID,
		ClientSecret: cs.Installed.ClientSecret,
		Scopes:       []string{drive.DriveFileScope},
		Endpoint:     google.Endpoint,
		RedirectURL:  redirectURL,
	}
}

// BuildWebOAuthConfig creates an oauth2.Config for the Web Application OAuth client.
// redirectURL is the full callback URI (e.g. from config.OAuth.WebRedirectURL).
// Same scope as BuildOAuthConfig (#scope — rationale there).
func BuildWebOAuthConfig(clientID, clientSecret, redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       []string{drive.DriveFileScope},
		Endpoint:     google.Endpoint,
		RedirectURL:  redirectURL,
	}
}

// BuildAuthURL returns the URL to navigate Chromium to for user consent.
func BuildAuthURL(cfg *oauth2.Config) string {
	return cfg.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
}

// ExchangeCode exchanges an OAuth2 authorization code for tokens.
func ExchangeCode(cfg *oauth2.Config, code string) (*oauth2.Token, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return cfg.Exchange(ctx, code)
}

// GetEmailFromToken fetches the authenticated user's email using the token.
func GetEmailFromToken(cfg *oauth2.Config, token *oauth2.Token) (string, error) {
	ctx := context.Background()
	client := cfg.Client(ctx, token)
	svc, err := drive.New(client) //nolint:staticcheck
	if err != nil {
		return "", fmt.Errorf("drive client: %w", err)
	}
	about, err := svc.About.Get().Fields("user").Do()
	if err != nil {
		return "", fmt.Errorf("get user info: %w", err)
	}
	return about.User.EmailAddress, nil
}

// LoadToken reads a GDriveToken from a file.
func LoadToken(path string) (*types.GDriveToken, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var t types.GDriveToken
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}
	return &t, nil
}

// GetDriveQuota returns (totalBytes, usedBytes) for a GDrive account.
func GetDriveQuota(cfg *oauth2.Config, t *types.GDriveToken) (totalBytes, usedBytes int64, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	oauthTok := &oauth2.Token{AccessToken: t.AccessToken, TokenType: t.TokenType, RefreshToken: t.RefreshToken, Expiry: t.Expiry}
	svc, err := drive.New(cfg.Client(ctx, oauthTok)) //nolint:staticcheck
	if err != nil {
		return 0, 0, err
	}
	about, err := svc.About.Get().Fields("storageQuota").Do()
	if err != nil {
		return 0, 0, err
	}
	return about.StorageQuota.Limit, about.StorageQuota.Usage, nil
}

// SaveToken persists a GDriveToken to the providers directory.
func SaveToken(configDir, providerID string, t *types.GDriveToken) error {
	dir := filepath.Join(configDir, "providers")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	path := filepath.Join(dir, "gdrive_"+providerID+".json")
	data, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// overwriteToken writes an updated token to an existing file path.
func overwriteToken(path string, t *types.GDriveToken) error {
	data, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// upsertProviderID returns an existing ProviderID for the email.
func upsertProviderID(configDir, email string) string {
	dir := filepath.Join(configDir, "providers")
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		t, err := LoadToken(filepath.Join(dir, e.Name()))
		if err == nil && strings.EqualFold(t.Email, email) {
			return t.ProviderID
		}
	}
	return "gdrive_" + fmt.Sprintf("%d", time.Now().UnixMilli())
}

// existingRefreshToken returns the stored refresh_token for an email.
func existingRefreshToken(configDir, email string) string {
	dir := filepath.Join(configDir, "providers")
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		t, err := LoadToken(filepath.Join(dir, e.Name()))
		if err == nil && strings.EqualFold(t.Email, email) && t.RefreshToken != "" {
			return t.RefreshToken
		}
	}
	return ""
}

// GetDriveQuotaRefreshing returns (refreshed token or nil, totalBytes, usedBytes, error).
func GetDriveQuotaRefreshing(cfg *oauth2.Config, t *types.GDriveToken) (*oauth2.Token, int64, int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	oauthTok := &oauth2.Token{AccessToken: t.AccessToken, TokenType: t.TokenType, RefreshToken: t.RefreshToken, Expiry: t.Expiry}
	ts := cfg.TokenSource(ctx, oauthTok)
	currentTok, err := ts.Token()
	if err != nil {
		return nil, 0, 0, fmt.Errorf("token refresh: %w", err)
	}
	client := oauth2.NewClient(ctx, ts)
	svc, err := drive.New(client) //nolint:staticcheck
	if err != nil {
		return nil, 0, 0, err
	}
	about, err := svc.About.Get().Fields("storageQuota").Do()
	if err != nil {
		return nil, 0, 0, err
	}
	var refreshed *oauth2.Token
	if currentTok.AccessToken != t.AccessToken {
		refreshed = currentTok
	}
	return refreshed, about.StorageQuota.Limit, about.StorageQuota.Usage, nil
}

// classifyTokenError returns a human-readable reason for a Drive API error.
func classifyTokenError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "token has been expired or revoked"),
		strings.Contains(msg, "invalid_grant"):
		return "Token revoked or expired (re-add account)"
	case strings.Contains(msg, "Token refresh failed") || strings.Contains(msg, "token refresh"):
		return "Token refresh failed — re-add account"
	case strings.Contains(msg, "connection refused") || strings.Contains(msg, "no such host"):
		return "Relay cannot reach Google Drive (network)"
	case strings.Contains(msg, "deadline exceeded") || strings.Contains(msg, "timeout"):
		return "Timeout connecting to Google Drive"
	case strings.Contains(msg, "403"):
		return "Access denied — token may be revoked"
	case strings.Contains(msg, "401"):
		return "Unauthorized — token expired, re-add account"
	default:
		return "Unavailable: " + msg
	}
}
