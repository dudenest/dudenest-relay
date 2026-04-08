// gdrive_oauth.go — OAuth2 token exchange and storage for Google Drive.
package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/drive/v3"
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

// GDriveToken is persisted to ~/.config/dudenest/providers/gdrive_<id>.json.
type GDriveToken struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	RefreshToken string    `json:"refresh_token"`
	Expiry       time.Time `json:"expiry"`
	Email        string    `json:"email"`
	ProviderID   string    `json:"provider_id"`
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
func BuildOAuthConfig(cs *GDriveClientSecret) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     cs.Installed.ClientID,
		ClientSecret: cs.Installed.ClientSecret,
		Scopes:       []string{drive.DriveFileScope},
		Endpoint:     google.Endpoint,
		RedirectURL:  CallbackURL(),
	}
}

// BuildWebOAuthConfig creates an oauth2.Config for the Web Application OAuth client.
// Used when Flutter web sends https://dudenest.com/auth as the callback URI.
// GDRIVE_WEB_CLIENT_ID and GDRIVE_WEB_CLIENT_SECRET must be set in the environment.
func BuildWebOAuthConfig(clientID, clientSecret string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       []string{drive.DriveFileScope},
		Endpoint:     google.Endpoint,
		RedirectURL:  "https://dudenest.com/auth", // Flutter web callback URL
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
	svc, err := drive.New(client) //nolint:staticcheck — drive.New deprecated but drive.NewService requires opts
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
func LoadToken(path string) (*GDriveToken, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var t GDriveToken
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}
	return &t, nil
}

// GetDriveQuota returns (totalBytes, usedBytes) for a GDrive account.
func GetDriveQuota(cfg *oauth2.Config, t *GDriveToken) (totalBytes, usedBytes int64, err error) {
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
func SaveToken(configDir, providerID string, t *GDriveToken) error {
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
