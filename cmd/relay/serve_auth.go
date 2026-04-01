// serve_auth.go — HTTP API server for browser-based cloud auth (Flutter integration).
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/dudenest/dudenest-relay/internal/browser"
)

var (
	authDisplay      string
	authListenAddr   string
	authClientSecret string
	authConfigDir    string
)

// serveAuthCmd starts the browser auth HTTP API server.
func serveAuthCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve-auth",
		Short: "Start browser auth HTTP API server (for Flutter UI integration)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cs, err := browser.LoadClientSecret(authClientSecret)
			if err != nil {
				return fmt.Errorf("load client_secret: %w", err)
			}
			cfg := browser.BuildOAuthConfig(cs)
			oauthURL := browser.BuildAuthURL(cfg)
			srv := browser.NewServer(authDisplay, authListenAddr, oauthURL, cfg, authConfigDir)
			fmt.Printf("OAuth2 URL: %s\n", oauthURL)
			return srv.Run()
		},
	}
	home, _ := os.UserHomeDir()
	cmd.Flags().StringVar(&authDisplay, "display", ":99", "X display for Chromium (Xvfb)")
	cmd.Flags().StringVar(&authListenAddr, "listen", "0.0.0.0:8086", "HTTP API listen address")
	cmd.Flags().StringVar(&authClientSecret, "client-secret", filepath.Join(home, ".config/dudenest/gdrive_client_secret.json"), "Path to Google OAuth2 client_secret.json")
	cmd.Flags().StringVar(&authConfigDir, "config-dir", filepath.Join(home, ".config/dudenest"), "Path to dudenest config directory")
	return cmd
}

// authGDriveCmd runs an interactive terminal auth flow (for testing without Flutter).
func authGDriveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth gdrive",
		Short: "Authenticate Google Drive account via controlled browser (CLI test mode)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cs, err := browser.LoadClientSecret(authClientSecret)
			if err != nil {
				return fmt.Errorf("load client_secret: %w", err)
			}
			cfg := browser.BuildOAuthConfig(cs)
			oauthURL := browser.BuildAuthURL(cfg)
			fmt.Printf("Starting Chromium on display %s...\n", authDisplay)
			// Start callback server in background
			codeCh := make(chan string, 1)
			go func() {
				code, err := browser.WaitForCallback(120 * time.Second)
				if err != nil {
					fmt.Fprintf(os.Stderr, "callback error: %v\n", err)
					codeCh <- ""
					return
				}
				codeCh <- code
			}()
			// Create session and run login flow
			mgr := browser.NewManager(authDisplay)
			sid, err := mgr.Create()
			if err != nil {
				return fmt.Errorf("browser start: %w", err)
			}
			s, _ := mgr.Get(sid)
			fmt.Println("Browser started. Navigating to Google login...")
			if err := s.Navigate("https://accounts.google.com"); err != nil {
				return fmt.Errorf("navigate: %w", err)
			}
			fmt.Printf("OAuth URL: %s\n\nPlease provide credentials via API or use serve-auth mode.\n", oauthURL)
			fmt.Println("Waiting for OAuth callback (120s timeout)...")
			code := <-codeCh
			if code == "" {
				return fmt.Errorf("no authorization code received")
			}
			fmt.Printf("Received code: %s...\n", code[:10])
			token, err := browser.ExchangeCode(cfg, code)
			if err != nil {
				return fmt.Errorf("token exchange: %w", err)
			}
			email, err := browser.GetEmailFromToken(cfg, token)
			if err != nil {
				return fmt.Errorf("get email: %w", err)
			}
			provID := email[:6]
			gt := &browser.GDriveToken{
				AccessToken:  token.AccessToken,
				TokenType:    token.TokenType,
				RefreshToken: token.RefreshToken,
				Expiry:       token.Expiry,
				Email:        email,
				ProviderID:   provID,
			}
			if err := browser.SaveToken(authConfigDir, provID, gt); err != nil {
				return fmt.Errorf("save token: %w", err)
			}
			mgr.Close(sid)
			fmt.Printf("✅ Authenticated: %s\nToken saved to: %s/providers/gdrive_%s.json\n", email, authConfigDir, provID)
			return nil
		},
	}
	home, _ := os.UserHomeDir()
	cmd.Flags().StringVar(&authDisplay, "display", ":99", "X display for Chromium (Xvfb)")
	cmd.Flags().StringVar(&authClientSecret, "client-secret", filepath.Join(home, ".config/dudenest/gdrive_client_secret.json"), "Path to Google OAuth2 client_secret.json")
	cmd.Flags().StringVar(&authConfigDir, "config-dir", filepath.Join(home, ".config/dudenest"), "Path to dudenest config directory")
	return cmd
}
