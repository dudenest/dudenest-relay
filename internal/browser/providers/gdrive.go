// Package providers contains provider-specific auth flows for browser-based login.
package providers

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/dudenest/dudenest-relay/internal/browser"
)

// GDriveAuthResult contains the result of a completed Google Drive auth flow.
type GDriveAuthResult struct {
	Code  string // OAuth2 authorization code
	Email string // Authenticated user email
}

// GDriveStep represents a single UI step in the Google login flow.
type GDriveStep struct {
	Fields       []Field // Input fields to show in Flutter UI
	ScreenshotB64 string // Base64 PNG of the relevant page area
	Status       string // "needs_email" | "needs_password" | "needs_2fa" | "needs_consent" | "done"
}

// Field describes one input the user needs to fill.
type Field struct {
	ID       string // Logical name (e.g. "email", "password", "2fa_code")
	Selector string // CSS selector in the real browser
	Type     string // "text" | "password" | "number"
	Label    string // Human-readable label for Flutter UI
}

// Google DOM selectors — exported for use in api.go, updated 2026-03-31, may need maintenance.
const (
	SelectorEmail    = `input[type="email"]`
	SelectorPassword = `input[type="password"]`
	SelectorEmailNext     = `#identifierNext`
	SelectorPasswordNext  = `#passwordNext`
	sel2FA           = `input[type="tel"], input[id="totpPin"]` // TOTP or SMS
	sel2FANext       = `#totpNext, #idvAggChallengeNext`
	selConsent       = `#submit_approve_access, button[id="submit_approve_access"]`
	screenshotArea   = `#view_container, form`                 // Main login form container
)

// GDriveStartFlow navigates to Google login page and returns the first step.
func GDriveStartFlow(s *browser.Session, oauthURL string) (*GDriveStep, error) {
	if err := s.Navigate("https://accounts.google.com"); err != nil {
		return nil, fmt.Errorf("navigate google: %w", err)
	}
	if err := s.WaitVisible(SelectorEmail, 10*time.Second); err != nil {
		return nil, fmt.Errorf("email field not found: %w", err)
	}
	shot, err := screenshotOrFull(s, screenshotArea)
	if err != nil {
		return nil, err
	}
	return &GDriveStep{
		Fields:        []Field{{ID: "email", Selector: SelectorEmail, Type: "text", Label: "Adres Gmail"}},
		ScreenshotB64: shot,
		Status:        "needs_email",
	}, nil
}

// GDriveSubmitEmail types the email and clicks Next, returns password step.
func GDriveSubmitEmail(s *browser.Session, email string) (*GDriveStep, error) {
	if err := s.SendKeys(SelectorEmail, email); err != nil {
		return nil, fmt.Errorf("type email: %w", err)
	}
	if err := s.Click(SelectorEmailNext); err != nil {
		return nil, fmt.Errorf("click next: %w", err)
	}
	if err := s.WaitVisible(SelectorPassword, 10*time.Second); err != nil {
		return nil, fmt.Errorf("password field not found: %w", err)
	}
	shot, err := screenshotOrFull(s, screenshotArea)
	if err != nil {
		return nil, err
	}
	return &GDriveStep{
		Fields:        []Field{{ID: "password", Selector: SelectorPassword, Type: "password", Label: "Hasło"}},
		ScreenshotB64: shot,
		Status:        "needs_password",
	}, nil
}

// GDriveSubmitPassword types password, clicks Next, detects next state (2FA or consent).
func GDriveSubmitPassword(s *browser.Session, password string, oauthURL string) (*GDriveStep, error) {
	if err := s.SendKeys(SelectorPassword, password); err != nil {
		return nil, fmt.Errorf("type password: %w", err)
	}
	if err := s.Click(SelectorPasswordNext); err != nil {
		return nil, fmt.Errorf("click next: %w", err)
	}
	time.Sleep(2 * time.Second) // Allow redirect to settle
	url, _ := s.CurrentURL()
	shot, _ := screenshotOrFull(s, screenshotArea)
	// Check what appeared next
	if err := s.WaitVisible(sel2FA, 3*time.Second); err == nil { // 2FA prompt
		return &GDriveStep{
			Fields:        []Field{{ID: "2fa_code", Selector: sel2FA, Type: "number", Label: "Kod weryfikacyjny"}},
			ScreenshotB64: shot,
			Status:        "needs_2fa",
		}, nil
	}
	// Navigate to OAuth consent
	if err := s.Navigate(oauthURL); err != nil {
		return nil, fmt.Errorf("navigate oauth: %w", err)
	}
	_ = url
	return detectConsentOrDone(s)
}

// GDriveSubmit2FA handles 2FA code submission.
func GDriveSubmit2FA(s *browser.Session, code string, oauthURL string) (*GDriveStep, error) {
	if err := s.SendKeys(sel2FA, code); err != nil {
		return nil, fmt.Errorf("type 2fa: %w", err)
	}
	if err := s.Click(sel2FANext); err != nil {
		return nil, fmt.Errorf("click 2fa next: %w", err)
	}
	time.Sleep(2 * time.Second)
	if err := s.Navigate(oauthURL); err != nil {
		return nil, fmt.Errorf("navigate oauth: %w", err)
	}
	return detectConsentOrDone(s)
}

// detectConsentOrDone checks if consent screen appeared or we already have a callback code.
func detectConsentOrDone(s *browser.Session) (*GDriveStep, error) {
	url, err := s.CurrentURL()
	if err != nil {
		return nil, err
	}
	if isCallbackURL(url) { // Auth completed without explicit consent click
		return &GDriveStep{Status: "done"}, nil
	}
	if err := s.WaitVisible(selConsent, 5*time.Second); err == nil { // Consent screen
		shot, _ := screenshotOrFull(s, `#docs-titlebar, #oauth2-approval`)
		return &GDriveStep{
			Fields:        []Field{{ID: "consent", Selector: selConsent, Type: "button", Label: "Zatwierdź dostęp"}},
			ScreenshotB64: shot,
			Status:        "needs_consent",
		}, nil
	}
	shot, _ := screenshotOrFull(s, screenshotArea)
	return &GDriveStep{ScreenshotB64: shot, Status: "needs_consent"}, nil
}

// GDriveApproveConsent clicks the "Allow" button and returns the callback URL.
func GDriveApproveConsent(s *browser.Session, callbackBase string) (string, error) {
	if err := s.Click(selConsent); err != nil {
		return "", fmt.Errorf("click consent: %w", err)
	}
	// Wait for redirect to our callback
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		url, _ := s.CurrentURL()
		if isCallbackURL(url) {
			return url, nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return "", fmt.Errorf("callback URL not reached within 10s")
}

func isCallbackURL(url string) bool {
	return len(url) > 20 && (contains(url, "localhost:8085") || contains(url, "urn:ietf:wg:oauth:2.0:oob"))
}

func contains(s, sub string) bool { return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub)) }
func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func screenshotOrFull(s *browser.Session, selector string) (string, error) {
	buf, err := s.Screenshot(selector)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}
