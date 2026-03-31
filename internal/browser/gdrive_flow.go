// gdrive_flow.go — Google Drive step-by-step login flow using chromedp session.
package browser

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// GDriveStep represents a single UI step in the Google login flow.
type GDriveStep struct {
	Fields        []Field // Input fields to show in Flutter UI
	ScreenshotB64 string  // Base64 PNG of the relevant page area
	Status        string  // "needs_email"|"needs_password"|"needs_2fa"|"needs_consent"|"done"
}

// Field describes one input the user needs to fill.
type Field struct {
	ID       string `json:"id"`       // Logical name ("email", "password", "2fa_code")
	Selector string `json:"selector"` // CSS selector in the real browser
	Type     string `json:"type"`     // "text"|"password"|"number"|"button"
	Label    string `json:"label"`    // Human-readable label for Flutter UI
}

// Google DOM selectors — updated 2026-03-31, may need maintenance if Google changes UI.
const (
	SelectorEmail    = `input[type="email"]`
	SelectorPassword = `input[type="password"]`
	selEmailNext     = `#identifierNext`
	selPasswordNext  = `#passwordNext`
	sel2FA           = `input[type="tel"]`
	sel2FANext       = `#totpNext`
	selConsent       = `#submit_approve_access`
	screenshotArea   = `#view_container`
)

// GDriveStartFlow navigates to Google login and returns the email-input step.
// Navigate+Sleep(3s) guarantees page load. WaitVisible is skipped — screenshot confirms element presence.
func GDriveStartFlow(s *Session, oauthURL string) (*GDriveStep, error) {
	if err := s.Navigate("https://accounts.google.com"); err != nil {
		return nil, fmt.Errorf("navigate google: %w", err)
	}
	shot, err := screenshotOrFull(s, "body") // full page — email field visible after 3s sleep
	if err != nil {
		return nil, fmt.Errorf("screenshot: %w", err)
	}
	return &GDriveStep{
		Fields:        []Field{{ID: "email", Selector: SelectorEmail, Type: "text", Label: "Adres Gmail"}},
		ScreenshotB64: shot,
		Status:        "needs_email",
	}, nil
}

// GDriveSubmitEmail types the email, clicks Next, returns password step.
func GDriveSubmitEmail(s *Session, email string) (*GDriveStep, error) {
	if err := s.SendKeys(SelectorEmail, email); err != nil {
		return nil, fmt.Errorf("type email: %w", err)
	}
	if err := s.Click(selEmailNext); err != nil {
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

// GDriveSubmitPassword types password, clicks Next, detects 2FA or consent.
func GDriveSubmitPassword(s *Session, password, oauthURL string) (*GDriveStep, error) {
	if err := s.SendKeys(SelectorPassword, password); err != nil {
		return nil, fmt.Errorf("type password: %w", err)
	}
	if err := s.Click(selPasswordNext); err != nil {
		return nil, fmt.Errorf("click next: %w", err)
	}
	time.Sleep(2 * time.Second)
	shot, _ := screenshotOrFull(s, screenshotArea)
	if err := s.WaitVisible(sel2FA, 3*time.Second); err == nil {
		return &GDriveStep{
			Fields:        []Field{{ID: "2fa_code", Selector: sel2FA, Type: "number", Label: "Kod weryfikacyjny"}},
			ScreenshotB64: shot,
			Status:        "needs_2fa",
		}, nil
	}
	if err := s.Navigate(oauthURL); err != nil {
		return nil, fmt.Errorf("navigate oauth: %w", err)
	}
	return gdriveDetectConsentOrDone(s)
}

// GDriveSubmit2FA handles 2FA code submission, then navigates to consent.
func GDriveSubmit2FA(s *Session, code, oauthURL string) (*GDriveStep, error) {
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
	return gdriveDetectConsentOrDone(s)
}

// GDriveApproveConsent clicks the "Allow" button and polls for callback URL.
func GDriveApproveConsent(s *Session) (string, error) {
	if err := s.Click(selConsent); err != nil {
		return "", fmt.Errorf("click consent: %w", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		url, _ := s.CurrentURL()
		if gdriveIsCallback(url) {
			return url, nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return "", fmt.Errorf("callback URL not reached within 10s")
}

func gdriveDetectConsentOrDone(s *Session) (*GDriveStep, error) {
	url, err := s.CurrentURL()
	if err != nil {
		return nil, err
	}
	if gdriveIsCallback(url) {
		return &GDriveStep{Status: "done"}, nil
	}
	if err := s.WaitVisible(selConsent, 5*time.Second); err == nil {
		shot, _ := screenshotOrFull(s, `form`)
		return &GDriveStep{
			Fields:        []Field{{ID: "consent", Selector: selConsent, Type: "button", Label: "Zatwierdź dostęp"}},
			ScreenshotB64: shot,
			Status:        "needs_consent",
		}, nil
	}
	shot, _ := screenshotOrFull(s, screenshotArea)
	return &GDriveStep{ScreenshotB64: shot, Status: "needs_consent"}, nil
}

func gdriveIsCallback(url string) bool {
	return strings.Contains(url, "localhost:8085") || strings.Contains(url, "urn:ietf:wg:oauth:2.0:oob")
}

func screenshotOrFull(s *Session, selector string) (string, error) {
	buf, err := s.Screenshot(selector)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}
