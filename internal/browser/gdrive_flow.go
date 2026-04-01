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

// Google DOM selectors — updated 2026-04-01, may need maintenance if Google changes UI.
// Verified with account chckbmkids@gmail.com on Chromium 146, headless=new.
const (
	SelectorEmail    = `input[type="email"]`
	SelectorPassword = `input[type="password"]`
	selEmailNext     = `#identifierNext`
	selPasswordNext  = `#passwordNext`
	sel2FA           = `input[type="tel"]`       // TOTP code input
	sel2FANext       = `#totpNext`               // TOTP submit button
	selSMSCode       = `input[type="tel"]`       // SMS code input (same selector as TOTP)
	selSMSNext       = `#idvPreregisteredPhoneNext` // SMS submit — fallback: any button[type=button]
	selPhoneNumber   = `input[type="tel"]`       // phone number entry (verify identity screen)
	selPhoneNext     = `#idvPreregisteredPhoneNext`
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
// Uses Sleep(3s) instead of WaitVisible — WaitVisible hangs in headless=new on Google pages.
func GDriveSubmitEmail(s *Session, email string) (*GDriveStep, error) {
	if err := s.SendKeys(SelectorEmail, email); err != nil {
		return nil, fmt.Errorf("type email: %w", err)
	}
	if err := s.Click(selEmailNext); err != nil {
		return nil, fmt.Errorf("click next: %w", err)
	}
	time.Sleep(3 * time.Second)
	shot, _ := screenshotOrFull(s, screenshotArea)
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
	time.Sleep(3 * time.Second) // wait for page transition after password submit
	shot, _ := screenshotOrFull(s, screenshotArea)
	// Detect verification type via current URL keywords (more reliable than selector in headless=new)
	currentURL, _ := s.CurrentURL()
	if strings.Contains(currentURL, "challenge/ipp") || strings.Contains(currentURL, "challenge/sms") ||
		strings.Contains(currentURL, "challenge/phone") {
		return &GDriveStep{ // SMS/phone code verification
			Fields:        []Field{{ID: "sms_code", Selector: selSMSCode, Type: "number", Label: "Kod SMS"}},
			ScreenshotB64: shot,
			Status:        "needs_sms",
		}, nil
	}
	if s.ElementExists(sel2FA) { // TOTP 2FA field detected via JS — no WaitVisible (hangs in headless=new)
		return &GDriveStep{
			Fields:        []Field{{ID: "2fa_code", Selector: sel2FA, Type: "number", Label: "Kod weryfikacyjny (TOTP)"}},
			ScreenshotB64: shot,
			Status:        "needs_2fa",
		}, nil
	}
	if err := s.Navigate(oauthURL); err != nil {
		return nil, fmt.Errorf("navigate oauth: %w", err)
	}
	return gdriveDetectConsentOrDone(s)
}

// GDriveSubmit2FA handles TOTP 2FA code submission, then navigates to consent.
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

// GDriveSubmitSMSCode handles SMS verification code (sent to phone number).
// Same input selector as TOTP but different Next button.
func GDriveSubmitSMSCode(s *Session, code, oauthURL string) (*GDriveStep, error) {
	if err := s.SendKeys(selSMSCode, code); err != nil {
		return nil, fmt.Errorf("type sms code: %w", err)
	}
	// Try primary SMS next button; fall back to generic submit if not found
	if s.ElementExists(selSMSNext) {
		if err := s.Click(selSMSNext); err != nil {
			return nil, fmt.Errorf("click sms next: %w", err)
		}
	} else {
		_ = s.Click(`button[type="button"]`) // generic fallback
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
	if s.ElementExists(selConsent) { // consent button detected via JS — no WaitVisible
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
