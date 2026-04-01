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

// GDriveStartFlow navigates to accounts.google.com and returns the email-input step.
// Navigate accounts.google.com (not oauthURL) to avoid GeneralOAuthLite rejection in headless mode.
func GDriveStartFlow(s *Session, oauthURL string) (*GDriveStep, error) {
	if err := s.Navigate("https://accounts.google.com"); err != nil {
		return nil, fmt.Errorf("navigate google: %w", err)
	}
	shot, err := screenshotOrFull(s, "body")
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

// GDriveSubmitPassword types password, clicks Next, waits for login then navigates to consent.
// IMPORTANT: Start flow from accounts.google.com (not oauthURL) to avoid headless rejection.
// After login completes, Navigate(oauthURL) lands on consent page (session cookie is already set).
func GDriveSubmitPassword(s *Session, password, oauthURL string) (*GDriveStep, error) {
	if err := s.SendKeys(SelectorPassword, password); err != nil {
		return nil, fmt.Errorf("type password: %w", err)
	}
	if err := s.Click(selPasswordNext); err != nil {
		return nil, fmt.Errorf("click next: %w", err)
	}
	time.Sleep(5 * time.Second) // wait for login to complete before navigating to OAuth
	shot, _ := screenshotOrFull(s, screenshotArea)
	currentURL, _ := s.CurrentURL()
	fmt.Printf("GDriveSubmitPassword: post-login url=%s\n", currentURL)
	if strings.Contains(currentURL, "signin/rejected") {
		return nil, fmt.Errorf("google rejected sign-in (security block or bad password)")
	}
	if strings.Contains(currentURL, "challenge/ipp") || strings.Contains(currentURL, "challenge/sms") ||
		strings.Contains(currentURL, "challenge/phone") {
		return &GDriveStep{ // SMS/phone verification
			Fields:        []Field{{ID: "sms_code", Selector: selSMSCode, Type: "number", Label: "Kod SMS"}},
			ScreenshotB64: shot,
			Status:        "needs_sms",
		}, nil
	}
	if s.ElementExists(sel2FA) { // TOTP 2FA detected via JS
		return &GDriveStep{
			Fields:        []Field{{ID: "2fa_code", Selector: sel2FA, Type: "number", Label: "Kod weryfikacyjny (TOTP)"}},
			ScreenshotB64: shot,
			Status:        "needs_2fa",
		}, nil
	}
	// Login complete — navigate to OAuth consent page
	if err := s.Navigate(oauthURL); err != nil {
		return nil, fmt.Errorf("navigate oauth consent: %w", err)
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
	time.Sleep(3 * time.Second)
	if err := s.Navigate(oauthURL); err != nil {
		return nil, fmt.Errorf("navigate oauth consent: %w", err)
	}
	return gdriveDetectConsentOrDone(s)
}

// GDriveSubmitSMSCode handles SMS verification code, then navigates to consent.
func GDriveSubmitSMSCode(s *Session, code, oauthURL string) (*GDriveStep, error) {
	if err := s.SendKeys(selSMSCode, code); err != nil {
		return nil, fmt.Errorf("type sms code: %w", err)
	}
	if s.ElementExists(selSMSNext) {
		if err := s.Click(selSMSNext); err != nil {
			return nil, fmt.Errorf("click sms next: %w", err)
		}
	} else {
		_ = s.Click(`button[type="button"]`) // generic fallback
	}
	time.Sleep(3 * time.Second)
	if err := s.Navigate(oauthURL); err != nil {
		return nil, fmt.Errorf("navigate oauth consent: %w", err)
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
		fmt.Printf("GDriveApproveConsent: polling url=%s\n", url)
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
	fmt.Printf("gdriveDetectConsentOrDone: url=%s consentExists=%v\n", url, s.ElementExists(selConsent))
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
	// Must start with callback URL — not just contain it (avoid false match on redirect_uri param)
	return strings.HasPrefix(url, "http://localhost:8085") || strings.Contains(url, "urn:ietf:wg:oauth:2.0:oob")
}

func screenshotOrFull(s *Session, selector string) (string, error) {
	buf, err := s.Screenshot(selector)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}
