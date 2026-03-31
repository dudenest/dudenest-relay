// Package browser manages Chromium sessions via CDP for cloud provider auth.
package browser

import (
	"context"
	"fmt"
	"time"

	"github.com/chromedp/chromedp"
)

// Session wraps a single chromedp browser session for one auth flow.
type Session struct {
	id       string
	ctx      context.Context
	cancel   context.CancelFunc
	allocCtx context.Context
	allocCnl context.CancelFunc
	created  time.Time
}

// NewSession creates a Chromium session using --headless=new (no Xvfb needed).
// DefaultExecAllocatorOptions contains old --headless; we build opts from scratch to avoid conflict.
// display kept for API compat but unused in headless mode.
func NewSession(id, display string) (*Session, error) {
	opts := []chromedp.ExecAllocatorOption{
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.Flag("headless", "new"),                                // new headless: full Chromium renderer
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-setuid-sandbox", true),
		chromedp.Flag("disable-blink-features", "AutomationControlled"), // reduce bot fingerprint
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("mute-audio", true),
		chromedp.WindowSize(1280, 800),
		chromedp.ExecPath("chromium"),
	}
	allocCtx, allocCnl := chromedp.NewExecAllocator(context.Background(), opts...)
	ctx, cancel := chromedp.NewContext(allocCtx, chromedp.WithLogf(func(f string, a ...any) {})) // silent logs
	if err := chromedp.Run(ctx); err != nil {
		cancel()
		allocCnl()
		return nil, fmt.Errorf("browser start: %w", err)
	}
	return &Session{id: id, ctx: ctx, cancel: cancel, allocCtx: allocCtx, allocCnl: allocCnl, created: time.Now()}, nil
}

// Navigate navigates to url and waits 3s for page settle.
// WaitReady is unreliable on Google pages in headless mode.
func (s *Session) Navigate(url string) error {
	return chromedp.Run(s.ctx, chromedp.Navigate(url), chromedp.Sleep(3*time.Second))
}

// Screenshot captures a PNG of the element matching selector.
// Falls back to full-page screenshot if selector not found.
func (s *Session) Screenshot(selector string) ([]byte, error) {
	var buf []byte
	err := chromedp.Run(s.ctx,
		chromedp.WaitVisible(selector, chromedp.ByQuery),
		chromedp.Screenshot(selector, &buf, chromedp.NodeVisible, chromedp.ByQuery),
	)
	if err != nil { // Fallback: full page
		err = chromedp.Run(s.ctx, chromedp.FullScreenshot(&buf, 90))
	}
	return buf, err
}

// SendKeys types text into the element matching selector.
func (s *Session) SendKeys(selector, text string) error {
	return chromedp.Run(s.ctx,
		chromedp.WaitVisible(selector, chromedp.ByQuery),
		chromedp.Click(selector, chromedp.ByQuery),
		chromedp.SendKeys(selector, text, chromedp.ByQuery),
	)
}

// Click clicks the element matching selector.
func (s *Session) Click(selector string) error {
	return chromedp.Run(s.ctx,
		chromedp.WaitVisible(selector, chromedp.ByQuery),
		chromedp.Click(selector, chromedp.ByQuery),
	)
}

// WaitVisible waits up to timeout for selector to appear.
func (s *Session) WaitVisible(selector string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(s.ctx, timeout)
	defer cancel()
	return chromedp.Run(ctx, chromedp.WaitVisible(selector, chromedp.ByQuery))
}

// CurrentURL returns the current page URL.
func (s *Session) CurrentURL() (string, error) {
	var u string
	err := chromedp.Run(s.ctx, chromedp.Location(&u))
	return u, err
}

// Close terminates the browser session and frees resources.
func (s *Session) Close() {
	s.cancel()
	s.allocCnl()
}

// Age returns how long the session has been alive.
func (s *Session) Age() time.Duration { return time.Since(s.created) }
