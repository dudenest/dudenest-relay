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

// NewSession creates a Chromium session on a real X display (TigerVNC :99 managed by tigervnc-99.service).
// NOT headless — headless=new exposes "HeadlessChrome" in User-Agent which Google detects and blocks.
// display parameter sets DISPLAY env var (e.g. ":99"). All sessions visible on that display via VNC.
// Each session uses an isolated --user-data-dir=/tmp/relay-session-{id} to prevent Chromium singleton
// delegation: without this, starting Chromium with an existing instance running (e.g. on :0) causes
// the new window to appear on the existing instance's display instead of :99.
func NewSession(id, display string) (*Session, error) {
	opts := []chromedp.ExecAllocatorOption{
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.Flag("no-sandbox", true),                               // required for root
		chromedp.Flag("disable-dev-shm-usage", true),                   // avoid /dev/shm OOM
		chromedp.Flag("disable-blink-features", "AutomationControlled"), // hide navigator.webdriver
		chromedp.Flag("disable-infobars", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("mute-audio", true),
		chromedp.Flag("window-size", "1280,1024"),
		chromedp.Flag("window-position", "0,0"),
		chromedp.Flag("user-data-dir", "/tmp/relay-session-"+id),       // isolated profile: prevents singleton delegation to :0
		// Real UA: same as normal Chrome on Linux — NO "HeadlessChrome" word
		chromedp.Flag("user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"),
		chromedp.Env("DISPLAY="+display),                               // use TigerVNC :99 (not headless)
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
// Uses 2s timeout for element query — falls back to full-page if element not found (ByQuery retries otherwise).
func (s *Session) Screenshot(selector string) ([]byte, error) {
	var buf []byte
	tctx, cancel := context.WithTimeout(s.ctx, 2*time.Second) // short timeout: ByQuery retries indefinitely
	defer cancel()
	err := chromedp.Run(tctx, chromedp.Screenshot(selector, &buf, chromedp.NodeVisible, chromedp.ByQuery))
	if err != nil { // Fallback: full page
		err = chromedp.Run(s.ctx, chromedp.FullScreenshot(&buf, 90))
	}
	return buf, err
}

// ElementExists returns true if selector matches at least one DOM element.
func (s *Session) ElementExists(selector string) bool {
	var exists bool
	chromedp.Run(s.ctx, chromedp.Evaluate( //nolint:errcheck
		fmt.Sprintf("document.querySelector(%q) !== null", selector), &exists,
	))
	return exists
}

// SendKeys types text into an input field via JS — avoids chromedp DOM polling which hangs in headless=new.
// Uses React-compatible native value setter + input/change events so framework picks up the change.
func (s *Session) SendKeys(selector, text string) error {
	script := fmt.Sprintf(`(function(){
		var el = document.querySelector(%q);
		if(!el) return;
		var setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value').set;
		setter.call(el, %q);
		el.dispatchEvent(new Event('input',{bubbles:true}));
		el.dispatchEvent(new Event('change',{bubbles:true}));
	})()`, selector, text)
	return chromedp.Run(s.ctx, chromedp.Evaluate(script, nil))
}

// TypeReal simulates real keyboard typing (key events, not JS value setter). Use for
// pages that ignore JS value changes (e.g. Google challenge/pwd confirmation page).
func (s *Session) TypeReal(selector, text string) error {
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
	defer cancel()
	return chromedp.Run(ctx, chromedp.SendKeys(selector, text, chromedp.ByQuery))
}

// ClickNative clicks via CDP mouse events (not JS el.click()) — works on Google challenge pages
// that ignore JS-initiated clicks. Uses 3s timeout to find the element.
func (s *Session) ClickNative(selector string) error {
	ctx, cancel := context.WithTimeout(s.ctx, 3*time.Second)
	defer cancel()
	return chromedp.Run(ctx, chromedp.Click(selector, chromedp.ByQuery))
}

// EvaluateResult executes JS and returns the string result (for debugging DOM state).
func (s *Session) EvaluateResult(script string) string {
	var result string
	chromedp.Run(s.ctx, chromedp.Evaluate(script, &result)) //nolint:errcheck
	return result
}

// Click clicks an element via JS — avoids chromedp DOM polling which hangs in headless=new.
func (s *Session) Click(selector string) error {
	return chromedp.Run(s.ctx, chromedp.Evaluate(
		fmt.Sprintf("(function(){var el=document.querySelector(%q);if(el)el.click();})()", selector), nil,
	))
}

// Evaluate executes arbitrary JS (fire-and-forget, result discarded).
func (s *Session) Evaluate(script string) error {
	return chromedp.Run(s.ctx, chromedp.Evaluate(script, nil))
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
