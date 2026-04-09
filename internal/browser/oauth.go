// oauth.go — OAuth2 callback server listening on localhost:8085.
package browser

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

const callbackPort = 8085

// CallbackResult holds the code or error from OAuth2 redirect.
type CallbackResult struct {
	Code  string
	Error string
}

// StartCallbackServer binds :8085 synchronously and returns a wait function.
// MUST be called BEFORE clicking consent — ensures port is bound before browser redirects.
// ctx cancellation immediately frees port :8085 — caller should defer cancel() to prevent port leaks.
func StartCallbackServer(ctx context.Context, timeout time.Duration) (wait func() (string, error), err error) {
	ch := make(chan CallbackResult, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		errMsg := r.URL.Query().Get("error")
		ch <- CallbackResult{Code: code, Error: errMsg}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<html><head><meta charset="utf-8"></head><body><h2>Authorization complete. You can close this page.</h2></body></html>`))
	})
	ln, listenErr := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", callbackPort)) // bind IPv4 only — Chrome may use ::1 for "localhost"
	if listenErr != nil {
		return nil, fmt.Errorf("callback server listen: %w", listenErr)
	}
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	shutdown := func() { // shutdown helper — frees port
		sctx, scancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer scancel()
		_ = srv.Shutdown(sctx)
	}
	go func() { <-ctx.Done(); shutdown() }() // free port when ctx cancelled (e.g. handler returned)
	wait = func() (string, error) {
		defer shutdown()
		select {
		case res := <-ch:
			if res.Error != "" {
				return "", fmt.Errorf("oauth error: %s", res.Error)
			}
			return res.Code, nil
		case <-time.After(timeout):
			return "", fmt.Errorf("callback timeout after %s", timeout)
		case <-ctx.Done():
			return "", fmt.Errorf("callback server cancelled")
		}
	}
	return wait, nil
}

// WaitForCallback is kept for backward compatibility — wraps StartCallbackServer.
func WaitForCallback(timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	wait, err := StartCallbackServer(ctx, timeout)
	if err != nil {
		return "", err
	}
	return wait()
}

// CallbackURL returns the redirect_uri to use in OAuth2 flow.
func CallbackURL() string { return fmt.Sprintf("http://127.0.0.1:%d/oauth/callback", callbackPort) }
