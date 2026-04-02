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
// The returned wait() blocks until OAuth code arrives or timeout.
func StartCallbackServer(timeout time.Duration) (wait func() (string, error), err error) {
	ch := make(chan CallbackResult, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		errMsg := r.URL.Query().Get("error")
		ch <- CallbackResult{Code: code, Error: errMsg}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><h2>Autoryzacja zakończona. Możesz zamknąć tę stronę.</h2></body></html>`))
	})
	ln, listenErr := net.Listen("tcp", fmt.Sprintf(":%d", callbackPort)) // bind port NOW (sync)
	if listenErr != nil {
		return nil, fmt.Errorf("callback server listen: %w", listenErr)
	}
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }() // accept loop in background; port already bound above
	wait = func() (string, error) {
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = srv.Shutdown(ctx)
		}()
		select {
		case res := <-ch:
			if res.Error != "" {
				return "", fmt.Errorf("oauth error: %s", res.Error)
			}
			return res.Code, nil
		case <-time.After(timeout):
			return "", fmt.Errorf("callback timeout after %s", timeout)
		}
	}
	return wait, nil
}

// WaitForCallback is kept for backward compatibility — wraps StartCallbackServer.
func WaitForCallback(timeout time.Duration) (string, error) {
	wait, err := StartCallbackServer(timeout)
	if err != nil {
		return "", err
	}
	return wait()
}

// CallbackURL returns the redirect_uri to use in OAuth2 flow.
func CallbackURL() string { return fmt.Sprintf("http://localhost:%d/oauth/callback", callbackPort) }
