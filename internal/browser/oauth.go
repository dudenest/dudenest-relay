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

// WaitForCallback starts a one-shot HTTP server on :8085 and returns the OAuth2 code.
// Blocks until callback received or timeout. Uses fresh ServeMux each call — safe for multiple calls.
func WaitForCallback(timeout time.Duration) (string, error) {
	ch := make(chan CallbackResult, 1)
	mux := http.NewServeMux() // fresh mux — avoids "pattern already registered" panic on second call
	mux.HandleFunc("/oauth/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		errMsg := r.URL.Query().Get("error")
		ch <- CallbackResult{Code: code, Error: errMsg}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><h2>Autoryzacja zakończona. Możesz zamknąć tę stronę.</h2></body></html>`))
	})
	srv := &http.Server{Addr: fmt.Sprintf(":%d", callbackPort), Handler: mux}
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", callbackPort))
	if err != nil {
		return "", fmt.Errorf("callback server listen: %w", err)
	}
	go func() { _ = srv.Serve(ln) }()
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

// CallbackURL returns the redirect_uri to use in OAuth2 flow.
func CallbackURL() string { return fmt.Sprintf("http://localhost:%d/oauth/callback", callbackPort) }
