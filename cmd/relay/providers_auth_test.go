package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/dudenest/dudenest-relay/internal/auth"
	"github.com/dudenest/dudenest-relay/internal/browser"
	"github.com/dudenest/dudenest-relay/internal/relaytoken"
	"github.com/dudenest/dudenest-relay/internal/remotehand"
	wsrelay "github.com/dudenest/dudenest-relay/internal/ws"
)

func testJWT(t *testing.T, sub string) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	body, _ := json.Marshal(map[string]any{"sub": sub, "email": sub + "@example.test", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix()})
	msg := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	mac := hmac.New(sha256.New, []byte("test-jwt-secret"))
	mac.Write([]byte(msg))
	return msg + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func testRelayToken(userID, secret string) string {
	exp := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(userID + ":" + exp))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)) + "." + exp
}

func providersAuthRecorder(t *testing.T, userID string, relayTok string) *httptest.ResponseRecorder {
	t.Helper()
	auth.SetJWTSecret("test-jwt-secret")
	t.Setenv("RELAY_SECRET", "relay-secret")
	lr := &lazyRegistrar{}
	lr.setOwner("owner-1")
	mux := http.NewServeMux()
	srv := browser.NewServer(":99", "", "", nil, nil, t.TempDir(), nil, nil, 0, "", time.Minute)
	srv.RegisterRoutesWithAuth(mux, func(h http.HandlerFunc) http.HandlerFunc { return requireAuthWithReg(lr, h) })
	req := httptest.NewRequest(http.MethodGet, "/providers", nil)
	req.Header.Set("Authorization", "Bearer "+testJWT(t, userID))
	if relayTok != "" {
		req.Header.Set("X-Relay-Token", relayTok)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func secureMux(t *testing.T) (*http.ServeMux, string) {
	t.Helper()
	auth.SetJWTSecret("test-jwt-secret")
	t.Setenv("RELAY_SECRET", "relay-secret")
	lr := &lazyRegistrar{}
	lr.setOwner("owner-1")
	mux := http.NewServeMux()
	srv := browser.NewServer(":99", "", "", nil, nil, t.TempDir(), nil, nil, 0, "127.0.0.1:1", time.Minute)
	srv.RegisterRoutesWithAuth(mux, func(h http.HandlerFunc) http.HandlerFunc { return requireAuthWithReg(lr, h) })
	mux.Handle("/ws", requireAuthHandlerWithReg(lr, wsrelay.NewHub()))
	return mux, testRelayToken("owner-1", "relay-secret")
}

func TestProvidersUsesOwnerAndRelayTokenAuth(t *testing.T) {
	if rr := providersAuthRecorder(t, "foreign-1", testRelayToken("foreign-1", "relay-secret")); rr.Code != http.StatusForbidden {
		t.Fatalf("foreign JWT status=%d want 403", rr.Code)
	}
	if rr := providersAuthRecorder(t, "owner-1", ""); rr.Code != http.StatusForbidden {
		t.Fatalf("missing relay token status=%d want 403", rr.Code)
	}
	if rr := providersAuthRecorder(t, "owner-1", "bad.token"); rr.Code != http.StatusForbidden {
		t.Fatalf("bad relay token status=%d want 403", rr.Code)
	}
	good := testRelayToken("owner-1", "relay-secret")
	if !relaytoken.Verify(good, "relay-secret", "owner-1") {
		t.Fatal("test relay token invalid")
	}
	if rr := providersAuthRecorder(t, "owner-1", good); rr.Code != http.StatusOK {
		t.Fatalf("owner+valid relay token status=%d want 200 body=%s", rr.Code, rr.Body.String())
	}
}

func TestQueryJWTStillRequiresRelayTokenOutsideFiles(t *testing.T) {
	mux, good := secureMux(t)
	jwt := testJWT(t, "owner-1")
	for _, path := range []string{"/providers?token=" + jwt, "/vnc/dudenest.html?token=" + jwt, "/ws?token=" + jwt} {
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != http.StatusForbidden {
			t.Fatalf("%s status=%d want 403", path, rr.Code)
		}
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/vnc/dudenest.html?token="+jwt+"&relay_token="+good, nil))
	if rr.Code == http.StatusUnauthorized || rr.Code == http.StatusForbidden {
		t.Fatalf("/vnc owner query auth status=%d want proxied response", rr.Code)
	}
}

func TestStandbyAccountRoutesDoNotFallThroughTo503(t *testing.T) {
	auth.SetJWTSecret("test-jwt-secret")
	mux := http.NewServeMux()
	lr := &lazyRegistrar{}
	rhMgr := remotehand.NewManager(wsrelay.NewHub(), remotehand.NewDisplayPool(":99"), "/no/such/sidecar.py", time.Minute)
	registerStandbyAccountRoutes(mux, lr, rhMgr)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { jsonErr(w, "standby", http.StatusServiceUnavailable) })
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/providers", nil)
	req.Header.Set("Authorization", "Bearer "+testJWT(t, "owner-1"))
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || rr.Body.String() != "[]" {
		t.Fatalf("/providers standby status=%d body=%q, want 200 []", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/relay/oauth3/start", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("/relay/oauth3/start standby status=%d body=%q, want 401 not catch-all 503", rr.Code, rr.Body.String())
	}
}
