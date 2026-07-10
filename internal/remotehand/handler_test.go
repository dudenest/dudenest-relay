package remotehand

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newFakeManager(t *testing.T, displays ...string) (*Manager, *fakeHub) {
	t.Helper()
	requireSidecar(t)
	hub := newFakeHub()
	m := NewManager(hub, NewDisplayPool(displays...), sidecarScript(), 20*time.Second,
		"RH_FAKE=1", "RH_STATES=email,success")
	return m, hub
}

func TestStartHandlerOK(t *testing.T) {
	m, _ := newFakeManager(t, ":0")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/start",
		strings.NewReader(`{"oauth_url":"https://accounts.google.com/o/oauth2/v2/auth"}`))
	m.StartHandler()(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(resp["session_id"], "rh-") {
		t.Fatalf("bad session_id: %q", resp["session_id"])
	}
	m.End(resp["session_id"]) // cleanup spawned sidecar
}

func TestStartHandlerCapacity503(t *testing.T) {
	m, _ := newFakeManager(t, ":0") // pool of one
	body := `{"oauth_url":"u"}`
	rr1 := httptest.NewRecorder()
	m.StartHandler()(rr1, httptest.NewRequest(http.MethodPost, "/start", strings.NewReader(body)))
	if rr1.Code != http.StatusOK {
		t.Fatalf("first start want 200, got %d", rr1.Code)
	}
	var r1 map[string]string
	_ = json.Unmarshal(rr1.Body.Bytes(), &r1)
	defer m.End(r1["session_id"])

	rr2 := httptest.NewRecorder()
	m.StartHandler()(rr2, httptest.NewRequest(http.MethodPost, "/start", strings.NewReader(body)))
	if rr2.Code != http.StatusServiceUnavailable {
		t.Fatalf("exhausted pool want 503, got %d", rr2.Code)
	}
}

func TestStartHandlerValidation(t *testing.T) {
	m, _ := newFakeManager(t, ":0")
	// wrong method
	rr := httptest.NewRecorder()
	m.StartHandler()(rr, httptest.NewRequest(http.MethodGet, "/start", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", rr.Code)
	}
	// missing oauth_url
	rr = httptest.NewRecorder()
	m.StartHandler()(rr, httptest.NewRequest(http.MethodPost, "/start", strings.NewReader(`{}`)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rr.Code)
	}
}

func TestStartHandlerProviderPath(t *testing.T) {
	m, _ := newFakeManager(t, ":0")
	var gotProvider string
	m.SetPrepare(func(p string) (string, error) {
		gotProvider = p
		return "file:///tmp/oauth.html", nil // in prod: browser.BuildAuthURL + arm capture
	})
	rr := httptest.NewRecorder()
	m.StartHandler()(rr, httptest.NewRequest(http.MethodPost, "/start", strings.NewReader(`{"provider":"gdrive"}`)))
	if rr.Code != http.StatusOK {
		t.Fatalf("provider path want 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	if gotProvider != "gdrive" {
		t.Fatalf("prepare called with %q, want gdrive", gotProvider)
	}
	var resp map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	m.End(resp["session_id"])
}

func TestStartHandlerProviderNotConfigured(t *testing.T) {
	m, _ := newFakeManager(t, ":0") // no SetPrepare
	rr := httptest.NewRecorder()
	m.StartHandler()(rr, httptest.NewRequest(http.MethodPost, "/start", strings.NewReader(`{"provider":"gdrive"}`)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("unconfigured provider want 400, got %d", rr.Code)
	}
}

func TestStartHandlerProviderRejected(t *testing.T) {
	m, _ := newFakeManager(t, ":0")
	m.SetPrepare(func(p string) (string, error) { return "", errors.New("unsupported") })
	rr := httptest.NewRecorder()
	m.StartHandler()(rr, httptest.NewRequest(http.MethodPost, "/start", strings.NewReader(`{"provider":"mega"}`)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("rejected provider want 400, got %d", rr.Code)
	}
}

func TestEndHandler(t *testing.T) {
	m, _ := newFakeManager(t, ":0")
	rr := httptest.NewRecorder()
	m.StartHandler()(rr, httptest.NewRequest(http.MethodPost, "/start", strings.NewReader(`{"oauth_url":"u"}`)))
	var r map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &r)

	er := httptest.NewRecorder()
	m.EndHandler()(er, httptest.NewRequest(http.MethodPost, "/end",
		strings.NewReader(`{"session_id":"`+r["session_id"]+`"}`)))
	if er.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d", er.Code)
	}
	if m.Active() != 0 {
		t.Fatalf("session should be gone, active=%d", m.Active())
	}
}
