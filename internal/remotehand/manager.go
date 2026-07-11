package remotehand

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"
)

// Broadcaster is the slice of ws.Hub that Remote-Hand needs: push sidecar output
// to Flutter (BroadcastRaw) and receive Flutter rh_input (SetOnClientMessage).
// *ws.Hub satisfies this (compile-time checked in manager_test.go).
type Broadcaster interface {
	BroadcastRaw([]byte)
	SetOnClientMessage(func([]byte))
	SetOnConnect(func())
}

// Manager runs many concurrent Remote-Hand sessions over one Hub. It allocates a
// display per session (§13), spawns a sidecar via a Bridge, and routes inbound
// Flutter rh_input to the right session by session_id — the multiplexing the
// single-handler Hub cannot do alone. Output goes out via BroadcastRaw (each
// message carries session_id; Flutter correlates).
type Manager struct {
	hub      Broadcaster
	pool     *DisplayPool
	script   string
	timeout  time.Duration
	extraEnv []string // e.g. RH_FAKE for tests; empty in production (real mode)

	mu       sync.Mutex
	sessions map[string]*mgrSession

	// prepareSession maps a provider (e.g. "gdrive") to the OAuth URL the sidecar
	// should open, AND arms server-side token capture as a side effect (serve.go
	// wires this to browser.Server.StartAssistedCapture). nil → only explicit
	// oauth_url requests are accepted (tests/advanced).
	prepareSession func(provider string) (string, error)
}

// SetPrepare installs the provider→OAuth-URL resolver that also arms token
// capture. Called once by serve.go after construction.
func (m *Manager) SetPrepare(fn func(provider string) (string, error)) {
	m.mu.Lock()
	m.prepareSession = fn
	m.mu.Unlock()
}

type mgrSession struct {
	bridge  *Bridge
	display string
	cancel  context.CancelFunc
	// last hello/prompt frames, replayed to a ws that connects after they were first sent
	// (the ws attaches a beat after /start — without replay the instant email form is lost).
	lastHello  []byte
	lastPrompt []byte
}

// NewManager wires the single inbound-frame router on the hub once. timeout caps
// how long a login session may run before auto-teardown (OAuth is minutes).
func NewManager(hub Broadcaster, pool *DisplayPool, script string, timeout time.Duration,
	extraEnv ...string) *Manager {
	m := &Manager{hub: hub, pool: pool, script: script, timeout: timeout,
		extraEnv: extraEnv, sessions: make(map[string]*mgrSession)}
	hub.SetOnClientMessage(m.routeInput)
	hub.SetOnConnect(m.replayToNewClient) // late-joining ws → re-send the last prompt
	return m
}

// sendAndCache forwards a sidecar frame to Flutter and remembers the last hello/prompt
// for this session so replayToNewClient can re-send them to a ws that connects later.
func (m *Manager) sendAndCache(sid string) func([]byte) {
	return func(line []byte) {
		var t struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(line, &t) == nil && (t.Type == "rh_hello" || t.Type == "rh_prompt") {
			cp := append([]byte(nil), line...)
			m.mu.Lock()
			if s := m.sessions[sid]; s != nil {
				if t.Type == "rh_hello" {
					s.lastHello = cp
				} else {
					s.lastPrompt = cp
				}
			}
			m.mu.Unlock()
		}
		m.hub.BroadcastRaw(line)
	}
}

// replayToNewClient re-broadcasts each live session's last hello+prompt so a ws that
// attached after they were first sent renders the form instead of a blank spinner.
func (m *Manager) replayToNewClient() {
	m.mu.Lock()
	var frames [][]byte
	for _, s := range m.sessions {
		if s.lastHello != nil {
			frames = append(frames, s.lastHello)
		}
		if s.lastPrompt != nil {
			frames = append(frames, s.lastPrompt)
		}
	}
	m.mu.Unlock()
	for _, f := range frames {
		m.hub.BroadcastRaw(f)
	}
}

// Start allocates a display, spawns a sidecar pointed at oauthURL, and returns
// the session id (echoed in every rh_* message). Caller ends it via End, or it
// auto-tears-down after timeout.
func (m *Manager) Start(oauthURL string) (string, error) {
	display, err := m.pool.Allocate()
	if err != nil {
		return "", err
	}
	sid := newSessionID()
	ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
	env := append([]string{"RH_OAUTH_URL=" + oauthURL}, m.extraEnv...)
	b := New(m.script, display, sid, m.sendAndCache(sid), env...)
	b.SetOnExit(func() { m.End(sid) }) // sidecar self-exit → free display now, not at timeout
	m.mu.Lock() // register BEFORE Start so the sidecar's first frames are cached for replay
	m.sessions[sid] = &mgrSession{bridge: b, display: display, cancel: cancel}
	m.mu.Unlock()
	if err := b.Start(ctx); err != nil {
		m.mu.Lock()
		delete(m.sessions, sid)
		m.mu.Unlock()
		cancel()
		m.pool.Release(display)
		return "", err
	}
	go func() { <-ctx.Done(); m.End(sid) }() // auto-teardown on timeout/cancel
	return sid, nil
}

// End tears down a session: kill sidecar, release its display (idempotent).
func (m *Manager) End(sid string) {
	m.mu.Lock()
	s := m.sessions[sid]
	delete(m.sessions, sid)
	m.mu.Unlock()
	if s == nil {
		return
	}
	_ = s.bridge.Close()
	s.cancel()
	m.pool.Release(s.display)
}

// Active reports the number of live sessions.
func (m *Manager) Active() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}

// routeInput dispatches one inbound Flutter frame to its session by session_id.
func (m *Manager) routeInput(frame []byte) {
	var env struct {
		SessionID string `json:"session_id"`
	}
	if json.Unmarshal(frame, &env) != nil || env.SessionID == "" {
		return
	}
	m.mu.Lock()
	s := m.sessions[env.SessionID]
	m.mu.Unlock()
	if s != nil {
		_ = s.bridge.SendInput(frame)
	}
}

func newSessionID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "rh-" + hex.EncodeToString(b[:])
}

// Attach wires a new sidecar session to the hub and starts it: sidecar output is
// broadcast to Flutter, and inbound Flutter frames (rh_input) are piped to the
// sidecar's stdin. Call this when the user picks method 3 for a provider; Close
// the returned Bridge when the flow ends (success/error/timeout).
func Attach(ctx context.Context, hub Broadcaster, script, display, sessionID string,
	extraEnv ...string) (*Bridge, error) {
	b := New(script, display, sessionID, hub.BroadcastRaw, extraEnv...)
	hub.SetOnClientMessage(func(frame []byte) { _ = b.SendInput(frame) })
	if err := b.Start(ctx); err != nil {
		return nil, err
	}
	return b, nil
}
