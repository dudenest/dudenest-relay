// manager.go — session lifecycle management (create, get, cleanup).
package browser

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

const sessionTimeout = 5 * time.Minute // Idle sessions auto-expire

// Manager manages browser sessions, one per auth flow.
type Manager struct {
	display  string
	sessions map[string]*Session
	mu       sync.Mutex
}

// NewManager creates a session manager for the given X display (e.g. ":99").
func NewManager(display string) *Manager {
	m := &Manager{display: display, sessions: make(map[string]*Session)}
	go m.cleanupLoop()
	return m
}

// Create starts a new browser session and returns its ID.
func (m *Manager) Create() (string, error) {
	id := uuid.New().String()
	s, err := NewSession(id, m.display)
	if err != nil {
		return "", fmt.Errorf("create session: %w", err)
	}
	m.mu.Lock()
	m.sessions[id] = s
	m.mu.Unlock()
	return id, nil
}

// Get returns a session by ID.
func (m *Manager) Get(id string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return nil, fmt.Errorf("session %s not found", id)
	}
	return s, nil
}

// Close terminates and removes a session.
func (m *Manager) Close(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[id]; ok {
		s.Close()
		delete(m.sessions, id)
	}
}

// cleanupLoop removes sessions older than sessionTimeout every minute.
func (m *Manager) cleanupLoop() {
	for range time.Tick(time.Minute) {
		m.mu.Lock()
		for id, s := range m.sessions {
			if s.Age() > sessionTimeout {
				s.Close()
				delete(m.sessions, id)
			}
		}
		m.mu.Unlock()
	}
}
