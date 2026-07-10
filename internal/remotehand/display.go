package remotehand

import (
	"errors"
	"sync"
)

// ErrNoDisplay is returned when every X display in the pool is in use.
var ErrNoDisplay = errors.New("remotehand: no free X display")

// DisplayPool hands out X display numbers for concurrent login sessions
// (RELAY-REMOTE-HAND-PLAN.md §13 multi-display). Today it wraps a small fixed set
// (e.g. just ":99"); the same API scales unchanged to hundreds of per-session Xvfb
// displays — only the seed list and a spawner grow. Concurrency-safe.
type DisplayPool struct {
	mu    sync.Mutex
	known map[string]bool // every display this pool owns (for Release validation)
	free  []string        // currently available
}

// NewDisplayPool seeds the pool. With no args it defaults to the single ":99"
// that relay-demo runs today.
func NewDisplayPool(displays ...string) *DisplayPool {
	if len(displays) == 0 {
		displays = []string{":99"}
	}
	p := &DisplayPool{known: make(map[string]bool, len(displays))}
	for _, d := range displays {
		if !p.known[d] { // dedupe seeds
			p.known[d] = true
			p.free = append(p.free, d)
		}
	}
	return p
}

// Allocate reserves a free display or returns ErrNoDisplay.
func (p *DisplayPool) Allocate() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.free) == 0 {
		return "", ErrNoDisplay
	}
	d := p.free[len(p.free)-1]
	p.free = p.free[:len(p.free)-1]
	return d, nil
}

// Release returns a display to the pool. Unknown displays and double-releases are
// ignored (idempotent) so a buggy caller can't corrupt the pool.
func (p *DisplayPool) Release(d string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.known[d] {
		return
	}
	for _, f := range p.free { // already free → no-op
		if f == d {
			return
		}
	}
	p.free = append(p.free, d)
}

// Available reports how many displays are currently free.
func (p *DisplayPool) Available() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.free)
}
