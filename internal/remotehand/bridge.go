// Package remotehand bridges the CDP-free Remote-Hand Python sidecar (method 3
// mediated login) to the relay's Flutter WebSocket.
//
// One Bridge == one login session == one sidecar process. The relay spawns the
// sidecar with DISPLAY=:N; the sidecar drives a vanilla Chromium via XTEST
// (undetectable — no CDP, no navigator.webdriver) and speaks one JSON object per
// line over stdio:
//
//	sidecar stdout → Flutter:  rh_hello / rh_prompt / rh_state   (via Send)
//	Flutter → sidecar stdin:   rh_input                           (via SendInput)
//
// This Go side only manages the process and moves bytes — it holds no crypto and
// no browser logic (both live in the sidecar), keeping the relay binary pure-Go
// (CGO_ENABLED=0) and the automation stack fully decoupled.
package remotehand

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
)

// Bridge owns one sidecar subprocess and pipes its stdio.
type Bridge struct {
	script    string   // path to rh_sidecar.py
	display   string   // X display, e.g. ":99"
	sessionID string   // correlates with ws messages
	env       []string // extra env (e.g. RH_FAKE=1 for tests)
	send      func([]byte)
	onExit    func() // invoked once when the sidecar exits (stdout EOF) — frees the display

	mu     sync.Mutex
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	closed bool
}

// SetOnExit registers a callback fired once when the sidecar process exits on its
// own (browser closed, crash, flow done) so the Manager can release the display
// immediately instead of waiting for the session timeout. Call before Start.
func (b *Bridge) SetOnExit(fn func()) { b.onExit = fn }

// New builds a Bridge. send is invoked for every line the sidecar emits
// (wire it to ws.Hub.BroadcastRaw). extraEnv is appended to the child env.
func New(script, display, sessionID string, send func([]byte), extraEnv ...string) *Bridge {
	return &Bridge{script: script, display: display, sessionID: sessionID, send: send, env: extraEnv}
}

// Start launches the sidecar and begins forwarding its stdout lines to send.
func (b *Bridge) Start(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cmd != nil {
		return fmt.Errorf("bridge already started")
	}
	cmd := exec.CommandContext(ctx, "python3", b.script)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // own process group → kill sidecar+Chromium tree together
	cmd.Env = append(os.Environ(),
		"DISPLAY="+b.display, "RH_DISPLAY="+b.display, "RH_SESSION="+b.sessionID)
	cmd.Env = append(cmd.Env, b.env...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}
	cmd.Stderr = os.Stderr // sidecar diagnostics (never secrets) go to relay logs
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start sidecar: %w", err)
	}
	b.cmd, b.stdin = cmd, stdin
	go b.readLoop(stdout)
	return nil
}

// readLoop forwards each sidecar stdout line to send until EOF. EOF means the
// sidecar exited — fire onExit so the Manager frees the display promptly (else it
// leaks until the session timeout and exhausts the small display pool under churn).
func (b *Bridge) readLoop(stdout io.Reader) {
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024) // captcha images can be large
	for sc.Scan() {
		line := append([]byte(nil), sc.Bytes()...) // copy — Scanner reuses its buffer
		if b.send != nil && len(line) > 0 {
			b.send(line)
		}
	}
	if b.onExit != nil {
		b.onExit() // sidecar gone; Manager.End is idempotent so a concurrent Close is safe
	}
}

// SendInput writes one Flutter rh_input frame to the sidecar's stdin.
func (b *Bridge) SendInput(line []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stdin == nil || b.closed {
		return fmt.Errorf("bridge not running")
	}
	if _, err := b.stdin.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("write sidecar stdin: %w", err)
	}
	return nil
}

// Close terminates the sidecar and releases resources (idempotent).
func (b *Bridge) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	if b.stdin != nil {
		_ = b.stdin.Close()
	}
	if b.cmd != nil && b.cmd.Process != nil {
		// Kill the whole process group (negative pid) so Chromium and its child tree
		// die with the sidecar — a lone Process.Kill leaves orphaned Chromium procs
		// that pile up on the display and break window mapping (the 'no form' bug).
		_ = syscall.Kill(-b.cmd.Process.Pid, syscall.SIGKILL)
		_ = b.cmd.Process.Kill() // fallback if the group kill didn't apply
		go func(c *exec.Cmd) { _ = c.Wait() }(b.cmd) // reap without holding the lock
	}
	return nil
}
