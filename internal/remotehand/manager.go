package remotehand

import "context"

// Broadcaster is the slice of ws.Hub that Remote-Hand needs: push sidecar output
// to Flutter (BroadcastRaw) and receive Flutter rh_input (SetOnClientMessage).
// *ws.Hub satisfies this (compile-time checked in manager_test.go).
type Broadcaster interface {
	BroadcastRaw([]byte)
	SetOnClientMessage(func([]byte))
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
