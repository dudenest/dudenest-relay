// Command rh-e2e is a thin end-to-end harness for the Remote-Hand backend.
// It wires the SAME production objects serve.go mounts — ws.Hub +
// remotehand.Manager + StartHandler/EndHandler + /ws — on a test port, so the
// full method-3 chain (HTTP → Manager → sidecar → vanilla Chromium → OCR → XTEST)
// can be exercised on relay-demo without touching the live relay service.
package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dudenest/dudenest-relay/internal/remotehand"
	"github.com/dudenest/dudenest-relay/internal/ws"
)

func main() {
	hub := ws.NewHub()
	script := os.Getenv("RH_SIDECAR_SCRIPT")
	if script == "" {
		log.Fatal("RH_SIDECAR_SCRIPT required")
	}
	display := os.Getenv("RH_DISPLAY")
	if display == "" {
		display = ":99"
	}
	mgr := remotehand.NewManager(hub, remotehand.NewDisplayPool(display), script, 3*time.Minute)

	mux := http.NewServeMux()
	mux.Handle("/ws", hub)
	mux.HandleFunc("/start", mgr.StartHandler())
	mux.HandleFunc("/end", mgr.EndHandler())

	addr := os.Getenv("RH_ADDR")
	if addr == "" {
		addr = "127.0.0.1:18080"
	}
	log.Printf("rh-e2e: listening %s  script=%s  display=%s", addr, script, display)
	log.Fatal(http.ListenAndServe(addr, mux))
}
