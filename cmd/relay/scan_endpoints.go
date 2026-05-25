// scan_endpoints.go — admin HTTP handlers for the P5c scan engine.
// All require X-Relay-Token (same auth wrapper as /files) — the same paired Flutter user can
// observe/control scans. No public access — scanning enumerates user's cloud contents.
//
//   GET  /admin/scan/status                       — JSON map of all providers + their scan states
//   POST /admin/scan/start?provider=<id>          — kick off (or resume) P5c full-walk scan
//   POST /admin/scan/pause?provider=<id>          — request pause (settles within seconds)
//   POST /admin/scan/bootstrap?provider=<id>      — s321: one-shot Drive-wide retro-index (catches files outside basefolder)
//   POST /admin/scan/bootstrap?provider=<id>&reset=1  — clear bootstrapped flag and re-run
//   GET  /admin/scan/config                       — read auto-rescan config
//   POST /admin/scan/config                       — update auto-rescan config (JSON body)
package main

import (
	"encoding/json"
	"net/http"

	"github.com/dudenest/dudenest-relay/internal/scan"
)

type scanHandlers struct{ scanner *scan.Scanner }

func (h *scanHandlers) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet { http.Error(w, "GET only", http.StatusMethodNotAllowed); return }
	writeJSON(w, http.StatusOK, h.scanner.StatusAll())
}

func (h *scanHandlers) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "POST only", http.StatusMethodNotAllowed); return }
	pid := r.URL.Query().Get("provider")
	if pid == "" { jsonErr(w, "provider query param required", http.StatusBadRequest); return }
	st, err := h.scanner.Start(pid)
	if err != nil { jsonErr(w, err.Error(), http.StatusBadRequest); return }
	writeJSON(w, http.StatusOK, st)
}

func (h *scanHandlers) handlePause(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "POST only", http.StatusMethodNotAllowed); return }
	pid := r.URL.Query().Get("provider")
	if pid == "" { jsonErr(w, "provider query param required", http.StatusBadRequest); return }
	if err := h.scanner.Pause(pid); err != nil { jsonErr(w, err.Error(), http.StatusBadRequest); return }
	writeJSON(w, http.StatusOK, map[string]string{"status": "pausing"})
}

// handleBootstrapWholeDrive triggers (or re-triggers via reset=1) a Drive-wide one-shot retro-index.
// Async — returns 202 Accepted immediately, scan runs in background goroutine. Poll /admin/scan/status
// to see WholeDriveBootstrapped flag + WholeDriveBootstrapIndexed counter. s321 (carry-over s320-A).
func (h *scanHandlers) handleBootstrapWholeDrive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "POST only", http.StatusMethodNotAllowed); return }
	pid := r.URL.Query().Get("provider")
	if pid == "" { jsonErr(w, "provider query param required", http.StatusBadRequest); return }
	if r.URL.Query().Get("reset") == "1" {
		if err := h.scanner.ResetWholeDriveBootstrap(pid); err != nil { jsonErr(w, err.Error(), http.StatusInternalServerError); return }
	}
	go func() {
		if err := h.scanner.BootstrapWholeDrive(pid); err != nil { /* logged inside scanner */ _ = err }
	}()
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted", "note": "bootstrap running in background; poll /admin/scan/status for whole_drive_bootstrap_indexed counter"})
}

func (h *scanHandlers) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, h.scanner.GetConfig())
	case http.MethodPost:
		var cfg scan.Config
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil { jsonErr(w, "bad json: "+err.Error(), 400); return }
		if err := h.scanner.SetConfig(cfg); err != nil { jsonErr(w, "save config: "+err.Error(), 500); return }
		writeJSON(w, http.StatusOK, cfg)
	default:
		http.Error(w, "GET or POST only", http.StatusMethodNotAllowed)
	}
}
