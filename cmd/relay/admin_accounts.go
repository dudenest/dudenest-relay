// Phase β admin endpoints — CRUD for CloudAccount + AccountPolicyConfig.
// All routes are wrapped in the same auth chain as /files (JWT + X-Relay-Token via requireAuthWithReg)
// so only the paired Flutter user can mutate their own relay's account state.
//
// Routes registered in serve.go full-server section:
//   GET    /admin/accounts                  → list (active + Removed)
//   POST   /admin/accounts/reorder          → bulk priority reorder
//   GET    /admin/accounts/{id}             → single
//   PATCH  /admin/accounts/{id}             → mutate Role / Pinned / per-account policy overrides
//   POST   /admin/accounts/{id}/refresh-quota → on-demand quota refresh
//   GET    /admin/policy                    → current AccountPolicyConfig
//   PATCH  /admin/policy                    → mutate any subset of policy fields
//
// All responses are JSON. Error format matches the rest of the relay: {"error": "..."}.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/dudenest/dudenest-relay/internal/account"
	"github.com/dudenest/dudenest-relay/pkg/types"
)

// globalDrainState holds the live drain progress tracker. Phase γ admin endpoint
// /admin/accounts/{id} GET surfaces this so Flutter UI can show "draining: 437/1247 replicas".
var globalDrainState *account.DrainState

// globalAdminAccounts is set by serve.go after account.Manager is constructed and read by the
// full-server route registration block. Package-level var because the construction (in serve.go's
// pipeline init section) happens before the mux is built, but the route registration happens after.
// Nil = Phase α legacy / no Manager attached → admin routes are skipped (existing /files works).
var globalAdminAccounts *accountAdmin

// accountAdmin holds the deps needed to serve /admin/accounts/* + /admin/policy.
// Built once in serve.go and registered on the mux. The fileServer-level lookup callback
// (provLookup) lets us resolve CloudAccount → CloudProvider for quota refresh without the
// admin code reaching into pipeline internals.
type accountAdmin struct {
	mgr        *account.Manager
	provLookup account.ProviderLookup
}

// registerAdminAccountRoutes wires the routes on the given mux. Uses authWrap to apply
// the same JWT+X-Relay-Token middleware that /files endpoints use (caller supplies it so
// this file doesn't depend on lazyRegistrar internals).
func (a *accountAdmin) register(mux *http.ServeMux, authWrap func(http.HandlerFunc) http.HandlerFunc) {
	if a == nil || a.mgr == nil {
		return // legacy/CLI path — Phase α also runs without admin endpoints
	}
	mux.HandleFunc("/admin/accounts", authWrap(a.handleListOrReorder))
	mux.HandleFunc("/admin/accounts/", authWrap(a.handleByID))
	mux.HandleFunc("/admin/policy", authWrap(a.handlePolicy))
}

// --- routes ---

// handleListOrReorder serves both GET /admin/accounts (list) and POST /admin/accounts/reorder
// (bulk priority reorder). Sub-route distinguished by path suffix to keep handler count down.
// POST without trailing /reorder is reserved for future "add account" workflow (Phase β UI).
func (a *accountAdmin) handleListOrReorder(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"accounts": a.mgr.Accounts(), "policy": a.mgr.Policy()})
	case http.MethodPost:
		// Sub-routes via path suffix (s319 #9: refresh-quota for bulk refresh)
		if strings.HasSuffix(r.URL.Path, "/refresh-quota") {
			a.handleRefreshQuotaAll(w, r)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/reorder") {
			httpErr(w, http.StatusNotFound, "expected /admin/accounts/reorder or /admin/accounts/refresh-quota")
			return
		}
		var body struct {
			IDs []int64 `json:"ids"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			httpErr(w, http.StatusBadRequest, "bad json: "+err.Error()); return
		}
		if err := a.mgr.Reorder(body.IDs); err != nil {
			httpErr(w, http.StatusBadRequest, err.Error()); return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "accounts": a.mgr.Accounts()})
	default:
		httpErr(w, http.StatusMethodNotAllowed, "GET or POST only")
	}
}

// handleByID dispatches /admin/accounts/{id} and /admin/accounts/{id}/refresh-quota.
// /admin/accounts/reorder is intentionally handled above to keep the bulk + per-id routes separate.
func (a *accountAdmin) handleByID(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/admin/accounts/")
	if rest == "" || rest == "reorder" {
		// /reorder is the bulk route, served by handleListOrReorder via the /admin/accounts mux entry.
		// Empty rest shouldn't reach us (different mux entry) but defensively handle it.
		httpErr(w, http.StatusBadRequest, "account id required")
		return
	}
	idStr, sub, _ := strings.Cut(rest, "/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httpErr(w, http.StatusBadRequest, "id must be integer")
		return
	}
	if sub == "refresh-quota" {
		a.handleRefreshQuota(w, r, id)
		return
	}
	if sub == "drain-progress" {
		a.handleDrainProgress(w, r, id)
		return
	}
	if sub != "" {
		httpErr(w, http.StatusNotFound, "unknown sub-resource: "+sub)
		return
	}
	switch r.Method {
	case http.MethodGet:
		a.handleGet(w, r, id)
	case http.MethodPatch:
		a.handlePatch(w, r, id)
	case http.MethodDelete:
		// Phase γ (v0.19.0+): drain worker is live. Account flips to Role=Drain immediately,
		// stops receiving new uploads via SelectReplicas filter, and within 2 min the StartDrainLoop
		// sweep starts migrating replicas to other accounts. Progress polled via /admin/accounts/{id}/drain-progress.
		if err := a.mgr.SetRole(id, types.RoleDrain); err != nil { httpErr(w, http.StatusNotFound, err.Error()); return }
		writeJSON(w, http.StatusOK, map[string]string{"status": "drain_initiated", "note": "account will not receive new uploads; poll /admin/accounts/{id}/drain-progress for migration status (background worker starts within 2 min)"})
	default:
		httpErr(w, http.StatusMethodNotAllowed, "GET, PATCH, DELETE only")
	}
}

func (a *accountAdmin) handleGet(w http.ResponseWriter, r *http.Request, id int64) {
	for _, acc := range a.mgr.Accounts() {
		if acc.ID == id { writeJSON(w, http.StatusOK, acc); return }
	}
	httpErr(w, http.StatusNotFound, fmt.Sprintf("account %d not found", id))
}

// handlePatch accepts a partial AccountPolicyConfig-like overlay. Only fields present in the JSON
// body are applied — others are left untouched. This is the "edit account" path the Flutter UI hits.
//
// Accepted fields:
//   role             → Role (any of the enum strings)
//   priority         → int (use POST /admin/accounts/reorder for bulk; this is single-account override)
//   pinned           → bool
//   soft_cap_pct     → int (per-account override of global SoftCapDefaultPct)
//   hard_cap_pct     → int (per-account override of global HardCapDefaultPct)
//   max_file_size_mb → int (translated to bytes internally)
//   accepts_content_types → []string (nil = inherit; [] = explicit no-types, accept-all stays nil)
//   region           → string (F4)
//   compression_level → int 0-9 (F3)
func (a *accountAdmin) handlePatch(w http.ResponseWriter, r *http.Request, id int64) {
	var patch struct {
		Role                *string  `json:"role,omitempty"`
		Priority            *int     `json:"priority,omitempty"`
		Pinned              *bool    `json:"pinned,omitempty"`
		SoftCapPct          *int     `json:"soft_cap_pct,omitempty"`
		HardCapPct          *int     `json:"hard_cap_pct,omitempty"`
		MaxFileSizeMB       *int64   `json:"max_file_size_mb,omitempty"`
		AcceptsContentTypes *[]string `json:"accepts_content_types,omitempty"`
		Region              *string  `json:"region,omitempty"`
		CompressionLevel    *int     `json:"compression_level,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		httpErr(w, http.StatusBadRequest, "bad json: "+err.Error()); return
	}
	// Find + mutate; persist via a custom helper since Manager doesn't expose direct setters
	// for per-account policy yet (Phase β additive). For role we use the existing SetRole().
	all := a.mgr.Accounts()
	var target *types.CloudAccount
	for i := range all {
		if all[i].ID == id { target = all[i]; break }
	}
	if target == nil {
		httpErr(w, http.StatusNotFound, fmt.Sprintf("account %d not found", id)); return
	}
	if patch.Role != nil {
		if err := a.mgr.SetRole(id, types.Role(*patch.Role)); err != nil {
			httpErr(w, http.StatusBadRequest, err.Error()); return
		}
	}
	if patch.Priority != nil || patch.Pinned != nil || patch.SoftCapPct != nil || patch.HardCapPct != nil ||
		patch.MaxFileSizeMB != nil || patch.AcceptsContentTypes != nil || patch.Region != nil || patch.CompressionLevel != nil {
		// Apply remaining fields by re-loading + writing through SaveAccounts. The Manager API
		// could grow typed setters for each, but a single PATCH-style overlay is more concise.
		live := a.mgr.Accounts()
		for _, acc := range live {
			if acc.ID != id { continue }
			if patch.Priority != nil { acc.Priority = *patch.Priority }
			if patch.Pinned != nil { acc.Pinned = *patch.Pinned }
			if patch.SoftCapPct != nil { v := *patch.SoftCapPct; acc.SoftCapPct = &v }
			if patch.HardCapPct != nil { v := *patch.HardCapPct; acc.HardCapPct = &v }
			if patch.MaxFileSizeMB != nil { v := *patch.MaxFileSizeMB * 1024 * 1024; acc.MaxFileSizeBytes = &v }
			if patch.AcceptsContentTypes != nil { acc.AcceptsContentTypes = patch.AcceptsContentTypes }
			if patch.Region != nil { acc.Region = *patch.Region }
			if patch.CompressionLevel != nil { acc.CompressionLevel = *patch.CompressionLevel }
		}
		// Replace internal slice via direct save — load+save is atomic enough since Accounts()
		// returns deep copies that we then re-marshal. For Phase β we use Manager.replaceAll
		// helper which lives next to the loaders; for now, leverage SaveAccounts after mutating
		// the in-place slice through reflection — but cleaner is to use the writeAccounts helper.
		// Pragmatic: SaveAccounts persists Manager.accounts; we need to mutate those, so call setAll.
		_ = a.mgr.ReplaceAll(live)
	}
	// Return refreshed view
	for _, acc := range a.mgr.Accounts() {
		if acc.ID == id { writeJSON(w, http.StatusOK, acc); return }
	}
	httpErr(w, http.StatusInternalServerError, "account vanished after patch")
}

// handleRefreshQuotaAll triggers concurrent on-demand quota fetch for ALL accounts. Useful when
// user opens the UI and wants up-to-date quota across the board without waiting for the 30-min
// scheduled poll. Returns immediately (fire-and-forget); next GET /admin/accounts will see refreshed
// values. Backed by goroutine pool sized at min(len(accounts), 8) to avoid hammering Drive API.
// s319 #9 carry-over.
func (a *accountAdmin) handleRefreshQuotaAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { httpErr(w, http.StatusMethodNotAllowed, "POST only"); return }
	if a.provLookup == nil {
		httpErr(w, http.StatusServiceUnavailable, "quota refresh disabled: no provider lookup configured")
		return
	}
	accts := a.mgr.Accounts()
	ids := []int64{}
	for _, acc := range accts {
		if acc.Status == types.StatusRemoved { continue } // skip soft-deleted
		ids = append(ids, acc.ID)
	}
	// Fire-and-forget: spawn goroutine that walks IDs with bounded concurrency.
	go func() {
		const maxConcurrent = 8
		sem := make(chan struct{}, maxConcurrent)
		for _, id := range ids {
			sem <- struct{}{}
			go func(id int64) {
				defer func() { <-sem }()
				if err := a.mgr.RefreshQuota(id, a.provLookup); err != nil {
					// Per-account error already logged inside RefreshQuota via Status=Error; nothing to do here
					_ = err
				}
			}(id)
		}
		// Drain sem to wait for all (so we know when done, though caller already returned)
		for i := 0; i < maxConcurrent; i++ { sem <- struct{}{} }
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "accepted", "accounts_queued": len(ids)})
}

// handleDrainProgress returns DrainState snapshot for one account. Surfaces background-worker
// progress to Flutter UI so user sees "draining 437/1247 replicas (35%)" instead of opaque "Role=Drain".
// Returns 200 always (drain may not have started yet — `started_at` is zero-time when in-flight not yet begun).
// 503 if globalDrainState not wired (legacy/CLI path).
func (a *accountAdmin) handleDrainProgress(w http.ResponseWriter, r *http.Request, id int64) {
	if r.Method != http.MethodGet { httpErr(w, http.StatusMethodNotAllowed, "GET only"); return }
	if globalDrainState == nil {
		httpErr(w, http.StatusServiceUnavailable, "drain state tracker not initialized (legacy build)")
		return
	}
	snap := globalDrainState.Snapshot(id)
	// Verify account actually exists + is in Drain role; otherwise UI gets misleading "0/0" forever.
	var acct *types.CloudAccount
	for _, acc := range a.mgr.Accounts() {
		if acc.ID == id { acct = acc; break }
	}
	if acct == nil { httpErr(w, http.StatusNotFound, fmt.Sprintf("account %d not found", id)); return }
	resp := map[string]any{
		"account_id":  id,
		"role":        string(acct.Role),
		"status":      string(acct.Status),
		"in_progress": acct.Role == types.RoleDrain && (snap == nil || snap.ReplicasMigrated < snap.ReplicasToMigrate),
		"snapshot":    snap, // nil before first sweep — Flutter renders "waiting for first sweep"
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleRefreshQuota triggers an on-demand quota fetch for one account. Useful when the user
// just freed up space on Drive and wants the relay to acknowledge the new headroom before the
// scheduled poll fires (which can be up to QuotaCheckIntervalMin minutes away).
func (a *accountAdmin) handleRefreshQuota(w http.ResponseWriter, r *http.Request, id int64) {
	if r.Method != http.MethodPost { httpErr(w, http.StatusMethodNotAllowed, "POST only"); return }
	if a.provLookup == nil {
		httpErr(w, http.StatusServiceUnavailable, "quota refresh disabled: no provider lookup configured")
		return
	}
	if err := a.mgr.RefreshQuota(id, a.provLookup); err != nil {
		httpErr(w, http.StatusBadGateway, err.Error()); return
	}
	for _, acc := range a.mgr.Accounts() {
		if acc.ID == id { writeJSON(w, http.StatusOK, acc); return }
	}
	httpErr(w, http.StatusNotFound, fmt.Sprintf("account %d not found", id))
}

// handlePolicy serves GET (current AccountPolicyConfig) and PATCH (overlay of partial fields).
// The PATCH body accepts any subset of AccountPolicyConfig — unset fields are preserved.
func (a *accountAdmin) handlePolicy(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, a.mgr.Policy())
	case http.MethodPatch:
		// PATCH takes a partial AccountPolicyConfig. We deserialize into a map, apply changes
		// onto the current policy, and persist. Type validation happens implicitly via json.Marshal
		// round-trip — anything that doesn't fit AccountPolicyConfig's field types is rejected.
		var patch map[string]any
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			httpErr(w, http.StatusBadRequest, "bad json: "+err.Error()); return
		}
		cur := a.mgr.Policy()
		// Round-trip current policy → map → apply patch → map → AccountPolicyConfig.
		buf, _ := json.Marshal(cur)
		var curMap map[string]any
		_ = json.Unmarshal(buf, &curMap)
		for k, v := range patch { curMap[k] = v }
		merged, _ := json.Marshal(curMap)
		var next types.AccountPolicyConfig
		if err := json.Unmarshal(merged, &next); err != nil {
			httpErr(w, http.StatusBadRequest, "merge: "+err.Error()); return
		}
		if err := a.mgr.UpdatePolicy(next); err != nil {
			httpErr(w, http.StatusInternalServerError, err.Error()); return
		}
		writeJSON(w, http.StatusOK, next)
	default:
		httpErr(w, http.StatusMethodNotAllowed, "GET or PATCH only")
	}
}

// --- helpers ---

// writeJSON is provided by admin.go (same package). httpErr stays local since it has different
// semantics (error envelope) from the rest of the codebase's jsonErr().

func httpErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
