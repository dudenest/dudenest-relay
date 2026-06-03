// admin.go — relay-local admin endpoints called by Flutter "Update" screen.
//
// /admin/version: returns the running relay version + the latest GitHub release tag + URLs
// (repo, release, changelog) so the Flutter UI can render a "you're on X, latest is Y" banner
// and offer one-click update. Cheap call — only hits GitHub when invoked, not on a timer.
//
// /admin/update: triggers an immediate self-update (downloads the matching binary from GitHub
// release assets, atomically replaces /usr/local/bin/relay) then SIGTERMs the process so systemd
// (Restart=always) brings the new binary up. Response is sent BEFORE the SIGTERM so the Flutter
// app gets a final {"status":"updating", ...} JSON before the connection drops; the app shows a
// "relay restarting…" spinner and re-checks /admin/version after a few seconds.
//
// Auth: same wrapper as /files (requireAuthWithReg — JWT + X-Relay-Token), so only the relay's
// paired Flutter user can trigger an update. No anonymous self-rooting.
//
// Why this lives on the relay (not on the dudenest-hub): the hub doesn't know per-relay
// binary versions, and the update *must* happen from the relay's own filesystem context. Hub-side
// admin would require either SSH (no) or a relay-side polling endpoint anyway, so we keep it here.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"
)

// versionResponse mirrors what the Flutter Update screen consumes.
type versionResponse struct {
	RelayVersion     string `json:"relay_version"`               // e.g. "v0.12.0"
	LatestRelease    string `json:"latest_release,omitempty"`    // e.g. "v0.12.0"; empty if GitHub fetch failed
	UpdateAvailable  bool   `json:"update_available"`            // true iff LatestRelease != "" && LatestRelease != RelayVersion && RelayVersion != "dev"
	RepoURL          string `json:"repo_url"`                    // canonical repo landing page
	ReleaseURL       string `json:"release_url,omitempty"`       // direct link to LatestRelease tag (empty if no fetch)
	LatestReleaseURL string `json:"latest_release_url"`          // /releases/latest — always present
	ChangelogURL     string `json:"changelog_url"`               // raw CHANGELOG.md on main branch
	FetchError       string `json:"fetch_error,omitempty"`       // GitHub fetch error message if LatestRelease is empty
}

const (
	repoURL          = "https://github.com/dudenest/dudenest-relay"
	latestReleaseURL = repoURL + "/releases/latest"
	changelogURL     = repoURL + "/blob/main/CHANGELOG.md"
)

func (fs *fileServer) handleAdminVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet { http.Error(w, "GET only", http.StatusMethodNotAllowed); return }
	resp := versionResponse{
		RelayVersion:     Version,
		RepoURL:          repoURL,
		LatestReleaseURL: latestReleaseURL,
		ChangelogURL:     changelogURL,
	}
	if rel, err := fetchLatestRelease(); err == nil {
		resp.LatestRelease = rel.TagName
		resp.ReleaseURL = repoURL + "/releases/tag/" + rel.TagName
		resp.UpdateAvailable = rel.TagName != "" && rel.TagName != Version && Version != "dev"
	} else {
		resp.FetchError = err.Error() // surface to UI so user knows why "Latest" is blank
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}

// updateResponse is the body returned by handleAdminUpdate BEFORE the relay restarts itself.
type updateResponse struct {
	Status      string `json:"status"`                  // "updating" | "already_up_to_date" | "no_binary_for_arch"
	FromVersion string `json:"from_version"`            // Version at the time of request
	ToVersion   string `json:"to_version,omitempty"`    // latest release tag (when applicable)
	Message     string `json:"message,omitempty"`       // human-readable hint for the UI
}

func (fs *fileServer) handleAdminUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "POST only", http.StatusMethodNotAllowed); return }
	rel, err := fetchLatestRelease()
	if err != nil { jsonErr(w, "fetch latest release: "+err.Error(), http.StatusBadGateway); return }
	latest := rel.TagName
	if Version != "dev" && Version == latest {
		writeJSON(w, http.StatusOK, updateResponse{Status: "already_up_to_date", FromVersion: Version, ToVersion: latest, Message: "Relay is already on the latest release."})
		return
	}
	suffix := archSuffix()
	downloadURL := ""
	for _, a := range rel.Assets {
		if strings.HasSuffix(a.Name, suffix) { downloadURL = a.BrowserDownloadURL; break }
	}
	if downloadURL == "" {
		writeJSON(w, http.StatusInternalServerError, updateResponse{Status: "no_binary_for_arch", FromVersion: Version, ToVersion: latest, Message: "Release " + latest + " has no asset for " + suffix})
		return
	}
	self, err := os.Executable()
	if err != nil { jsonErr(w, "exe path: "+err.Error(), http.StatusInternalServerError); return }
	if err := downloadReplace(downloadURL, self); err != nil { jsonErr(w, "download: "+err.Error(), http.StatusInternalServerError); return }
	log.Printf("✅ admin update: downloaded %s → %s, restarting in 2s", latest, self)
	writeJSON(w, http.StatusOK, updateResponse{Status: "updating", FromVersion: Version, ToVersion: latest, Message: "Binary replaced. Relay will restart in ~2 seconds (systemd Restart=always brings the new version up)."})
	go func() { // give the response a chance to flush, then SIGTERM ourselves
		time.Sleep(2 * time.Second)
		if proc, perr := os.FindProcess(os.Getpid()); perr == nil { _ = proc.Signal(syscall.SIGTERM) } //nolint:errcheck
	}()
}

// writeJSON is a thin helper so admin handlers don't repeat the Header/WriteHeader/Encode dance.
func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(body) //nolint:errcheck
}

