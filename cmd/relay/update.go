package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

const githubReleaseAPI = "https://api.github.com/repos/dudenest/dudenest-relay/releases/latest"

type githubRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show relay version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("dudenest-relay %s (%s/%s)\n", Version, runtime.GOOS, runtime.GOARCH)
		},
	}
}

func updateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Check for updates and install latest release from GitHub",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("Current version: %s\n", Version)
			if url, target := os.Getenv("DUDENEST_RELAY_DOWNLOAD_URL"), os.Getenv("DUDENEST_RELAY_TARGET_VERSION"); url != "" && target != "" {
				defer clearSystemdUpdateEnv()
				fmt.Printf("Hub-provided target: %s\n", target)
				if Version != "dev" && !versionGreater(target, Version) {
					fmt.Println("Already up to date.")
					return nil
				}
				self, err := os.Executable()
				if err != nil {
					return fmt.Errorf("cannot determine own path: %w", err)
				}
				fmt.Printf("Downloading %s from hub-provided URL ...\n", target)
				if err := downloadReplace(url, self); err != nil {
					return fmt.Errorf("update failed: %w", err)
				}
				fmt.Printf("✅ Updated to %s — restart relay to apply\n", target)
				return nil
			}
			fmt.Println("Checking GitHub for latest release ...")
			release, err := fetchLatestRelease()
			if err != nil {
				return fmt.Errorf("check update: %w", err)
			}
			latest := release.TagName
			fmt.Printf("Latest release:  %s\n", latest)
			if Version != "dev" && Version == latest {
				fmt.Println("Already up to date.")
				return nil
			}
			suffix := archSuffix()
			downloadURL := ""
			for _, a := range release.Assets {
				if strings.HasSuffix(a.Name, suffix) {
					downloadURL = a.BrowserDownloadURL
					break
				}
			}
			if downloadURL == "" {
				return fmt.Errorf("no binary found for %s in release %s", suffix, latest)
			}
			self, err := os.Executable()
			if err != nil {
				return fmt.Errorf("cannot determine own path: %w", err)
			}
			fmt.Printf("Downloading %s ...\n", latest)
			if err := downloadReplace(downloadURL, self); err != nil {
				return fmt.Errorf("update failed: %w", err)
			}
			fmt.Printf("✅ Updated to %s — restart relay to apply\n", latest)
			return nil
		},
	}
}

func fetchLatestRelease() (*githubRelease, error) {
	req, err := http.NewRequest(http.MethodGet, githubReleaseAPI, nil)
	if err != nil {
		return nil, err
	}
	// Authenticate when GITHUB_TOKEN is available. Without auth GitHub gives 60 req/h per IP,
	// which is exceeded fleet-wide when the hub already polls /releases/latest every minute
	// (60/h baseline) and the auto-update.timer fires at the same time. With auth the budget
	// climbs to 5000/h, well above anything a single relay would consume.
	// The token is searched in env first (12-factor friendly), then in /etc/dudenest/relay.env
	// (where install.sh writes RELAY_KEY and friends), then /root/.config/dudenest/relay.env.
	// Empty result = unauthenticated request, same as before — preserves backward compat.
	if tok := githubToken(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}
	var r githubRelease
	return &r, json.NewDecoder(resp.Body).Decode(&r)
}

// githubToken returns the first non-empty value among GITHUB_TOKEN env and either of the two
// relay.env locations install.sh writes to. Returns "" if not configured anywhere — caller
// falls back to unauthenticated request (still works for low-frequency operations).
func githubToken() string {
	if v := os.Getenv("GITHUB_TOKEN"); v != "" {
		return v
	}
	for _, envFile := range []string{"/etc/dudenest/relay.env", os.ExpandEnv("$HOME/.config/dudenest/relay.env")} {
		data, err := os.ReadFile(envFile)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "GITHUB_TOKEN=") {
				return strings.Trim(strings.TrimPrefix(line, "GITHUB_TOKEN="), `"`)
			}
		}
	}
	return ""
}

func clearSystemdUpdateEnv() {
	if runtime.GOOS == "linux" {
		_ = exec.Command("systemctl", "unset-environment", "DUDENEST_RELAY_DOWNLOAD_URL", "DUDENEST_RELAY_TARGET_VERSION").Run()
	}
}

func versionGreater(a, b string) bool {
	ax, ay, az, okA := parseVersion(a)
	bx, by, bz, okB := parseVersion(b)
	if !okA || !okB {
		return a > b
	}
	if ax != bx {
		return ax > bx
	}
	if ay != by {
		return ay > by
	}
	return az > bz
}

func parseVersion(v string) (int, int, int, bool) {
	v = strings.TrimPrefix(v, "v")
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return 0, 0, 0, false
	}
	var out [3]int
	for i, p := range parts {
		for _, r := range p {
			if r < '0' || r > '9' {
				return 0, 0, 0, false
			}
			out[i] = out[i]*10 + int(r-'0')
		}
	}
	return out[0], out[1], out[2], true
}

func archSuffix() string {
	arch := runtime.GOARCH
	if arch == "arm" {
		arch = "armv7"
	}
	return fmt.Sprintf("%s-%s", runtime.GOOS, arch)
}

func downloadReplace(url, dest string) error {
	restoreImmutable, err := clearImmutableIfNeeded(dest)
	if err != nil {
		return err
	}
	if restoreImmutable {
		defer func() { _ = exec.Command("chattr", "+i", dest).Run() }()
	}
	resp, err := http.Get(url) //nolint:noctx
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned %d", resp.StatusCode)
	}
	tmp := dest + ".new"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(tmp) //nolint:errcheck
		return fmt.Errorf("write: %w", err)
	}
	f.Close()
	if err := os.Rename(tmp, dest); err != nil {
		return err
	}
	return nil
}

func clearImmutableIfNeeded(dest string) (bool, error) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return false, nil
	}
	if _, err := exec.LookPath("lsattr"); err != nil {
		return false, nil
	}
	if _, err := exec.LookPath("chattr"); err != nil {
		return false, nil
	}
	out, err := exec.Command("lsattr", "-d", dest).Output()
	if err != nil {
		return false, nil
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 || !strings.Contains(fields[0], "i") {
		return false, nil
	}
	if out, err := exec.Command("chattr", "-i", dest).CombinedOutput(); err != nil {
		return false, fmt.Errorf("clear immutable bit: %w (%s)", err, tail(out, 200))
	}
	return true, nil
}
