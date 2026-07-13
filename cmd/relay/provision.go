package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Method-3 (Remote-Hand) needs Python sidecar files plus anti-abuse host state that a
// binary-only `relay update` historically did not deliver. EnsureSidecar now also applies
// the B5 host migration (real Google Chrome on amd64 + timezone-from-IP) on every startup,
// before the version marker can short-circuit sidecar downloads. Best-effort: never crash
// relay startup, but log clearly if the host cannot be made safe for real-account testing.

const sidecarDir = "/usr/local/lib/dudenest/remotehand"
const rawBase = "https://raw.githubusercontent.com/dudenest/dudenest-relay"
const noVNCDir = "/usr/share/novnc"

var sidecarFiles = []string{
	"rh_protocol.py", "rh_catalog.py", "rh_input.py", "rh_screen.py", "rh_fsm.py",
	"rh_classify.py", "rh_crypto.py", "rh_browser.py", "rh_sidecar.py",
}

var noVNCFiles = []string{"dudenest-form.html"}

// small method-3 deps only (OCR read + XTEST input + clipboard verify).
var sidecarAptDeps = []string{"tesseract-ocr", "xdotool", "scrot", "xclip"}

// EnsureSidecar downloads the sidecar matching this binary's version and installs the small
// deps if missing. Call it in a goroutine — it must never block or crash relay startup.
// provisionRef maps the binary version to the git ref to fetch the sidecar from: a real
// release tag pulls the matching sidecar; dev/empty falls back to main.
func provisionRef(version string) string {
	if version == "" || version == "dev" {
		return "main"
	}
	return version
}

func EnsureSidecar(version string) {
	ref := provisionRef(version)
	ensureAntiAbuseHost()
	marker := filepath.Join(sidecarDir, ".provisioned-"+ref)
	if _, err := os.Stat(marker); err == nil && sidecarReady(ref) {
		return // already provisioned for this version
	}
	if err := os.MkdirAll(sidecarDir, 0o755); err != nil {
		log.Printf("provision: mkdir %s: %v", sidecarDir, err)
		return
	}
	ok := true
	for _, f := range sidecarFiles {
		url := fmt.Sprintf("%s/%s/remotehand/%s", rawBase, ref, f)
		if err := downloadTo(url, filepath.Join(sidecarDir, f)); err != nil {
			log.Printf("provision: fetch %s: %v", f, err)
			ok = false
		}
	}
	if !ensureNoVNCFiles(ref) {
		ok = false
	}
	if !ensureSidecarAptDeps() {
		ok = false
	}
	if !ensureSidecarPipDeps() {
		ok = false
	}
	if ok {
		_ = os.WriteFile(marker, []byte(ref), 0o644)
		log.Printf("provision: method-3 sidecar %s ready in %s", ref, sidecarDir)
	} else {
		log.Printf("provision: method-3 sidecar incomplete (retry next start) — method 3 degraded")
	}
}

func ensureNoVNCFiles(ref string) bool {
	if err := os.MkdirAll(noVNCDir, 0o755); err != nil {
		log.Printf("provision: mkdir %s: %v", noVNCDir, err)
		return false
	}
	ok := true
	for _, f := range noVNCFiles {
		url := fmt.Sprintf("%s/%s/deploy/relay-poc/%s", rawBase, ref, f)
		if err := downloadTo(url, filepath.Join(noVNCDir, f)); err != nil {
			log.Printf("provision: fetch noVNC %s: %v", f, err)
			ok = false
		}
	}
	return ok
}

func sidecarReady(ref string) bool {
	for _, f := range sidecarFiles {
		if _, err := os.Stat(filepath.Join(sidecarDir, f)); err != nil {
			return false
		}
	}
	for _, f := range noVNCFiles {
		if _, err := os.Stat(filepath.Join(noVNCDir, f)); err != nil {
			return false
		}
	}
	return sidecarAptDepsReady() && sidecarPipDepsReady()
}

func downloadTo(url, dest string) error {
	resp, err := http.Get(url) //nolint:noctx,gosec
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %d", url, resp.StatusCode)
	}
	tmp := dest + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(tmp) //nolint:errcheck
		return err
	}
	f.Close()
	return os.Rename(tmp, dest)
}

// ensureAntiAbuseHost applies B5 automatically after a binary-only update: real Google
// Chrome on Debian/Ubuntu amd64, no open-source Chromium package left behind, a neutral
// /usr/local/bin/dudenest-browser launcher, and daily timezone-from-IP sync. ARM cannot run
// Google Chrome .deb; for real-account OAuth on ARM use a supported Chrome build/appliance.
func ensureAntiAbuseHost() {
	if os.Geteuid() != 0 {
		log.Printf("provision: B5 host migration skipped (not root)")
		return
	}
	if _, err := exec.LookPath("apt-get"); err != nil {
		log.Printf("provision: B5 host migration skipped (apt-get unavailable)")
		return
	}
	if !isDebianLikeAMD64() {
		log.Printf("provision: B5 real Chrome unavailable on this OS/arch — do not use real Google accounts until a real Chrome build is provided")
		return
	}
	script := `set -e
export DEBIAN_FRONTEND=noninteractive
install -d -m 755 /etc/apt/keyrings
if [ ! -f /etc/apt/sources.list.d/google-chrome.list ]; then curl -fsSL https://dl.google.com/linux/linux_signing_key.pub | gpg --dearmor -o /etc/apt/keyrings/google-chrome.gpg; echo 'deb [arch=amd64 signed-by=/etc/apt/keyrings/google-chrome.gpg] https://dl.google.com/linux/chrome/deb/ stable main' > /etc/apt/sources.list.d/google-chrome.list; apt-get update -qq; fi
dpkg -s google-chrome-stable >/dev/null 2>&1 || { apt-get update -qq; apt-get install -y --no-install-recommends google-chrome-stable; }
ln -sfn /usr/bin/google-chrome-stable /usr/local/bin/dudenest-browser
ln -sfn /usr/bin/google-chrome-stable /usr/local/bin/chromium
apt-get purge -y chromium chromium-sandbox chromium-browser >/dev/null 2>&1 || true
cat >/usr/local/sbin/dudenest-tz-sync <<'TZS'
#!/bin/bash
set -uo pipefail
TZ_NEW="$(curl -fsS --max-time 10 https://ipapi.co/timezone 2>/dev/null || true)"
[ -z "$TZ_NEW" ] && TZ_NEW="$(curl -fsS --max-time 10 'http://ip-api.com/line/?fields=timezone' 2>/dev/null || true)"
if [ -n "$TZ_NEW" ] && [ -f "/usr/share/zoneinfo/$TZ_NEW" ]; then timedatectl set-timezone "$TZ_NEW" && echo "dudenest-tz-sync: timezone → $TZ_NEW"; else echo "dudenest-tz-sync: could not resolve timezone from IP"; fi
TZS
chmod 755 /usr/local/sbin/dudenest-tz-sync
cat >/etc/systemd/system/dudenest-tz-sync.service <<'TZU'
[Unit]
Description=Sync system timezone to public egress IP (method-3 anti-abuse)
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/dudenest-tz-sync
[Install]
WantedBy=multi-user.target
TZU
cat >/etc/systemd/system/dudenest-tz-sync.timer <<'TZT'
[Unit]
Description=Daily timezone re-sync to public egress IP
[Timer]
OnBootSec=2min
OnUnitActiveSec=1d
Persistent=true
[Install]
WantedBy=timers.target
TZT
if [ -f /etc/systemd/system/dudenest-kiosk.service ]; then perl -0pi -e 's#/usr/local/bin/chromium#/usr/local/bin/dudenest-browser#g; s#/usr/bin/chromium#/usr/local/bin/dudenest-browser#g; s#/usr/bin/google-chrome-stable#/usr/local/bin/dudenest-browser#g' /etc/systemd/system/dudenest-kiosk.service; fi
systemctl daemon-reload
systemctl enable --now dudenest-tz-sync.timer >/dev/null 2>&1 || true
/usr/local/sbin/dudenest-tz-sync || true
systemctl try-restart dudenest-kiosk.service >/dev/null 2>&1 || true
`
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = os.Environ()
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("provision: B5 host migration failed: %v (%s)", err, tail(out, 400))
		return
	}
	log.Printf("provision: B5 host migration ready (Google Chrome + TZ sync + Chromium package purge)")
}

func isDebianLikeAMD64() bool {
	out, err := exec.Command("dpkg", "--print-architecture").Output()
	if err != nil || strings.TrimSpace(string(out)) != "amd64" {
		return false
	}
	data, _ := os.ReadFile("/etc/os-release")
	s := strings.ToLower(string(data))
	return strings.Contains(s, "id=debian") || strings.Contains(s, "id=ubuntu") || strings.Contains(s, "id_like=debian")
}

// ensureSidecarAptDeps installs the OCR/input tools if any is missing — only as root with
// apt-get available (Debian/Ubuntu relay hosts). Silent no-op otherwise.
func sidecarAptDepsReady() bool {
	for _, bin := range []string{"tesseract", "xdotool", "scrot", "xclip", "python3"} {
		if _, err := exec.LookPath(bin); err != nil {
			return false
		}
	}
	return true
}

func ensureSidecarAptDeps() bool {
	missing := false
	for _, bin := range []string{"tesseract", "xdotool", "scrot", "xclip", "python3"} {
		if _, err := exec.LookPath(bin); err != nil {
			missing = true
			break
		}
	}
	if !missing {
		return true
	}
	if os.Geteuid() != 0 {
		log.Printf("provision: method-3 deps missing but not root — run scripts/install.sh")
		return false
	}
	if _, err := exec.LookPath("apt-get"); err != nil {
		log.Printf("provision: method-3 deps missing and no apt-get — install manually: %v", sidecarAptDeps)
		return false
	}
	deps := append([]string{"python3-pip", "python3-pil"}, sidecarAptDeps...)
	script := "apt-get update -qq && dpkg --configure -a && apt-get install -y --fix-broken && apt-get install -y --no-install-recommends " + strings.Join(deps, " ")
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("provision: apt-get install failed: %v (%s)", err, tail(out, 200))
		return false
	} else {
		log.Printf("provision: installed method-3 apt deps")
	}
	return sidecarAptDepsReady()
}

func sidecarPipDepsReady() bool {
	return exec.Command("python3", "-c", "import nacl, pytesseract").Run() == nil
}

func ensureSidecarPipDeps() bool {
	if sidecarPipDepsReady() {
		return true
	}
	commands := [][]string{{"python3", "-m", "pip", "install", "--break-system-packages", "--quiet", "pynacl", "pytesseract"}, {"pip3", "install", "--break-system-packages", "--quiet", "pynacl", "pytesseract"}}
	for _, args := range commands {
		cmd := exec.Command(args[0], args[1:]...)
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Printf("provision: pip install via %s failed: %v (%s)", strings.Join(args[:3], " "), err, tail(out, 200))
			continue
		}
		log.Printf("provision: installed method-3 pip deps via %s", strings.Join(args[:3], " "))
		return sidecarPipDepsReady()
	}
	return false
}

func tail(b []byte, n int) string {
	if len(b) > n {
		b = b[len(b)-n:]
	}
	return string(b)
}
