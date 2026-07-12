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

// Method-3 (Remote-Hand) needs a Python sidecar + small OCR/input tools that a binary-only
// `relay update` does NOT deliver (update.go replaces only the executable). EnsureSidecar
// tops those up on startup so a fleet relay that auto-updates gets a working method 3
// without a full re-install. Best-effort and version-marked (runs once per version).
//
// NOTE: the X/VNC desktop + Chromium themselves come from scripts/install.sh — this only
// provisions the sidecar layer on top of an already-provisioned relay host.

const sidecarDir = "/usr/local/lib/dudenest/remotehand"
const rawBase = "https://raw.githubusercontent.com/dudenest/dudenest-relay"

var sidecarFiles = []string{
	"rh_protocol.py", "rh_catalog.py", "rh_input.py", "rh_screen.py", "rh_fsm.py",
	"rh_classify.py", "rh_crypto.py", "rh_browser.py", "rh_sidecar.py",
}

// small method-3 deps only (OCR read + XTEST input + clipboard verify); the browser and
// desktop stack are install.sh's job.
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
	marker := filepath.Join(sidecarDir, ".provisioned-"+ref)
	if _, err := os.Stat(marker); err == nil {
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
	ensureSidecarAptDeps()
	ensureSidecarPipDeps()
	ensureBrowserIsChrome()
	if ok {
		_ = os.WriteFile(marker, []byte(ref), 0o644)
		log.Printf("provision: method-3 sidecar %s ready in %s", ref, sidecarDir)
	} else {
		log.Printf("provision: method-3 sidecar incomplete (retry next start) — method 3 degraded")
	}
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

// ensureBrowserIsChrome logs a hint when the method-3 browser is still open-source Chromium
// instead of real Google Chrome (B5). Installing Chrome (apt repo + package) is install.sh's job;
// a binary-only update can't add an apt repo, so here we only surface the gap — never mutate.
func ensureBrowserIsChrome() {
	path, err := exec.LookPath("chromium") // symlink install.sh points at the chosen browser
	if err != nil {
		return
	}
	real, _ := filepath.EvalSymlinks(path)
	if strings.Contains(strings.ToLower(real), "chrome") { // google-chrome[-stable]
		return
	}
	if _, err := exec.LookPath("google-chrome-stable"); err == nil {
		return // real Chrome present under its own name
	}
	log.Printf("provision: method-3 browser is %q (open-source Chromium) — run scripts/install.sh to install Google Chrome (B5 anti-abuse)", real)
}

// ensureSidecarAptDeps installs the OCR/input tools if any is missing — only as root with
// apt-get available (Debian/Ubuntu relay hosts). Silent no-op otherwise.
func ensureSidecarAptDeps() {
	missing := false
	for _, bin := range []string{"tesseract", "xdotool", "scrot", "xclip", "python3"} {
		if _, err := exec.LookPath(bin); err != nil {
			missing = true
			break
		}
	}
	if !missing {
		return
	}
	if os.Geteuid() != 0 {
		log.Printf("provision: method-3 deps missing but not root — run scripts/install.sh")
		return
	}
	if _, err := exec.LookPath("apt-get"); err != nil {
		log.Printf("provision: method-3 deps missing and no apt-get — install manually: %v", sidecarAptDeps)
		return
	}
	args := append([]string{"install", "-y", "--no-install-recommends", "python3-pip", "python3-pil"}, sidecarAptDeps...)
	cmd := exec.Command("apt-get", args...)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("provision: apt-get install failed: %v (%s)", err, tail(out, 200))
	} else {
		log.Printf("provision: installed method-3 apt deps")
	}
}

func ensureSidecarPipDeps() {
	if exec.Command("python3", "-c", "import nacl, pytesseract").Run() == nil {
		return // already importable
	}
	cmd := exec.Command("pip3", "install", "--break-system-packages", "--quiet", "pynacl", "pytesseract")
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("provision: pip install failed: %v (%s)", err, tail(out, 200))
	} else {
		log.Printf("provision: installed method-3 pip deps")
	}
}

func tail(b []byte, n int) string {
	if len(b) > n {
		b = b[len(b)-n:]
	}
	return string(b)
}
