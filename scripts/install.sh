#!/usr/bin/env bash
# Dudenest Relay — full bootstrap installer (relay binary + X11 + Chromium + noVNC).
#
# Installs everything a fully-functional Dudenest Relay needs:
#   1. apt packages: lightdm, xfce4, xorg, tigervnc-standalone-server, novnc/websockify, chromium, zerotier
#   2. Linux user `dude` with LightDM autologin → Xfce on :0
#   3. Chromium autostart on :0 showing http://localhost:6080/dudenest.html (kiosk-style viewer)
#   4. TigerVNC headless on :99 (where the relay launches Chromium for Google OAuth)
#   5. noVNC websockify on :6080 bridging :5999 → browser
#   6. dudenest.html + dudenest-form.html — full and form-only noVNC clients
#   7. Relay binary from GitHub Releases (https://github.com/dudenest/dudenest-relay/releases/latest)
#   8. 4 systemd units: tigervnc-99, novnc, dudenest-relay, dudenest-relay-update.{service,timer}
#   9. Daily auto-update: timer runs `relay update` and restarts the service on new releases
#  10. ZeroTier overlay + hub auto-provisioning (relay_id, relay_url, JWT_SECRET, etc.)
#
# Usage (idempotent — safe to re-run):
#   curl -sSL https://raw.githubusercontent.com/dudenest/dudenest-relay/main/scripts/install.sh | sudo bash
#
# Tested on Debian 12 (bookworm). Other Debian/Ubuntu releases should also work.
set -euo pipefail

# ── configuration ────────────────────────────────────────────────────────────
RELAY_REPO="${RELAY_REPO:-dudenest/dudenest-relay}"
RELAY_BIN="/usr/local/bin/relay"
CONFIG_DIR="/etc/dudenest"
DATA_DIR="/var/lib/dudenest"
ZT_NETWORK="${ZT_NETWORK:-932df01efb1ebd71}"
BACKUP_URL="${BACKUP_URL:-https://hub.dudenest.com}"   # s364: default → hub.dudenest.com (env var name kept for compat)
DUDE_USER="${DUDE_USER:-dude}"
# DUDE_UID is preferred (matches the reference relay-poc) but skipped if already taken
DUDE_UID="${DUDE_UID:-1000}"
VNC_DISPLAY=":99"
VNC_PORT="5999"
NOVNC_PORT="6080"
RAW_BASE="https://raw.githubusercontent.com/${RELAY_REPO}/main/deploy/relay-poc"

# ── helpers ──────────────────────────────────────────────────────────────────
ok()    { echo "  ✓ $*"; }
step()  { echo ""; echo "▸ $*"; }
warn()  { echo "  ⚠ $*"; }
fail()  { echo ""; echo "  ✗ ERROR: $*" >&2; exit 1; }
have()  { command -v "$1" >/dev/null 2>&1; }
require() { have "$1" || fail "Required tool not found: $1"; }
pkg_ok() { [[ -x "/usr/bin/$1" ]] && [[ "$(dpkg-query -W -f='${Status}' "$1" 2>/dev/null || true)" == "install ok installed" ]]; }

require curl
[[ $EUID -eq 0 ]] || fail "Run as root: sudo bash install.sh"

ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  RELAY_ARCH="linux-amd64" ;;
  aarch64) RELAY_ARCH="linux-arm64" ;;
  armv7l)  RELAY_ARCH="linux-armv7" ;;
  *) fail "Unsupported architecture: $ARCH" ;;
esac

echo ""
echo "┌─────────────────────────────────────────────────────────────────────┐"
echo "│       Dudenest Relay — Full Bootstrap (X11 + Chromium + noVNC)      │"
echo "├─────────────────────────────────────────────────────────────────────┤"
echo "│  No domain, no port forwarding, no configuration required.          │"
echo "│  ZeroTier overlay + hub auto-provisioning handle the rest.          │"
echo "└─────────────────────────────────────────────────────────────────────┘"

# ── step 1: apt packages ─────────────────────────────────────────────────────
step "Step 1/9: System packages (apt)"
export DEBIAN_FRONTEND=noninteractive
. /etc/os-release  # populates ID=ubuntu|debian, VERSION_ID=…
DISTRO_ID="${ID:-unknown}"
APT_PKGS=(
  ca-certificates curl wget openssl jq gnupg
  xorg xserver-xorg lightdm accountsservice dbus-x11 dbus-user-session at-spi2-core
  xfce4 xfce4-session xfce4-settings xfwm4 xfdesktop4 xfce4-panel
  xfce4-terminal  # satisfies xorg's `x-terminal-emulator` dep so gnome-terminal isn't pulled in
  wmctrl  # enforces maximized window state after Chromium launch (saved state overrides --start-maximized)
  tigervnc-standalone-server tigervnc-common tigervnc-tools
  novnc python3-websockify websockify
  tesseract-ocr xdotool scrot xclip python3-pil python3-pip  # remote-hand method 3: CDP-free OCR read + XTEST input + clipboard field-verify
  unattended-upgrades apt-listchanges
)
APT_OPTS=(-y --no-install-recommends -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confnew)
# Browser: use REAL Google Chrome (B5). Open-source Chromium is a known inconsistent
# fingerprint for Google OAuth, so method-3-capable installs fail closed when Chrome is
# unavailable instead of silently falling back to Chromium.
DEB_ARCH="$(dpkg --print-architecture 2>/dev/null || echo unknown)"
if [[ "$DEB_ARCH" == "amd64" && ( "$DISTRO_ID" == "debian" || "$DISTRO_ID" == "ubuntu" ) ]]; then
  if ! [[ -f /etc/apt/sources.list.d/google-chrome.list ]]; then
    install -d -m 755 /etc/apt/keyrings
    curl -fsSL https://dl.google.com/linux/linux_signing_key.pub | gpg --dearmor -o /etc/apt/keyrings/google-chrome.gpg
    echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/google-chrome.gpg] https://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list
    ok "Added Google Chrome apt repo"
  fi
  APT_PKGS+=(google-chrome-stable)
else
  fail "Google Chrome unavailable for ${DISTRO_ID}/${DEB_ARCH}; Remote-Hand real-account OAuth is disabled on this host/arch"
fi
MISSING=()
for p in "${APT_PKGS[@]}"; do
  if [[ "$p" == "google-chrome-stable" ]]; then pkg_ok google-chrome-stable || MISSING+=("$p"); else dpkg -s "$p" >/dev/null 2>&1 || MISSING+=("$p"); fi
done
if [[ ${#MISSING[@]} -gt 0 ]]; then
  echo "  Installing ${#MISSING[@]} package(s): ${MISSING[*]}"
  apt-get update -qq
  # Recover any half-configured packages from a previous interrupted run before installing new ones
  dpkg --configure -a 2>/dev/null || true
  apt-get install --fix-broken "${APT_OPTS[@]}" 2>/dev/null || true
  apt-get install "${APT_OPTS[@]}" "${MISSING[@]}"
  if printf '%s\n' "${MISSING[@]}" | grep -qx google-chrome-stable && ! pkg_ok google-chrome-stable; then apt-get install "${APT_OPTS[@]}" --reinstall google-chrome-stable; fi
fi
# Pick the browser binary the relay can use. `dudenest-browser` is the canonical launcher;
# `/usr/local/bin/chromium` remains only as a legacy compatibility symlink to Chrome.
BROWSER_BIN=""
for cand in /usr/bin/google-chrome-stable /usr/bin/google-chrome; do
  [[ -x "$cand" ]] && { BROWSER_BIN="$cand"; break; }
done
pkg_ok google-chrome-stable || fail "google-chrome-stable package not healthy after apt install/reinstall"
[[ -n "$BROWSER_BIN" ]] || fail "Google Chrome binary not found after apt install"
ln -sfn "$BROWSER_BIN" /usr/local/bin/dudenest-browser
ln -sfn "$BROWSER_BIN" /usr/local/bin/chromium  # legacy compatibility; target is Chrome
apt-get purge -y chromium chromium-sandbox chromium-browser >/dev/null 2>&1 || true
ok "All required packages installed (browser: $BROWSER_BIN → /usr/local/bin/dudenest-browser)"

# B5: keep the system timezone matching the public egress IP. The method-3 browser reports its
# JS timezone (Intl/Date) from the system tz; if that disagrees with the IP's geolocation Google
# reads it as an inconsistency signal. A boot-time oneshot + daily timer follow IP/location changes.
cat > /usr/local/sbin/dudenest-tz-sync <<'TZS'
#!/bin/bash
# Set system timezone from the public egress IP so browser JS tz == network location (anti-abuse).
set -uo pipefail
TZ_NEW="$(curl -fsS --max-time 10 https://ipapi.co/timezone 2>/dev/null || true)"
[ -z "$TZ_NEW" ] && TZ_NEW="$(curl -fsS --max-time 10 'http://ip-api.com/line/?fields=timezone' 2>/dev/null || true)"
if [ -n "$TZ_NEW" ] && [ -f "/usr/share/zoneinfo/$TZ_NEW" ]; then
  timedatectl set-timezone "$TZ_NEW" && echo "dudenest-tz-sync: timezone → $TZ_NEW"
else
  echo "dudenest-tz-sync: could not resolve timezone from IP (kept $(cat /etc/timezone 2>/dev/null))"
fi
TZS
chmod 755 /usr/local/sbin/dudenest-tz-sync
cat > /etc/systemd/system/dudenest-tz-sync.service <<'TZU'
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
cat > /etc/systemd/system/dudenest-tz-sync.timer <<'TZT'
[Unit]
Description=Daily timezone re-sync to public egress IP
[Timer]
OnBootSec=2min
OnUnitActiveSec=1d
Persistent=true
[Install]
WantedBy=timers.target
TZT
systemctl daemon-reload
systemctl enable --now dudenest-tz-sync.timer >/dev/null 2>&1 || true
/usr/local/sbin/dudenest-tz-sync || true
ok "Timezone-from-IP sync installed (dudenest-tz-sync.timer)"

# ── step 2: dude user + groups ───────────────────────────────────────────────
step "Step 2/9: User '$DUDE_USER'"
if ! id "$DUDE_USER" >/dev/null 2>&1; then
  # Prefer the canonical UID 1000 but fall back to whatever useradd picks if it's taken
  if getent passwd "$DUDE_UID" >/dev/null; then
    OWNER=$(getent passwd "$DUDE_UID" | cut -d: -f1)
    warn "UID $DUDE_UID already used by '$OWNER' — letting useradd pick the next free UID"
    useradd -m -s /bin/bash -G audio,video,plugdev "$DUDE_USER"
  else
    useradd -m -u "$DUDE_UID" -s /bin/bash -G audio,video,plugdev "$DUDE_USER"
  fi
  ok "Created user $DUDE_USER (uid $(id -u "$DUDE_USER"))"
else
  usermod -aG audio,video,plugdev "$DUDE_USER" 2>/dev/null || true
  ok "User $DUDE_USER exists (uid $(id -u "$DUDE_USER"))"
fi

# ── step 3: LightDM autologin → minimal X session ─────────────────────────────
step "Step 3/9: LightDM autologin (minimal 'dudenest' X session for '$DUDE_USER')"
mkdir -p /etc/lightdm/lightdm.conf.d
cat > /etc/lightdm/lightdm.conf.d/50-dudenest-autologin.conf <<EOF
[Seat:*]
autologin-user=$DUDE_USER
autologin-user-timeout=0
user-session=dudenest
EOF
# Minimal X session: authorize root on :0 (so dudenest-kiosk can open Chromium there) and idle.
# Full Xfce was unreliable under lightdm-autologin on Ubuntu 24.04 (xfconfd D-Bus race
# producing a "failsafe session" popup that floated above the kiosk Chromium).
cat > /usr/local/bin/dudenest-xsession <<'EOF'
#!/bin/bash
# Xfce-like desktop on :0. We wrap everything in `dbus-run-session` so xfconfd's
# dbus-activation gets a clean session bus with HOME/XDG_CONFIG_HOME inherited correctly —
# on Ubuntu 24.04 the lightdm-autologin path strips that env and xfconfd dies with
# "Unable to create configuration directory '(null)'", leaving xfce4-panel rendered as a
# tiny 128×50 stub. dbus-run-session inside a normal user shell fixes both problems.
export HOME="${HOME:-/home/$USER}"
export XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
export XDG_DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
mkdir -p "$XDG_CONFIG_HOME/xfce4/xfconf/xfce-perchannel-xml" "$XDG_DATA_HOME"
xhost +SI:localuser:root 2>/dev/null
xset s off -dpms 2>/dev/null
exec dbus-run-session -- bash -c '
  /usr/lib/x86_64-linux-gnu/xfce4/xfconf/xfconfd &
  sleep 1
  xfwm4 --replace &
  xfsettingsd &
  sleep 1
  xfce4-panel &
  xfdesktop &
  exec sleep infinity
'
EOF
chmod 755 /usr/local/bin/dudenest-xsession
cat > /usr/share/xsessions/dudenest.desktop <<EOF
[Desktop Entry]
Name=Dudenest Relay
Comment=Xfce components (xfwm4 + xfsettingsd + xfce4-panel + xfdesktop) without xfce4-session
Exec=/usr/local/bin/dudenest-xsession
Type=Application
EOF
# /etc/X11/Xsession.d/99x11-common_start does `exec $STARTUP`, where STARTUP defaults to
# `x-session-manager` (a Debian alternative). Without this, even when lightdm asks for our
# dudenest session, Xsession would fall back to startxfce4 → xfce4-session which floods the
# kiosk with "failsafe session" popups. Make dudenest-xsession the highest-priority alternative.
update-alternatives --install /usr/bin/x-session-manager x-session-manager /usr/local/bin/dudenest-xsession 200 >/dev/null 2>&1 || true
update-alternatives --set x-session-manager /usr/local/bin/dudenest-xsession >/dev/null 2>&1 || true
# Belt-and-braces: mask the xfce4-session systemd user unit so dbus-launch can't dbus-activate it
mkdir -p /etc/systemd/user
ln -sfn /dev/null /etc/systemd/user/xfce4-session.service
systemctl set-default graphical.target >/dev/null 2>&1 || true
systemctl enable lightdm >/dev/null 2>&1 || true
# `systemctl enable lightdm` only sets "indirect" via display-manager.service alias — must also
# start it explicitly here so the console is in graphical mode without rebooting the VM.
systemctl start lightdm 2>/dev/null || warn "lightdm failed to start — check: journalctl -u lightdm"
ok "LightDM autologin configured → $DUDE_USER (dudenest minimal session), service started"

# ── step 4: dude home — xstartup, kiosk script, Chromium autostart ──────────
step "Step 4/9: Desktop files (Xfce + Chromium autostart on :0)"
DUDE_HOME="/home/$DUDE_USER"
# Create parent dirs FIRST as dude (install -d only chowns the leaf, leaving parents as root).
# This bug bit us before: ~/.config became root:root → xfconfd couldn't write its xml config
# → xfce4-panel fell back to a tiny 128×50 stub. Always run mkdir-then-chown to be safe.
mkdir -p "$DUDE_HOME/.vnc" "$DUDE_HOME/.config/autostart" "$DUDE_HOME/.config/chromium-novnc" \
         "$DUDE_HOME/.config/xfce4/xfconf/xfce-perchannel-xml" "$DUDE_HOME/.local/share"
chown -R "$DUDE_USER:$DUDE_USER" "$DUDE_HOME/.vnc" "$DUDE_HOME/.config" "$DUDE_HOME/.local"
chmod 700 "$DUDE_HOME/.vnc"
# Clean up obsolete files from earlier bootstrap versions. These were Xfce autostart
# entries / helper scripts that launched a SECOND Chromium under `dude` — the new
# `dudenest-kiosk.service` runs Chromium as root, so the dude-side launchers must go
# (otherwise we end up with two Chromium instances fighting for the same user-data-dir).
for stale in chromium-novnc.desktop xhost-allow-root.desktop xfwm4-nocomp.desktop; do
  rm -f "$DUDE_HOME/.config/autostart/$stale"
done
rm -f "$DUDE_HOME/kiosk-novnc.sh" "$DUDE_HOME/xfwm4_nocomp.sh"

cat > "$DUDE_HOME/.vnc/xstartup" <<'EOF'
#!/bin/bash
# Xfce-like desktop on :99 — same dbus-run-session wrapper as the :0 dudenest-xsession.
unset SESSION_MANAGER
export HOME="${HOME:-/home/$USER}"
export XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
export XDG_DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
mkdir -p "$XDG_CONFIG_HOME/xfce4/xfconf/xfce-perchannel-xml" "$XDG_DATA_HOME"
xhost +SI:localuser:root 2>/dev/null
xset s off -dpms 2>/dev/null
exec dbus-run-session -- bash -c '
  /usr/lib/x86_64-linux-gnu/xfce4/xfconf/xfconfd &
  sleep 1
  xfwm4 --replace &
  xfsettingsd &
  sleep 1
  xfce4-panel &
  xfdesktop &
  exec sleep infinity
'
EOF
chown "$DUDE_USER:$DUDE_USER" "$DUDE_HOME/.vnc/xstartup"
chmod 755 "$DUDE_HOME/.vnc/xstartup"

# Kiosk Chromium runs as ROOT via dudenest-kiosk.service (see Step 8). The dudenest-xsession
# script (registered as `x-session-manager`) handles xhost + xfwm4 + xfce4-panel + xfdesktop,
# so dude's ~/.config/autostart/ stays empty of helper launchers — keeps the X session
# deterministic and avoids spawning a second Chromium under dude that fights for user-data-dir.
# Light-locker is hidden so it can't interfere with the kiosk Chromium.
cat > "$DUDE_HOME/.config/autostart/light-locker.desktop" <<'EOF'
[Desktop Entry]
Hidden=true
EOF
chown "$DUDE_USER:$DUDE_USER" "$DUDE_HOME/.config/autostart/light-locker.desktop"
ok "Xfce autostart minimal (light-locker hidden, no second-Chromium launchers)"

# ── step 5: dudenest.html (custom noVNC viewer) ─────────────────────────────
step "Step 5/9: dudenest.html (cropped noVNC viewer)"
cat > /usr/share/novnc/dudenest.html <<'EOF'
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>dudenest relay</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { background:#000; overflow:hidden; height:100vh; }
#screen {
  position: fixed;
  top: calc(-1 * var(--crop-top, 115px));
  left: 0; right: 0;
  height: calc(100vh + var(--crop-top, 115px));
  overflow: hidden;
}
#dot {
  position: fixed; bottom: 6px; right: 8px; z-index: 100;
  width: 8px; height: 8px; border-radius: 50%; background: #555;
}
#dot.connected { background: #4caf50; }
</style>
</head>
<body>
<div id="screen"></div>
<div id="dot" title="VNC status"></div>
<script type="module">
import RFB from "./core/rfb.js";
const dot = document.getElementById("dot");
const host = window.location.hostname;
const port = window.location.port || (window.location.protocol === "https:" ? "443" : "80");
const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
const viaRelay = window.location.pathname.startsWith("/vnc");
const wsPath = viaRelay ? "/vnc/websockify" : "/websockify";
const sessionParam = new URLSearchParams(window.location.search).get("session");
const wsURL = proto + "//" + host + ":" + port + wsPath + (sessionParam ? "?session=" + encodeURIComponent(sessionParam) : "");
let rfb;
function connect() {
  rfb = new RFB(document.getElementById("screen"), wsURL);
  rfb.scaleViewport = true;
  rfb.resizeSession = false;
  rfb.addEventListener("connect", () => { dot.className = "connected"; });
  rfb.addEventListener("disconnect", () => { dot.className = ""; setTimeout(connect, 3000); });
}
connect();
</script>
</body>
</html>
EOF
curl -fsSL "$RAW_BASE/dudenest-form.html" -o /usr/share/novnc/dudenest-form.html || warn "Could not fetch dudenest-form.html — Remote-Hand takeover form view unavailable until next provision"
ok "/usr/share/novnc/dudenest.html installed; dudenest-form.html installed when fetch succeeds"

# ── step 6: ZeroTier ─────────────────────────────────────────────────────────
step "Step 6/9: ZeroTier"
if ! have zerotier-cli; then
  curl -fsSL https://install.zerotier.com | bash >/dev/null 2>&1
  systemctl enable zerotier-one >/dev/null 2>&1
  systemctl start  zerotier-one >/dev/null 2>&1
  sleep 3
fi
zerotier-cli join "$ZT_NETWORK" >/dev/null 2>&1 || true
ok "Joined ZT $ZT_NETWORK (hub will authorize automatically)"

# ── step 7: Relay binary + config ────────────────────────────────────────────
step "Step 7/9: Relay binary + configuration"
RELAY_URL="https://github.com/$RELAY_REPO/releases/latest/download/relay-$RELAY_ARCH"
# Download to .new and atomic-rename so a currently-running relay process doesn't block the write
RELAY_TMP="${RELAY_BIN}.new"
curl -fsSL "$RELAY_URL" -o "$RELAY_TMP" || fail "Failed to download relay binary"
chmod +x "$RELAY_TMP"
mv -f "$RELAY_TMP" "$RELAY_BIN"
ok "Relay binary: $RELAY_BIN ($RELAY_ARCH)"

# Remote-Hand sidecar (method 3: CDP-free mediated login — Python, spawned per session
# by the relay). Optional: failures degrade method 3 only, they never break the install.
RH_DIR="/usr/local/lib/dudenest/remotehand"
RH_BASE="https://raw.githubusercontent.com/$RELAY_REPO/main/remotehand"
mkdir -p "$RH_DIR"
RH_OK=1
for f in rh_protocol.py rh_catalog.py rh_input.py rh_screen.py rh_fsm.py rh_classify.py rh_crypto.py rh_browser.py rh_sidecar.py; do
  curl -fsSL "$RH_BASE/$f" -o "$RH_DIR/$f" || { warn "remote-hand: fetch $f failed"; RH_OK=0; }
done
if [[ $RH_OK -eq 1 ]]; then
  if pip3 install --break-system-packages --quiet pynacl pytesseract >/dev/null 2>&1; then
    ok "Remote-Hand sidecar: $RH_DIR + pynacl/pytesseract (method 3 ready)"
  else
    warn "Remote-Hand sidecar files installed but pip deps failed — method 3 degraded"
  fi
else
  warn "Remote-Hand sidecar incomplete — method 3 unavailable (retry on next install)"
fi

mkdir -p "$CONFIG_DIR/providers" "$DATA_DIR/maps" "$DATA_DIR/thumbs"
# Legacy migration: relay-poc (pre-bootstrap) stored config in /root/.config/dudenest/.
# Move it into /etc/dudenest/ so RELAY_KEY, OAuth tokens and relay_creds survive.
LEGACY_DIR="/root/.config/dudenest"
if [[ -f "$LEGACY_DIR/relay.env" && ! -f "$CONFIG_DIR/relay.env" ]]; then
  warn "Found legacy config at $LEGACY_DIR — migrating to $CONFIG_DIR"
  cp -an "$LEGACY_DIR/." "$CONFIG_DIR/"  # copy everything we don't already have
  ln -sfn "$CONFIG_DIR" "$LEGACY_DIR.new" && mv -T "$LEGACY_DIR" "$LEGACY_DIR.legacy" && mv "$LEGACY_DIR.new" "$LEGACY_DIR"
  ok "Migrated legacy config; previous dir kept as $LEGACY_DIR.legacy, $LEGACY_DIR now symlinks to $CONFIG_DIR"
fi
if [[ ! -f "$CONFIG_DIR/relay.env" ]]; then
  RELAY_KEY=$(openssl rand -hex 32)
  cat > "$CONFIG_DIR/relay.env" <<EOF
RELAY_KEY=$RELAY_KEY
BACKUP_URL=$BACKUP_URL
ZT_ANNOUNCE=true
EOF
  chmod 600 "$CONFIG_DIR/relay.env"
  ok "Generated $CONFIG_DIR/relay.env (new RELAY_KEY)"
else
  ok "Preserved existing $CONFIG_DIR/relay.env (RELAY_KEY untouched)"
fi

# Legacy compat: earlier bootstraps used the shorter name `client_secret.json` — keep both names pointed
# at the same content so the unit file stays canonical regardless of which name exists first.
# No placeholder is created here anymore: relay binary v0.9.0+ pulls real OAuth credentials from the hub
# during /relay/bootstrap (fleet-wide auto-distribution); on-disk real credentials are preserved by shouldReplaceOAuth().
if [[ -f "$CONFIG_DIR/client_secret.json" && ! -e "$CONFIG_DIR/gdrive_client_secret.json" ]]; then
  ln -s client_secret.json "$CONFIG_DIR/gdrive_client_secret.json"
  ok "Linked legacy client_secret.json → gdrive_client_secret.json"
elif [[ -f "$CONFIG_DIR/gdrive_client_secret.json" ]]; then
  ok "OAuth gdrive_client_secret.json present (kept as-is; relay will refresh from hub only if it's a placeholder)"
else
  ok "OAuth gdrive_client_secret.json will be delivered by hub on first /relay/bootstrap"
fi

# ── step 8: systemd units (4 units) ──────────────────────────────────────────
step "Step 8/9: systemd units (tigervnc-99, novnc, dudenest-relay, update timer)"

cat > /etc/systemd/system/tigervnc-99.service <<EOF
[Unit]
Description=TigerVNC server on display $VNC_DISPLAY (Xfce + VNC combined)
After=network.target
Before=novnc.service
[Service]
Type=forking
User=$DUDE_USER
Group=$DUDE_USER
WorkingDirectory=$DUDE_HOME
Environment=HOME=$DUDE_HOME USER=$DUDE_USER LOGNAME=$DUDE_USER
ExecStartPre=/bin/bash -c 'rm -f /tmp/.X99-lock /tmp/.X11-unix/X99 2>/dev/null; true'
ExecStart=/usr/bin/tigervncserver $VNC_DISPLAY -geometry 1280x1024 -depth 24 -rfbport $VNC_PORT -localhost no -SecurityTypes None --I-KNOW-THIS-IS-INSECURE -desktop dudenest-relay
ExecStop=/usr/bin/tigervncserver -kill $VNC_DISPLAY
ExecStopPost=/bin/bash -c 'rm -f /tmp/.X99-lock /tmp/.X11-unix/X99 2>/dev/null; true'
Restart=on-failure
RestartSec=10
StartLimitBurst=3
[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/novnc.service <<EOF
[Unit]
Description=noVNC websocket proxy for VNC $VNC_DISPLAY on HTTP :$NOVNC_PORT
After=tigervnc-99.service
Requires=tigervnc-99.service
[Service]
Type=simple
User=$DUDE_USER
ExecStartPre=/bin/sleep 5
ExecStart=/usr/bin/websockify --web=/usr/share/novnc $NOVNC_PORT localhost:$VNC_PORT
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/dudenest-relay.service <<EOF
[Unit]
Description=Dudenest Relay — full API (files + OAuth browser auth on display $VNC_DISPLAY)
After=network.target tigervnc-99.service zerotier-one.service
Requires=tigervnc-99.service
Wants=zerotier-one.service
[Service]
Type=simple
User=root
EnvironmentFile=$CONFIG_DIR/relay.env
ExecStartPre=-$RELAY_BIN update
ExecStart=$RELAY_BIN serve --display $VNC_DISPLAY --listen 0.0.0.0:8086 --key \${RELAY_KEY} --config-dir $CONFIG_DIR --map-store $DATA_DIR/maps --client-secret $CONFIG_DIR/gdrive_client_secret.json
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/dudenest-relay-update.service <<EOF
[Unit]
Description=Dudenest Relay — check GitHub for new release and restart if updated
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/bin/bash -c '$RELAY_BIN update | tee /tmp/relay-update.log; if grep -q "Updated to" /tmp/relay-update.log; then systemctl restart dudenest-relay; fi; rm -f /tmp/relay-update.log'
EOF

cat > /etc/systemd/system/dudenest-relay-update.timer <<EOF
[Unit]
Description=Daily check for Dudenest Relay updates (GitHub Releases)
[Timer]
OnBootSec=10min
OnUnitActiveSec=24h
RandomizedDelaySec=30min
Persistent=true
[Install]
WantedBy=timers.target
EOF

# Kiosk Chromium as root on display :0. dude's Xfce autostart issues `xhost +SI:localuser:root`,
# which authorizes this service to draw on the lightdm Xorg server.
# `ExecStartPre` polls for both the X socket and lightdm's auth file — handles boot ordering
# without coupling to graphical-session.target (which isn't reliable when no user is logged in
# via a real greeter).
# Helper script that polls for the kiosk Chromium window via wmctrl and forces maximize.
# Called from dudenest-kiosk.service ExecStartPost. Keeps inline systemd quoting sane.
cat > /usr/local/bin/dudenest-maximize-kiosk <<'EOF'
#!/bin/bash
export DISPLAY=:0
export XAUTHORITY=/var/run/lightdm/root/:0
for i in $(seq 1 20); do
  WID=$(wmctrl -l 2>/dev/null | grep -iE 'dudenest|chromium|google chrome' | head -1 | awk '{print $1}')
  if [[ -n "$WID" ]]; then
    wmctrl -i -r "$WID" -b add,maximized_vert,maximized_horz
    exit 0
  fi
  sleep 1
done
exit 1
EOF
chmod 755 /usr/local/bin/dudenest-maximize-kiosk
mkdir -p /var/lib/dudenest/kiosk-chrome/Default
# Pre-seed Chrome Preferences with `custom_chrome_frame=false` so Chrome uses the
# system (xfwm4) title bar + window decorations instead of its built-in CSD frame.
# This is equivalent to chrome://settings → Appearance → "Use system title bar and borders".
if [[ ! -f /var/lib/dudenest/kiosk-chrome/Default/Preferences ]]; then
  cat > /var/lib/dudenest/kiosk-chrome/Default/Preferences <<'PREFEOF'
{"browser":{"custom_chrome_frame":false,"window_placement":{"maximized":true}}}
PREFEOF
fi
cat > /etc/systemd/system/dudenest-kiosk.service <<EOF
[Unit]
Description=Dudenest noVNC kiosk — Chromium on :0 showing http://localhost:$NOVNC_PORT/dudenest.html
After=lightdm.service novnc.service
Wants=lightdm.service novnc.service
[Service]
Type=simple
User=root
# XDG_CURRENT_DESKTOP=XFCE tells Google Chrome to use server-side decorations (drawn by xfwm4)
# instead of its built-in CSD frame. GTK_USE_PORTAL=0 disables the GTK portal that also draws CSD.
Environment=DISPLAY=:0 XAUTHORITY=/var/run/lightdm/root/:0 XDG_CURRENT_DESKTOP=XFCE GTK_USE_PORTAL=0
# Wait not only for the X socket but also for xfwm4 to be running — otherwise Chromium
# starts before the window manager and ends up with no decorations.
ExecStartPre=/bin/bash -c 'for i in {1..30}; do [[ -S /tmp/.X11-unix/X0 && -f /var/run/lightdm/root/:0 ]] && pgrep -x xfwm4 >/dev/null && exit 0; sleep 2; done; exit 1'
# --test-type suppresses the --no-sandbox warning banner. Other flags match relay-poc reference.
ExecStart=/usr/local/bin/dudenest-browser --no-sandbox --test-type --no-first-run --disable-infobars --user-data-dir=/var/lib/dudenest/kiosk-chrome --start-maximized http://localhost:$NOVNC_PORT/dudenest.html
# Chromium's `--start-maximized` is only honored on first launch; after Chrome saves window
# state, subsequent launches restore the saved (often non-maximized) geometry. wmctrl forces
# the maximize state every boot, regardless of saved Preferences.
ExecStartPost=/usr/local/bin/dudenest-maximize-kiosk
Restart=on-failure
RestartSec=8
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
for svc in tigervnc-99 novnc dudenest-relay dudenest-relay-update.timer dudenest-kiosk; do
  systemctl enable "$svc" >/dev/null 2>&1
done
# Replace legacy relay.service (older relay-poc setup) with the new dudenest-relay.service.
# Only swap if the new service can actually start with /etc/dudenest/relay.env present.
if systemctl is-enabled --quiet relay.service 2>/dev/null && [[ -f "$CONFIG_DIR/relay.env" ]]; then
  warn "Found legacy relay.service — disabling in favor of dudenest-relay.service"
  systemctl stop relay.service 2>/dev/null || true
  systemctl disable relay.service 2>/dev/null || true
fi
# (Re)start in dependency order
systemctl restart tigervnc-99 || warn "tigervnc-99 failed to start — check: journalctl -u tigervnc-99"
systemctl restart novnc       || warn "novnc failed to start"
systemctl restart dudenest-relay || warn "dudenest-relay failed to start"
systemctl restart dudenest-relay-update.timer
systemctl restart dudenest-kiosk 2>/dev/null || warn "dudenest-kiosk failed (Chromium kiosk on :0)"
ok "All 5 systemd units enabled and started"

# ── step 9: ZT auto-provisioning wait ────────────────────────────────────────
step "Step 9/9: ZeroTier hub auto-provisioning"
BOOTSTRAP_DONE=false
for i in $(seq 1 24); do  # up to 120s
  sleep 5
  RELAY_ID=$(grep -o '"relay_id":"[^"]*"' "$CONFIG_DIR/relay_creds.json" 2>/dev/null | cut -d'"' -f4 || true)
  if [[ -n "${RELAY_ID:-}" ]]; then
    RELAY_URL=$(grep -o '"relay_url":"[^"]*"' "$CONFIG_DIR/relay_creds.json" 2>/dev/null | cut -d'"' -f4 || true)
    ok "Provisioned: relay_id=${RELAY_ID:0:8}…"
    [[ -n "${RELAY_URL:-}" ]] && ok "Relay URL: $RELAY_URL"
    BOOTSTRAP_DONE=true
    break
  fi
  echo "  … waiting (${i}/24) — hub is authorizing ZT membership"
done
$BOOTSTRAP_DONE || warn "Provisioning still pending — relay runs in background. Logs: journalctl -u dudenest-relay -f"

# ── summary ──────────────────────────────────────────────────────────────────
echo ""
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║  ✅  Dudenest Relay installed — full media-capable stack running.     ║"
echo "╠═══════════════════════════════════════════════════════════════════════╣"
echo "║  Local screen flow (auto-starts on VM console):                       ║"
echo "║    lightdm autologin → Xfce on :0 → Chromium maximized →              ║"
echo "║    http://localhost:6080/dudenest.html → noVNC → TigerVNC :99 →       ║"
echo "║    where relay launches Chromium for Google OAuth.                    ║"
echo "║                                                                       ║"
echo "║  Updates: dudenest-relay-update.timer checks GitHub Releases daily.   ║"
echo "║                                                                       ║"
echo "║  Next: open the Dudenest app → Settings → My Relays → add Cloud.      ║"
echo "╠═══════════════════════════════════════════════════════════════════════╣"
echo "║  Useful:                                                              ║"
echo "║    journalctl -u dudenest-relay -f                                    ║"
echo "║    systemctl status tigervnc-99 novnc dudenest-relay                  ║"
echo "║    systemctl list-timers dudenest-relay-update.timer                  ║"
echo "║    curl http://localhost:8086/health                                  ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo ""
