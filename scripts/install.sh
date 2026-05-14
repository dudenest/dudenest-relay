#!/usr/bin/env bash
# Dudenest Relay — automatic installer (ZT auto-provisioning mode)
# Usage: curl -sSL https://get.dudenest.com/relay | bash
# No domain, no port forwarding, no JWT_SECRET needed.
# Uses ZeroTier overlay network + hub auto-provisioning.
set -euo pipefail

RELAY_VERSION="latest"
RELAY_REPO="dudenest/dudenest-relay"
RELAY_BIN="/usr/local/bin/relay"
CONFIG_DIR="/etc/dudenest"
DATA_DIR="/var/lib/dudenest"
ZT_NETWORK="932df01efb1ebd71"  # dudenest busybox ZeroTier network
HUB_URL="${HUB_URL:-https://hub.dudenest.com}"
BACKUP_URL="${BACKUP_URL:-https://backup.dudenest.com}"

# ── helpers ──────────────────────────────────────────────────────────────────
info()  { echo "[dudenest] $*"; }
error() { echo "[ERROR] $*" >&2; exit 1; }
require() { command -v "$1" >/dev/null 2>&1 || error "Required: $1 (install it first)"; }

require curl
[[ $EUID -eq 0 ]] || error "Run as root: sudo bash install.sh"

# ── detect arch ──────────────────────────────────────────────────────────────
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  RELAY_ARCH="linux-amd64"  ;;
  aarch64) RELAY_ARCH="linux-arm64"  ;;
  armv7l)  RELAY_ARCH="linux-armv7"  ;;
  *) error "Unsupported architecture: $ARCH" ;;
esac

echo ""
echo "┌─────────────────────────────────────────────────────────────────┐"
echo "│          Dudenest Relay Installer (ZeroTier mode)               │"
echo "├─────────────────────────────────────────────────────────────────┤"
echo "│  No domain, no port forwarding required!                        │"
echo "│  Uses ZeroTier overlay network for secure connectivity.         │"
echo "└─────────────────────────────────────────────────────────────────┘"
echo ""

info "Installing Dudenest Relay (ZT auto-provisioning mode) ..."

# ── install zerotier-one ──────────────────────────────────────────────────────
if ! command -v zerotier-cli >/dev/null 2>&1; then
  info "Installing ZeroTier ..."
  curl -fsSL https://install.zerotier.com | bash
  systemctl enable zerotier-one
  systemctl start zerotier-one
  sleep 3
fi
info "zerotier-one: $(zerotier-cli -v 2>/dev/null || echo 'running')"

# ── join dudenest ZT network ──────────────────────────────────────────────────
info "Joining dudenest ZeroTier network ($ZT_NETWORK) ..."
zerotier-cli join "$ZT_NETWORK" || true
info "ZeroTier network join requested — hub will authorize this relay"

# ── install relay binary ──────────────────────────────────────────────────────
info "Downloading relay binary ($RELAY_ARCH) ..."
RELAY_URL="https://github.com/$RELAY_REPO/releases/latest/download/relay-$RELAY_ARCH"
curl -fsSL "$RELAY_URL" -o "$RELAY_BIN"
chmod +x "$RELAY_BIN"
info "relay binary: $("$RELAY_BIN" version 2>/dev/null || echo 'installed')"

# ── create directories ────────────────────────────────────────────────────────
mkdir -p "$CONFIG_DIR/providers" "$DATA_DIR/maps"

# ── generate relay encryption key ────────────────────────────────────────────
RELAY_KEY=$(openssl rand -hex 32)
info "Generated relay encryption key"

# ── write relay.env ───────────────────────────────────────────────────────────
# JWT_SECRET and RELAY_PUBLIC_URL are delivered via /relay/bootstrap (ZT provisioning)
cat > "$CONFIG_DIR/relay.env" <<EOF
RELAY_KEY=$RELAY_KEY
BACKUP_URL=$BACKUP_URL
ZT_ANNOUNCE=true
EOF
chmod 600 "$CONFIG_DIR/relay.env"
info "Config written to $CONFIG_DIR/relay.env"

# ── systemd: relay ────────────────────────────────────────────────────────────
cat > /etc/systemd/system/dudenest-relay.service <<EOF
[Unit]
Description=Dudenest Relay (ZeroTier provisioned)
After=network.target zerotier-one.service
Wants=zerotier-one.service
[Service]
Type=simple
User=root
EnvironmentFile=$CONFIG_DIR/relay.env
ExecStart=$RELAY_BIN serve --key \${RELAY_KEY} --listen 0.0.0.0:8086 --config-dir $CONFIG_DIR --map-store $DATA_DIR/maps --client-secret $CONFIG_DIR/client_secret.json
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
[Install]
WantedBy=multi-user.target
EOF

# ── client_secret.json (required for GDrive OAuth) ────────────────────────────
if [[ ! -f "$CONFIG_DIR/client_secret.json" ]]; then
  info "client_secret.json not found — downloading from hub ..."
  if ! curl -fsSL "$HUB_URL/relay/client-secret" -o "$CONFIG_DIR/client_secret.json" 2>/dev/null; then
    info "⚠️  Could not download client_secret.json from hub."
    info "    Copy your client_secret.json to $CONFIG_DIR/client_secret.json and restart relay."
    echo '{"type":"service_account"}' > "$CONFIG_DIR/client_secret.json"  # placeholder — relay will start in degraded mode
  fi
  chmod 600 "$CONFIG_DIR/client_secret.json"
fi

# ── start services ────────────────────────────────────────────────────────────
systemctl daemon-reload
systemctl enable dudenest-relay
systemctl restart dudenest-relay

# ── verify ────────────────────────────────────────────────────────────────────
sleep 3
if curl -sf "http://localhost:8086/health" >/dev/null 2>&1; then
  info "✅ Relay is running (localhost:8086)"
else
  echo "[WARN] Relay not responding on :8086 yet — check: journalctl -u dudenest-relay -n 30"
fi

echo ""
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║  ✅  Dudenest Relay installed successfully!                       ║"
echo "╠═══════════════════════════════════════════════════════════════════╣"
echo "║  Mode:    ZeroTier auto-provisioning (no domain needed)          ║"
echo "║  Logs:    journalctl -u dudenest-relay -f                        ║"
echo "║  Status:  systemctl status dudenest-relay                        ║"
echo "╠═══════════════════════════════════════════════════════════════════╣"
echo "║  Next steps in the Dudenest app:                                 ║"
echo "║   1. Open app → Settings → Add Relay                            ║"
echo "║   2. App detects relay automatically (same network)              ║"
echo "║   3. Settings → Cloud Accounts → Add Google Drive               ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""
