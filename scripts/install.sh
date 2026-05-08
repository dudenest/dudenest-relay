#!/usr/bin/env bash
# Dudenest Relay — automatic installer
# Usage (copy from Dudenest app → Settings → Add Relay):
#   curl -sSL https://raw.githubusercontent.com/dudenest/dudenest-relay/main/scripts/install.sh \
#     | DUDENEST_JWT_SECRET=xxx BACKUP_URL=https://backup.dudenest.com bash
set -euo pipefail

RELAY_VERSION="latest"
RELAY_REPO="dudenest/dudenest-relay"
RELAY_BIN="/usr/local/bin/relay"
CONFIG_DIR="/etc/dudenest"
DATA_DIR="/var/lib/dudenest"
CADDY_REPO="https://github.com/caddyserver/caddy/releases/latest/download"

# ── helpers ──────────────────────────────────────────────────────────────────
info()  { echo "[dudenest] $*"; }
error() { echo "[ERROR] $*" >&2; exit 1; }
require() { command -v "$1" >/dev/null 2>&1 || error "Required: $1 (install it first)"; }

require curl
require openssl
[[ $EUID -eq 0 ]] || error "Run as root: sudo bash install.sh"
[[ -n "${DUDENEST_JWT_SECRET:-}" ]] || error "DUDENEST_JWT_SECRET not set — copy the install command from the Dudenest app"
[[ -n "${BACKUP_URL:-}" ]] || BACKUP_URL="https://backup.dudenest.com"

# ── detect arch ──────────────────────────────────────────────────────────────
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  RELAY_ARCH="linux-amd64";  CADDY_ARCH="linux_amd64"  ;;
  aarch64) RELAY_ARCH="linux-arm64";  CADDY_ARCH="linux_arm64"  ;;
  armv7l)  RELAY_ARCH="linux-armv7";  CADDY_ARCH="linux_armv7"  ;;
  *) error "Unsupported architecture: $ARCH" ;;
esac

# ── ask for domain ────────────────────────────────────────────────────────────
if [[ -z "${RELAY_DOMAIN:-}" ]]; then
  echo ""
  echo "┌─────────────────────────────────────────────────────────────────┐"
  echo "│          Dudenest Relay Installer                               │"
  echo "├─────────────────────────────────────────────────────────────────┤"
  echo "│  Requirements:                                                  │"
  echo "│   • Port 443 forwarded to this machine on your router           │"
  echo "│   • Port 80 forwarded to this machine (needed for HTTPS cert)   │"
  echo "│   • Domain pointing to your public IP (dynamic DNS is fine)     │"
  echo "└─────────────────────────────────────────────────────────────────┘"
  echo ""
  read -rp "Enter your relay domain (e.g. relay.example.com or xyz.duckdns.org): " RELAY_DOMAIN
fi
[[ -n "$RELAY_DOMAIN" ]] || error "Domain cannot be empty"

info "Installing Dudenest Relay on $RELAY_DOMAIN ..."

# ── install relay binary ──────────────────────────────────────────────────────
info "Downloading relay binary ($RELAY_ARCH)..."
RELAY_URL="https://github.com/$RELAY_REPO/releases/latest/download/relay-$RELAY_ARCH"
curl -fsSL "$RELAY_URL" -o "$RELAY_BIN"
chmod +x "$RELAY_BIN"
info "relay binary: $("$RELAY_BIN" version 2>/dev/null || echo 'installed')"

# ── install caddy ─────────────────────────────────────────────────────────────
if ! command -v caddy >/dev/null 2>&1; then
  info "Downloading Caddy (reverse proxy + automatic HTTPS)..."
  curl -fsSL "$CADDY_REPO/caddy_${CADDY_ARCH}.tar.gz" | tar -xz -C /usr/local/bin caddy
  chmod +x /usr/local/bin/caddy
fi
info "caddy: $(caddy version)"

# ── create directories ────────────────────────────────────────────────────────
mkdir -p "$CONFIG_DIR/providers" "$DATA_DIR/maps"

# ── generate relay key ────────────────────────────────────────────────────────
RELAY_KEY=$(openssl rand -hex 32)
info "Generated new encryption key (unique to this relay)"

# ── write relay.env ───────────────────────────────────────────────────────────
cat > "$CONFIG_DIR/relay.env" <<EOF
RELAY_KEY=$RELAY_KEY
JWT_SECRET=$DUDENEST_JWT_SECRET
RELAY_PUBLIC_URL=https://$RELAY_DOMAIN
BACKUP_URL=$BACKUP_URL
EOF
chmod 600 "$CONFIG_DIR/relay.env"
info "Config written to $CONFIG_DIR/relay.env"

# ── write Caddyfile ───────────────────────────────────────────────────────────
cat > /etc/caddy/Caddyfile <<EOF
$RELAY_DOMAIN {
  reverse_proxy localhost:8086
}
EOF
mkdir -p /etc/caddy

# write again (mkdir must come first)
cat > /etc/caddy/Caddyfile <<EOF
$RELAY_DOMAIN {
  reverse_proxy localhost:8086
}
EOF
info "Caddyfile written (/etc/caddy/Caddyfile)"

# ── systemd: relay ────────────────────────────────────────────────────────────
cat > /etc/systemd/system/dudenest-relay.service <<EOF
[Unit]
Description=Dudenest Relay
After=network.target caddy.service
[Service]
Type=simple
User=root
EnvironmentFile=$CONFIG_DIR/relay.env
ExecStart=$RELAY_BIN serve --key \${RELAY_KEY} --listen 0.0.0.0:8086 --config-dir $CONFIG_DIR --map-store $DATA_DIR/maps
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
[Install]
WantedBy=multi-user.target
EOF

# ── systemd: caddy ────────────────────────────────────────────────────────────
# Only create if not already provided by caddy package install
if [[ ! -f /etc/systemd/system/caddy.service ]]; then
  cat > /etc/systemd/system/caddy.service <<EOF
[Unit]
Description=Caddy
After=network.target
[Service]
Type=notify
ExecStart=/usr/local/bin/caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
ExecReload=/usr/local/bin/caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile
TimeoutStopSec=5s
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
fi

# ── start services ────────────────────────────────────────────────────────────
systemctl daemon-reload
systemctl enable caddy dudenest-relay
systemctl restart caddy
sleep 2
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
echo "║  Domain:  https://$RELAY_DOMAIN"
echo "║  Logs:    journalctl -u dudenest-relay -f"
echo "║  Status:  systemctl status dudenest-relay"
echo "╠═══════════════════════════════════════════════════════════════════╣"
echo "║  Next steps in the Dudenest app:                                 ║"
echo "║   1. Open app → Files tab (triggers relay registration)          ║"
echo "║   2. Settings → Cloud Accounts → Add Google Drive                ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""
