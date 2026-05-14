#!/usr/bin/env bash
# Dudenest Relay — automatic installer (ZT auto-provisioning mode)
# Usage: curl -sSL https://raw.githubusercontent.com/dudenest/dudenest-relay/main/scripts/install.sh | bash
# No domain, no port forwarding, no JWT_SECRET needed.
# Uses ZeroTier overlay network + hub auto-provisioning.
set -euo pipefail

RELAY_REPO="dudenest/dudenest-relay"
RELAY_BIN="/usr/local/bin/relay"
CONFIG_DIR="/etc/dudenest"
DATA_DIR="/var/lib/dudenest"
ZT_NETWORK="932df01efb1ebd71"
BACKUP_URL="${BACKUP_URL:-https://backup.dudenest.com}"

# ── helpers ───────────────────────────────────────────────────────────────────
ok()    { echo "  ✓ $*"; }
step()  { echo ""; echo "▸ $*"; }
fail()  { echo ""; echo "  ✗ ERROR: $*" >&2; exit 1; }
require() { command -v "$1" >/dev/null 2>&1 || fail "Required tool not found: $1"; }

require curl
[[ $EUID -eq 0 ]] || fail "Run as root: sudo bash install.sh"

ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  RELAY_ARCH="linux-amd64"  ;;
  aarch64) RELAY_ARCH="linux-arm64"  ;;
  armv7l)  RELAY_ARCH="linux-armv7"  ;;
  *) fail "Unsupported architecture: $ARCH" ;;
esac

echo ""
echo "┌─────────────────────────────────────────────────────────────────┐"
echo "│          Dudenest Relay Installer (ZeroTier mode)               │"
echo "├─────────────────────────────────────────────────────────────────┤"
echo "│  No domain, no port forwarding, no configuration required.      │"
echo "│  Relay will be provisioned automatically within seconds.        │"
echo "└─────────────────────────────────────────────────────────────────┘"

# ── step 1: ZeroTier ─────────────────────────────────────────────────────────
step "Step 1/5: ZeroTier"
if ! command -v zerotier-cli >/dev/null 2>&1; then
  echo "  Installing ZeroTier ..."
  curl -fsSL https://install.zerotier.com | bash >/dev/null 2>&1
  systemctl enable zerotier-one >/dev/null 2>&1
  systemctl start zerotier-one >/dev/null 2>&1
  sleep 3
fi
ZT_VERSION=$(zerotier-cli -v 2>/dev/null || echo "running")
ok "ZeroTier $ZT_VERSION"
zerotier-cli join "$ZT_NETWORK" >/dev/null 2>&1 || true
ok "Joined network $ZT_NETWORK (authorization will complete automatically)"

# ── step 2: relay binary ─────────────────────────────────────────────────────
step "Step 2/5: Relay binary"
RELAY_URL="https://github.com/$RELAY_REPO/releases/latest/download/relay-$RELAY_ARCH"
echo "  Downloading relay binary ($RELAY_ARCH) ..."
curl -fsSL "$RELAY_URL" -o "$RELAY_BIN" || fail "Failed to download relay binary from GitHub"
chmod +x "$RELAY_BIN"
ok "Relay binary installed: $RELAY_BIN"

# ── step 3: config ───────────────────────────────────────────────────────────
step "Step 3/5: Configuration"
mkdir -p "$CONFIG_DIR/providers" "$DATA_DIR/maps"
RELAY_KEY=$(openssl rand -hex 32)

# JWT_SECRET and relay credentials are delivered automatically via ZT bootstrap
cat > "$CONFIG_DIR/relay.env" <<EOF
RELAY_KEY=$RELAY_KEY
BACKUP_URL=$BACKUP_URL
ZT_ANNOUNCE=true
EOF
chmod 600 "$CONFIG_DIR/relay.env"
ok "Config written to $CONFIG_DIR/relay.env"

# client_secret.json — placeholder; relay works without it until GDrive auth is added
if [[ ! -f "$CONFIG_DIR/client_secret.json" ]]; then
  echo '{"installed":{"client_id":"placeholder"}}' > "$CONFIG_DIR/client_secret.json"
  chmod 600 "$CONFIG_DIR/client_secret.json"
fi
ok "OAuth config ready"

# ── step 4: systemd service ───────────────────────────────────────────────────
step "Step 4/5: System service"
cat > /etc/systemd/system/dudenest-relay.service <<EOF
[Unit]
Description=Dudenest Relay
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
systemctl daemon-reload >/dev/null 2>&1
systemctl enable dudenest-relay >/dev/null 2>&1
systemctl restart dudenest-relay >/dev/null 2>&1
ok "Service dudenest-relay enabled and started"

# ── step 5: provisioning ─────────────────────────────────────────────────────
step "Step 5/5: Provisioning"
echo "  Waiting for relay to announce and receive credentials ..."
BOOTSTRAP_DONE=false
for i in $(seq 1 24); do  # up to 120s
  sleep 5
  HEALTH=$(curl -sf "http://localhost:8086/health" 2>/dev/null || echo "")
  RELAY_ID=$(grep -o '"relay_id":"[^"]*"' "$CONFIG_DIR/relay_creds.json" 2>/dev/null | cut -d'"' -f4 || echo "")
  if [[ -n "$RELAY_ID" ]]; then
    RELAY_URL=$(grep -o '"relay_url":"[^"]*"' "$CONFIG_DIR/relay_creds.json" 2>/dev/null | cut -d'"' -f4 || echo "")
    ok "Provisioned: relay_id=${RELAY_ID:0:8}..."
    ok "Relay URL: $RELAY_URL"
    BOOTSTRAP_DONE=true
    break
  fi
  echo "  ... waiting (${i}/24) — provisioner is authorizing ZeroTier membership"
done

if [[ "$BOOTSTRAP_DONE" != "true" ]]; then
  echo ""
  echo "  NOTE: Provisioning is taking longer than expected."
  echo "  The relay is running and will complete in the background."
  echo "  Check status: journalctl -u dudenest-relay -f"
fi

# ── summary ───────────────────────────────────────────────────────────────────
echo ""
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║  ✅  Dudenest Relay installed and running!                        ║"
echo "╠═══════════════════════════════════════════════════════════════════╣"
echo "║  Next steps:                                                      ║"
echo "║   1. Open the Dudenest app and log in                            ║"
echo "║   2. Your relay will appear in Settings → My Relays              ║"
echo "║   3. Add Google Drive in Settings → Cloud Accounts               ║"
echo "╠═══════════════════════════════════════════════════════════════════╣"
echo "║  Commands:                                                        ║"
echo "║   journalctl -u dudenest-relay -f      (live logs)               ║"
echo "║   systemctl status dudenest-relay      (service status)          ║"
echo "║   curl http://localhost:8086/health    (health check)            ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""
