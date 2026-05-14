#!/usr/bin/env bash
# Dudenest Relay — uninstaller
# Removes all relay components and restores the machine to clean state.
# Usage: sudo bash uninstall.sh
set -euo pipefail

ZT_NETWORK="932df01efb1ebd71"

ok()   { echo "  ✓ $*"; }
step() { echo ""; echo "▸ $*"; }
warn() { echo "  ! $*"; }

[[ $EUID -eq 0 ]] || { echo "Run as root: sudo bash uninstall.sh"; exit 1; }

echo ""
echo "┌─────────────────────────────────────────────────────────────────┐"
echo "│          Dudenest Relay — Uninstaller                           │"
echo "└─────────────────────────────────────────────────────────────────┘"
echo ""
read -r -p "  This will remove all Dudenest Relay components. Continue? [y/N] " CONFIRM
[[ "$CONFIRM" =~ ^[Yy]$ ]] || { echo "  Cancelled."; exit 0; }

# ── step 1: stop and disable service ─────────────────────────────────────────
step "Step 1/5: Stopping service"
if systemctl is-active --quiet dudenest-relay 2>/dev/null; then
  systemctl stop dudenest-relay
  ok "Service stopped"
else
  warn "Service was not running"
fi
if systemctl is-enabled --quiet dudenest-relay 2>/dev/null; then
  systemctl disable dudenest-relay
  ok "Service disabled"
fi
if [[ -f /etc/systemd/system/dudenest-relay.service ]]; then
  rm -f /etc/systemd/system/dudenest-relay.service
  systemctl daemon-reload >/dev/null 2>&1
  ok "Service unit removed"
fi

# ── step 2: relay binary ─────────────────────────────────────────────────────
step "Step 2/5: Relay binary"
if [[ -f /usr/local/bin/relay ]]; then
  rm -f /usr/local/bin/relay
  ok "Binary removed: /usr/local/bin/relay"
else
  warn "Binary not found (already removed?)"
fi

# ── step 3: config and data ───────────────────────────────────────────────────
step "Step 3/5: Configuration and data"
if [[ -d /etc/dudenest ]]; then
  rm -rf /etc/dudenest
  ok "Config removed: /etc/dudenest"
fi
if [[ -d /var/lib/dudenest ]]; then
  rm -rf /var/lib/dudenest
  ok "Data removed: /var/lib/dudenest"
fi

# ── step 4: ZeroTier ─────────────────────────────────────────────────────────
step "Step 4/5: ZeroTier"
if command -v zerotier-cli >/dev/null 2>&1; then
  zerotier-cli leave "$ZT_NETWORK" >/dev/null 2>&1 && ok "Left ZeroTier network $ZT_NETWORK" || warn "Could not leave network (may already be left)"
  echo ""
  read -r -p "  Remove ZeroTier completely from this machine? [y/N] " RM_ZT
  if [[ "$RM_ZT" =~ ^[Yy]$ ]]; then
    systemctl stop zerotier-one 2>/dev/null || true
    systemctl disable zerotier-one 2>/dev/null || true
    if command -v apt-get >/dev/null 2>&1; then
      apt-get remove -y zerotier-one >/dev/null 2>&1 && ok "ZeroTier removed (apt)"
    elif command -v rpm >/dev/null 2>&1; then
      rpm -e zerotier-one >/dev/null 2>&1 && ok "ZeroTier removed (rpm)"
    else
      warn "Could not auto-remove ZeroTier — remove manually"
    fi
  else
    ok "ZeroTier kept (left the dudenest network only)"
  fi
else
  warn "ZeroTier not installed"
fi

# ── step 5: verify ────────────────────────────────────────────────────────────
step "Step 5/5: Verification"
LEFTOVER=false
[[ -f /usr/local/bin/relay ]]                            && { warn "Binary still present: /usr/local/bin/relay"; LEFTOVER=true; }
[[ -d /etc/dudenest ]]                                   && { warn "Config still present: /etc/dudenest"; LEFTOVER=true; }
[[ -d /var/lib/dudenest ]]                               && { warn "Data still present: /var/lib/dudenest"; LEFTOVER=true; }
[[ -f /etc/systemd/system/dudenest-relay.service ]]      && { warn "Service unit still present"; LEFTOVER=true; }
[[ "$LEFTOVER" == "false" ]] && ok "All components removed"

echo ""
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║  ✅  Dudenest Relay uninstalled successfully.                     ║"
echo "║  The relay entry in the hub will expire automatically.           ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""
