#!/bin/sh
# entrypoint.sh — reads Docker secrets and starts relay serve
# Secrets mounted at /run/secrets/ by Docker Swarm
set -e
RELAY_KEY=$(cat /run/secrets/relay_key 2>/dev/null || echo "${RELAY_KEY:-}")
JWT_SECRET=$(cat /run/secrets/relay_jwt_secret 2>/dev/null || echo "${JWT_SECRET:-}")
[ -z "$RELAY_KEY" ] && { echo "ERROR: relay_key secret missing"; exit 1; }
[ -z "$JWT_SECRET" ] && { echo "ERROR: relay_jwt_secret secret missing"; exit 1; }
export JWT_SECRET
exec /relay serve \
  --key "$RELAY_KEY" \
  --gdrive-token /run/secrets/relay_gdrive_token \
  --gdrive-secret /run/secrets/relay_gdrive_client_secret \
  --map-store /var/lib/dudenest/maps \
  --config-dir /etc/dudenest \
  --listen 0.0.0.0:8086
