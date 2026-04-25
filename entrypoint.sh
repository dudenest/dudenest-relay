#!/bin/sh
# entrypoint.sh — reads Docker secrets and starts relay serve
# Secrets mounted at /run/secrets/ by Docker Swarm
# relay_gdrive_client_secret = OAuth app registration (shared, not per-user)
# User tokens are added at runtime via OAuth flow → stored in relay_maps volume
set -e
RELAY_KEY=$(cat /run/secrets/relay_key 2>/dev/null || echo "${RELAY_KEY:-}")
JWT_SECRET=$(cat /run/secrets/relay_jwt_secret 2>/dev/null || echo "${JWT_SECRET:-}")
[ -z "$RELAY_KEY" ] && { echo "ERROR: relay_key secret missing"; exit 1; }
[ -z "$JWT_SECRET" ] && { echo "ERROR: relay_jwt_secret secret missing"; exit 1; }
export JWT_SECRET
exec /relay serve \
  --key "$RELAY_KEY" \
  --client-secret /run/secrets/relay_gdrive_client_secret \
  --config-dir /var/lib/dudenest/maps \
  --map-store /var/lib/dudenest/maps \
  --listen 0.0.0.0:8086
