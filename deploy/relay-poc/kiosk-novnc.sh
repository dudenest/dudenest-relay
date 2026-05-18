#!/bin/bash
# Autostart Chromium showing noVNC view of display :99 — only on the local screen (:0).
# Skip when this script runs inside the TigerVNC :99 session (would loop).
[ "$DISPLAY" = ":0" ] || exit 0
# --user-data-dir isolates from the Chromium instance relay launches for OAuth on :99
exec chromium \
  --no-sandbox \
  --no-first-run \
  --disable-infobars \
  --user-data-dir=/home/dude/.config/chromium-novnc \
  --start-maximized \
  http://localhost:6080/dudenest.html
