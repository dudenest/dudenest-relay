#!/bin/bash
# Disable xfwm4 compositing on display :99 — improves Chromium rendering inside VNC
sleep 5
DISPLAY=:99 XAUTHORITY=/home/dude/.Xauthority xfconf-query -c xfwm4 -p /general/use_compositing -s false 2>/dev/null || \
  DISPLAY=:99 XAUTHORITY=/home/dude/.Xauthority xfwm4 --compositor=off --replace &
