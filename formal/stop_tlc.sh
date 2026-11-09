#!/bin/bash
# Stop this user's TLC run (run_tlc.sh and its java child).
for p in $(pgrep -u "$(id -u)" -f run_tlc.sh) $(pgrep -u "$(id -u)" -f tlc2.TLC); do kill "$p" 2>/dev/null; done
sleep 2
pgrep -u "$(id -u)" -f tlc2.TLC >/dev/null && echo "still running" || echo "stopped"
