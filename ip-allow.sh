#!/bin/sh
# boris.gb 2026-10-29 23:30 - panel access by IP from the server shell (works even if the browser has lost access)
# Usage: ./ip-allow.sh list | add <address-or-subnet> [note] | remove <address-or-number> | clear
set -e
cd "$(dirname "$0")"
exec docker compose exec -T panel python -m app.ipallow "$@"
