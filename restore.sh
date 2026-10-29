#!/bin/sh
# boris.gb 2026-10-30 00:29 - restore TrustPanel and the TrustTunnel settings from an encrypted portal backup (.ttbak) on this server
# Usage (in /opt/trust-panel, after deploy.sh and with TrustTunnel installed in /opt/trusttunnel): ./restore.sh <backup.ttbak> [new-public-ip]
# Puts back .env, the panel database, data.key and the TrustTunnel settings, restarts the endpoint and starts the panel.
set -e
cd "$(dirname "$0")"
[ -f "$1" ] || { echo "usage: $0 <backup.ttbak> [new-public-ip]" >&2; exit 2; }
F=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
docker image inspect trust-panel:latest >/dev/null 2>&1 || docker build -q --network host -t trust-panel:latest panel >/dev/null
[ -f .env ] || { touch .env; chmod 600 .env; }
mkdir -p data
docker compose stop panel >/dev/null 2>&1 || true
# в контейнере панели: каталог TrustTunnel, data/ и .env на запись
docker run --rm -it --network host --pid host --privileged -e PANEL_DATA=/data \
  -v "$PWD/data:/data" -v "$PWD/.env:/srv/host.env" -v "$F:/srv/backup.ttbak:ro" -v /opt/trusttunnel:/opt/trusttunnel \
  trust-panel:latest python -m app.backup restore /srv/backup.ttbak --env /srv/host.env ${2:+--host "$2"}
systemctl restart trusttunnel
docker compose up -d --no-build
H=$(grep '^PANEL_HOST=' .env | cut -d= -f2); P=$(grep '^PANEL_PORT=' .env | cut -d= -f2)
echo "Done. Panel: https://$H:${P:-15443}"
