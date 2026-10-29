#!/bin/sh
# boris.gb 2026-10-30 00:29 - deploy TrustPanel from a workstation to the server: tests inside the image, then recreate the panel container
# target host from the argument or the local .deploy-host file (gitignored), no address in the repository
# Usage: ./deploy.sh root@<server>   or   echo root@<server> > .deploy-host; ./deploy.sh
set -e
cd "$(dirname "$0")"
HOST=${1:-$(cat .deploy-host 2>/dev/null)}
[ -n "$HOST" ] || { echo "usage: $0 root@<server>  (or put it into .deploy-host)" >&2; exit 2; }
COPYFILE_DISABLE=1 tar --no-xattrs -czf - --exclude '__pycache__' --exclude .pytest_cache \
  panel docker-compose.yml Caddyfile .env.example init-admin.sh deploy.sh restore.sh ip-allow.sh README.md | ssh "$HOST" '
set -e
mkdir -p /opt/trust-panel && tar -xzf - -C /opt/trust-panel --no-same-owner
cd /opt/trust-panel
# some hosts have no DNS inside the bridge build network — build in the host network
docker build -q --network host -t trust-panel:latest panel >/dev/null
docker run --rm --network host trust-panel:latest sh -c "pip install -q pytest httpx >/dev/null 2>&1; python -m pytest -q -p no:warnings tests" | tail -1
docker compose up -d --no-build --force-recreate panel
sleep 5; curl -s http://127.0.0.1:$(grep -s ^PANEL_BIND_PORT= .env | cut -d= -f2 | grep . || echo 8081)/healthz; echo'
