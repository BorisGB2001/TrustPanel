#!/bin/sh
# Set the admin password and bind TOTP (interactive), write them into .env and restart the panel.
# Password only: ./init-admin.sh hash; new TOTP only: ./init-admin.sh totp
set -e
cd "$(dirname "$0")"
docker compose run --rm -v "$PWD/.env:/srv/.env" panel python -m app.auth "${1:-init}" --env /srv/.env
docker compose up -d --no-build --force-recreate panel
