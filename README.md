# TrustPanel

[Русская версия](README.ru.md)

A web panel for a [TrustTunnel](https://github.com/TrustTunnel/TrustTunnel) VPN endpoint (the systemd service `trusttunnel`). It shows who is connected, from where and how much traffic they use, lets you add, disable and delete clients and issue their configs (`tt://` link with a QR code for the TrustTunnel apps, `.toml` for the CLI client). It also has alerts, traffic quotas, client groups with their own administrators, a monthly archive, a self-service portal for clients, Telegram/e-mail notifications and encrypted backups.

TrustPanel is a port of [AWG Panel](https://github.com/BorisGB2001/awg-panel) (the same panel for AmneziaWG) to TrustTunnel.

| | |
|---|---|
| Address | `https://<server-ip>:15443` (port is `PANEL_PORT` in `.env`; certificate from Caddy's internal CA — **port 80 is not used**) |
| Install dir | `/opt/trust-panel` on the TrustTunnel server |
| Containers | `trust-panel` (Python, FastAPI), `trust-panel-caddy` (HTTPS) |
| Data | `/opt/trust-panel/data`: `panel.db` (SQLite), `backups/` (credentials.toml before every change, DB), `geo/` (DB-IP), `data.key` |
| Login | user `admin`, password + TOTP code |

## Features

- **Overview**: online now and peak, traffic for 24 h / 7 / 30 days, top 10 by traffic today and this month (downloaded / uploaded bars, a chart on hover), traffic by group, every client with status, last seen, where they connect from (country, city, provider), traffic today and total.
- **Client card**: sessions, IP addresses with geo, hourly activity heat map, events, quota, group, portal link and contacts.
- **Management**: add a client (login generated from the name or set by hand, random password), rename, disable / enable (the panel keeps the password, so the same config works again), delete, issue a new password.
- **Configs**: `tt://` deep link with a QR code, `.toml` for the CLI client — exported by the endpoint itself (`trusttunnel_endpoint -c`), so they always match the server settings. Send to the client by Telegram or e-mail, or with a one-time bot link.
- **Events and alerts**: connections, IP changes, a config used from several places, a new country, traffic spikes, quota thresholds, never connected / inactive clients, endpoint restarted or unavailable, disk and connection table, password guessing. Alerts go to administrators' Telegram (with quiet hours).
- **Groups and administrators**: groups can be nested (head organisation → branches → departments, any depth), with breadcrumbs on every page; a group's clients, traffic and quota include its subgroups. Super administrators see everything; a group administrator sees and manages only the clients of their groups and their subgroups, and can create, move and delete subgroups. Traffic quotas per group or client per day / month with an alert or automatic disabling.
- **Client portal** (`/me`, personal link): own traffic, sessions, quota, optional config download, daily report image and notifications in Telegram or e-mail.
- **Backups** to Telegram / e-mail on a schedule, encrypted with your password (AES-256-GCM, scrypt): the whole portal (DB, `.env`, `data.key`, TrustTunnel settings) or, for a group administrator, the configs of their groups. Restore on the same server from the Backups page or on a new one with `restore.sh`.
- **Client path to the internet** (Server page): traceroute to test hosts and to "what is my IP" services from the clients' network context, routes merged into a tree and the list of exit addresses — with split routing clients exit from several addresses. Each address shows DB-IP, ipinfo.io (optional API key in the settings, stored encrypted) and Yandex (IP, ASN, VPN flag) data.
- **Access by IP** to the administrator part, interface in English and Russian, light and dark theme.

## How it works

- The endpoint keeps users in `credentials.toml` and reads it **only at start** (SIGHUP reloads only the TLS hosts). So every change of the client list is: lock → backup of `credentials.toml` → write → `systemctl restart trusttunnel` → check the service is back. On failure the file is restored and the endpoint restarted again. **A restart drops all tunnels for a second or two; the TrustTunnel apps reconnect by themselves.** Rename, quotas, groups and portal settings do not restart anything.
- Online status, client IP and traffic come from the endpoint's metrics (`/clients` with `per_client_metrics = true`) every `POLL_INTERVAL` seconds. Counters reset when the endpoint restarts — the panel handles that.
- Users added to `credentials.toml` by hand are imported automatically (with their password, so the panel can export their config) and get no group.
- The panel container runs with `network_mode: host`, `pid: host` and `privileged` to reach the metrics on `127.0.0.1` and to run `systemctl` in the host namespaces via `nsenter`. The endpoint directory is mounted into the container; the static `trusttunnel_endpoint` binary runs inside it for exports.
- What TrustTunnel does not report, the panel cannot show: there are no visited sites / DNS log and no per-site blocking as in AWG Panel.

## Requirements

- Linux server with Docker (compose v2) and the TrustTunnel endpoint installed as a systemd service (`/opt/trusttunnel`, see the TrustTunnel README).
- In `vpn.toml` of the endpoint — metrics with per-client series, listening on localhost only:

  ```toml
  [metrics]
  address = "127.0.0.1:1987"
  request_timeout_secs = 3
  per_client_metrics = true
  ```

- In `hosts.toml` the main host must be a **hostname**, not an IP: the endpoint drops TLS connections without SNI, and an IP is not a valid SNI. Without a domain use a wildcard DNS name such as `203-0-113-10.sslip.io` (resolves to 203.0.113.10) with a self-signed certificate; the certificate is embedded in the exported configs.
- A free TCP port for the panel (`PANEL_PORT`, default 15443) open in the firewall.

## Installation

```bash
# on your workstation, from the repository root
cp .env.example .env.server         # fill PANEL_HOST, PUBLIC_HOST, SESSION_SECRET, DATA_KEY (commands are in the file)
scp .env.server root@<server>:/opt/trust-panel/.env && ssh root@<server> chmod 600 /opt/trust-panel/.env
./deploy.sh root@<server>           # copies the code, builds the image, runs the tests, starts the panel
ssh root@<server> 'cd /opt/trust-panel && ./init-admin.sh && docker compose up -d caddy && ufw allow 15443/tcp'
```

`init-admin.sh` asks for the administrator password and shows a QR code for the authenticator app. Then open `https://<server-ip>:15443`. The browser warns about the certificate once: it is issued by Caddy's local CA. Compare the fingerprint (`openssl s_client -connect <server-ip>:15443 | openssl x509 -noout -fingerprint -sha256` on the server) or install the root `docker compose exec caddy cat /data/caddy/pki/authorities/local/root.crt` as trusted.

## Updating

```bash
./deploy.sh root@<server>
```

The tests run inside the new image before the container is replaced; the database migrates itself.

## Health and logs

```bash
curl -s http://127.0.0.1:8081/healthz           # on the server: poller status, version, schema
docker compose logs -f panel                     # in /opt/trust-panel
journalctl -u trusttunnel -f                     # the endpoint
```

## Backups and restore

- Before every client change: `data/backups/<time>-<operation>/credentials.toml` (the last 200 are kept). Nightly: a copy of the database in `data/backups/db/` (14 kept).
- Backups page: scheduled encrypted backups to Telegram / e-mail. Decrypt by hand: `python3 -m app.backup decrypt <file>.ttbak`.
- Restore on the same server: Backups page → choose the `.ttbak` file, password and what to restore (database, TrustTunnel settings).
- New server: install TrustTunnel and Docker, `./deploy.sh`, then `./restore.sh <file>.ttbak [new-public-ip]` in `/opt/trust-panel`.

## Access by IP

The Administrators page (super administrators) limits the administrator part, including sign-in, to listed addresses and subnets; the client portal stays open. If you lock yourself out: `./ip-allow.sh list | add <ip> | remove <n> | clear` on the server.

## Known quirks

- Any change of the client list restarts the endpoint (see "How it works").
- The browser warns about the self-signed panel certificate until you trust Caddy's local CA.
- Session times are as seen by the poller (every `POLL_INTERVAL` seconds), not exact connect moments.

## Development

```bash
cd panel && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt pytest httpx
.venv/bin/python -m pytest -q
```

Phrases in code and templates are English; translations live in `panel/app/locales/<code>.json` (a test checks that every phrase is translated).
