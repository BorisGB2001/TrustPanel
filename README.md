# TrustPanel

[Русская версия](README.ru.md)

A web panel for a [TrustTunnel](https://github.com/TrustTunnel/TrustTunnel) VPN endpoint (the systemd service `trusttunnel`). It shows who is connected, from where and how much traffic they use, lets you add, disable and delete clients and issue their configs (`tt://` link with a QR code for the TrustTunnel apps, `.toml` for the CLI client). It also has alerts, traffic quotas, client groups with their own administrators, a monthly archive, a self-service portal for clients, Telegram/e-mail notifications and encrypted backups.

TrustPanel is a port of [AWG Panel](https://github.com/BorisGB2001/awg-panel) (the same panel for AmneziaWG) to TrustTunnel.

| | |
|---|---|
| Address | `https://<server-ip>:15443` (port is `PANEL_PORT` in `.env`; Let's Encrypt certificate for the server IP, renewed by Caddy) |
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

- In `hosts.toml` the main host must be a **hostname**, not an IP: the endpoint drops TLS connections without SNI, and an IP is not a valid SNI. Without a domain use a wildcard DNS name such as `203-0-113-10.sslip.io` (resolves to 203.0.113.10) — a Let's Encrypt certificate can be issued for it. Recommended: certbot (`certonly --standalone`, http-01 on :80) with a deploy hook that copies `fullchain.pem` / `privkey.pem` into the endpoint directory (it is mounted into the panel container — paths under `/etc/letsencrypt` are not) and sends `SIGHUP`: the endpoint reloads the certificate without dropping tunnels (see TrustTunnel's CERT_RENEWAL.md). A publicly trusted certificate is not embedded in the exported configs, so renewals do not break them; a self-signed one is embedded.
- Many networks and antivirus engines dislike `*.sslip.io` names in the SNI. The endpoint can decouple the ClientHello SNI from the certificate: add the masking names to `allowed_sni` of the main host in `hosts.toml` (keep the real host name in the list too, for existing configs) and reload with `SIGHUP`. On the panel's **Server** page set the **Custom SNI** (e.g. `metrika.yandex.ru`); exported configs then carry it in the ClientHello while the certificate is still verified against the real host name. With TLS 1.3 only the SNI is visible on the wire, not the real certificate. Re-issue client configs after changing it.
- A free TCP port for the panel (`PANEL_PORT`, default 15443) and port 80/tcp for the Let's Encrypt check, open in the firewall (:80 is used only for the seconds of validation).

## Installation

```bash
# on your workstation, from the repository root
cp .env.example .env.server         # fill PANEL_HOST, PUBLIC_HOST, SESSION_SECRET, DATA_KEY (commands are in the file)
scp .env.server root@<server>:/opt/trust-panel/.env && ssh root@<server> chmod 600 /opt/trust-panel/.env
./deploy.sh root@<server>           # copies the code, builds the image, runs the tests, starts the panel
ssh root@<server> 'cd /opt/trust-panel && ./init-admin.sh && docker compose up -d caddy && ufw allow 15443/tcp && ufw allow 80/tcp'
```

`init-admin.sh` asks for the administrator password and shows a QR code for the authenticator app. Then open `https://<server-ip>:15443`. Caddy gets a Let's Encrypt certificate for the server IP (the `shortlived` profile, about 6 days) and renews it by itself. It is validated by http-01: Caddy listens on :80 only for those few seconds, so :80 can be shared with another Caddy that does the same (for example AWG Panel). Without port 80, replace the `tls { … }` block in `Caddyfile` with `tls internal`: the certificate then comes from Caddy's local CA and the browser warns once.

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
- The panel certificate is valid for about 6 days and is renewed automatically; port 80/tcp must stay open in the firewall for that.
- Session times are as seen by the poller (every `POLL_INTERVAL` seconds), not exact connect moments.

## Development

```bash
cd panel && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt pytest httpx
.venv/bin/python -m pytest -q
```

Phrases in code and templates are English; translations live in `panel/app/locales/<code>.json` (a test checks that every phrase is translated).
