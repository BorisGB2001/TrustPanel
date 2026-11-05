# Changelog

## 1.2.1 — 2026-11-05

- Sign-in: a stale login form (opened before a panel restart, signed in in another tab, "back") shows the sign-in page
  again with a hint instead of `{"detail":"CSRF"}`; the TOTP setup page does the same. A foreign Origin is still refused.
  From AWG Panel 1.14.2.

## 1.2.0 — 2026-11-01

- Server page: "Client path to the internet". The server address and the address clients exit from may differ, and
  with split routing there are several exits. The panel runs traceroute from the host network (TrustTunnel's outgoing connections use the host routes) to test
  hosts and to "what is my IP" services (Yandex, ipinfo.io, Cloudflare, ipify), merges the routes into a tree and lists
  the exit addresses with what each service reports. "details" on any address shows DB-IP, ipinfo.io Lite and Yandex
  (IP, ASN, VPN flag) data. Settings: test hosts, address names (`IP = name`) and an optional ipinfo.io API key
  (stored encrypted). The measurement runs on demand and when the page is opened with a result older than 6 hours.
- Monthly archive: years with month tiles › year › month, breadcrumbs "All clients › Archive › year › month" and
  previous/next month links. A month is split into tiles: totals, top 10 and groups side by side (bars at the same
  scale as on the overview), and the client table.
- The image includes `curl`.
- Archive table: the client login instead of an empty IP column.

## 1.1.0 — 2026-11-01

Groups and traffic from AWG Panel 1.9.1–1.13.0.

- Overview: "Traffic today / this month — top 10" ranked by total traffic, stacked bars (downloaded / uploaded); hovering
  a client shows its traffic and chart by hour or by day. The monthly archive uses the same bars.
- Traffic by group today and this month on the overview and the Groups page, with a chart on hover.
- Subgroups: a group can be placed inside another one (any depth). The Groups page shows a tree; clients, online,
  traffic and quotas of a group include its subgroups. The group filter includes subgroups. A group administrator
  sees the subgroups of their groups and can create, rename, move and delete them.
- Groups page: edit and delete icons in each row. Deleting a group asks about its subgroups (move to the parent or
  delete) and its clients (keep them without a group or delete them, typing the group name). Clients deleted with a
  group are removed from `credentials.toml` in one endpoint restart.
- Breadcrumbs with the group path on the client card, the config page and the filtered overview.
- Time zone captions show the panel's offset (for example "panel time (UTC+01:00)"); the default `TZ` is UTC.
- Database schema 2 (`groups.parent_id`), applied automatically.

## 1.0.1 — 2026-10-30

- Daily report image: the left margin follows the widest axis label (labels like "757.3 MiB" were cut off); in the
  connections list the value, the bar and the label are laid out by measured text width (the bar overlapped the value);
  country as a code instead of a flag emoji (the font has no flags); the image height follows the content.
- Caddyfile: `form-action` also allows `https://t.me` — "Connect Telegram" did nothing because the browser blocked the
  redirect to the bot.

## 1.0.0 — 2026-10-30

First release: AWG Panel 1.8.1 ported to TrustTunnel.

- Backend for the TrustTunnel endpoint: clients from `credentials.toml`, online / client IP / traffic from the endpoint
  metrics (`/clients`, `per_client_metrics = true`), service control through `systemctl` in the host namespaces.
- Client management: add (login from the name or set by hand, random password), rename, disable / enable with the same
  password, delete, new password. Every change: backup of `credentials.toml`, endpoint restart, check, rollback on failure.
- Configs exported by the endpoint itself: `tt://` deep link with a QR code and `.toml` for the CLI client; sending by
  Telegram / e-mail and the one-time bot link as before.
- Kept from AWG Panel: overview, client card, sessions and geo, events and alerts, groups and group administrators,
  quotas, monthly archive, client portal, Telegram / e-mail notifications, encrypted backups (`.ttbak`, now with the
  TrustTunnel settings), access by IP, English and Russian, light and dark theme.
- Removed (TrustTunnel does not report them): visited sites, DNS / SNI log, per-site blocking.
- HTTPS on `PANEL_PORT` (default 15443) with Caddy's internal CA: port 80 is not used. Internal port 8081.
