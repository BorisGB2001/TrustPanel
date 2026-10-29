# Changelog

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
