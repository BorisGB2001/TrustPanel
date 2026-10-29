"""Опрос TrustTunnel раз в POLL_INTERVAL: состав клиентов (credentials.toml), онлайн, трафик, сессии, адреса клиентов."""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from dataclasses import dataclass

from . import db
from .alerts import new_country
from .ttctl import TT, ClientStat, TTUnavailable
from .config import Settings
from .geo import Geo

log = logging.getLogger("poller")


@dataclass
class Status:
    """Последний опрос — для страницы сервера и /healthz."""
    last_ok: float = 0.0
    last_error: str | None = None
    online: int = 0
    peers: int = 0


class Poller:
    def __init__(self, settings: Settings, tt: TT, conn: sqlite3.Connection, geo: Geo | None, fernet=None):
        self.s, self.tt, self.conn, self.geo = settings, tt, conn, geo
        self.fernet = fernet
        self.status = Status()
        self.counters: dict[str, tuple[int, int]] = json.loads(db.get_state(conn, "counters", "{}"))
        self._was_up = True

    # ---- синхронизация состава клиентов ----

    def sync_peers(self, now: int) -> dict[str, int]:
        """Приводит таблицу peers к credentials.toml; возвращает username → peer_id для клиентов из файла.
        Клиенты, добавленные в файл вне панели, импортируются вместе с паролем (он нужен для выдачи конфига)."""
        creds = {c["username"]: c["password"] for c in self.tt.read_credentials()}
        rows = {r["username"]: r for r in self.conn.execute("SELECT id, username, name, deleted_at, disabled, password_enc FROM peers")}
        first_import = not rows
        ids: dict[str, int] = {}
        self.conn.execute("BEGIN")
        try:
            for user, password in creds.items():
                enc = self.fernet.encrypt(password.encode()) if self.fernet else None
                row = rows.get(user)
                if row is None:
                    cur = self.conn.execute(
                        "INSERT INTO peers (username, name, source, password_enc, created_at) VALUES (?, ?, 'endpoint', ?, ?)",
                        (user, user, enc, now))
                    ids[user] = cur.lastrowid
                    if not first_import:
                        db.event(self.conn, "peer_discovered", ids[user], {"name": user, "username": user}, ts=now)
                    continue
                ids[user] = row["id"]
                if row["deleted_at"] or row["disabled"]:
                    self.conn.execute("UPDATE peers SET deleted_at = NULL, disabled = 0 WHERE id = ?", (row["id"],))
                    db.event(self.conn, "peer_discovered", row["id"], {"name": row["name"], "username": user, "returned": True}, ts=now)
                if enc and (not row["password_enc"] or self.fernet.decrypt(row["password_enc"]).decode() != password):
                    self.conn.execute("UPDATE peers SET password_enc = ? WHERE id = ?", (enc, row["id"]))
            for user, row in rows.items():
                if user not in creds and not row["deleted_at"] and not row["disabled"]:
                    self.conn.execute("UPDATE peers SET deleted_at = ? WHERE id = ?", (now, row["id"]))
                    db.event(self.conn, "peer_removed_external", row["id"], {"name": row["name"], "username": user}, ts=now)
            if first_import and creds:
                db.event(self.conn, "peers_imported", detail={"count": len(creds)}, ts=now)
            self.conn.execute("COMMIT")
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        return ids

    # ---- опрос ----

    def tick(self, now: int | None = None) -> None:
        now = int(time.time()) if now is None else now
        self.check_restart(now)
        with self.tt.locked():  # не пересекаться с операциями управления (manage.py)
            ids = self.sync_peers(now)
        stats = {p.username: p for p in self.tt.clients()}
        minute, hour = now - now % 60, now - now % 3600
        open_sessions = {r["peer_id"]: r for r in self.conn.execute(
            "SELECT id, peer_id, start, endpoint_ip, rx, tx, last_active FROM sessions WHERE end IS NULL")}
        peers = {r["id"]: r for r in self.conn.execute("SELECT id, name, last_endpoint, first_handshake FROM peers")}
        online = 0
        self.conn.execute("BEGIN")
        try:
            for key, pid in ids.items():
                p = stats.get(key)
                if p is None:   # метрик клиента нет: ещё не авторизовался после старта endpoint'а
                    if pid in open_sessions:
                        self.close_session(open_sessions[pid], now)
                    continue
                drx, dtx = self.delta(key, p)
                if drx or dtx:
                    for table, ts in (("traffic_min", minute), ("traffic_hour", hour)):
                        self.conn.execute(
                            f"INSERT INTO {table} (ts, peer_id, rx, tx) VALUES (?, ?, ?, ?) "
                            "ON CONFLICT(ts, peer_id) DO UPDATE SET rx = rx + excluded.rx, tx = tx + excluded.tx",
                            (ts, pid, drx, dtx))
                    self.conn.execute("UPDATE peers SET rx_total = rx_total + ?, tx_total = tx_total + ? WHERE id = ?",
                                      (drx, dtx, pid))
                fresh = p.sessions > 0          # открыт хотя бы один туннель (HTTP/2 или QUIC)
                is_online = fresh or bool(drx or dtx)
                online += is_online
                if is_online:
                    self.conn.execute(
                        "UPDATE peers SET last_handshake = ?, first_handshake = COALESCE(first_handshake, ?) WHERE id = ?",
                        (now, now, pid))
                self.track_endpoint(pid, peers[pid], p, now, is_online)
                self.track_session(pid, p, now, is_online, drx, dtx, fresh, open_sessions.get(pid))
            # сессии клиентов, которых больше нет в конфиге
            for pid, sess in open_sessions.items():
                if pid not in ids.values():
                    self.close_session(sess, now)
            self.conn.execute(
                "INSERT INTO online_min (ts, online) VALUES (?, ?) ON CONFLICT(ts) DO UPDATE SET online = MAX(online, excluded.online)",
                (minute, online))
            db.set_state(self.conn, "counters", json.dumps(self.counters))
            self.conn.execute("COMMIT")
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        self.status.online, self.status.peers = online, len(ids)
        self.backfill_geo()

    def backfill_geo(self) -> None:
        """Гео для IP, записанных до загрузки баз DB-IP."""
        if not self.geo or not self.geo.built():
            return
        for r in self.conn.execute("SELECT peer_id, ip FROM endpoints WHERE country IS NULL AND asn IS NULL LIMIT 200").fetchall():
            g = self.geo.lookup(r["ip"])
            if g["country"] or g["asn"]:
                self.conn.execute("UPDATE endpoints SET country = ?, city = ?, asn = ?, org = ? WHERE peer_id = ? AND ip = ?",
                                  (g["country"], g["city"], g["asn"], g["org"], r["peer_id"], r["ip"]))

    def delta(self, key: str, p: ClientStat) -> tuple[int, int]:
        """Прирост счётчиков с прошлого опроса; меньше прошлого — счётчик сброшен (перезапуск endpoint'а)."""
        prev = self.counters.get(key)
        self.counters[key] = (p.rx, p.tx)
        if prev is None:
            return 0, 0  # первый раз видим клиента: точка отсчёта, без накопленного до нас
        drx = p.rx - prev[0] if p.rx >= prev[0] else p.rx
        dtx = p.tx - prev[1] if p.tx >= prev[1] else p.tx
        return drx, dtx

    def track_endpoint(self, pid: int, peer: sqlite3.Row, p: ClientStat, now: int, is_online: bool) -> None:
        ip = p.endpoint_ip
        if not ip:
            return
        changed = ip != peer["last_endpoint"]
        if not changed and not is_online:
            return
        g = self.geo.lookup(ip) if self.geo else {"country": None, "city": None, "asn": None, "org": None}
        self.conn.execute(
            "INSERT INTO endpoints (peer_id, ip, first_seen, last_seen, count, country, city, asn, org) "
            "VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?) ON CONFLICT(peer_id, ip) DO UPDATE SET last_seen = excluded.last_seen, "
            "count = count + ?, country = COALESCE(excluded.country, country), city = COALESCE(excluded.city, city), "
            "asn = COALESCE(excluded.asn, asn), org = COALESCE(excluded.org, org)",
            (pid, ip, now, now, g["country"], g["city"], g["asn"], g["org"], 1 if changed else 0))
        if changed:
            new_country(self.conn, pid, ip, g["country"], now)
            self.conn.execute("UPDATE peers SET last_endpoint = ? WHERE id = ?", (ip, pid))
            if peer["last_endpoint"]:
                db.event(self.conn, "endpoint_change", pid,
                         {"from": peer["last_endpoint"], "to": ip, **g}, ts=now)

    def track_session(self, pid: int, p: ClientStat, now: int, is_online: bool, drx: int, dtx: int, fresh: bool,
                      sess: sqlite3.Row | None) -> None:
        active = now if (fresh or drx or dtx) else 0
        if sess is None:
            if not is_online:
                return
            start = now
            cur = self.conn.execute(
                "INSERT INTO sessions (peer_id, start, endpoint_ip, rx, tx, last_active) VALUES (?, ?, ?, ?, ?, ?)",
                (pid, start, p.endpoint_ip, drx, dtx, active or start))
            g = self.geo.lookup(p.endpoint_ip) if self.geo and p.endpoint_ip else {}
            db.event(self.conn, "connect", pid, {"session": cur.lastrowid, "endpoint": p.endpoint_ip,
                                                 "country": g.get("country"), "org": g.get("org")}, ts=start)
            return
        if is_online:
            self.conn.execute(
                "UPDATE sessions SET rx = rx + ?, tx = tx + ?, last_active = MAX(COALESCE(last_active, start), ?), "
                "endpoint_ip = COALESCE(?, endpoint_ip) WHERE id = ?",
                (drx, dtx, active, p.endpoint_ip, sess["id"]))
        else:
            self.close_session(sess, now)

    def close_session(self, sess: sqlite3.Row, now: int) -> None:
        row = self.conn.execute("SELECT start, rx, tx, last_active FROM sessions WHERE id = ?", (sess["id"],)).fetchone()
        end = min(now, row["last_active"] or row["start"])
        self.conn.execute("UPDATE sessions SET end = ? WHERE id = ?", (end, sess["id"]))
        db.event(self.conn, "disconnect", sess["peer_id"],
                 {"session": sess["id"], "duration": end - row["start"], "rx": row["rx"], "tx": row["tx"]}, ts=end)

    # ---- перезапуск endpoint'а ----

    def check_restart(self, now: int) -> None:
        pid = self.tt.pid()
        prev = db.get_state(self.conn, "tt_pid")
        if prev and int(prev) != pid:
            # перезапуск панелью (manage.py) — не тревога: событие admin_* уже записано
            planned = self.conn.execute("SELECT 1 FROM events WHERE kind LIKE 'admin_%' AND ts >= ? LIMIT 1",
                                        (now - 2 * self.s.poll_interval - 30,)).fetchone()
            if not planned:
                db.event(self.conn, "alert_server", detail={"reason": "tt_restarted", "pid": pid}, ts=now)
        if prev != str(pid):
            db.set_state(self.conn, "tt_pid", str(pid))

    # ---- поток ----

    def run(self, stop: threading.Event) -> None:
        while not stop.is_set():
            t0 = time.time()
            try:
                self.tick()
                if not self._was_up:
                    log.info("TrustTunnel снова доступен")
                self._was_up = True
                self.status.last_ok, self.status.last_error = time.time(), None
            except TTUnavailable as e:
                self.status.last_error = str(e)
                if self._was_up:
                    log.warning("TrustTunnel недоступен: %s", e)
                    db.event(self.conn, "alert_server", detail={"reason": "tt_unavailable", "error": str(e)})
                self._was_up = False
            except Exception as e:  # noqa: BLE001 — поток не должен умирать
                self.status.last_error = repr(e)
                log.exception("poller")
            stop.wait(max(1.0, self.s.poll_interval - (time.time() - t0)))
