"""Алерты: события alert_* в журнале, счётчик непрочитанных на главной.

alert_new_country пишет poller в момент смены IP; остальное проверяется здесь раз в 5 минут.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import statistics
import threading
import time

from . import db
from .ttctl import TT
from .config import Settings
from .quotas import Quotas

log = logging.getLogger("alerts")


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


class Alerts:
    def __init__(self, settings: Settings, conn: sqlite3.Connection, tt: TT | None = None):
        self.s, self.conn, self.tt = settings, conn, tt
        self.shared_changes = _env_int("ALERT_SHARED_CHANGES", 6)
        self.shared_window = _env_int("ALERT_SHARED_WINDOW_MIN", 30) * 60
        self.spike_factor = _env_int("ALERT_SPIKE_FACTOR", 5)
        self.spike_min = _env_int("ALERT_SPIKE_MIN_BYTES", 1 << 30)
        self.quotas = Quotas(conn)

    def recent(self, kind: str, peer_id: int | None, within: int, now: int) -> bool:
        return self.conn.execute("SELECT 1 FROM events WHERE kind = ? AND peer_id IS ? AND ts >= ? LIMIT 1",
                                 (kind, peer_id, now - within)).fetchone() is not None

    def emit(self, kind: str, peer_id: int | None, detail: dict, now: int, dedup: int = 3600) -> bool:
        if self.recent(kind, peer_id, dedup, now):
            return False
        db.event(self.conn, kind, peer_id, detail, ts=now)
        return True

    # ---- проверки ----

    def check_shared(self, now: int) -> int:
        """Частые смены IP между разными провайдерами — похоже, один конфиг на нескольких устройствах."""
        n = 0
        rows = self.conn.execute("SELECT peer_id, detail FROM events WHERE kind = 'endpoint_change' AND ts >= ?",
                                 (now - self.shared_window,)).fetchall()
        per: dict[int, list[dict]] = {}
        for r in rows:
            per.setdefault(r["peer_id"], []).append(json.loads(r["detail"] or "{}"))
        for pid, changes in per.items():
            asns = {c.get("asn") or c.get("org") for c in changes} - {None}
            ips = {c.get("to") for c in changes}
            if len(changes) >= self.shared_changes and len(asns) >= 2 and len(ips) >= 2:
                n += self.emit("alert_shared_config", pid, {"changes": len(changes), "ips": sorted(ips)[:6],
                                                            "providers": sorted(map(str, asns))[:4]}, now)
        return n

    def check_spike(self, now: int) -> int:
        """Трафик за прошедший час больше медианы часового трафика за 7 дней в N раз и больше порога."""
        hour = now - now % 3600 - 3600
        n = 0
        for r in self.conn.execute("SELECT peer_id, rx + tx b FROM traffic_hour WHERE ts = ?", (hour,)).fetchall():
            if r["b"] < self.spike_min:
                continue
            hist = [x[0] for x in self.conn.execute(
                "SELECT rx + tx FROM traffic_hour WHERE peer_id = ? AND ts >= ? AND ts < ?", (r["peer_id"], hour - 7 * 86400, hour))]
            med = statistics.median(hist) if len(hist) >= 12 else 0
            if med and r["b"] > self.spike_factor * med:
                n += self.emit("alert_traffic_spike", r["peer_id"], {"bytes": r["b"], "median": int(med), "hour": hour}, now)
        return n

    def check_weekly(self, now: int) -> int:
        """Раз в неделю сводкой: не подключавшиеся (с начала наблюдения) и неактивные больше 30 дней."""
        start = int(db.get_state(self.conn, "observe_start", "0") or 0)
        if not start:
            db.set_state(self.conn, "observe_start", str(now))
            return 0
        last = int(db.get_state(self.conn, "alerts_weekly_ts", "0") or 0)
        if now - start < 7 * 86400 or now - last < 7 * 86400:
            return 0
        db.set_state(self.conn, "alerts_weekly_ts", str(now))
        n = 0
        never = [r["name"] for r in self.conn.execute(
            "SELECT name FROM peers WHERE deleted_at IS NULL AND disabled = 0 AND first_handshake IS NULL AND COALESCE(created_at, 0) < ?",
            (now - 7 * 86400,))]
        if never:
            db.event(self.conn, "alert_never_connected", detail={"count": len(never), "names": never[:30]}, ts=now)
            n += 1
        idle = [r["name"] for r in self.conn.execute(
            "SELECT name FROM peers WHERE deleted_at IS NULL AND disabled = 0 AND last_handshake < ?", (now - 30 * 86400,))]
        if idle:
            db.event(self.conn, "alert_inactive", detail={"count": len(idle), "names": idle[:30]}, ts=now)
            n += 1
        return n

    def check_server(self, now: int) -> int:
        n = 0
        st = os.statvfs(self.s.data_dir)
        used = 1 - st.f_bavail / st.f_blocks if st.f_blocks else 0
        if used > 0.85:
            n += self.emit("alert_server", None, {"reason": "disk", "used": round(used * 100)}, now, dedup=6 * 3600)
        try:   # сеть хоста (network_mode: host): таблица соединений ядра видна напрямую
            cnt, mx = (int(open(f"/proc/sys/net/netfilter/nf_conntrack_{k}").read()) for k in ("count", "max"))
            if mx and cnt / mx > 0.8:
                n += self.emit("alert_server", None, {"reason": "conntrack", "count": cnt, "max": mx}, now, dedup=3600)
        except (OSError, ValueError):
            pass
        return n

    def tick(self, now: int | None = None) -> None:
        now = int(time.time()) if now is None else now
        self.check_shared(now)
        self.check_spike(now)
        if self.tt and self.quotas.manager is None:
            from .manage import Manager      # отключение и включение клиентов по квоте
            self.quotas.manager = Manager(self.s, self.tt, self.conn)
        self.quotas.check(now)
        self.check_weekly(now)
        self.check_server(now)

    def run(self, stop: threading.Event) -> None:
        while not stop.wait(300):
            try:
                self.tick()
            except Exception:  # noqa: BLE001 — поток не должен умирать
                log.exception("alerts")


def new_country(conn: sqlite3.Connection, peer_id: int, ip: str, country: str | None, now: int) -> bool:
    """Вызывается poller'ом при новом IP клиента: страны не было у него за 30 дней (и это не первое подключение).

    Учитываются только адреса с известной страной: без этого переход с CGNAT-адреса (100.64/10, страны нет в базе)
    обратно на домашний давал алерт «новая страна, раньше: —» при каждой смене. Адрес, который уже встречался
    раньше, страну не меняет — его строка в endpoints тоже считается известной.
    """
    if not country:
        return False
    known = {r["country"] for r in conn.execute(
        "SELECT DISTINCT country FROM endpoints WHERE peer_id = ? AND country IS NOT NULL AND last_seen >= ? "
        "AND NOT (ip = ? AND first_seen >= ?)", (peer_id, now - 30 * 86400, ip, now))}
    if not known or country in known:
        return False
    db.event(conn, "alert_new_country", peer_id, {"country": country, "ip": ip, "known": sorted(known)}, ts=now)
    return True
