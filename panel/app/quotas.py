"""Квоты трафика на группы и клиентов.

Квота — лимит трафика (скачано + отдано) за день или календарный месяц (по времени панели, как месячный архив).
На 80 % и 100 % — алерт alert_quota (один раз за период). Действие при превышении: только алерт или отключение
клиента (для квоты группы — всех её клиентов) до начала следующего периода. Отключённый квотой клиент помечается
peers.quota_blocked = «scope:id:period:ключ периода»; с нового периода, если лимит подняли или квоту сняли, он
включается обратно. Включённый администратором вручную в этом периоде квотой больше не отключается.
"""
from __future__ import annotations

import logging
import sqlite3

from . import db, fmt, groups, monthly
from .i18n import t

log = logging.getLogger("quotas")

PERIODS = ("month", "day")
ACTIONS = ("alert", "disable")
GIB = 1 << 30
WARN = 0.8


class QuotaError(ValueError):
    pass


def period_bounds(period: str, now: int) -> tuple[int, str]:
    """(начало периода, ключ периода) — сутки или календарный месяц по часовому поясу панели."""
    if period == "day":
        start = fmt.day_start(now)
        return start, fmt.dt(start, "%Y-%m-%d")
    month = monthly.current_month(now, fmt.TZ)
    return monthly.month_bounds(month, fmt.TZ)[0], month


def usage(conn: sqlite3.Connection, peers, since: int) -> int:
    where, args = db.peer_filter(peers)
    return conn.execute(f"SELECT COALESCE(SUM(rx + tx), 0) FROM traffic_hour WHERE ts >= ?{where}", (since, *args)).fetchone()[0]


def parse_limit(gib: str) -> int | None:
    """Лимит из формы в ГиБ (дробный допускается); пусто или 0 — без квоты."""
    gib = (gib or "").strip().replace(",", ".")
    if not gib:
        return None
    try:
        v = float(gib)
    except ValueError:
        raise QuotaError(t("The limit is a number of GiB, e.g. 50 or 0.5.")) from None
    if v < 0 or v > 1_000_000:
        raise QuotaError(t("The limit is a number of GiB, e.g. 50 or 0.5."))
    return int(v * GIB) or None


def _clean(period: str, action: str) -> tuple[str, str]:
    if period not in PERIODS or action not in ACTIONS:
        raise QuotaError(t("Unknown period or action."))
    return period, action


def set_group_quota(conn: sqlite3.Connection, group_id: int, gib: str, period: str, action: str,
                    actor: str | None = None, actor_ip: str | None = None) -> None:
    limit, (period, action) = parse_limit(gib), _clean(period, action)
    row = conn.execute("SELECT name FROM groups WHERE id = ?", (group_id,)).fetchone()
    if row is None:
        raise QuotaError(t("Group not found."))
    conn.execute("UPDATE groups SET quota_bytes = ?, quota_period = ?, quota_action = ? WHERE id = ?",
                 (limit, period, action, group_id))
    db.event(conn, "quota_set", None, {"group": row["name"], "limit": limit, "period": period, "action": action}, actor, actor_ip)


def set_peer_quota(conn: sqlite3.Connection, peer_id: int, gib: str, period: str, action: str,
                   actor: str | None = None, actor_ip: str | None = None) -> None:
    limit, (period, action) = parse_limit(gib), _clean(period, action)
    conn.execute("UPDATE peers SET quota_bytes = ?, quota_period = ?, quota_action = ? WHERE id = ?",
                 (limit, period, action, peer_id))
    db.event(conn, "quota_set", peer_id, {"limit": limit, "period": period, "action": action}, actor, actor_ip)


def status(conn: sqlite3.Connection, limit: int | None, period: str, peers, now: int) -> dict | None:
    """Использование квоты для показа: used, limit, pct, period."""
    if not limit:
        return None
    since, _ = period_bounds(period, now)
    used = usage(conn, peers, since)
    return {"used": used, "limit": limit, "pct": min(999, round(used * 100 / limit)), "period": period}


def group_peers(conn: sqlite3.Connection, group_id: int) -> set[int]:
    """Клиенты группы вместе с клиентами её подгрупп."""
    return groups.peers_of(conn, groups.subtree(conn, {group_id}))


class Quotas:
    """Проверка квот раз в 5 минут (из потока алертов). manager — для отключения и включения клиентов."""

    def __init__(self, conn: sqlite3.Connection, manager=None):
        self.conn, self.manager = conn, manager

    def check(self, now: int) -> int:
        n = self.release(now)
        for g in self.conn.execute("SELECT * FROM groups WHERE quota_bytes > 0").fetchall():
            peers = group_peers(self.conn, g["id"])
            n += self._one("group", g["id"], g["name"], g["quota_bytes"], g["quota_period"], g["quota_action"],
                           peers, sorted(peers), None, now)
        for p in self.conn.execute("SELECT * FROM peers WHERE quota_bytes > 0 AND deleted_at IS NULL").fetchall():
            n += self._one("client", p["id"], p["name"], p["quota_bytes"], p["quota_period"], p["quota_action"],
                           p["id"], [p["id"]], p["id"], now)
        return n

    def _one(self, scope: str, oid: int, name: str, limit: int, period: str, action: str, peers, targets: list[int],
             event_peer: int | None, now: int) -> int:
        since, key = period_bounds(period, now)
        used = usage(self.conn, peers, since)
        state = f"quota:{scope}:{oid}:{period}:{key}:{limit}"   # лимит подняли — предупредим заново
        n = 0
        for level in (80, 100):
            if used < limit * level / 100 or db.get_state(self.conn, f"{state}:{level}"):
                continue
            db.set_state(self.conn, f"{state}:{level}", str(now))
            detail = {"scope": scope, "name": name, "level": level, "used": used, "limit": limit, "period": period,
                      "action": action if level == 100 else "alert"}
            db.event(self.conn, "alert_quota", event_peer, detail, ts=now)
            n += 1
            if level == 100 and action == "disable":
                self._block(targets, f"{scope}:{oid}:{period}:{key}")
        return n

    def _block(self, peer_ids: list[int], mark: str) -> None:
        for pid in peer_ids:
            row = self.conn.execute("SELECT disabled, deleted_at FROM peers WHERE id = ?", (pid,)).fetchone()
            if row is None or row["disabled"] or row["deleted_at"]:
                continue
            try:
                self.manager.disable(pid, actor="quota")
                self.conn.execute("UPDATE peers SET quota_blocked = ? WHERE id = ?", (mark, pid))
            except Exception:  # noqa: BLE001 — один сбой не должен мешать остальным
                log.exception("quota: disable %s", pid)

    def release(self, now: int) -> int:
        """Снять блокировку квотой: новый период, квоту сняли или подняли выше расхода; включённых вручную — отпустить."""
        n = 0
        for p in self.conn.execute("SELECT id, disabled, quota_blocked FROM peers WHERE quota_blocked IS NOT NULL").fetchall():
            if not p["disabled"]:          # администратор включил вручную — дальше этот период не трогаем
                self.conn.execute("UPDATE peers SET quota_blocked = NULL WHERE id = ?", (p["id"],))
                continue
            if self._still_blocked(p["quota_blocked"], now):
                continue
            try:
                self.manager.enable(p["id"], actor="quota")
                self.conn.execute("UPDATE peers SET quota_blocked = NULL WHERE id = ?", (p["id"],))
                n += 1
            except Exception:  # noqa: BLE001
                log.exception("quota: enable %s", p["id"])
        return n

    def _still_blocked(self, mark: str, now: int) -> bool:
        try:
            scope, oid, period, key = mark.split(":", 3)
            oid = int(oid)
        except ValueError:
            return False
        if period_bounds(period, now)[1] != key:
            return False                   # начался новый период
        if scope == "group":
            row = self.conn.execute("SELECT quota_bytes, quota_period FROM groups WHERE id = ?", (oid,)).fetchone()
            peers = group_peers(self.conn, oid)
        else:
            row = self.conn.execute("SELECT quota_bytes, quota_period FROM peers WHERE id = ?", (oid,)).fetchone()
            peers = oid
        if row is None or not row["quota_bytes"] or row["quota_period"] != period:
            return False
        return usage(self.conn, peers, period_bounds(period, now)[0]) >= row["quota_bytes"]
