"""Месяц как отчётный период: с 1-го числа 00:00 (TZ) счёт начинается заново, итоги прошлых месяцев — в архив."""
from __future__ import annotations

import datetime
import logging
import sqlite3
import threading
import time
from zoneinfo import ZoneInfo

from . import db

log = logging.getLogger("monthly")


def month_bounds(ym: str, tz: ZoneInfo) -> tuple[int, int]:
    y, m = map(int, ym.split("-"))
    start = datetime.datetime(y, m, 1, tzinfo=tz)
    end = datetime.datetime(y + (m == 12), m % 12 + 1, 1, tzinfo=tz)
    return int(start.timestamp()), int(end.timestamp())


def current_month(now: float, tz: ZoneInfo) -> str:
    return datetime.datetime.fromtimestamp(now, tz).strftime("%Y-%m")


def prev_month(ym: str) -> str:
    y, m = map(int, ym.split("-"))
    return f"{y - (m == 1)}-{(m - 2) % 12 + 1:02d}"


def month_totals(conn: sqlite3.Connection, start: int, end: int) -> list[sqlite3.Row]:
    """Итоги по клиентам за [start, end): трафик из traffic_hour, сессии и время онлайн из sessions."""
    return conn.execute(
        "SELECT p.id peer_id, p.name, p.username, COALESCE(t.rx, 0) rx, COALESCE(t.tx, 0) tx, "
        "COALESCE(s.n, 0) sessions, COALESCE(s.sec, 0) online_sec FROM peers p "
        "LEFT JOIN (SELECT peer_id, SUM(rx) rx, SUM(tx) tx FROM traffic_hour WHERE ts >= ? AND ts < ? GROUP BY peer_id) t ON t.peer_id = p.id "
        "LEFT JOIN (SELECT peer_id, COUNT(*) n, SUM(MIN(COALESCE(end, last_active, start), ?) - MAX(start, ?)) sec FROM sessions "
        "           WHERE start < ? AND COALESCE(end, last_active, start) >= ? GROUP BY peer_id) s ON s.peer_id = p.id "
        "WHERE t.peer_id IS NOT NULL OR s.peer_id IS NOT NULL ORDER BY tx DESC",
        (start, end, end, start, end, start)).fetchall()


def archive(conn: sqlite3.Connection, ym: str, tz: ZoneInfo, now: int | None = None) -> int:
    """Фиксирует итоги месяца (повторный вызов перезаписывает — на случай дозагрузки данных)."""
    start, end = month_bounds(ym, tz)
    rows = month_totals(conn, start, end)
    conn.execute("BEGIN")
    try:
        conn.execute("DELETE FROM monthly_archive WHERE month = ?", (ym,))
        conn.executemany(
            "INSERT INTO monthly_archive (month, peer_id, name, username, rx, tx, sessions, online_sec, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [(ym, r["peer_id"], r["name"], r["username"], r["rx"], r["tx"], r["sessions"], r["online_sec"], now or int(time.time())) for r in rows])
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    return len(rows)


def archive_due(conn: sqlite3.Connection, tz: ZoneInfo, now: float | None = None) -> list[str]:
    """Архивирует все завершённые месяцы, которых ещё нет в архиве (начиная с первых данных)."""
    now = time.time() if now is None else now
    first = conn.execute("SELECT MIN(ts) FROM traffic_hour").fetchone()[0]
    if first is None:
        return []
    done = {r[0] for r in conn.execute("SELECT DISTINCT month FROM monthly_archive")}
    done |= set(filter(None, (db.get_state(conn, "archived_months", "") or "").split(",")))
    cur = current_month(now, tz)
    ym, out = current_month(first, tz), []
    while ym < cur:
        if ym not in done:
            archive(conn, ym, tz, int(now))
            db.event(conn, "month_archived", detail={"month": ym}, ts=int(now))
            out.append(ym)
        y, m = map(int, ym.split("-"))
        ym = f"{y + (m == 12)}-{m % 12 + 1:02d}"
    if out:
        db.set_state(conn, "archived_months", ",".join(sorted(done | set(out))))
    return out


def run(conn: sqlite3.Connection, tz: ZoneInfo, stop: threading.Event) -> None:
    """Проверка раз в минуту: после 00:00 1-го числа прошлый месяц уходит в архив."""
    while not stop.is_set():
        try:
            for ym in archive_due(conn, tz):
                log.info("месяц %s в архиве", ym)
        except Exception:  # noqa: BLE001 — поток не должен умирать
            log.exception("monthly")
        stop.wait(60)
