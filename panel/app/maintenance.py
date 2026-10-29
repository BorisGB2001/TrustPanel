"""Обслуживание БД: удаление старых данных, бэкап, оптимизация."""
from __future__ import annotations

import datetime
import logging
import sqlite3
import threading
import time

from . import db, fmt
from .config import Settings

log = logging.getLogger("maintenance")

KEEP_DB_BACKUPS = 14


def cleanup(conn: sqlite3.Connection, s: Settings, now: int) -> dict[str, int]:
    """Удаляет данные старше сроков хранения; traffic_hour, sessions, endpoints, архив — бессрочно."""
    plan = {
        "traffic_min": ("ts", s.retention_min_days),
        "online_min": ("ts", s.retention_raw_days),
        "events": ("ts", s.retention_events_days),
    }
    out = {}
    for table, (col, days) in plan.items():
        out[table] = conn.execute(f"DELETE FROM {table} WHERE {col} < ?", (now - days * 86400,)).rowcount
    return out


def backup_db(conn: sqlite3.Connection, s: Settings, now: int) -> str:
    d = s.data_dir / "backups" / "db"
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = d / f"panel-{time.strftime('%Y%m%d-%H%M', time.localtime(now))}.db"
    dst = sqlite3.connect(path)
    try:
        conn.backup(dst)
    finally:
        dst.close()
    path.chmod(0o600)
    for old in sorted(d.glob("panel-*.db"))[:-KEEP_DB_BACKUPS]:
        old.unlink(missing_ok=True)
    return path.name


def tick(conn: sqlite3.Connection, s: Settings, now: int | None = None) -> None:
    now = int(time.time()) if now is None else now
    removed = cleanup(conn, s, now)
    if any(removed.values()):
        log.info("очистка: %s", removed)
    local = datetime.datetime.fromtimestamp(now, fmt.TZ)
    day = local.strftime("%Y-%m-%d")
    if local.hour >= 4 and db.get_state(conn, "daily_done") != day:   # ночью, раз в сутки
        name = backup_db(conn, s, now)
        conn.execute("PRAGMA optimize")
        if local.weekday() == 6:
            conn.execute("VACUUM")
        db.set_state(conn, "daily_done", day)
        log.info("бэкап БД %s", name)


def run(conn: sqlite3.Connection, s: Settings, stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            tick(conn, s)
        except Exception:  # noqa: BLE001 — поток не должен умирать
            log.exception("maintenance")
        stop.wait(3600)
