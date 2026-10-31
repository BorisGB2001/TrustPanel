from zoneinfo import ZoneInfo

from app import db, monthly

TZ = ZoneInfo("UTC")


def test_bounds_and_prev():
    s, e = monthly.month_bounds("2026-10", TZ)
    assert e - s == 31 * 86400
    assert monthly.prev_month("2026-01") == "2025-12" and monthly.prev_month("2026-10") == "2026-09"


def test_archive_due_once_per_month(tmp_path):
    conn = db.open_db(tmp_path / "p.db")
    conn.execute("INSERT INTO peers (id, username, name) VALUES (1, 'a', 'Анна')")
    oct_start, nov_start = monthly.month_bounds("2026-10", TZ)
    conn.execute("INSERT INTO traffic_hour VALUES (?, 1, 100, 1000)", (oct_start + 3600,))
    conn.execute("INSERT INTO traffic_hour VALUES (?, 1, 5, 50)", (nov_start + 3600,))       # ноябрь — уже новый месяц
    conn.execute("INSERT INTO sessions (peer_id, start, end) VALUES (1, ?, ?)", (nov_start - 1800, nov_start + 1800))
    assert monthly.archive_due(conn, TZ, now=nov_start - 60) == []                          # октябрь ещё идёт
    assert monthly.archive_due(conn, TZ, now=nov_start + 60) == ["2026-10"]
    assert monthly.archive_due(conn, TZ, now=nov_start + 120) == []                         # повторно не архивирует
    r = conn.execute("SELECT * FROM monthly_archive").fetchone()
    assert (r["month"], r["tx"], r["rx"], r["sessions"], r["online_sec"]) == ("2026-10", 1000, 100, 1, 1800)
