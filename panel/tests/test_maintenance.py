from app import db, maintenance
from app.config import Settings

DAY = 86400


def test_cleanup_keeps_hourly_traffic(tmp_path):
    s = Settings(data_dir=tmp_path, retention_raw_days=30, retention_min_days=7, retention_events_days=365)
    conn = db.open_db(tmp_path / "p.db")
    now = 1_800_000_000
    conn.execute("INSERT INTO traffic_min VALUES (?, 1, 1, 1)", (now - 8 * DAY,))
    conn.execute("INSERT INTO traffic_hour VALUES (?, 1, 1, 1)", (now - 400 * DAY,))
    conn.execute("INSERT INTO online_min VALUES (?, 3)", (now - 31 * DAY,))
    removed = maintenance.cleanup(conn, s, now)
    assert removed["traffic_min"] == 1 and removed["online_min"] == 1
    assert conn.execute("SELECT COUNT(*) FROM traffic_hour").fetchone()[0] == 1   # часовой трафик — бессрочно


def test_backup_rotation(tmp_path, monkeypatch):
    s = Settings(data_dir=tmp_path)
    conn = db.open_db(tmp_path / "p.db")
    monkeypatch.setattr(maintenance, "KEEP_DB_BACKUPS", 2)
    for i in range(4):
        maintenance.backup_db(conn, s, 1_800_000_000 + i * 120)
    files = sorted((tmp_path / "backups" / "db").glob("*.db"))
    assert len(files) == 2 and oct(files[0].stat().st_mode)[-3:] == "600"
