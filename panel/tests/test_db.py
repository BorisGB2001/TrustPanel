from app import db


def test_migrate_fresh_and_idempotent(tmp_path):
    conn = db.open_db(tmp_path / "p.db")
    assert db.version(conn) == len(db.MIGRATIONS)
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"peers", "traffic_min", "traffic_hour", "sessions", "endpoints", "events", "state", "online_min",
            "monthly_archive", "contacts", "admins", "groups", "backup_jobs", "ip_allow"} <= tables
    assert not tables & {"flows", "dns", "hosts_day", "block_rules"}
    assert db.migrate(conn) == len(db.MIGRATIONS)


def test_event_and_state(tmp_path):
    conn = db.open_db(tmp_path / "p.db")
    db.event(conn, "admin_login", detail={"ok": "да"}, actor="admin", actor_ip="1.2.3.4")
    row = conn.execute("SELECT kind, detail, actor_ip FROM events").fetchone()
    assert row["kind"] == "admin_login" and "да" in row["detail"] and row["actor_ip"] == "1.2.3.4"
    db.set_state(conn, "k", "1")
    db.set_state(conn, "k", "2")
    assert db.get_state(conn, "k") == "2"
    assert db.get_state(conn, "none", "d") == "d"


def test_wal_mode(tmp_path):
    conn = db.open_db(tmp_path / "p.db")
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
