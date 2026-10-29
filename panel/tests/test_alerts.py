import json

from app import db
from app.alerts import Alerts, new_country
from app.config import Settings

NOW = 1_800_000_000


def setup(tmp_path):
    conn = db.open_db(tmp_path / "p.db")
    conn.execute("INSERT INTO peers (id, username, name, created_at) VALUES (1, 'a', 'Анна', 0)")
    return conn, Alerts(Settings(data_dir=tmp_path), conn)


def kinds(conn):
    return [r[0] for r in conn.execute("SELECT kind FROM events ORDER BY id")]


def test_shared_config(tmp_path):
    conn, a = setup(tmp_path)
    for i in range(6):
        db.event(conn, "endpoint_change", 1, {"to": f"1.1.1.{i % 2}", "asn": 100 + i % 2}, ts=NOW - 60 * i)
    assert a.check_shared(NOW) == 1
    assert a.check_shared(NOW + 60) == 0   # не чаще раза в час
    d = json.loads(conn.execute("SELECT detail FROM events WHERE kind='alert_shared_config'").fetchone()[0])
    assert d["changes"] == 6


def test_roaming_same_provider_is_not_shared(tmp_path):
    conn, a = setup(tmp_path)
    for i in range(8):
        db.event(conn, "endpoint_change", 1, {"to": f"1.1.1.{i}", "asn": 100}, ts=NOW - 60 * i)
    assert a.check_shared(NOW) == 0


def test_spike(tmp_path):
    conn, a = setup(tmp_path)
    hour = NOW - NOW % 3600 - 3600
    for h in range(1, 30):
        conn.execute("INSERT INTO traffic_hour VALUES (?, 1, 10000000, 100000000)", (hour - h * 3600,))
    conn.execute("INSERT INTO traffic_hour VALUES (?, 1, 0, ?)", (hour, 3 << 30))
    assert a.check_spike(NOW) == 1
    assert "alert_traffic_spike" in kinds(conn)


def test_new_country(tmp_path):
    conn, _ = setup(tmp_path)
    assert not new_country(conn, 1, "5.5.5.5", "NL", NOW)          # первое подключение — без алерта
    conn.execute("INSERT INTO endpoints (peer_id, ip, first_seen, last_seen, country) VALUES (1, '95.1.1.1', ?, ?, 'RU')", (NOW, NOW))
    assert not new_country(conn, 1, "95.2.2.2", "RU", NOW)
    assert new_country(conn, 1, "5.5.5.5", "NL", NOW)


def test_new_country_ignores_addresses_without_country(tmp_path):
    """Телефон прыгает между домашним RU-адресом и CGNAT 100.80.x.x (страны нет в гео-базе) — это не новая страна."""
    conn, _ = setup(tmp_path)
    ins = "INSERT INTO endpoints (peer_id, ip, first_seen, last_seen, country) VALUES (1, ?, ?, ?, ?)"
    conn.execute(ins, ("100.80.1.1", NOW - 600, NOW - 60, None))
    assert not new_country(conn, 1, "79.1.1.1", "RU", NOW)          # других стран нет — сравнивать не с чем
    conn.execute(ins, ("79.1.1.1", NOW - 3600, NOW, "RU"))
    assert not new_country(conn, 1, "79.1.1.1", "RU", NOW + 300)    # возврат на знакомый адрес
    conn.execute(ins, ("5.5.5.5", NOW + 400, NOW + 400, "NL"))      # строку пишет poller до вызова
    assert new_country(conn, 1, "5.5.5.5", "NL", NOW + 400)
    assert conn.execute("SELECT detail FROM events WHERE kind = 'alert_new_country'").fetchone()[0].count("RU") == 1


def test_weekly_needs_week_of_observation(tmp_path):
    conn, a = setup(tmp_path)
    assert a.check_weekly(NOW) == 0                       # отметка начала наблюдения
    assert a.check_weekly(NOW + 86400) == 0
    assert a.check_weekly(NOW + 8 * 86400) == 1           # Анна ни разу не подключалась
    assert a.check_weekly(NOW + 9 * 86400) == 0           # раз в неделю
