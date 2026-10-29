import json

import pytest
from cryptography.fernet import Fernet

from app import db
from app.config import Settings
from app.poller import Poller
from app.ttctl import render_credentials
from tests.conftest import FakeTT, make_tt_dir

T0 = 1_800_000_000


class FakeGeo:
    def built(self):
        return "2026-10-01"

    def lookup(self, ip):
        return {"country": "RU", "city": "Москва", "asn": 8402, "org": "Beeline"} if ip.startswith("95.") \
            else {"country": "NL", "city": None, "asn": 1, "org": "X"}


@pytest.fixture
def penv(tmp_path):
    d = make_tt_dir(tmp_path / "tt")
    s = Settings(data_dir=tmp_path / "data", tt_dir=str(d), online_window=180)
    conn = db.open_db(s.data_dir / "p.db")
    tt = FakeTT(s)
    f = Fernet(Fernet.generate_key())
    return Poller(s, tt, conn, FakeGeo(), f), tt, d, conn, f


def kinds(conn):
    return [r[0] for r in conn.execute("SELECT kind FROM events ORDER BY id")]


def test_first_import_keeps_passwords(penv):
    p, tt, d, conn, f = penv
    tt.set_stat("anna", 1, 1000, 5000, ip="95.24.72.224")
    p.tick(T0)
    rows = {r["username"]: r for r in conn.execute("SELECT * FROM peers")}
    assert set(rows) == {"anna", "boris"} and rows["anna"]["source"] == "endpoint" and rows["anna"]["name"] == "anna"
    assert f.decrypt(rows["boris"]["password_enc"]).decode() == "pw-boris"   # пароль — для выдачи конфига
    assert kinds(conn) == ["peers_imported", "connect"]
    assert conn.execute("SELECT COUNT(*) FROM traffic_min").fetchone()[0] == 0   # первый опрос — точка отсчёта
    assert p.status.online == 1


def test_traffic_deltas_and_counter_reset(penv):
    p, tt, d, conn, f = penv
    tt.set_stat("anna", 1, 1000, 5000)
    p.tick(T0)
    tt.set_stat("anna", 1, 1600, 9000)
    p.tick(T0 + 30)
    tt.set_stat("anna", 1, 100, 200)        # перезапуск endpoint'а: счётчики с нуля
    p.tick(T0 + 60)
    rx, tx = conn.execute("SELECT SUM(rx), SUM(tx) FROM traffic_hour").fetchone()
    assert (rx, tx) == (600 + 100, 4000 + 200)
    assert conn.execute("SELECT rx_total, tx_total FROM peers WHERE username='anna'").fetchone()[:] == (700, 4200)
    assert json.loads(db.get_state(conn, "counters"))["anna"] == [100, 200]


def test_session_open_close(penv):
    p, tt, d, conn, f = penv
    tt.set_stat("anna", 1, 1000, 5000)
    p.tick(T0)
    tt.set_stat("anna", 1, 2000, 6000)
    p.tick(T0 + 30)
    tt.set_stat("anna", 0, 2000, 6000)      # туннель закрыт, трафика нет
    p.tick(T0 + 60)
    s = conn.execute("SELECT start, end, rx, tx FROM sessions").fetchone()
    assert s["start"] == T0 and s["end"] == T0 + 30 and (s["rx"], s["tx"]) == (1000, 1000)
    assert kinds(conn)[-1] == "disconnect"
    tt.set_stat("anna", 2, 2100, 6100)
    p.tick(T0 + 90)
    assert conn.execute("SELECT COUNT(*) FROM sessions WHERE end IS NULL").fetchone()[0] == 1
    assert kinds(conn).count("connect") == 2


def test_session_closes_when_metrics_vanish(penv):
    p, tt, d, conn, f = penv
    tt.set_stat("anna", 1, 10, 10)
    p.tick(T0)
    tt.stats = {}                           # клиента нет в /clients (endpoint перезапущен)
    p.tick(T0 + 30)
    assert conn.execute("SELECT COUNT(*) FROM sessions WHERE end IS NULL").fetchone()[0] == 0


def test_endpoint_change_with_geo(penv):
    p, tt, d, conn, f = penv
    tt.set_stat("anna", 1, 0, 0, ip="95.24.72.224")
    p.tick(T0)
    tt.set_stat("anna", 1, 0, 0, ip="5.6.7.8")
    p.tick(T0 + 30)
    dd = json.loads(conn.execute("SELECT detail FROM events WHERE kind='endpoint_change'").fetchone()[0])
    assert dd["from"] == "95.24.72.224" and dd["to"] == "5.6.7.8" and dd["country"] == "NL"
    eps = {r["ip"]: r for r in conn.execute("SELECT * FROM endpoints")}
    assert eps["95.24.72.224"]["org"] == "Beeline" and eps["5.6.7.8"]["count"] == 1


def test_sync_remove_return_and_password_change(penv):
    p, tt, d, conn, f = penv
    p.tick(T0)
    (d / "credentials.toml").write_text(render_credentials([{"username": "anna", "password": "new"},
                                                            {"username": "vika", "password": "v"}]))
    p.tick(T0 + 30)
    assert sorted(kinds(conn)[1:]) == ["peer_discovered", "peer_removed_external"]
    assert conn.execute("SELECT deleted_at FROM peers WHERE username='boris'").fetchone()[0] == T0 + 30
    enc = conn.execute("SELECT password_enc FROM peers WHERE username='anna'").fetchone()[0]
    assert f.decrypt(enc).decode() == "new"
    (d / "credentials.toml").write_text(render_credentials([{"username": "boris", "password": "pw-boris"}]))
    p.tick(T0 + 60)
    assert conn.execute("SELECT deleted_at FROM peers WHERE username='boris'").fetchone()[0] is None


def test_restart_alert_only_when_unplanned(penv):
    p, tt, d, conn, f = penv
    p.tick(T0)
    tt.svc_pid = 500
    p.tick(T0 + 30)
    assert "alert_server" in kinds(conn)
    db.event(conn, "admin_add", None, {}, ts=T0 + 50)   # перезапуск панелью — без тревоги
    tt.svc_pid = 600
    p.tick(T0 + 60)
    assert kinds(conn).count("alert_server") == 1
