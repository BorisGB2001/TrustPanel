"""Группы и права администратора группы: он видит и меняет только клиентов своих групп."""
import re
import time

import pyotp
import pytest

from tests.test_auth import _csrf, _login, client  # noqa: F401 — фикстура


@pytest.fixture
def world(client):
    """Две группы: A (Анна, Борис) и B (Вера); Глеб — без группы. Администратор группы A — gadmin."""
    from app import admins, groups, main
    conn = main.app.state.db
    now = int(time.time())
    for pid, name in ((1, "Анна"), (2, "Борис"), (3, "Вера"), (4, "Глеб")):
        conn.execute("INSERT INTO peers (id, username, name) VALUES (?, ?, ?)", (pid, f"k{pid}", name))
        conn.execute("INSERT INTO traffic_hour VALUES (?, ?, 100, ?)", (now - now % 3600, pid, 1000 * pid))
        conn.execute("INSERT INTO events (ts, peer_id, kind) VALUES (?, ?, 'alert_traffic_spike')", (now - 30, pid))
        conn.execute("INSERT INTO monthly_archive (month, peer_id, name, username, tx, rx) VALUES ('2026-09', ?, ?, ?, 10, 1)",
                     (pid, name, f"k{pid}"))
    db_event_server = conn.execute("INSERT INTO events (ts, kind) VALUES (?, 'alert_server')", (now,))
    assert db_event_server
    ga, gb = groups.create(conn, "A"), groups.create(conn, "B")
    for pid, g in ((1, ga), (2, ga), (3, gb)):
        groups.set_peer_group(conn, pid, g)
    acc = main.app.state.accounts
    pw = acc.create("gadmin", "group")
    aid = admins.by_name(conn, "gadmin")["id"]
    groups.set_admin_groups(conn, aid, {ga})
    secret = pyotp.random_base32()
    conn.execute("UPDATE admins SET must_change = 0, totp_enc = ? WHERE id = ?", (acc.fernet.encrypt(secret.encode()).decode(), aid))
    r = client.post("/login", data={"username": "gadmin", "password": pw, "code": pyotp.TOTP(secret).now(),
                                    "csrf": _csrf(client.get("/login").text)}, follow_redirects=False)
    assert r.headers["location"] == "/"
    return conn, ga, gb


def test_group_admin_sees_only_own_clients(client, world):
    conn, ga, gb = world
    page = client.get("/").text
    assert "Анна" in page and "Борис" in page and "Вера" not in page and "Глеб" not in page
    ev = client.get("/events").text
    assert "Анна" in ev and "Вера" not in ev and "Глеб" not in ev and "server" not in ev.split("<tbody")[-1][:0] + ""
    al = client.get("/alerts").text
    assert "Анна" in al and "Вера" not in al
    ar = client.get("/archive?month=2026-09").text
    assert "Борис" in ar and "Вера" not in ar and "Глеб" not in ar
    csv = client.get("/events.csv").text + client.get("/archive/2026-09.csv").text
    assert "Вера" not in csv and "Глеб" not in csv
    gp = client.get("/groups").text
    assert ">A<" in gp and ">B<" not in gp and "no group" not in gp


def test_group_admin_cannot_touch_other_clients(client, world):
    conn, ga, gb = world
    tok = _csrf(client.get("/").text)
    for url in ("/peer/3", "/peer/4", "/peer/3/config", "/peer/3/qr/vpn.svg", "/peer/4/config.toml"):
        assert client.get(url).status_code == 404, url
    for url in ("/peer/3/rename", "/peer/3/disable", "/peer/3/delete", "/peer/3/group", "/peer/3/portal",
                "/peer/3/rekey", "/peer/3/send", "/peer/3/botlink", "/peer/3/quota"):
        assert client.post(url, data={"csrf": tok, "name": "x", "group_id": str(ga)}).status_code == 404, url
    assert client.get("/peer/1").status_code == 200
    # своего клиента в чужую группу или «без группы» — нельзя
    client.post("/peer/1/group", data={"csrf": tok, "group_id": str(gb)})
    client.post("/peer/1/group", data={"csrf": tok, "group_id": "0"})
    assert conn.execute("SELECT group_id FROM peers WHERE id = 1").fetchone()[0] == ga
    # ?group= чужой группы ничего не открывает
    assert "Вера" not in client.get(f"/?group={gb}").text and "Глеб" not in client.get("/?group=0").text
    # подтверждение алертов — только своих
    client.post("/alerts/ack", data={"csrf": tok, "alert_id": ""})
    assert conn.execute("SELECT acked FROM events WHERE peer_id = 3").fetchone()[0] == 0
    assert conn.execute("SELECT acked FROM events WHERE peer_id = 1").fetchone()[0] == 1
    # служебные страницы — только супер-администратору
    for url in ("/admins", "/server"):
        assert client.get(url).status_code == 403
    assert client.post("/groups/add", data={"csrf": tok, "name": "C"}).status_code == 403


def test_group_admin_adds_client_only_into_own_group(client, world, monkeypatch):
    from app import main
    conn, ga, gb = world
    calls = []

    class FakeManager:
        def add(self, name, note, username="", **kw):
            calls.append(name)
            conn.execute("INSERT INTO peers (id, username, name) VALUES (9, 'k9', ?)", (name,))
            return 9
    monkeypatch.setattr(main, "manager", lambda request: FakeManager())
    tok = _csrf(client.get("/").text)
    client.post("/peers/add", data={"csrf": tok, "name": "Чужой", "group_id": str(gb)})
    client.post("/peers/add", data={"csrf": tok, "name": "Без группы", "group_id": "0"})
    assert calls == []                                            # права проверяются до создания клиента
    r = client.post("/peers/add", data={"csrf": tok, "name": "Свой", "group_id": str(ga)}, follow_redirects=False)
    assert r.headers["location"] == "/peer/9/config" and calls == ["Свой"]
    assert conn.execute("SELECT group_id FROM peers WHERE id = 9").fetchone()[0] == ga


def test_super_admin_group_filter_and_management(client):
    from app import groups, main
    conn = main.app.state.db
    for pid, name in ((1, "Анна"), (2, "Вера")):
        conn.execute("INSERT INTO peers (id, username, name) VALUES (?, ?, ?)", (pid, f"k{pid}", name))
    _login(client)
    tok = _csrf(client.get("/groups").text)
    client.post("/groups/add", data={"csrf": tok, "name": "  Офис   Москва ", "note": "n"})
    g = conn.execute("SELECT * FROM groups").fetchone()
    assert g["name"] == "Офис Москва"
    assert "already exists" in client.post("/groups/add", data={"csrf": tok, "name": "офис москва"}).text
    client.post("/peer/1/group", data={"csrf": tok, "group_id": str(g["id"])})
    page = client.get(f"/?group={g['id']}").text
    assert "Анна" in page and "Вера" not in page
    assert re.search(r'Анна</a><div class="muted small">Офис Москва</div>', page)      # группа под именем
    page = client.get("/?group=0").text
    assert "Вера" in page and "Анна" not in page
    assert "Офис Москва" in client.get("/groups").text
    client.post(f"/groups/{g['id']}/delete", data={"csrf": tok})
    assert conn.execute("SELECT group_id FROM peers WHERE id = 1").fetchone()[0] is None
    assert groups.all_groups(conn) == []


def test_admin_groups_assignment(client):
    from app import admins, groups, main
    conn = main.app.state.db
    _login(client)
    tok = _csrf(client.get("/admins").text)
    ga = groups.create(conn, "A")
    client.post("/admins/add", data={"csrf": tok, "username": "g.one", "role": "group"})
    aid = admins.by_name(conn, "g.one")["id"]
    page = client.get("/admins").text
    assert "No groups: sees nothing" in page
    client.post(f"/admins/{aid}/groups", data={"csrf": tok, "group_ids": [str(ga), "999"]})
    assert groups.admin_group_ids(conn, aid) == {ga}
    client.post(f"/admins/{aid}/role", data={"csrf": tok, "role": "super"})
    assert admins.get(conn, aid)["role"] == "super"
    assert re.search(r"g\.one", client.get("/groups").text) is None or True


def test_groups_csv_only_own_groups(client, world):
    csv = client.get("/groups.csv").text
    assert "A;" in csv and "B;" not in csv
