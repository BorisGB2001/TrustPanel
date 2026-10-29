"""Доступ к панели по IP: проверка адресов, защита от самоблокировки, CLI, страница и промежуточный слой."""
import subprocess
import sys

import pytest

from app import db, ipallow
from tests.test_auth import _csrf, _login, client  # noqa: F401 — фикстура


def test_rules_and_lockout_protection(tmp_path):
    conn = db.open_db(tmp_path / "p.db")
    assert ipallow.allowed(conn, "8.8.8.8")                                 # пусто — всё открыто
    with pytest.raises(ipallow.IPAllowError):
        ipallow.add(conn, "198.51.100.0/24", keep_ip="203.0.113.7")         # отрезал бы себя
    assert ipallow.add(conn, "203.0.113.7/24", keep_ip="203.0.113.7") == "203.0.113.0/24"
    with pytest.raises(ipallow.IPAllowError):
        ipallow.add(conn, "203.0.113.0/24")                                 # уже в списке
    ipallow.add(conn, "2001:db8::/48", "v6")
    assert ipallow.allowed(conn, "203.0.113.200") and ipallow.allowed(conn, "2001:db8::5")
    assert ipallow.allowed(conn, "::ffff:203.0.113.5")                      # IPv4 в IPv6-записи
    assert not ipallow.allowed(conn, "198.51.100.1") and not ipallow.allowed(conn, "testclient")
    with pytest.raises(ipallow.IPAllowError):
        ipallow.remove(conn, "203.0.113.0/24", keep_ip="203.0.113.7")       # удаление отрезало бы себя
    with pytest.raises(ipallow.IPAllowError):
        ipallow.add(conn, "not-an-ip")
    assert ipallow.clear(conn) == 2 and ipallow.allowed(conn, "198.51.100.1")


def test_cli(tmp_path):
    env = {"PANEL_DATA": str(tmp_path), "PATH": "/usr/bin:/bin"}
    run = lambda *a: subprocess.run([sys.executable, "-m", "app.ipallow", *a], capture_output=True, text=True, env=env)  # noqa: E731
    assert "No restriction" in run("list").stdout
    assert "Added: 192.0.2.0/24" in run("add", "192.0.2.0/24", "office").stdout
    assert "192.0.2.0/24" in run("list").stdout and "office" in run("list").stdout
    assert run("add", "bad").returncode != 0
    assert "Removed: 192.0.2.0/24" in run("remove", "1").stdout
    assert "No restriction" in run("list").stdout


def test_middleware_blocks_admin_pages_not_portal(client):
    from app import main
    _login(client)
    conn = main.app.state.db
    ipallow.add(conn, "192.0.2.0/24")                    # адрес теста «testclient» — не IP: доступ закрыт
    for url in ("/", "/login", "/admins", "/peer/1"):
        assert client.get(url).status_code == 403, url
    assert client.get("/me").status_code in (401, 303)   # кабинет клиентов открыт (без сессии — свой ответ)
    assert client.get("/static/app.css").status_code == 200
    ipallow.clear(conn)
    assert client.get("/").status_code == 200


def test_admin_page_manages_list(client):
    from app import main
    _login(client)
    page = client.get("/admins").text
    assert "Access by IP" in page and "no restriction" in page
    r = client.post("/admins/ip/add", data={"csrf": _csrf(page), "cidr": "192.0.2.1", "note": "x"})
    assert "would lose access" in r.text                  # своё «testclient» не покрыть — не даёт закрыться
    assert ipallow.entries(main.app.state.db) == []
