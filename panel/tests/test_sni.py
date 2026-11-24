"""Маскировка SNI: allowed_sni() из hosts.toml, проброс custom_sni в экспорт, роут /server/tt/sni."""
from app import db, main
from app.config import Settings
from app.ttctl import TT
from tests.conftest import env  # noqa: F401 — фикстура
from tests.test_auth import _csrf, _login, client  # noqa: F401 — фикстура


def test_allowed_sni_reads_hostname_and_list(tmp_path):
    d = tmp_path / "tt"
    d.mkdir()
    (d / "hosts.toml").write_text(
        '[[main_hosts]]\nhostname = "a.example"\nallowed_sni = ["a.example", "metrika.yandex.ru"]\n'
        '[[main_hosts]]\nhostname = "b.example"\nallowed_sni = []\n')
    tt = TT(Settings(tt_dir=str(d)))
    assert tt.allowed_sni() == ["a.example", "metrika.yandex.ru", "b.example"]  # hostname + allowed, без дублей


def test_allowed_sni_empty_when_no_hosts(tmp_path):
    assert TT(Settings(tt_dir=str(tmp_path / "missing"))).allowed_sni() == []


def test_build_config_threads_custom_sni(env):  # noqa: F811
    m, tt, d, conn = env
    pid = conn.execute("SELECT id FROM peers WHERE username = 'boris'").fetchone()[0]
    assert "sni=" not in main.build_config(m, pid)["vpn"]           # по умолчанию без маскировки
    db.set_state(conn, "custom_sni", "metrika.yandex.ru")
    cfg = main.build_config(m, pid)
    assert "&sni=metrika.yandex.ru" in cfg["vpn"]                   # в tt:// уходит фейковый SNI
    assert 'custom_sni = "metrika.yandex.ru"' in cfg["conf"]        # и в toml


def test_sni_route_saves_and_validates(client, monkeypatch):  # noqa: F811
    _login(client)
    monkeypatch.setattr("app.ttctl.TT.allowed_sni", lambda self: ["157-228-183-43.sslip.io", "metrika.yandex.ru"])
    tok = _csrf(client.get("/server").text)

    # не из allowed_sni — отказ, значение не сохраняется
    r = client.post("/server/tt/sni", data={"custom_sni": "evil.example", "csrf": tok}, follow_redirects=True)
    assert "allowed_sni" in r.text
    assert db.get_state(main.app.state.db, "custom_sni") in (None, "")

    # неверный формат — отказ
    client.post("/server/tt/sni", data={"custom_sni": "not a host", "csrf": tok})
    assert db.get_state(main.app.state.db, "custom_sni") in (None, "")

    # допустимое имя — сохраняется (в нижнем регистре)
    client.post("/server/tt/sni", data={"custom_sni": "Metrika.Yandex.RU", "csrf": tok})
    assert db.get_state(main.app.state.db, "custom_sni") == "metrika.yandex.ru"
    assert "metrika.yandex.ru" in client.get("/server").text

    # пустое — очищает
    client.post("/server/tt/sni", data={"custom_sni": "", "csrf": tok})
    assert db.get_state(main.app.state.db, "custom_sni") == ""


def test_sni_route_requires_login(client):  # noqa: F811
    r = client.post("/server/tt/sni", data={"custom_sni": "metrika.yandex.ru", "csrf": "x"}, follow_redirects=False)
    assert r.status_code in (302, 303, 401, 403)               # без входа роут не выполняется
    assert db.get_state(main.app.state.db, "custom_sni") in (None, "")
