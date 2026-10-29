import importlib
import re

import pyotp
import pytest
from fastapi.testclient import TestClient

from app import auth


def test_password_hash_roundtrip():
    h = auth.hash_password("correct horse battery")
    assert h.startswith("scrypt:") and "$" not in h
    assert auth.verify_password("correct horse battery", h)
    assert not auth.verify_password("wrong", h)
    assert not auth.verify_password("x", "garbage")
    assert auth.verify_password("correct horse battery", h.replace(":", "$"))  # старый формат тоже читается


def test_totp_window_and_replay():
    secret = pyotp.random_base32()
    g = auth.TOTPGuard(secret)
    now = 1_800_000_000
    code = pyotp.TOTP(secret).at(now)
    assert g.verify(code, now)
    assert not g.verify(code, now)  # повтор того же кода
    assert g.verify(pyotp.TOTP(secret).at(now + 30), now + 30)
    assert not g.verify("12345", now)


def test_rate_limiter():
    rl = auth.RateLimiter(per_ip=3, window=60, block=100, global_limit=5, global_window=60)
    for _ in range(3):
        rl.fail("1.1.1.1", now=0)
    assert rl.blocked("1.1.1.1", now=1) == 99
    assert rl.blocked("2.2.2.2", now=1) == 0
    assert not rl.fail("2.2.2.2", now=2)
    assert not rl.fail("3.3.3.3", now=2)
    assert rl.fail("4.4.4.4", now=2)  # 6-я неудача за минуту — глобальный блок
    assert rl.blocked("5.5.5.5", now=3) > 0


@pytest.fixture
def client(tmp_path, monkeypatch):
    secret = pyotp.random_base32()
    monkeypatch.setenv("PANEL_DATA", str(tmp_path))
    monkeypatch.setenv("ADMIN_USER", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", auth.hash_password("s3cret-password"))
    monkeypatch.setenv("TOTP_SECRET", secret)
    monkeypatch.setenv("SESSION_SECRET", "x" * 48)
    monkeypatch.setenv("COOKIE_SECURE", "false")
    monkeypatch.setenv("PANEL_COLLECTORS", "0")
    from app import config, main
    importlib.reload(config)
    importlib.reload(main)
    with TestClient(main.app, base_url="http://panel.test") as c:
        c.totp_secret = secret
        yield c


def _csrf(html: str) -> str:
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def test_login_flow(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert client.get("/api/x").status_code == 401

    page = client.get("/login")
    tok = _csrf(page.text)
    bad = client.post("/login", data={"username": "admin", "password": "nope", "code": "000000", "csrf": tok})
    assert "Wrong username" in bad.text

    code = pyotp.TOTP(client.totp_secret).now()
    ok = client.post("/login", data={"username": "admin", "password": "s3cret-password", "code": code, "csrf": tok},
                     follow_redirects=False)
    assert ok.status_code == 303 and ok.headers["location"] == "/"
    assert "Overview" in client.get("/").text


def test_login_requires_csrf(client):
    client.get("/login")
    r = client.post("/login", data={"username": "admin", "password": "x", "code": "1", "csrf": "forged"})
    assert r.status_code == 403


def test_healthz_local_only(client):
    assert client.get("/healthz").status_code == 404  # TestClient — не localhost


def test_login_with_null_origin(client):
    tok = _csrf(client.get("/login").text)
    code = pyotp.TOTP(client.totp_secret).now()
    r = client.post("/login", data={"username": "admin", "password": "s3cret-password", "code": code, "csrf": tok},
                    headers={"Origin": "null"}, follow_redirects=False)
    assert r.status_code == 303


def test_foreign_origin_rejected(client):
    tok = _csrf(client.get("/login").text)
    r = client.post("/login", data={"username": "admin", "password": "x", "code": "1", "csrf": tok},
                    headers={"Origin": "https://evil.example"})
    assert r.status_code == 403


def test_stage7_pages_render(client):
    tok = _csrf(client.get("/login").text)
    code = pyotp.TOTP(client.totp_secret).now()
    client.post("/login", data={"username": "admin", "password": "s3cret-password", "code": code, "csrf": tok})
    for url in ("/?days=7", "/?days=30", "/events?kind=alert_*", "/alerts", "/server", "/archive", "/groups", "/backups"):
        r = client.get(url)
        assert r.status_code == 200, url
    # фильтр по группе применяется скриптом — он подключён на каждой странице, с версией против старого кэша
    from app import __version__
    for url in ("/", "/events", "/archive", "/groups"):
        assert f'src="/static/app.js?v={__version__}"' in client.get(url).text, url
    assert client.get("/hosts").status_code == 404 and client.get("/blocks").status_code == 404
    page = client.get("/server").text
    assert page.count('aria-current="page"') == 1 and '<a href="/server" class="on"' in page
    csv = client.get("/events.csv")
    assert csv.status_code == 200 and csv.text.startswith("﻿time;")


def test_language_switch(client):
    tok = _csrf(client.get("/login").text)
    assert "Sign in" in client.get("/login").text
    r = client.get("/lang/ru", headers={"referer": "http://panel.test/login"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login" and "lang=ru" in r.headers["set-cookie"]
    assert "Вход" in client.get("/login").text
    client.get("/lang/en")
    assert "Sign in" in client.get("/login").text
    assert client.get("/lang/xx", follow_redirects=False).headers["location"] == "/"


def _login(client):
    tok = _csrf(client.get("/login").text)
    code = pyotp.TOTP(client.totp_secret).now()
    client.post("/login", data={"username": "admin", "password": "s3cret-password", "code": code, "csrf": tok})


def test_every_admin_post_needs_csrf(client):
    """Все POST-действия админа отклоняют запрос без верного CSRF-токена (новый маршрут без проверки уронит тест)."""
    from app import main
    _login(client)
    skip = {"/login", "/me/logout"}   # вход проверяет токен сам; выход из кабинета безопасен и без него
    routes = [r.path for r in main.app.routes if "POST" in getattr(r, "methods", ()) and r.path not in skip]
    assert len(routes) >= 15
    for path in routes:
        url = re.sub(r"\{\w+\}", "1", path)
        r = client.post(url, data={"csrf": "forged", "name": "x", "value": "example.com"}, follow_redirects=False)
        assert r.status_code == 403 or (path.startswith("/me") and r.status_code == 303), (path, r.status_code)


def test_csv_has_no_formulas_and_month_is_checked(client):
    from app import db, main
    _login(client)
    conn = main.app.state.db
    conn.execute("INSERT INTO peers (id, username, name) VALUES (9, 'k9', '=HYPERLINK(\"http://x\")')")
    db.event(conn, "admin_add", 9, {"name": "x"})
    assert "\"'=HYPERLINK" in client.get("/events.csv").text
    assert client.get("/archive/2026-10%22x.csv").status_code == 404


def test_data_files_are_private(client, tmp_path):
    import stat
    assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(f.stat().st_mode) == 0o600 for f in tmp_path.glob("panel.db*"))


def test_redirect_targets_stay_local():
    from app.main import local_path
    assert local_path("/peer/5?days=7")
    for bad in ("//evil.com", "/\\evil.com", "/x\\y", "https://evil.com", "/\r\nSet-Cookie: x", ""):
        assert not local_path(bad), bad
