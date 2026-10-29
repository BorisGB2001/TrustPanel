import importlib
import re
import time

import pyotp
import pytest
from fastapi.testclient import TestClient

import app
from app import auth, db, notify, portal, report
from app.config import Settings


@pytest.fixture
def app_client(tmp_path, monkeypatch):
    monkeypatch.setenv("PANEL_DATA", str(tmp_path))
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", auth.hash_password("s3cret-password"))
    monkeypatch.setenv("TOTP_SECRET", pyotp.random_base32())
    monkeypatch.setenv("SESSION_SECRET", "x" * 48)
    monkeypatch.setenv("COOKIE_SECURE", "false")
    monkeypatch.setenv("PANEL_COLLECTORS", "0")
    from app import config, main
    importlib.reload(config)
    importlib.reload(main)
    with TestClient(main.app, base_url="http://panel.test") as c:
        conn = main.app.state.db
        conn.execute("INSERT INTO peers (id, username, name) VALUES (5, 'k5', 'Анна')")
        conn.execute("INSERT INTO peers (id, username, name) VALUES (6, 'k6', 'Борис')")
        now = int(time.time())
        conn.execute("INSERT INTO traffic_hour VALUES (?, 5, 1000, 50000)", (now - now % 3600,))
        conn.execute("INSERT INTO endpoints (peer_id, ip, first_seen, last_seen, org) VALUES (5, '95.1.1.1', ?, ?, 'Anna ISP')",
                     (now - 60, now - 60))
        conn.execute("INSERT INTO endpoints (peer_id, ip, first_seen, last_seen, org) VALUES (6, '198.51.100.66', ?, ?, 'secret-of-boris')",
                     (now - 60, now - 60))
        conn.execute("INSERT INTO sessions (peer_id, start, endpoint_ip) VALUES (5, ?, '95.1.1.1')", (now - 60,))
        conn.execute("INSERT INTO sessions (peer_id, start, endpoint_ip) VALUES (6, ?, '198.51.100.66')", (now - 60,))
        yield c, conn


def test_portal_link_login_and_isolation(app_client):
    c, conn = app_client
    assert c.get("/me").status_code == 401
    token = portal.issue_link(conn, 5, "admin", None)
    assert c.get("/me/k/wrong-token-wrong-token-wrong").status_code == 404
    r = c.get(f"/me/k/{token}", follow_redirects=False)
    assert r.status_code == 303 and "ttme" in r.headers["set-cookie"]
    page = c.get("/me")
    assert page.status_code == 200 and "Анна" in page.text and "95.1.1.1" in page.text
    assert "secret-of-boris" not in page.text and "198.51.100.66" not in page.text and "Борис" not in page.text      # только свои данные
    assert c.get("/").status_code in (303, 401) or "/login" in c.get("/", follow_redirects=False).headers.get("location", "")
    assert c.get("/me/stats.png").headers["content-type"] == "image/png"
    assert c.get("/me/config.toml").status_code == 404                           # конфиг не разрешён
    portal.issue_link(conn, 5, "admin", None)                                     # перевыпуск — старая сессия недействительна
    assert c.get("/me").status_code == 401


def test_portal_prefs_need_csrf(app_client):
    c, conn = app_client
    c.get(f"/me/k/{portal.issue_link(conn, 5, None, None)}")
    csrf = re.search(r'name="csrf" value="([^"]+)"', c.get("/me").text).group(1)
    assert c.post("/me/prefs", data={"daily": "1", "hour": "9", "events": "1", "csrf": "bad"}).status_code == 403
    c.post("/me/prefs", data={"daily": "1", "hour": "9", "csrf": csrf})
    row = portal.contact(conn, 5)
    assert (row["daily"], row["daily_hour"], row["events"]) == (1, 9, 0)


def test_email_flow(tmp_path):
    conn = db.open_db(tmp_path / "p.db")
    conn.execute("INSERT INTO peers (id, username, name) VALUES (5, 'k5', 'Анна')")
    with pytest.raises(ValueError):
        portal.set_email(conn, 5, "не почта")
    code = portal.set_email(conn, 5, "anna@example.com")
    assert portal.contact(conn, 5)["email_verified"] == 0
    assert portal.verify_email(conn, code) == 5 and portal.contact(conn, 5)["email_verified"] == 1
    assert portal.verify_email(conn, code) is None


class FakeTG:
    def __init__(self):
        self.sent = []

    def send(self, chat, text):
        self.sent.append(("text", chat, text))

    def send_photo(self, chat, png, caption):
        self.sent.append(("photo", chat, caption, png[:8]))

    def me(self):
        return "awg_test_bot"


def test_telegram_bind_daily_and_events(tmp_path):
    conn = db.open_db(tmp_path / "p.db")
    conn.execute("INSERT INTO peers (id, username, name) VALUES (5, 'k5', 'Анна')")
    n = notify.Notifier(Settings(data_dir=tmp_path), conn)
    n.tg = FakeTG()
    code = portal.telegram_code(conn, 5)
    n.handle_update({"message": {"chat": {"id": 777}, "text": f"/start {code}", "from": {"username": "anna"}}})
    assert portal.contact(conn, 5)["tg_chat_id"] == 777 and "Done" in n.tg.sent[-1][2]
    n.handle_update({"message": {"chat": {"id": 888}, "text": f"/start {code}"}})  # код одноразовый
    assert portal.contact(conn, 5)["tg_chat_id"] == 777
    assert n.daily(5) == 1 and n.tg.sent[-1][0] == "photo" and n.tg.sent[-1][3] == b"\x89PNG\r\n\x1a\n"
    n.due_events()                                     # первый запуск — без истории
    db.event(conn, "alert_new_country", 5, {"country": "NL", "ip": "5.5.5.5", "known": ["RU"]})
    db.event(conn, "connect", 5, {})                   # такое не пересылается
    n.due_events()
    assert sum(1 for x in n.tg.sent if x[0] == "text" and "new country" in x[2]) == 1
    n.handle_update({"message": {"chat": {"id": 777}, "text": "/stop"}})
    assert portal.contact(conn, 5)["tg_chat_id"] is None


def test_daily_due_once(tmp_path):
    conn = db.open_db(tmp_path / "p.db")
    conn.execute("INSERT INTO peers (id, username, name) VALUES (5, 'k5', 'Анна')")
    n = notify.Notifier(Settings(data_dir=tmp_path), conn)
    n.tg = FakeTG()
    portal.contact(conn, 5)
    conn.execute("UPDATE contacts SET tg_chat_id = 1, daily_hour = 21 WHERE peer_id = 5")
    import datetime
    from app import fmt
    t = int(datetime.datetime(2026, 10, 29, 21, 5, tzinfo=fmt.TZ).timestamp())
    n.due_daily(t)
    n.due_daily(t + 600)
    assert len(n.tg.sent) == 1


def test_report_png(tmp_path):
    conn = db.open_db(tmp_path / "p.db")
    conn.execute("INSERT INTO peers (id, username, name) VALUES (5, 'k5', 'Анна')")
    png, caption = report.daily_png(conn, 5, int(time.time()))
    assert png.startswith(b"\x89PNG") and "Анна" in caption


def test_theme_switch_and_back_redirect(app_client):
    c, _ = app_client
    page = c.get("/login").text
    assert 'data-theme' not in page                               # по умолчанию — как в системе
    assert f"v{app.__version__}" in page                          # версия в подвале
    r = c.get("/theme/dark", headers={"referer": "http://panel.test/login"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login" and "theme=dark" in r.headers["set-cookie"]
    page = c.get("/login").text
    assert 'data-theme="dark"' in page and 'href="/theme/dark" class="on"' in page
    r = c.get("/theme/evil", headers={"referer": "https://other.example/x"}, follow_redirects=False)
    assert r.headers["location"] == "/" and "theme=auto" in r.headers["set-cookie"]


def test_portal_theme_switch(app_client):
    """В кабинете клиента тема переключается так же, как в панели, и переключатель один."""
    c, conn = app_client
    c.get(f"/me/k/{portal.issue_link(conn, 5, 'admin', None)}")
    page = c.get("/me").text
    assert 'data-theme' not in page and page.count('href="/theme/dark"') == 1 and page.count('href="/lang/') == len(i18n_codes())
    r = c.get("/theme/dark", headers={"referer": "http://panel.test/me"}, follow_redirects=False)
    assert r.headers["location"] == "/me"
    page = c.get("/me").text
    assert 'data-theme="dark"' in page and 'href="/theme/dark" class="on"' in page


def i18n_codes():
    from app import i18n
    return [code for code, _ in i18n.languages()]


def test_portal_telegram_unlink(app_client):
    c, conn = app_client
    c.get(f"/me/k/{portal.issue_link(conn, 5, 'admin', None)}")
    portal.contact(conn, 5)
    conn.execute("UPDATE contacts SET tg_chat_id = 77, tg_name = '@anna' WHERE peer_id = 5")
    tok = re.search(r'name="csrf" value="([^"]+)"', c.get("/me").text).group(1)
    c.post("/me/telegram/unlink", data={"csrf": "wrong"})
    assert conn.execute("SELECT tg_chat_id FROM contacts WHERE peer_id = 5").fetchone()[0] == 77
    c.post("/me/telegram/unlink", data={"csrf": tok})
    assert conn.execute("SELECT tg_chat_id FROM contacts WHERE peer_id = 5").fetchone()[0] is None


def test_admin_sets_client_contacts(app_client, monkeypatch):
    from app import main
    c, conn = app_client
    sent = []

    class TG:
        def send(self, chat, text):
            if chat == 999:
                raise RuntimeError("Telegram sendMessage: Bad Request: chat not found")
            sent.append(chat)

        def me(self):
            return "demo_bot"
    n = main.notifier(type("R", (), {"app": main.app})())
    n.tg = TG()
    login(c)
    tok = re.search(r'name="csrf" value="([^"]+)"', c.get("/peer/5").text).group(1)
    r = c.post("/peer/5/contacts", data={"csrf": tok, "tg_id": "999", "email": "anna@example.com", "with_email": "1"})
    assert "Start" in r.text and portal.contact(conn, 5)["tg_chat_id"] is None       # бот не может писать — не сохраняем
    c.post("/peer/5/contacts", data={"csrf": tok, "tg_id": "abc", "email": "", "with_email": "1"})
    assert portal.contact(conn, 5)["tg_chat_id"] is None
    c.post("/peer/5/contacts", data={"csrf": tok, "tg_id": "123456789", "email": "anna@example.com", "with_email": "1"})
    ct = portal.contact(conn, 5)
    assert ct["tg_chat_id"] == 123456789 and sent == [123456789] and ct["email"] == "anna@example.com" and ct["email_verified"] == 1
    c.post("/peer/5/contacts", data={"csrf": tok, "tg_id": "123456789"})                # без поля почты — почта та же
    assert portal.contact(conn, 5)["email"] == "anna@example.com" and sent == [123456789]
    c.post("/peer/5/contacts", data={"csrf": tok, "tg_id": "", "email": "", "with_email": "1"})
    ct = portal.contact(conn, 5)
    assert ct["tg_chat_id"] is None and ct["email"] is None


def login(c):
    import os
    tok = re.search(r'name="csrf" value="([^"]+)"', c.get("/login").text).group(1)
    c.post("/login", data={"username": "admin", "password": "s3cret-password",
                           "code": pyotp.TOTP(os.environ["TOTP_SECRET"]).now(), "csrf": tok})
