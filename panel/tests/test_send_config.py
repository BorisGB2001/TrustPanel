"""Отправка конфига клиенту: Telegram (в привязанный чат и по одноразовой ссылке на бота) и e-mail."""
import time

import pytest

from app import db, notify, portal
from app.config import Settings

CFG = {"name": "Анна", "username": "k5", "conf": 'username = "k5"\n', "vpn": "tt://?AAAA", "disabled": 0}


class FakeTG:
    def __init__(self):
        self.out = []

    def send(self, chat, text):
        self.out.append(("text", chat, text))

    def send_photo(self, chat, png, caption):
        assert png.startswith(b"\x89PNG")
        self.out.append(("photo", chat, caption))

    def send_document(self, chat, name, data, caption=""):
        self.out.append(("doc", chat, name, data))

    def me(self):
        return "demo_bot"


@pytest.fixture
def n(tmp_path, monkeypatch):
    conn = db.open_db(tmp_path / "p.db")
    conn.execute("INSERT INTO peers (id, username, name) VALUES (5, 'k5', 'Анна')")
    s = Settings(data_dir=tmp_path, smtp_host="smtp.example")
    x = notify.Notifier(s, conn)
    x.tg = FakeTG()
    x.config_for = lambda pid: CFG if pid == 5 else None
    mails = []
    monkeypatch.setattr(notify, "send_email", lambda s, to, subj, text, png=None, files=None: mails.append((to, subj, text, files)))
    x.mails = mails
    return x


def test_send_to_bound_telegram(n):
    with pytest.raises(ValueError):
        n.send_config(5, "telegram")                       # чат ещё не привязан
    portal.contact(n.conn, 5)
    n.conn.execute("UPDATE contacts SET tg_chat_id = 42, tg_name = '@anna' WHERE peer_id = 5")
    assert n.send_config(5, "telegram", actor="admin") == "@anna"
    kinds = [o[0] for o in n.tg.out]
    assert kinds == ["doc", "photo", "text"] and n.tg.out[0][3] == CFG["conf"].encode() and n.tg.out[2][2] == "tt://?AAAA"
    assert n.tg.out[0][2].endswith(".toml")
    assert n.conn.execute("SELECT detail FROM events WHERE kind = 'config_sent'").fetchone()[0].count("telegram") == 1


def test_send_by_email(n):
    with pytest.raises(ValueError):
        n.send_config(5, "email", "not-an-email")
    n.send_config(5, "email", "anna@example.com")
    to, subj, text, files = n.mails[0]
    assert to == "anna@example.com" and "tt://?AAAA" in text and [f[0].endswith(".toml") for f in files] == [True, False]
    assert files[1][2:] == ("image", "png")


def test_bot_link_sends_config_once_and_binds(n):
    code = portal.config_link_code(n.conn, 5)
    assert code.startswith("cfg_")
    n.handle_update({"message": {"chat": {"id": 77}, "text": f"/start {code}", "from": {"username": "anna"}}})
    assert [o[0] for o in n.tg.out][:3] == ["doc", "photo", "text"]
    assert portal.contact(n.conn, 5)["tg_chat_id"] == 77                # уведомления тоже подключены
    n.tg.out.clear()
    n.handle_update({"message": {"chat": {"id": 88}, "text": f"/start {code}"}})   # второй раз — не работает
    assert not any(o[0] == "doc" for o in n.tg.out)
    n.conn.execute("UPDATE contacts SET cfg_code = 'x', cfg_code_exp = ? WHERE peer_id = 5", (int(time.time()) - 1,))
    n.handle_update({"message": {"chat": {"id": 88}, "text": "/start cfg_x"}})      # просроченный
    assert portal.contact(n.conn, 5)["tg_chat_id"] == 77


def test_no_private_key(n):
    n.config_for = lambda pid: None
    with pytest.raises(ValueError):
        n.send_config(5, "email", "anna@example.com")
