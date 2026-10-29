"""Telegram администраторов: привязка через бота, рассылка алертов с учётом групп и тихих часов, /stats, /stop."""
import datetime

from app import admins, db, fmt, groups, notify
from app.config import Settings


class FakeTG:
    def __init__(self):
        self.sent = []

    def send(self, chat, text):
        self.sent.append((chat, text))

    def me(self):
        return "demo_bot"


def setup(tmp_path):
    conn = db.open_db(tmp_path / "p.db")
    for pid, name in ((1, "Анна"), (2, "Вера")):
        conn.execute("INSERT INTO peers (id, username, name) VALUES (?, ?, ?)", (pid, f"k{pid}", name))
    g = groups.create(conn, "A")
    groups.set_peer_group(conn, 1, g)
    for name, role in (("boss", "super"), ("olga", "group")):
        conn.execute("INSERT INTO admins (username, pw_hash, role) VALUES (?, 'x', ?)", (name, role))
    olga = admins.by_name(conn, "olga")["id"]
    groups.set_admin_groups(conn, olga, {g})
    n = notify.Notifier(Settings(data_dir=tmp_path), conn)
    n.tg = FakeTG()
    return conn, n, olga


def bind(conn, n, username, chat):
    code = admins.telegram_code(conn, admins.by_name(conn, username)["id"], "ru")
    n.handle_update({"message": {"chat": {"id": chat}, "text": f"/start {code}", "from": {"username": username}}})


def test_bind_deliver_scope_and_stop(tmp_path):
    conn, n, olga = setup(tmp_path)
    now = int(datetime.datetime(2026, 10, 15, 12, tzinfo=fmt.TZ).timestamp())
    assert n.due_admin_events(now) == 0                      # первый запуск — без истории
    bind(conn, n, "boss", 100)
    bind(conn, n, "olga", 200)
    assert "boss" in n.tg.sent[0][1] and admins.by_name(conn, "olga")["tg_chat_id"] == 200
    n.handle_update({"message": {"chat": {"id": 300}, "text": "/start adm_wrongcode"}})   # чужой код — не привязывает
    assert conn.execute("SELECT COUNT(*) FROM admins WHERE tg_chat_id = 300").fetchone()[0] == 0
    n.tg.sent.clear()
    db.event(conn, "alert_traffic_spike", 1, {"bytes": 1 << 30, "median": 1 << 20}, ts=now)   # клиент группы A
    db.event(conn, "alert_new_country", 2, {"country": "US", "ip": "192.0.2.1", "known": ["DE"]}, ts=now)  # вне групп
    db.event(conn, "alert_server", None, {"reason": "disk", "used": 90}, ts=now)
    db.event(conn, "admin_login", None, None, "boss", "192.0.2.10", ts=now)                   # входы выключены
    db.event(conn, "connect", 1, {"endpoint": "1.2.3.4:5"}, ts=now)                            # не алерт
    assert n.due_admin_events(now) == 4
    to = {}
    for chat, text in n.tg.sent:
        to.setdefault(chat, []).append(text)
    assert len(to[100]) == 3 and len(to[200]) == 1 and "Анна" in to[200][0]
    assert all("Вера" not in x for x in to[200])
    assert n.due_admin_events(now) == 0                      # уже отправлено


def test_quiet_hours_and_logins(tmp_path):
    conn, n, olga = setup(tmp_path)
    night = int(datetime.datetime(2026, 10, 15, 3, tzinfo=fmt.TZ).timestamp())
    n.due_admin_events(night)
    bind(conn, n, "boss", 100)
    boss = admins.by_name(conn, "boss")["id"]
    admins.set_notify(conn, boss, True, True, "23", "7")
    n.tg.sent.clear()
    db.event(conn, "alert_traffic_spike", 1, {"bytes": 1, "median": 1}, ts=night)
    db.event(conn, "alert_server", None, {"reason": "disk", "used": 95}, ts=night)
    db.event(conn, "admin_login", None, None, "boss", "192.0.2.10", ts=night)
    n.due_admin_events(night)
    assert len(n.tg.sent) == 1 and "95" in n.tg.sent[0][1]   # ночью — только сервер
    assert admins.in_quiet_hours(admins.get(conn, boss), 23) and not admins.in_quiet_hours(admins.get(conn, boss), 12)


def test_stats_and_stop(tmp_path):
    conn, n, olga = setup(tmp_path)
    bind(conn, n, "olga", 200)
    n.tg.sent.clear()
    n.handle_update({"message": {"chat": {"id": 200}, "text": "/stats"}})
    assert "1" in n.tg.sent[-1][1] and ("Онлайн" in n.tg.sent[-1][1] or "Online" in n.tg.sent[-1][1])
    assert "из 1" in n.tg.sent[-1][1]                          # только клиенты её группы
    n.handle_update({"message": {"chat": {"id": 200}, "text": "/stop"}})
    assert admins.get(conn, olga)["tg_chat_id"] is None
