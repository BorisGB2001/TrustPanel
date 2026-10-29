"""Квоты трафика: предупреждения 80/100 %, отключение и включение клиентов по периодам."""
import datetime

from app import db, fmt, groups, quotas
from tests.test_auth import client  # noqa: F401 — фикстура
from tests.test_groups import world  # noqa: F401 — фикстура

GIB = quotas.GIB
# 15 октября 2026, 12:00 по времени панели; следующий месяц — 1 ноября
NOW = int(datetime.datetime(2026, 10, 15, 12, tzinfo=fmt.TZ).timestamp())
NEXT_MONTH = int(datetime.datetime(2026, 11, 1, 0, 5, tzinfo=fmt.TZ).timestamp())


class FakeManager:
    def __init__(self, conn):
        self.conn, self.calls = conn, []

    def disable(self, pid, actor=None):
        self.calls.append(("disable", pid))
        self.conn.execute("UPDATE peers SET disabled = 1 WHERE id = ?", (pid,))

    def enable(self, pid, actor=None):
        self.calls.append(("enable", pid))
        self.conn.execute("UPDATE peers SET disabled = 0 WHERE id = ?", (pid,))


def setup(tmp_path):
    conn = db.open_db(tmp_path / "p.db")
    for pid in (1, 2, 3):
        conn.execute("INSERT INTO peers (id, username, name) VALUES (?, ?, ?)", (pid, f"k{pid}", f"c{pid}"))
    g = groups.create(conn, "Офис")
    groups.set_peer_group(conn, 1, g)
    groups.set_peer_group(conn, 2, g)
    m = FakeManager(conn)
    return conn, g, m, quotas.Quotas(conn, m)


def traffic(conn, pid, gib, ts=NOW):
    conn.execute("INSERT INTO traffic_hour VALUES (?, ?, 0, ?) ON CONFLICT(ts, peer_id) DO UPDATE SET tx = tx + excluded.tx",
                 (ts - ts % 3600, pid, int(gib * GIB)))


def alerts(conn):
    return [r[0] for r in conn.execute("SELECT detail FROM events WHERE kind = 'alert_quota' ORDER BY id")]


def test_group_quota_warns_once_and_disables(tmp_path):
    conn, g, m, q = setup(tmp_path)
    quotas.set_group_quota(conn, g, "10", "month", "disable")
    traffic(conn, 1, 5)
    assert q.check(NOW) == 0
    traffic(conn, 2, 3.5)                                  # 8.5 из 10 — 85 %
    assert q.check(NOW) == 1 and q.check(NOW + 300) == 0   # один раз за период
    assert m.calls == []
    traffic(conn, 1, 2)                                    # 10.5 — превышение
    q.check(NOW + 600)
    assert sorted(m.calls) == [("disable", 1), ("disable", 2)]
    assert conn.execute("SELECT COUNT(*) FROM peers WHERE quota_blocked LIKE 'group:%'").fetchone()[0] == 2
    assert conn.execute("SELECT disabled FROM peers WHERE id = 3").fetchone()[0] == 0   # не из группы
    assert '"level": 100' in alerts(conn)[-1]
    q.check(NOW + 900)
    assert len(m.calls) == 2                               # повторно не отключает
    q.check(NEXT_MONTH)                                    # новый месяц — включены обратно
    assert sorted(c for c in m.calls if c[0] == "enable") == [("enable", 1), ("enable", 2)]
    assert conn.execute("SELECT COUNT(*) FROM peers WHERE quota_blocked IS NOT NULL").fetchone()[0] == 0


def test_alert_only_quota_never_disables(tmp_path):
    conn, g, m, q = setup(tmp_path)
    quotas.set_peer_quota(conn, 3, "1", "day", "alert")
    traffic(conn, 3, 2)
    assert q.check(NOW) == 2 and m.calls == []             # 80 % и 100 % сразу, без отключения


def test_manual_enable_and_raised_limit(tmp_path):
    conn, g, m, q = setup(tmp_path)
    quotas.set_peer_quota(conn, 3, "1", "month", "disable")
    traffic(conn, 3, 1.5)
    q.check(NOW)
    assert ("disable", 3) in m.calls
    conn.execute("UPDATE peers SET disabled = 0 WHERE id = 3")      # администратор включил вручную
    q.check(NOW + 300)
    assert m.calls.count(("disable", 3)) == 1                       # в этом периоде больше не трогаем
    # лимит подняли выше расхода — блокировка снимается сразу
    conn.execute("UPDATE peers SET disabled = 1, quota_blocked = ? WHERE id = 3",
                 ("client:3:month:" + quotas.period_bounds("month", NOW)[1],))
    quotas.set_peer_quota(conn, 3, "5", "month", "disable")
    q.check(NOW + 600)
    assert ("enable", 3) in m.calls and conn.execute("SELECT quota_blocked FROM peers WHERE id = 3").fetchone()[0] is None


def test_parse_limit():
    assert quotas.parse_limit("") is None and quotas.parse_limit("0") is None
    assert quotas.parse_limit("0,5") == GIB // 2 and quotas.parse_limit(" 50 ") == 50 * GIB
    for bad in ("abc", "-1"):
        try:
            quotas.parse_limit(bad)
            raise AssertionError(bad)
        except quotas.QuotaError:
            pass


def test_quota_forms_permissions(client, world):
    from app import main
    conn, ga, gb = world
    tok = client.get("/").text.split('name="csrf" value="')[1].split('"')[0]
    client.post("/peer/1/quota", data={"csrf": tok, "gib": "20", "period": "month", "action": "alert"})
    assert conn.execute("SELECT quota_bytes FROM peers WHERE id = 1").fetchone()[0] == 20 * GIB
    assert client.post("/peer/3/quota", data={"csrf": tok, "gib": "1"}).status_code == 404       # чужой клиент
    assert client.post(f"/groups/{ga}/quota", data={"csrf": tok, "gib": "1"}).status_code == 403  # квота группы — супер
    assert "20.0 GiB" in client.get("/peer/1").text
    assert main.app is not None
