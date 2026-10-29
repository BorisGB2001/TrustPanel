"""Доступ к панели администратора только с разрешённых IP и подсетей.

Пустой список — ограничения нет. Ограничение действует на всю админскую часть, включая страницу входа; кабинет
клиентов (/me), статика и переключатели языка и темы открыты. Список хранится в БД и меняется в панели
(«Администраторы», супер-администратор) или скриптом на сервере — он работает и тогда, когда доступ из браузера потерян:

    ./ip-allow.sh list
    ./ip-allow.sh add 203.0.113.7 "офис"        # адрес или подсеть: 203.0.113.0/24, 2001:db8::/48
    ./ip-allow.sh remove 203.0.113.7            # или номер из list
    ./ip-allow.sh clear                          # снять ограничение совсем
"""
from __future__ import annotations

import ipaddress
import sqlite3
import sys
import time

from . import db
from .i18n import t

_cache: dict[str, tuple[float, list]] = {}   # файл БД → (время, сети)
TTL = 5   # список, изменённый скриптом в другом процессе, подхватывается за несколько секунд


class IPAllowError(ValueError):
    pass


def normalize(value: str) -> str:
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError:
        raise IPAllowError(t("Not an IP address or subnet: {value}", value=value.strip()[:60])) from None


def entries(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM ip_allow ORDER BY id").fetchall()


def _nets(conn: sqlite3.Connection, fresh: bool = False):
    key = conn.execute("PRAGMA database_list").fetchone()[2]
    now = time.monotonic()
    hit = _cache.get(key)
    if fresh or hit is None or now - hit[0] > TTL:
        hit = _cache[key] = (now, [ipaddress.ip_network(r["cidr"]) for r in conn.execute("SELECT cidr FROM ip_allow")])
    return hit[1]


def covers(nets, ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return any(addr in n for n in nets if n.version == addr.version)


def allowed(conn: sqlite3.Connection, ip: str) -> bool:
    nets = _nets(conn)
    return not nets or covers(nets, ip)


def add(conn: sqlite3.Connection, value: str, note: str = "", actor: str | None = None, actor_ip: str | None = None,
        keep_ip: str | None = None) -> str:
    """Добавить адрес/подсеть. keep_ip — адрес текущего администратора: список не должен его отрезать."""
    cidr = normalize(value)
    nets = [ipaddress.ip_network(r["cidr"]) for r in entries(conn)]
    if keep_ip and not covers(nets + [ipaddress.ip_network(cidr)], keep_ip):
        raise IPAllowError(t("Your current address {ip} would lose access: add it first.", ip=keep_ip))
    try:
        conn.execute("INSERT INTO ip_allow (cidr, note, created_at, actor) VALUES (?, ?, ?, ?)",
                     (cidr, (note or "").strip()[:200] or None, int(time.time()), actor))
    except sqlite3.IntegrityError:
        raise IPAllowError(t("{cidr} is already in the list.", cidr=cidr)) from None
    db.event(conn, "ip_allow_add", None, {"cidr": cidr, "note": note or None}, actor, actor_ip)
    _nets(conn, fresh=True)
    return cidr


def remove(conn: sqlite3.Connection, value: str, actor: str | None = None, actor_ip: str | None = None,
           keep_ip: str | None = None) -> str:
    row = (conn.execute("SELECT * FROM ip_allow WHERE id = ?", (int(value),)).fetchone() if value.strip().isdigit()
           else conn.execute("SELECT * FROM ip_allow WHERE cidr = ?", (normalize(value),)).fetchone())
    if row is None:
        raise IPAllowError(t("{cidr} is not in the list.", cidr=value.strip()[:60]))
    rest = [ipaddress.ip_network(r["cidr"]) for r in entries(conn) if r["id"] != row["id"]]
    if keep_ip and rest and not covers(rest, keep_ip):
        raise IPAllowError(t("Your current address {ip} would lose access.", ip=keep_ip))
    conn.execute("DELETE FROM ip_allow WHERE id = ?", (row["id"],))
    db.event(conn, "ip_allow_remove", None, {"cidr": row["cidr"]}, actor, actor_ip)
    _nets(conn, fresh=True)
    return row["cidr"]


def clear(conn: sqlite3.Connection, actor: str | None = None) -> int:
    n = conn.execute("DELETE FROM ip_allow").rowcount
    db.event(conn, "ip_allow_clear", None, {"count": n}, actor)
    _nets(conn, fresh=True)
    return n


def _cli() -> None:
    from .config import settings
    conn = db.open_db(settings.db_path)
    cmd, args = (sys.argv[1] if len(sys.argv) > 1 else "list"), sys.argv[2:]
    try:
        if cmd == "list":
            rows = entries(conn)
            if not rows:
                print("No restriction: the panel is open from any address.")
            for r in rows:
                print(f"{r['id']:>3}  {r['cidr']:<40} {r['note'] or ''}")
        elif cmd == "add" and args:
            print("Added:", add(conn, args[0], " ".join(args[1:]), actor="cli"))
        elif cmd in ("remove", "rm", "del") and args:
            print("Removed:", remove(conn, args[0], actor="cli"))
        elif cmd == "clear":
            print(f"Removed {clear(conn, actor='cli')} entries: the panel is open from any address.")
        else:
            sys.exit(__doc__)
    except IPAllowError as e:
        sys.exit(f"Error: {e}")


if __name__ == "__main__":
    _cli()
