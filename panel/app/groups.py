"""Группы клиентов и администраторы групп.

Клиент состоит не более чем в одной группе (peers.group_id; NULL — «без группы»: так попадают клиенты, добавленные
в credentials.toml вне панели). Администратор группы видит и меняет только клиентов своих групп; супер-администратор — всех.
"""
from __future__ import annotations

import sqlite3
import time

from . import db
from .i18n import t

NAME_MAX = 64


class GroupError(ValueError):
    pass


def all_groups(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT g.*, (SELECT COUNT(*) FROM peers p WHERE p.group_id = g.id AND p.deleted_at IS NULL) AS clients "
        "FROM groups g ORDER BY g.name COLLATE NOCASE").fetchall()


def get(conn: sqlite3.Connection, group_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()


def peers_of(conn: sqlite3.Connection, group_ids) -> set[int]:
    """Клиенты групп (вместе с удалёнными: их история тоже принадлежит группе)."""
    where, args = db.peer_filter(set(group_ids), "group_id")
    return {r[0] for r in conn.execute(f"SELECT id FROM peers WHERE 1{where}", args)}


def peers_without_group(conn: sqlite3.Connection) -> set[int]:
    return {r[0] for r in conn.execute("SELECT id FROM peers WHERE group_id IS NULL")}


def admin_group_ids(conn: sqlite3.Connection, admin_id: int) -> set[int]:
    return {r[0] for r in conn.execute("SELECT group_id FROM admin_groups WHERE admin_id = ?", (admin_id,))}


def admins_of(conn: sqlite3.Connection) -> dict[int, list[str]]:
    """group_id → логины администраторов группы."""
    out: dict[int, list[str]] = {}
    for r in conn.execute("SELECT ag.group_id, a.username FROM admin_groups ag JOIN admins a ON a.id = ag.admin_id "
                          "ORDER BY a.username COLLATE NOCASE"):
        out.setdefault(r[0], []).append(r[1])
    return out


def _clean_name(conn: sqlite3.Connection, name: str, own_id: int | None = None) -> str:
    name = " ".join(name.split())
    if not name or len(name) > NAME_MAX:
        raise GroupError(t("Group name: 1–{n} characters.", n=NAME_MAX))
    # NOCASE в SQLite не сравнивает кириллицу без учёта регистра — сравнение в Python
    if any(r[1].casefold() == name.casefold() and r[0] != own_id for r in conn.execute("SELECT id, name FROM groups")):
        raise GroupError(t("A group with this name already exists."))
    return name


def create(conn: sqlite3.Connection, name: str, note: str = "", actor: str | None = None, actor_ip: str | None = None) -> int:
    name = _clean_name(conn, name)
    cur = conn.execute("INSERT INTO groups (name, note, created_at) VALUES (?, ?, ?)", (name, note.strip()[:200], int(time.time())))
    db.event(conn, "group_created", None, {"group": name}, actor, actor_ip)
    return cur.lastrowid


def update(conn: sqlite3.Connection, group_id: int, name: str, note: str, actor: str | None = None,
           actor_ip: str | None = None) -> None:
    row = _get_or_fail(conn, group_id)
    name = _clean_name(conn, name, group_id)
    conn.execute("UPDATE groups SET name = ?, note = ? WHERE id = ?", (name, note.strip()[:200], group_id))
    if name != row["name"]:
        db.event(conn, "group_renamed", None, {"from": row["name"], "to": name}, actor, actor_ip)


def delete(conn: sqlite3.Connection, group_id: int, actor: str | None = None, actor_ip: str | None = None) -> None:
    """Удалить группу; её клиенты остаются «без группы», администраторы теряют к ним доступ."""
    row = _get_or_fail(conn, group_id)
    conn.execute("UPDATE peers SET group_id = NULL WHERE group_id = ?", (group_id,))
    conn.execute("DELETE FROM admin_groups WHERE group_id = ?", (group_id,))
    conn.execute("DELETE FROM groups WHERE id = ?", (group_id,))
    db.event(conn, "group_deleted", None, {"group": row["name"]}, actor, actor_ip)


def set_peer_group(conn: sqlite3.Connection, peer_id: int, group_id: int | None, actor: str | None = None,
                   actor_ip: str | None = None) -> None:
    peer = conn.execute("SELECT group_id FROM peers WHERE id = ?", (peer_id,)).fetchone()
    if peer is None:
        raise GroupError(t("Client not found."))
    name = _get_or_fail(conn, group_id)["name"] if group_id is not None else None
    if peer["group_id"] == group_id:
        return
    conn.execute("UPDATE peers SET group_id = ? WHERE id = ?", (group_id, peer_id))
    db.event(conn, "group_member", peer_id, {"group": name}, actor, actor_ip)


def set_admin_groups(conn: sqlite3.Connection, admin_id: int, group_ids: set[int], actor: str | None = None,
                     actor_ip: str | None = None) -> None:
    known = {r[0] for r in conn.execute("SELECT id FROM groups")}
    group_ids = group_ids & known
    conn.execute("DELETE FROM admin_groups WHERE admin_id = ?", (admin_id,))
    conn.executemany("INSERT INTO admin_groups (admin_id, group_id) VALUES (?, ?)", [(admin_id, g) for g in sorted(group_ids)])
    name = conn.execute("SELECT username FROM admins WHERE id = ?", (admin_id,)).fetchone()
    db.event(conn, "acct_groups", None, {"username": name[0] if name else "?",
                                         "groups": [get(conn, g)["name"] for g in sorted(group_ids)]}, actor, actor_ip)


def _get_or_fail(conn: sqlite3.Connection, group_id: int) -> sqlite3.Row:
    row = get(conn, group_id)
    if row is None:
        raise GroupError(t("Group not found."))
    return row
