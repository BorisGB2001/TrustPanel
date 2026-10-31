"""Группы клиентов и администраторы групп.

Клиент состоит не более чем в одной группе (peers.group_id; NULL — «без группы»: так попадают клиенты, добавленные
в credentials.toml вне панели). Администратор группы видит и меняет только клиентов своих групп; супер-администратор — всех.

Группы вкладываются (groups.parent_id): головная организация → филиалы → отделы. Администратор группы видит и её
подгруппы; трафик, число клиентов и квота группы считаются по всему её поддереву.
"""
from __future__ import annotations

import sqlite3
import time

from . import db
from .i18n import t

NAME_MAX = 64


class GroupError(ValueError):
    pass


def all_groups(conn: sqlite3.Connection) -> list[dict]:
    """Группы деревом: родитель, под ним его подгруппы (по имени). depth — уровень вложенности, label — имя с
    отступом для выпадающих списков, path — «Головная / Филиал», clients — клиенты самой группы (без подгрупп)."""
    rows = [dict(r) for r in conn.execute(
        "SELECT g.*, (SELECT COUNT(*) FROM peers p WHERE p.group_id = g.id AND p.deleted_at IS NULL) AS clients "
        "FROM groups g").fetchall()]
    ids = {r["id"] for r in rows}
    kids: dict[int | None, list[dict]] = {}
    for r in rows:
        kids.setdefault(r["parent_id"] if r["parent_id"] in ids else None, []).append(r)
    out: list[dict] = []

    def walk(parent: int | None, depth: int, path: str) -> None:
        for r in sorted(kids.get(parent, []), key=lambda r: r["name"].casefold()):
            r["depth"], r["path"] = depth, f"{path} / {r['name']}" if path else r["name"]
            r["label"] = "\u00a0\u00a0\u00a0" * depth + r["name"]
            out.append(r)
            walk(r["id"], depth + 1, r["path"])
    walk(None, 0, "")
    return out


def children(conn: sqlite3.Connection) -> dict[int | None, set[int]]:
    out: dict[int | None, set[int]] = {}
    for gid, parent in conn.execute("SELECT id, parent_id FROM groups"):
        out.setdefault(parent, set()).add(gid)
    return out


def subtree(conn: sqlite3.Connection, group_ids) -> set[int]:
    """Группы вместе со всеми их подгруппами."""
    kids, out, todo = children(conn), set(), list(group_ids)
    while todo:
        g = todo.pop()
        if g not in out:
            out.add(g)
            todo.extend(kids.get(g, ()))
    return out


def get(conn: sqlite3.Connection, group_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()


def peers_of(conn: sqlite3.Connection, group_ids) -> set[int]:
    """Клиенты групп (вместе с удалёнными: их история тоже принадлежит группе)."""
    where, args = db.peer_filter(set(group_ids), "group_id")
    return {r[0] for r in conn.execute(f"SELECT id FROM peers WHERE 1{where}", args)}


def peers_without_group(conn: sqlite3.Connection) -> set[int]:
    return {r[0] for r in conn.execute("SELECT id FROM peers WHERE group_id IS NULL")}


def admin_direct_ids(conn: sqlite3.Connection, admin_id: int) -> set[int]:
    """Группы, назначенные администратору на странице «Администраторы»."""
    return {r[0] for r in conn.execute("SELECT group_id FROM admin_groups WHERE admin_id = ?", (admin_id,))}


def admin_group_ids(conn: sqlite3.Connection, admin_id: int) -> set[int]:
    """Группы, которые видит администратор: назначенные и все их подгруппы."""
    return subtree(conn, admin_direct_ids(conn, admin_id))


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


def _check_parent(conn: sqlite3.Connection, group_id: int | None, parent_id: int | None) -> None:
    if parent_id is None:
        return
    _get_or_fail(conn, parent_id)
    if group_id is not None and parent_id in subtree(conn, {group_id}):
        raise GroupError(t("A group cannot be placed inside itself or its own subgroup."))


def create(conn: sqlite3.Connection, name: str, note: str = "", parent_id: int | None = None, actor: str | None = None,
           actor_ip: str | None = None) -> int:
    name = _clean_name(conn, name)
    _check_parent(conn, None, parent_id)
    cur = conn.execute("INSERT INTO groups (name, note, parent_id, created_at) VALUES (?, ?, ?, ?)",
                       (name, note.strip()[:200], parent_id, int(time.time())))
    detail = {"group": name} | ({"parent": get(conn, parent_id)["name"]} if parent_id else {})
    db.event(conn, "group_created", None, detail, actor, actor_ip)
    return cur.lastrowid


def update(conn: sqlite3.Connection, group_id: int, name: str, note: str, parent_id: int | None | bool = False,
           actor: str | None = None, actor_ip: str | None = None) -> None:
    """parent_id: False — родителя не менять, None — сделать группой верхнего уровня."""
    row = _get_or_fail(conn, group_id)
    name = _clean_name(conn, name, group_id)
    parent = row["parent_id"] if parent_id is False else parent_id
    _check_parent(conn, group_id, parent)
    conn.execute("UPDATE groups SET name = ?, note = ?, parent_id = ? WHERE id = ?", (name, note.strip()[:200], parent, group_id))
    if name != row["name"]:
        db.event(conn, "group_renamed", None, {"from": row["name"], "to": name}, actor, actor_ip)
    if parent != row["parent_id"]:
        db.event(conn, "group_moved", None, {"group": name, "parent": get(conn, parent)["name"] if parent else None},
                 actor, actor_ip)


def delete(conn: sqlite3.Connection, group_id: int, with_subgroups: bool = False, actor: str | None = None,
           actor_ip: str | None = None) -> set[int]:
    """Удалить группу; её клиенты остаются «без группы», администраторы теряют к ним доступ. Подгруппы переходят
    к родителю удалённой группы или (with_subgroups) удаляются вместе с ней. Возвращает id удалённых групп."""
    row = _get_or_fail(conn, group_id)
    gone = subtree(conn, {group_id}) if with_subgroups else {group_id}
    if not with_subgroups:
        conn.execute("UPDATE groups SET parent_id = ? WHERE parent_id = ?", (row["parent_id"], group_id))
    subs = sorted(get(conn, g)["name"] for g in gone - {group_id})
    for g in gone:
        conn.execute("UPDATE peers SET group_id = NULL WHERE group_id = ?", (g,))
        conn.execute("DELETE FROM admin_groups WHERE group_id = ?", (g,))
    for g in sorted(gone, key=lambda g: -len(_ancestors(conn, g))):     # сначала самые глубокие
        conn.execute("DELETE FROM groups WHERE id = ?", (g,))
    db.event(conn, "group_deleted", None, {"group": row["name"]} | ({"subgroups": subs} if subs else {}), actor, actor_ip)
    return gone


def chain(conn: sqlite3.Connection, group_id: int | None) -> list[sqlite3.Row]:
    """Группа и её родители — от верхнего уровня к самой группе (для хлебных крошек)."""
    if group_id is None or get(conn, group_id) is None:
        return []
    return [get(conn, g) for g in reversed([group_id, *_ancestors(conn, group_id)])]


def _ancestors(conn: sqlite3.Connection, group_id: int) -> list[int]:
    out, cur = [], conn.execute("SELECT parent_id FROM groups WHERE id = ?", (group_id,)).fetchone()
    while cur and cur[0] is not None and cur[0] not in out:
        out.append(cur[0])
        cur = conn.execute("SELECT parent_id FROM groups WHERE id = ?", (cur[0],)).fetchone()
    return out


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
