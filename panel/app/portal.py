"""Личный кабинет клиента: вход по личной ссылке, только свои данные, контакты и подписки."""
from __future__ import annotations

import hashlib
import re
import secrets
import sqlite3
import time

from . import db
from .i18n import t

LINK_CODE_TTL = 3600


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def issue_link(conn: sqlite3.Connection, peer_id: int, actor: str | None, actor_ip: str | None) -> str:
    """Новая личная ссылка (старая перестаёт работать). Токен в БД не хранится — только хеш."""
    token = secrets.token_urlsafe(32)
    conn.execute("UPDATE peers SET portal_hash = ? WHERE id = ?", (token_hash(token), peer_id))
    db.event(conn, "portal_link_issued", peer_id, None, actor, actor_ip)
    return token


def revoke_link(conn: sqlite3.Connection, peer_id: int, actor: str | None, actor_ip: str | None) -> None:
    conn.execute("UPDATE peers SET portal_hash = NULL WHERE id = ?", (peer_id,))
    db.event(conn, "portal_link_revoked", peer_id, None, actor, actor_ip)


def peer_by_token(conn: sqlite3.Connection, token: str) -> sqlite3.Row | None:
    if not token or len(token) < 20:
        return None
    return conn.execute("SELECT * FROM peers WHERE portal_hash = ? AND deleted_at IS NULL", (token_hash(token),)).fetchone()


def contact(conn: sqlite3.Connection, peer_id: int) -> sqlite3.Row:
    conn.execute("INSERT OR IGNORE INTO contacts (peer_id) VALUES (?)", (peer_id,))
    return conn.execute("SELECT * FROM contacts WHERE peer_id = ?", (peer_id,)).fetchone()


def telegram_code(conn: sqlite3.Connection, peer_id: int) -> str:
    """Одноразовый код для t.me/<бот>?start=<код> (час)."""
    contact(conn, peer_id)
    code = secrets.token_urlsafe(12).replace("-", "a").replace("_", "b")
    conn.execute("UPDATE contacts SET tg_code = ?, tg_code_exp = ? WHERE peer_id = ?", (code, int(time.time()) + LINK_CODE_TTL, peer_id))
    return code


def bind_telegram(conn: sqlite3.Connection, code: str, chat_id: int, name: str) -> sqlite3.Row | None:
    row = conn.execute("SELECT c.peer_id, p.name FROM contacts c JOIN peers p ON p.id = c.peer_id "
                       "WHERE c.tg_code = ? AND c.tg_code_exp >= ? AND p.deleted_at IS NULL", (code, int(time.time()))).fetchone()
    if not row:
        return None
    conn.execute("UPDATE contacts SET tg_chat_id = ?, tg_name = ?, tg_code = NULL WHERE peer_id = ?", (chat_id, name, row["peer_id"]))
    db.event(conn, "contact_telegram", row["peer_id"], {"name": name})
    return row


def unbind_telegram(conn: sqlite3.Connection, chat_id: int) -> int:
    return conn.execute("UPDATE contacts SET tg_chat_id = NULL, tg_name = NULL WHERE tg_chat_id = ?", (chat_id,)).rowcount


EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


def set_email(conn: sqlite3.Connection, peer_id: int, email: str) -> str | None:
    """Новый адрес требует подтверждения; возвращает код для письма (None — адрес удалён)."""
    contact(conn, peer_id)
    email = (email or "").strip()[:200]
    if not email:
        conn.execute("UPDATE contacts SET email = NULL, email_verified = 0, email_code = NULL WHERE peer_id = ?", (peer_id,))
        return None
    if not EMAIL_RE.fullmatch(email):
        raise ValueError(t("Invalid e-mail."))
    code = secrets.token_urlsafe(24)
    conn.execute("UPDATE contacts SET email = ?, email_verified = 0, email_code = ? WHERE peer_id = ?", (email, code, peer_id))
    return code


def verify_email(conn: sqlite3.Connection, code: str) -> int | None:
    row = conn.execute("SELECT peer_id FROM contacts WHERE email_code = ?", (code,)).fetchone()
    if not row:
        return None
    conn.execute("UPDATE contacts SET email_verified = 1, email_code = NULL WHERE peer_id = ?", (row[0],))
    db.event(conn, "contact_email", row[0], None)
    return row[0]


def set_prefs(conn: sqlite3.Connection, peer_id: int, daily: bool, hour: int, events: bool) -> None:
    contact(conn, peer_id)
    conn.execute("UPDATE contacts SET daily = ?, daily_hour = ?, events = ? WHERE peer_id = ?",
                 (int(daily), max(0, min(23, hour)), int(events), peer_id))


CFG_PREFIX = "cfg_"          # коды привязки из кабинета — без «_», по префиксу бот их различает
CFG_CODE_TTL = 7 * 86400


def config_link_code(conn: sqlite3.Connection, peer_id: int) -> str:
    """Одноразовый код для t.me/<бот>?start=cfg_<код> (7 дней): бот пришлёт клиенту конфиг и подключит уведомления."""
    contact(conn, peer_id)
    code = secrets.token_hex(12)
    conn.execute("UPDATE contacts SET cfg_code = ?, cfg_code_exp = ? WHERE peer_id = ?", (code, int(time.time()) + CFG_CODE_TTL, peer_id))
    return CFG_PREFIX + code


def take_config_code(conn: sqlite3.Connection, start: str, chat_id: int, name: str) -> sqlite3.Row | None:
    """Код из ссылки → клиент; чат привязывается к клиенту, код гасится."""
    if not start.startswith(CFG_PREFIX):
        return None
    row = conn.execute("SELECT c.peer_id, p.name FROM contacts c JOIN peers p ON p.id = c.peer_id WHERE c.cfg_code = ? "
                       "AND c.cfg_code_exp >= ? AND p.deleted_at IS NULL", (start[len(CFG_PREFIX):], int(time.time()))).fetchone()
    if not row:
        return None
    conn.execute("UPDATE contacts SET tg_chat_id = ?, tg_name = ?, cfg_code = NULL WHERE peer_id = ?", (chat_id, name, row["peer_id"]))
    db.event(conn, "contact_telegram", row["peer_id"], {"name": name})
    return row


def set_contacts_by_admin(conn: sqlite3.Connection, peer_id: int, tg_id: int | None, tg_name: str | None,
                          email: str | None, actor: str | None = None, actor_ip: str | None = None) -> None:
    """Контакты клиента, введённые администратором: Telegram ID (уже проверен пробным сообщением) и e-mail
    (адрес от администратора считается подтверждённым). Пустое поле — контакт удаляется."""
    c = contact(conn, peer_id)
    if email is not None:   # None — поля почты в форме не было: адрес не трогаем
        email = email.strip()[:200]
        if email and not EMAIL_RE.fullmatch(email):
            raise ValueError(t("Invalid e-mail."))   # до любых изменений
    conn.execute("UPDATE contacts SET tg_chat_id = ?, tg_name = ? WHERE peer_id = ?", (tg_id, tg_name if tg_id else None, peer_id))
    if email is not None:
        if email != (c["email"] or ""):
            conn.execute("UPDATE contacts SET email = ?, email_verified = ?, email_code = NULL WHERE peer_id = ?",
                         (email or None, int(bool(email)), peer_id))
    db.event(conn, "contacts_set", peer_id, {"telegram": tg_name if tg_id else None,
                                             "email": email if email is not None else c["email"]}, actor, actor_ip)
