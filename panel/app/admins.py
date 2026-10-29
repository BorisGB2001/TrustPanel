"""Учётные записи администраторов: супер-администратор и администраторы групп.

Учётка из .env (ADMIN_USER, ADMIN_PASSWORD_HASH, TOTP_SECRET; init-admin.sh) — всегда супер-администратор: её строка
в admins синхронизируется при старте, пароль и TOTP проверяются по .env. Это запасной вход, если в БД что-то сломали.
Остальных заводит супер-администратор: панель выдаёт временный пароль, при первом входе администратор привязывает TOTP
и меняет пароль. Секрет TOTP в БД — под Fernet (тот же ключ, что у приватных ключей клиентов).
"""
from __future__ import annotations

import re
import secrets
import sqlite3
import time

import pyotp
from cryptography.fernet import Fernet

from . import auth, db
from .config import Settings
from .i18n import t

ROLES = ("super", "group")
# роль «администратор группы» включается вместе с ограничением прав по группам : до этого
# такой администратор видел бы всех клиентов
GROUP_ROLE_READY = True


def creatable_roles() -> tuple[str, ...]:
    return ROLES if GROUP_ROLE_READY else ("super",)
NAME_RE = re.compile(r"^[A-Za-z0-9._@-]{3,32}$")
MIN_PASSWORD = 12


class AdminError(ValueError):
    pass


def ensure_env_admin(conn: sqlite3.Connection, s: Settings) -> None:
    """Строка учётки из .env: супер-администратор, пароль и TOTP — из .env (в БД не хранятся)."""
    if not s.admin_user:
        return
    row = conn.execute("SELECT id FROM admins WHERE env = 1").fetchone()
    if row:
        conn.execute("UPDATE admins SET username = ?, role = 'super', disabled = 0 WHERE id = ?", (s.admin_user, row["id"]))
    else:
        conn.execute("DELETE FROM admins WHERE username = ? COLLATE NOCASE AND env = 0", (s.admin_user,))
        conn.execute("INSERT INTO admins (username, pw_hash, role, env, created_at) VALUES (?, '', 'super', 1, ?)",
                     (s.admin_user, int(time.time())))


def get(conn: sqlite3.Connection, admin_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM admins WHERE id = ?", (admin_id,)).fetchone()


def by_name(conn: sqlite3.Connection, username: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM admins WHERE username = ? COLLATE NOCASE", (username.strip(),)).fetchone()


def all_admins(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM admins ORDER BY env DESC, role DESC, username COLLATE NOCASE").fetchall()


def temp_password() -> str:
    return secrets.token_urlsafe(12)


def check_password_rules(password: str) -> None:
    if len(password) < MIN_PASSWORD:
        raise AdminError(t("The password must be at least {n} characters.", n=MIN_PASSWORD))


class Accounts:
    """Проверка входа и управление учётками. env_totp — TOTPGuard учётки из .env (запрет повтора кода в памяти)."""

    def __init__(self, s: Settings, conn: sqlite3.Connection, fernet: Fernet, env_totp: auth.TOTPGuard | None):
        self.s, self.conn, self.fernet, self.env_totp = s, conn, fernet, env_totp

    # ---- вход ----

    def check_password(self, row: sqlite3.Row | None, password: str) -> bool:
        if row is None or row["disabled"]:
            auth.verify_password(password, auth.DUMMY_HASH)   # одинаковое время ответа для несуществующих
            return False
        stored = self.s.admin_password_hash if row["env"] else row["pw_hash"]
        return bool(stored) and auth.verify_password(password, stored)

    def has_totp(self, row: sqlite3.Row) -> bool:
        return bool(self.s.totp_secret) if row["env"] else bool(row["totp_enc"])

    def check_totp(self, row: sqlite3.Row, code: str, now: float | None = None) -> bool:
        if row["env"]:
            return self.env_totp is not None and self.env_totp.verify(code, now)
        if not row["totp_enc"]:
            return False
        secret = self.fernet.decrypt(row["totp_enc"].encode()).decode()
        step = auth.totp_step(secret, code, row["totp_step"], now)
        if step is None:
            return False
        # шаг запоминается в БД: тот же код не пройдёт второй раз и после перезапуска панели
        cur = self.conn.execute("UPDATE admins SET totp_step = ? WHERE id = ? AND totp_step < ?", (step, row["id"], step))
        return cur.rowcount == 1

    def logged_in(self, row: sqlite3.Row, ip: str) -> None:
        self.conn.execute("UPDATE admins SET last_login = ?, last_ip = ? WHERE id = ?", (int(time.time()), ip, row["id"]))

    # ---- привязка TOTP при первом входе ----

    def new_totp_secret(self) -> str:
        return pyotp.random_base32()

    def provisioning_uri(self, username: str, secret: str) -> str:
        return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="TrustPanel")

    def bind_totp(self, row: sqlite3.Row, secret: str, code: str, actor_ip: str | None = None) -> bool:
        step = auth.totp_step(secret, code, -1)
        if step is None:
            return False
        self.conn.execute("UPDATE admins SET totp_enc = ?, totp_step = ? WHERE id = ?",
                          (self.fernet.encrypt(secret.encode()).decode(), step, row["id"]))
        db.event(self.conn, "acct_totp_bound", None, {"username": row["username"]}, row["username"], actor_ip)
        return True

    # ---- управление (супер-администратор) ----

    def create(self, username: str, role: str, note: str = "", actor: str | None = None, actor_ip: str | None = None) -> str:
        """Новая учётка; возвращает временный пароль (показывается один раз)."""
        username = username.strip()
        if not NAME_RE.fullmatch(username):
            raise AdminError(t("Username: 3–32 Latin letters, digits and . _ @ -"))
        if role not in creatable_roles():
            raise AdminError(t("Unknown role."))
        if by_name(self.conn, username):
            raise AdminError(t("An administrator with this name already exists."))
        password = temp_password()
        self.conn.execute(
            "INSERT INTO admins (username, pw_hash, role, must_change, created_at, note) VALUES (?, ?, ?, 1, ?, ?)",
            (username, auth.hash_password(password), role, int(time.time()), note.strip()[:200]))
        db.event(self.conn, "acct_created", None, {"username": username, "role": role}, actor, actor_ip)
        return password

    def _editable(self, admin_id: int) -> sqlite3.Row:
        row = get(self.conn, admin_id)
        if row is None:
            raise AdminError(t("Administrator not found."))
        if row["env"]:
            raise AdminError(t("This account is managed with init-admin.sh on the server."))
        return row

    def _supers_left(self, without: int) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM admins WHERE role = 'super' AND disabled = 0 AND id != ?",
                                 (without,)).fetchone()[0]

    def reset(self, admin_id: int, actor: str | None = None, actor_ip: str | None = None) -> str:
        """Новый временный пароль и повторная привязка TOTP; все сессии администратора закрываются."""
        row = self._editable(admin_id)
        password = temp_password()
        self.conn.execute("UPDATE admins SET pw_hash = ?, totp_enc = NULL, totp_step = -1, must_change = 1, "
                          "session_ver = session_ver + 1 WHERE id = ?", (auth.hash_password(password), admin_id))
        db.event(self.conn, "acct_reset", None, {"username": row["username"]}, actor, actor_ip)
        return password

    def set_disabled(self, admin_id: int, disabled: bool, actor: str | None = None, actor_ip: str | None = None) -> None:
        row = self._editable(admin_id)
        if disabled and row["role"] == "super" and self._supers_left(admin_id) == 0:
            raise AdminError(t("The last active super administrator cannot be disabled."))
        self.conn.execute("UPDATE admins SET disabled = ?, session_ver = session_ver + 1 WHERE id = ?",
                          (int(disabled), admin_id))
        db.event(self.conn, "acct_disabled" if disabled else "acct_enabled", None, {"username": row["username"]},
                 actor, actor_ip)

    def set_role(self, admin_id: int, role: str, actor: str | None = None, actor_ip: str | None = None) -> None:
        row = self._editable(admin_id)
        if role not in creatable_roles():
            raise AdminError(t("Unknown role."))
        if row["role"] == "super" and role != "super" and self._supers_left(admin_id) == 0:
            raise AdminError(t("The last active super administrator cannot be disabled."))
        self.conn.execute("UPDATE admins SET role = ?, session_ver = session_ver + 1 WHERE id = ?", (role, admin_id))
        db.event(self.conn, "acct_role", None, {"username": row["username"], "role": role}, actor, actor_ip)

    def delete(self, admin_id: int, actor: str | None = None, actor_ip: str | None = None) -> None:
        row = self._editable(admin_id)
        if row["role"] == "super" and self._supers_left(admin_id) == 0:
            raise AdminError(t("The last active super administrator cannot be disabled."))
        self.conn.execute("DELETE FROM admins WHERE id = ?", (admin_id,))
        self.conn.execute("DELETE FROM admin_groups WHERE admin_id = ?", (admin_id,))
        db.event(self.conn, "acct_deleted", None, {"username": row["username"]}, actor, actor_ip)

    # ---- своя учётка ----

    def change_password(self, row: sqlite3.Row, current: str, new: str, repeat: str, actor_ip: str | None = None) -> None:
        if row["env"]:
            raise AdminError(t("This account is managed with init-admin.sh on the server."))
        if not self.check_password(row, current):
            raise AdminError(t("The current password is wrong."))
        if new != repeat:
            raise AdminError(t("The new passwords do not match."))
        check_password_rules(new)
        if new == current:
            raise AdminError(t("The new password must differ from the current one."))
        self.conn.execute("UPDATE admins SET pw_hash = ?, must_change = 0 WHERE id = ?", (auth.hash_password(new), row["id"]))
        db.event(self.conn, "acct_password", None, {"username": row["username"]}, row["username"], actor_ip)


# ---- Telegram администратора ----

TG_PREFIX = "adm_"     # коды клиентов без «_»: по префиксу бот отличает привязку администратора
TG_CODE_TTL = 3600


def telegram_code(conn: sqlite3.Connection, admin_id: int, lang: str | None) -> str:
    """Одноразовый код для t.me/<бот>?start=adm_<код> (час); язык сообщений — язык интерфейса в момент привязки."""
    code = secrets.token_hex(12)
    conn.execute("UPDATE admins SET tg_code = ?, tg_code_exp = ?, lang = ? WHERE id = ?",
                 (code, int(time.time()) + TG_CODE_TTL, lang, admin_id))
    return TG_PREFIX + code


def bind_telegram(conn: sqlite3.Connection, start: str, chat_id: int, name: str) -> sqlite3.Row | None:
    if not start.startswith(TG_PREFIX):
        return None
    row = conn.execute("SELECT * FROM admins WHERE tg_code = ? AND tg_code_exp >= ? AND disabled = 0",
                       (start[len(TG_PREFIX):], int(time.time()))).fetchone()
    if not row:
        return None
    conn.execute("UPDATE admins SET tg_chat_id = ?, tg_name = ?, tg_code = NULL WHERE id = ?", (chat_id, name, row["id"]))
    db.event(conn, "acct_telegram", None, {"username": row["username"], "name": name}, row["username"])
    return row


def unbind_telegram(conn: sqlite3.Connection, admin_id: int | None = None, chat_id: int | None = None) -> int:
    if admin_id is not None:
        return conn.execute("UPDATE admins SET tg_chat_id = NULL, tg_name = NULL WHERE id = ?", (admin_id,)).rowcount
    return conn.execute("UPDATE admins SET tg_chat_id = NULL, tg_name = NULL WHERE tg_chat_id = ?", (chat_id,)).rowcount


def set_notify(conn: sqlite3.Connection, admin_id: int, alerts: bool, logins: bool, quiet_from: str, quiet_to: str) -> None:
    qf = int(quiet_from) if quiet_from.isdigit() and int(quiet_from) < 24 else None
    qt = int(quiet_to) if quiet_to.isdigit() and int(quiet_to) < 24 else None
    if qf is None or qt is None or qf == qt:
        qf = qt = None
    conn.execute("UPDATE admins SET notify_alerts = ?, notify_logins = ?, quiet_from = ?, quiet_to = ? WHERE id = ?",
                 (int(alerts), int(logins), qf, qt, admin_id))


def in_quiet_hours(row: sqlite3.Row, hour: int) -> bool:
    qf, qt = row["quiet_from"], row["quiet_to"]
    if qf is None or qt is None:
        return False
    return qf <= hour < qt if qf < qt else (hour >= qf or hour < qt)   # 23–7: через полночь
