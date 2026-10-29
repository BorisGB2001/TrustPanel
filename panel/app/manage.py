"""Управление клиентами: добавить, удалить, переименовать, отключить, включить, сменить пароль.

Каждая операция, меняющая доступ: блокировка → свежее чтение credentials.toml → бэкап → запись → перезапуск
endpoint'а (credentials.toml он читает только при старте) → проверка, что служба поднялась. Ошибка после бэкапа —
файл возвращается в исходное состояние и endpoint перезапускается ещё раз. Перезапуск на пару секунд обрывает
соединения всех клиентов; приложения TrustTunnel переподключаются сами.
"""
from __future__ import annotations

import os
import re
import secrets
import shutil
import sqlite3
import time
import unicodedata
from pathlib import Path

from cryptography.fernet import Fernet

from . import db
from .config import Settings
from .i18n import t
from .ttctl import TT, USERNAME

KEEP_BACKUPS = 200


class ManageError(RuntimeError):
    """Понятная администратору причина отказа или сбоя."""


def gen_password() -> str:
    return secrets.token_urlsafe(18)


def clean_name(name: str) -> str:
    name = "".join(ch for ch in unicodedata.normalize("NFC", name or "") if unicodedata.category(ch)[0] != "C").strip()
    if not 1 <= len(name) <= 64:
        raise ManageError(t("Client name must be 1 to 64 characters."))
    return name


def suggest_username(name: str, taken: set[str]) -> str:
    """Логин TrustTunnel из имени: латиница, цифры, «._-»; кириллица и пр. — user-N."""
    base = re.sub(r"[^a-z0-9._-]+", "-", name.lower()).strip("-._")[:32]
    base = base if len(base) >= 2 else "user"
    if base not in taken and base != "user":
        return base
    n = 1
    while f"{base}-{n}" in taken:
        n += 1
    return f"{base}-{n}"


def load_fernet(settings: Settings) -> Fernet:
    """Ключ шифрования паролей клиентов: DATA_KEY из .env, иначе файл /data/data.key (создаётся сам)."""
    if settings.data_key:
        return Fernet(settings.data_key.encode())
    path = settings.data_dir / "data.key"
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(Fernet.generate_key())
    return Fernet(path.read_bytes().strip())


class Manager:
    def __init__(self, settings: Settings, tt: TT, conn: sqlite3.Connection, fernet: Fernet | None = None):
        self.s, self.tt, self.conn = settings, tt, conn
        self.fernet = fernet or load_fernet(settings)

    # ---- общий каркас операции ----

    def _apply(self, op: str, build) -> None:
        """build(clients) -> новый список клиентов. Под блокировкой (её берёт вызывающий), с бэкапом и откатом."""
        raw = self.tt.read_credentials_raw()
        backup = self.backup(op, {"credentials.toml": raw})
        new = build(self.tt.read_credentials())
        try:
            self.tt.write_credentials(new)
            self.tt.restart()
            self._verify()
        except Exception as e:
            problems = self._rollback(raw)
            msg = t("The operation failed ({error}); credentials.toml is restored to the state before it, backup: {backup}.",
                    error=e, backup=backup.name)
            if problems:
                msg += " " + t("Warning, the rollback was incomplete: {items}", items="; ".join(problems))
            raise ManageError(msg) from e

    def _verify(self) -> None:
        for _ in range(20):
            if self.tt.service()["state"] == "active":
                try:
                    self.tt.clients()
                    return
                except Exception:  # noqa: BLE001 — метрики поднимаются чуть позже порта
                    pass
            time.sleep(0.5)
        raise ManageError(t("the endpoint did not come back after the restart"))

    def _rollback(self, raw: str) -> list[str]:
        problems = []
        try:
            self.tt.write_credentials_raw(raw)
        except Exception as e:  # noqa: BLE001
            problems.append(f"credentials.toml: {e}")
        try:
            self.tt.restart()
        except Exception as e:  # noqa: BLE001
            problems.append(f"restart: {e}")
        return problems

    def backup(self, op: str, files: dict[str, str]) -> Path:
        root = self.s.data_dir / "backups"
        root.mkdir(parents=True, exist_ok=True)
        os.chmod(root, 0o700)
        d = root / f"{time.strftime('%Y%m%d-%H%M%S')}-{op}"
        n = 1
        while d.exists():
            n += 1
            d = root / f"{time.strftime('%Y%m%d-%H%M%S')}-{op}-{n}"
        d.mkdir(mode=0o700)
        for name, text in files.items():
            fd = os.open(d / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(text)
        for old in sorted(p for p in root.iterdir() if p.is_dir() and p.name[:8].isdigit())[:-KEEP_BACKUPS]:
            shutil.rmtree(old, ignore_errors=True)
        return d

    # ---- проверки ----

    def _peer(self, peer_id: int) -> sqlite3.Row:
        row = self.conn.execute("SELECT * FROM peers WHERE id = ?", (peer_id,)).fetchone()
        if row is None or row["deleted_at"]:
            raise ManageError(t("Client not found."))
        return row

    def _check_unique(self, name: str, skip_id: int | None = None) -> None:
        # lower() в SQLite не знает кириллицу — сравниваем в Python
        rows = self.conn.execute("SELECT id, name FROM peers WHERE deleted_at IS NULL AND id IS NOT ?", (skip_id,))
        if any((r["name"] or "").casefold() == name.casefold() for r in rows):
            raise ManageError(t("A client named “{name}” already exists.", name=name))

    def _taken_usernames(self) -> set[str]:
        taken = {c["username"] for c in self.tt.read_credentials()}
        return taken | {r[0] for r in self.conn.execute("SELECT username FROM peers")}

    def _password(self, row: sqlite3.Row) -> str | None:
        return self.fernet.decrypt(row["password_enc"]).decode() if row["password_enc"] else None

    # ---- операции ----

    def add(self, name: str, note: str = "", username: str = "", actor: str | None = None,
            actor_ip: str | None = None) -> int:
        name = clean_name(name)
        with self.tt.locked():
            self._check_unique(name)
            taken = self._taken_usernames()
            username = (username or "").strip() or suggest_username(name, taken)
            if not USERNAME.match(username):
                raise ManageError(t("Login: 1 to 64 Latin letters, digits and . _ -"))
            if username in taken:
                raise ManageError(t("Login “{name}” is already taken.", name=username))
            password = gen_password()
            self._apply("add", lambda clients: clients + [{"username": username, "password": password}])
            now = int(time.time())
            cur = self.conn.execute(
                "INSERT INTO peers (username, name, note, source, password_enc, created_at) VALUES (?, ?, ?, 'panel', ?, ?)",
                (username, name, (note or "").strip()[:500] or None, self.fernet.encrypt(password.encode()), now))
            db.event(self.conn, "admin_add", cur.lastrowid, {"name": name, "username": username}, actor, actor_ip, now)
            return cur.lastrowid

    def rename(self, peer_id: int, name: str, actor: str | None = None, actor_ip: str | None = None) -> None:
        """Только имя в панели: логин TrustTunnel и конфиг клиента не меняются."""
        name = clean_name(name)
        with self.tt.locked():
            row = self._peer(peer_id)
            if name == row["name"]:
                return
            self._check_unique(name, peer_id)
            self.conn.execute("UPDATE peers SET name = ? WHERE id = ?", (name, peer_id))
            db.event(self.conn, "admin_rename", peer_id, {"from": row["name"], "to": name}, actor, actor_ip)

    def _without(self, username: str):
        def build(clients):
            rest = [c for c in clients if c["username"] != username]
            if len(rest) == len(clients):
                raise ManageError(t("the client is not in credentials.toml"))
            return rest
        return build

    def delete(self, peer_id: int, confirm: str, actor: str | None = None, actor_ip: str | None = None) -> None:
        with self.tt.locked():
            row = self._peer(peer_id)
            if confirm.strip() != row["name"]:
                raise ManageError(t("To delete, type the client name exactly."))
            if not row["disabled"]:
                self._apply("delete", self._without(row["username"]))
            now = int(time.time())
            # логин освобождается: новый клиент с тем же логином — уже другая строка истории
            self.conn.execute("UPDATE peers SET deleted_at = ?, disabled = 0, password_enc = NULL, username = ? WHERE id = ?",
                              (now, f"{row['username']}#deleted-{peer_id}", peer_id))
            self.conn.execute("UPDATE sessions SET end = COALESCE(last_active, start) WHERE peer_id = ? AND end IS NULL", (peer_id,))
            db.event(self.conn, "admin_delete", peer_id, {"name": row["name"], "username": row["username"]}, actor, actor_ip, now)

    def rekey(self, peer_id: int, actor: str | None = None, actor_ip: str | None = None) -> None:
        """Новый пароль с тем же логином: старый конфиг перестаёт работать, новый выдаёт панель."""
        with self.tt.locked():
            row = self._peer(peer_id)
            password = gen_password()
            if not row["disabled"]:
                def build(clients):
                    for c in clients:
                        if c["username"] == row["username"]:
                            c["password"] = password
                            return clients
                    return clients + [{"username": row["username"], "password": password}]

                self._apply("rekey", build)
            self.conn.execute("UPDATE peers SET password_enc = ? WHERE id = ?", (self.fernet.encrypt(password.encode()), peer_id))
            self.conn.execute("UPDATE sessions SET end = COALESCE(last_active, start) WHERE peer_id = ? AND end IS NULL", (peer_id,))
            db.event(self.conn, "admin_rekey", peer_id, {"name": row["name"], "username": row["username"]}, actor, actor_ip)

    def disable(self, peer_id: int, actor: str | None = None, actor_ip: str | None = None) -> None:
        with self.tt.locked():
            row = self._peer(peer_id)
            if row["disabled"]:
                return
            if not row["password_enc"]:
                raise ManageError(t("The panel does not know this client's password, it could not be enabled again."))
            self._apply("disable", self._without(row["username"]))
            self.conn.execute("UPDATE peers SET disabled = 1 WHERE id = ?", (peer_id,))
            self.conn.execute("UPDATE sessions SET end = COALESCE(last_active, start) WHERE peer_id = ? AND end IS NULL", (peer_id,))
            db.event(self.conn, "admin_disable", peer_id, {"name": row["name"], "username": row["username"]}, actor, actor_ip)

    def enable(self, peer_id: int, actor: str | None = None, actor_ip: str | None = None) -> None:
        with self.tt.locked():
            row = self._peer(peer_id)
            if not row["disabled"]:
                return
            password = self._password(row)
            if not password:
                raise ManageError(t("The panel does not know this client's password: issue a new one."))

            def build(clients):
                if any(c["username"] == row["username"] for c in clients):
                    raise ManageError(t("Login “{name}” was added to credentials.toml outside the panel.", name=row["username"]))
                return clients + [{"username": row["username"], "password": password}]

            self._apply("enable", build)
            self.conn.execute("UPDATE peers SET disabled = 0 WHERE id = ?", (peer_id,))
            db.event(self.conn, "admin_enable", peer_id, {"name": row["name"], "username": row["username"]}, actor, actor_ip)

    def password(self, peer_id: int) -> str | None:
        row = self.conn.execute("SELECT password_enc FROM peers WHERE id = ?", (peer_id,)).fetchone()
        return self.fernet.decrypt(row[0]).decode() if row and row[0] else None
