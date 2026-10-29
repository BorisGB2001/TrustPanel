"""Бэкапы в Telegram и на e-mail.

Супер-администратор получает бэкап всего портала: снимок БД панели, data.key (ключ шифрования паролей клиентов)
и настройки TrustTunnel (credentials.toml, vpn.toml, hosts.toml, rules.toml, certs/) — из него восстанавливаются
и панель, и VPN. Администратор группы — бэкап своих групп: список клиентов (CSV) и их конфиги (.toml и tt://).

Полный бэкап портала содержит ещё и .env панели (пароль и TOTP администратора, ключи, токен бота, почта): по нему
поднимается новый сервер — см. restore.sh и README, раздел «Восстановление из бэкапа».

Архив всегда зашифрован паролем, который задаёт администратор (AES-256-GCM, ключ из пароля через scrypt): в нём
пароли клиентов, а Telegram и почта — чужие серверы. Расшифровать:

    docker compose exec panel python -m app.backup decrypt /data/<файл>.ttbak      # спросит пароль
    python3 -m app.backup decrypt tt-backup.ttbak -o tt-backup.tar.gz               # то же на любом компьютере с пакетами панели
    python -m app.backup restore <файл> [--env /srv/host.env] [--host <новый IP>]  # восстановление (панель остановлена)
"""
from __future__ import annotations

import csv
import datetime
import getpass
import hashlib
import io
import logging
import os
import sqlite3
import sys
import tarfile
import tempfile
import threading
import time
import zipfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import db, fmt, groups
from .i18n import t

log = logging.getLogger("backup")

MAGIC = b"TTPBAK1\n"
ENV_FILE = os.environ.get("PANEL_ENV_FILE", "/srv/host.env")   # .env панели, смонтирован только для чтения
SQLITE_HEADER = b"SQLite format 3\x00"
MIN_PASSWORD = 8
PERIODS = ("daily", "weekly")
LIMIT = 45 << 20            # Telegram принимает документы до 50 МБ


class BackupError(ValueError):
    pass


# ---- шифрование ----

def _key(passphrase: str, salt: bytes) -> bytes:
    return hashlib.scrypt(passphrase.encode(), salt=salt, n=2**15, r=8, p=1, maxmem=64 * 1024 * 1024, dklen=32)


def encrypt(data: bytes, passphrase: str) -> bytes:
    salt, nonce = os.urandom(16), os.urandom(12)
    return MAGIC + salt + nonce + AESGCM(_key(passphrase, salt)).encrypt(nonce, data, MAGIC)


def decrypt(blob: bytes, passphrase: str) -> bytes:
    if not blob.startswith(MAGIC):
        raise BackupError(t("This is not a TrustPanel backup."))
    salt, nonce, body = blob[len(MAGIC):len(MAGIC) + 16], blob[len(MAGIC) + 16:len(MAGIC) + 28], blob[len(MAGIC) + 28:]
    try:
        return AESGCM(_key(passphrase, salt)).decrypt(nonce, body, MAGIC)
    except Exception as e:  # cryptography.exceptions.InvalidTag
        raise BackupError(t("Wrong password or the file is damaged.")) from e


# ---- архивы ----

RESTORE_TXT = """TrustPanel backup — {when}
Restore: README, section "Restore from a backup" (restore.sh on a new server, Backups page on the same one).

panel.env         /opt/trust-panel/.env (admin password and TOTP, keys, bot token, mail)
panel.db          panel database (stop the panel, put it into /opt/trust-panel/data/, delete panel.db-wal/-shm)
data.key          key that encrypts client passwords in panel.db (put next to panel.db; DATA_KEY in .env instead, if set)
trusttunnel/      TrustTunnel endpoint settings from /opt/trusttunnel (credentials, vpn, hosts, rules, certs/)
                  (copy back, then: systemctl restart trusttunnel)
"""

TT_FILES = ("credentials.toml", "vpn.toml", "hosts.toml", "rules.toml")


def tt_files(folder) -> dict[str, bytes]:
    """Настройки endpoint'а без бинарников: *.toml из списка и сертификаты certs/."""
    from pathlib import Path
    folder = Path(folder)
    out = {n: (folder / n).read_bytes() for n in TT_FILES if (folder / n).is_file()}
    certs = folder / "certs"
    if certs.is_dir():
        out |= {f"certs/{p.name}": p.read_bytes() for p in sorted(certs.iterdir()) if p.is_file()}
    return out


def portal_archive(db_path, data_dir, tt) -> bytes:
    """tar.gz: снимок БД (sqlite backup — без остановки панели), data.key и настройки TrustTunnel."""
    buf = io.BytesIO()
    now = int(time.time())
    with tarfile.open(fileobj=buf, mode="w:gz", compresslevel=6) as tar:
        def add(name: str, data: bytes) -> None:
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode = len(data), now, 0o600
            tar.addfile(info, io.BytesIO(data))

        with tempfile.TemporaryDirectory(dir=data_dir) as tmp:
            snap = os.path.join(tmp, "panel.db")
            src, dst = sqlite3.connect(db_path), sqlite3.connect(snap)
            try:
                src.backup(dst)
            finally:
                dst.close()
                src.close()
            with open(snap, "rb") as f:
                add("panel.db", f.read())
        if os.path.exists(ENV_FILE):
            with open(ENV_FILE, "rb") as f:
                add("panel.env", f.read())
        key = os.path.join(data_dir, "data.key")
        if os.path.exists(key):
            with open(key, "rb") as f:
                add("data.key", f.read())
        if tt is not None:
            for name, data in tt_files(tt.dir).items():
                add(f"trusttunnel/{name}", data)
        add("RESTORE.txt", RESTORE_TXT.format(when=fmt.dt(now, "%Y-%m-%d %H:%M")).encode())
    return buf.getvalue()


def group_archive(conn: sqlite3.Connection, group_ids: set[int], config_for) -> bytes:
    """zip: clients.csv и конфиги клиентов групп (.toml и tt://, у кого пароль есть у панели)."""
    peers = conn.execute(
        "SELECT p.*, g.name AS group_name, c.email, c.tg_chat_id FROM peers p JOIN groups g ON g.id = p.group_id "
        f"LEFT JOIN contacts c ON c.peer_id = p.id WHERE p.deleted_at IS NULL{db.peer_filter(group_ids, 'p.group_id')[0]} "
        "ORDER BY g.name, p.name", db.peer_filter(group_ids, "p.group_id")[1]).fetchall()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        out = io.StringIO()
        w = csv.writer(out, delimiter=";")
        w.writerow(["group", "name", "login", "disabled", "quota_bytes", "quota_period", "email", "telegram_id", "note", "config"])
        names: set[str] = set()
        for p in peers:
            cfg = config_for(p["id"]) if config_for else None
            fname = ""
            if cfg:
                from .clientconf import file_name
                fname = file_name(cfg["name"], cfg["username"])
                if fname in names:
                    fname = fname.removesuffix(".toml") + f"-{p['username']}.toml"
                names.add(fname)
                z.writestr(f"configs/{fname}", cfg["conf"])
                z.writestr(f"configs/{fname.removesuffix('.toml')}.tt.txt", cfg["vpn"] + "\n")
            w.writerow([p["group_name"], p["name"], p["username"], p["disabled"], p["quota_bytes"] or "", p["quota_period"],
                        p["email"] or "", p["tg_chat_id"] or "", p["note"] or "", fname])
        z.writestr("clients.csv", "﻿" + out.getvalue())
    return buf.getvalue()


# ---- восстановление ----

PARTS = ("db", "tt", "env")


def read_archive(blob: bytes, passphrase: str) -> dict[str, bytes]:
    """Расшифровать бэкап портала и вернуть его файлы; бэкап группы (zip) восстанавливать нечем — это конфиги."""
    data = decrypt(blob, passphrase)
    if data[:2] != b"\x1f\x8b":
        raise BackupError(t("This is a group backup: it holds client configs, there is nothing to restore on the server."))
    out: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for m in tar.getmembers():
            if m.isfile() and ".." not in m.name and not m.name.startswith("/"):
                out[m.name] = tar.extractfile(m).read()
    if "panel.db" not in out or not out["panel.db"].startswith(SQLITE_HEADER):
        raise BackupError(t("The backup has no panel database."))
    return out


def set_host(env: bytes, host: str) -> bytes:
    """Новый публичный IP/домен сервера в .env (PANEL_HOST и PUBLIC_HOST)."""
    lines, seen = env.decode().splitlines(), set()
    for i, line in enumerate(lines):
        k = line.split("=", 1)[0].strip()
        if k in ("PANEL_HOST", "PUBLIC_HOST"):
            lines[i] = f"{k}={host}"
            seen.add(k)
    lines += [f"{k}={host}" for k in ("PANEL_HOST", "PUBLIC_HOST") if k not in seen]
    return ("\n".join(lines) + "\n").encode()


def _write(path, data: bytes, mode: int = 0o600) -> None:
    tmp = f"{path}.restore-tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def restore(files: dict[str, bytes], settings, tt, parts: set[str], live: bool, env_path: str | None = None,
            host: str | None = None) -> list[str]:
    """Вернуть из бэкапа выбранное: db — база и data.key, tt — настройки TrustTunnel (с перезапуском endpoint'а),
    env — .env панели. live=True: панель работает — база кладётся в data/restore и подставляется при старте.
    Текущее состояние перед этим сохраняется в data/backups. Возвращает список сделанного."""
    done: list[str] = []
    data_dir = str(settings.data_dir)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    keep = os.path.join(data_dir, "backups", f"{stamp}-pre-restore")
    os.makedirs(keep, mode=0o700, exist_ok=True)
    if "tt" in parts:
        names = [n.split("/", 1)[1] for n in files if n.startswith("trusttunnel/")]
        if "credentials.toml" not in names:
            raise BackupError(t("The backup has no TrustTunnel settings."))
        with tt.locked():
            for name, data in tt_files(tt.dir).items():
                os.makedirs(os.path.dirname(os.path.join(keep, "trusttunnel", name)), mode=0o700, exist_ok=True)
                _write(os.path.join(keep, "trusttunnel", name), data)
            for name in names:
                if name.count("/") > 1 or (name not in TT_FILES and not name.startswith("certs/")):
                    continue        # в каталог endpoint'а — только его настройки, без бинарников и путей наружу
                os.makedirs(tt.dir / os.path.dirname(name), mode=0o700, exist_ok=True)
                _write(tt.dir / name, files[f"trusttunnel/{name}"])
            if live:
                tt.restart()
        done.append(t("TrustTunnel settings restored, endpoint restarted") if live else t("TrustTunnel settings restored"))
    if "db" in parts:
        if os.path.exists(settings.db_path):
            src, dst = sqlite3.connect(settings.db_path), sqlite3.connect(os.path.join(keep, "panel.db"))
            try:
                src.backup(dst)
            finally:
                dst.close()
                src.close()
        target = os.path.join(data_dir, "restore") if live else data_dir
        os.makedirs(target, mode=0o700, exist_ok=True)
        _write(os.path.join(target, "panel.db"), files["panel.db"])
        if "data.key" in files:
            _write(os.path.join(target, "data.key"), files["data.key"])
        if not live:
            for ext in ("-wal", "-shm"):
                try:
                    os.remove(os.path.join(data_dir, "panel.db" + ext))
                except FileNotFoundError:
                    pass
        done.append(t("panel database restored") if not live else t("panel database will be restored when the panel restarts"))
    if "env" in parts and "panel.env" in files:
        if not env_path:
            done.append(t(".env was not changed (restore it with restore.sh)"))
        else:
            env = set_host(files["panel.env"], host) if host else files["panel.env"]
            with open(env_path, "wb") as f:          # bind-mount: перезапись на месте, без rename
                f.write(env)
            done.append(t(".env restored") + (f" (PANEL_HOST/PUBLIC_HOST = {host})" if host else ""))
    return done


def apply_staged(data_dir) -> bool:
    """При старте панели: база из data/restore заменяет текущую (её копия уже в data/backups/…-pre-restore)."""
    staged = os.path.join(str(data_dir), "restore", "panel.db")
    if not os.path.exists(staged):
        return False
    for ext in ("-wal", "-shm"):
        try:
            os.remove(os.path.join(str(data_dir), "panel.db" + ext))
        except FileNotFoundError:
            pass
    os.replace(staged, os.path.join(str(data_dir), "panel.db"))
    key = os.path.join(str(data_dir), "restore", "data.key")
    if os.path.exists(key):
        os.replace(key, os.path.join(str(data_dir), "data.key"))
    log.warning("panel database restored from a backup")
    return True


# ---- задания ----

def job(conn: sqlite3.Connection, admin_id: int) -> sqlite3.Row:
    conn.execute("INSERT OR IGNORE INTO backup_jobs (admin_id) VALUES (?)", (admin_id,))
    return conn.execute("SELECT * FROM backup_jobs WHERE admin_id = ?", (admin_id,)).fetchone()


def save_job(conn: sqlite3.Connection, fernet, admin_id: int, enabled: bool, to_telegram: bool, to_email: bool, email: str,
             period: str, hour: str, weekday: str, password: str) -> None:
    from .portal import EMAIL_RE
    cur = job(conn, admin_id)
    email = (email or "").strip()[:200]
    if to_email and not EMAIL_RE.fullmatch(email):
        raise BackupError(t("Enter a valid e-mail address."))
    if period not in PERIODS:
        raise BackupError(t("Unknown period or action."))
    if password and len(password) < MIN_PASSWORD:
        raise BackupError(t("The archive password must be at least {n} characters.", n=MIN_PASSWORD))
    pass_enc = fernet.encrypt(password.encode()).decode() if password else cur["pass_enc"]
    if enabled and not pass_enc:
        raise BackupError(t("Set an archive password: backups are always encrypted."))
    if enabled and not (to_telegram or to_email):
        raise BackupError(t("Choose where to send the backup: Telegram, e-mail or both."))
    conn.execute("UPDATE backup_jobs SET enabled = ?, to_telegram = ?, to_email = ?, email = ?, period = ?, hour = ?, "
                 "weekday = ?, pass_enc = ? WHERE admin_id = ?",
                 (int(enabled), int(to_telegram), int(to_email), email or None, period,
                  int(hour) % 24 if hour.isdigit() else 3, int(weekday) % 7 if weekday.isdigit() else 0, pass_enc, admin_id))


class Backups:
    """Расписание и отправка. notifier — каналы (Telegram, e-mail) и сборка конфигов; tt — настройки TrustTunnel."""

    def __init__(self, settings, conn: sqlite3.Connection, notifier, fernet, tt=None):
        self.s, self.conn, self.n, self.fernet, self.tt = settings, conn, notifier, fernet, tt
        self._lock = threading.Lock()

    def build(self, admin: sqlite3.Row, now: int) -> tuple[str, bytes]:
        stamp = fmt.dt(now, "%Y%m%d-%H%M")
        if admin["role"] == "super":
            return f"tt-portal-{stamp}.ttbak", portal_archive(self.s.db_path, str(self.s.data_dir), self.tt)
        gids = groups.admin_group_ids(self.conn, admin["id"])
        if not gids:
            raise BackupError(t("No groups: sees nothing"))
        return f"tt-groups-{admin['username']}-{stamp}.ttbak", group_archive(self.conn, gids, self.n.config_for)

    def run(self, admin_id: int, now: int | None = None) -> str:
        """Собрать, зашифровать и отправить бэкап администратора; итог пишется в задание и в журнал."""
        now = int(time.time()) if now is None else now
        with self._lock:
            admin = self.conn.execute("SELECT * FROM admins WHERE id = ?", (admin_id,)).fetchone()
            j = job(self.conn, admin_id)
            sent, errors, size = [], [], 0
            try:
                if not j["pass_enc"]:
                    raise BackupError(t("Set an archive password: backups are always encrypted."))
                name, raw = self.build(admin, now)
                blob = encrypt(raw, self.fernet.decrypt(j["pass_enc"].encode()).decode())
                size = len(blob)
                if size > LIMIT:
                    raise BackupError(t("The backup is too large to send ({size}).", size=fmt.size(size)))
                caption = t("TrustPanel backup {name}, {size}. Encrypted with your backup password.", name=name, size=fmt.size(size))
                if j["to_telegram"]:
                    try:
                        if not (self.n.tg and admin["tg_chat_id"]):
                            raise BackupError(t("Telegram is not connected on the My account page."))
                        self.n.tg.send_document(admin["tg_chat_id"], name, blob, caption, "application/octet-stream")
                        sent.append("Telegram")
                    except Exception as e:  # noqa: BLE001 — второй канал всё равно пробуем
                        errors.append(f"Telegram: {e}")
                if j["to_email"]:
                    try:
                        if not self.n.email_on:
                            raise BackupError(t("E-mail is not configured: add SMTP_* to .env on the server."))
                        from .notify import send_email
                        send_email(self.s, j["email"], t("TrustPanel backup {name}", name=name), caption,
                                   files=[(name, blob, "application", "octet-stream")])
                        sent.append(j["email"])
                    except Exception as e:  # noqa: BLE001
                        errors.append(f"e-mail: {e}")
            except Exception as e:  # noqa: BLE001
                errors.append(str(e))
            ok = bool(sent) and not errors
            status = (t("sent: {to}", to=", ".join(sent)) if sent else "") + ("; " if sent and errors else "") + "; ".join(errors)
            self.conn.execute("UPDATE backup_jobs SET last_ts = ?, last_ok = ?, last_status = ?, last_size = ? WHERE admin_id = ?",
                              (now, int(ok), status[:500], size, admin_id))
            db.event(self.conn, "backup_sent" if ok else "alert_backup", None,
                     {"username": admin["username"], "status": status[:300]}, admin["username"] if ok else None, ts=now)
            return status

    def due(self, now: int) -> int:
        local = datetime.datetime.fromtimestamp(now, fmt.TZ)
        day = local.strftime("%Y-%m-%d")
        n = 0
        for j in self.conn.execute("SELECT j.* FROM backup_jobs j JOIN admins a ON a.id = j.admin_id "
                                   "WHERE j.enabled = 1 AND a.disabled = 0 AND j.hour = ?", (local.hour,)).fetchall():
            if j["last_day"] == day or (j["period"] == "weekly" and local.weekday() != j["weekday"]):
                continue
            self.conn.execute("UPDATE backup_jobs SET last_day = ? WHERE admin_id = ?", (day, j["admin_id"]))
            self.run(j["admin_id"], now)
            n += 1
        return n

    def loop(self, stop: threading.Event) -> None:
        while not stop.wait(60):
            try:
                self.due(int(time.time()))
            except Exception:  # noqa: BLE001
                log.exception("backup")


def _cli() -> None:
    if len(sys.argv) < 3 or sys.argv[1] not in ("decrypt", "restore"):
        sys.exit(__doc__)
    src = sys.argv[2]
    if sys.argv[1] == "restore":
        from .config import settings
        from .ttctl import TT
        arg = lambda k: sys.argv[sys.argv.index(k) + 1] if k in sys.argv else None  # noqa: E731
        with open(src, "rb") as f:
            files = read_archive(f.read(), getpass.getpass("Backup password: "))
        parts = set((arg("--parts") or "db,tt,env").split(","))
        for line in restore(files, settings, TT(settings), parts, live=False, env_path=arg("--env"), host=arg("--host")):
            print("✓", line)
        return
    out = sys.argv[sys.argv.index("-o") + 1] if "-o" in sys.argv else None
    with open(src, "rb") as f:
        blob = f.read()
    data = decrypt(blob, getpass.getpass("Backup password: "))
    if not out:
        base = src.removesuffix(".ttbak")
        out = base + (".tar.gz" if data[:2] == b"\x1f\x8b" else ".zip")
    with open(out, "wb") as f:
        f.write(data)
    print(f"Decrypted: {out}")


if __name__ == "__main__":
    _cli()
