"""SQLite: схема, миграции, соединения. Каждый поток открывает своё соединение через connect()."""
from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path

# Каждая миграция применяется один раз, по порядку; номер версии = индекс + 1.
MIGRATIONS: list[str] = [
    """
    CREATE TABLE peers (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,    -- логин клиента в credentials.toml TrustTunnel
        name TEXT,
        note TEXT,
        source TEXT,                      -- 'endpoint' (был в credentials.toml до панели) | 'panel'
        password_enc BLOB,                -- Fernet(DATA_KEY): нужен, чтобы вернуть отключённого и выдать конфиг
        created_at INT,
        deleted_at INT,
        disabled INT NOT NULL DEFAULT 0,
        first_handshake INT,              -- первое / последнее время, когда клиент был подключён
        last_handshake INT,
        last_endpoint TEXT,
        rx_total INT NOT NULL DEFAULT 0,
        tx_total INT NOT NULL DEFAULT 0,
        portal_hash TEXT,
        portal_config INT NOT NULL DEFAULT 0,
        group_id INT,
        quota_bytes INT,
        quota_period TEXT NOT NULL DEFAULT 'month',
        quota_action TEXT NOT NULL DEFAULT 'alert',
        quota_blocked TEXT
    );
    CREATE INDEX peers_group ON peers(group_id);

    CREATE TABLE traffic_min (ts INT, peer_id INT, rx INT, tx INT, PRIMARY KEY (ts, peer_id));
    CREATE INDEX traffic_min_peer ON traffic_min(peer_id, ts);
    CREATE TABLE traffic_hour (ts INT, peer_id INT, rx INT, tx INT, PRIMARY KEY (ts, peer_id));
    CREATE INDEX traffic_hour_peer ON traffic_hour(peer_id, ts);
    CREATE TABLE online_min (ts INT PRIMARY KEY, online INT);

    CREATE TABLE sessions (
        id INTEGER PRIMARY KEY,
        peer_id INT NOT NULL,
        start INT NOT NULL,
        end INT,
        endpoint_ip TEXT,
        rx INT NOT NULL DEFAULT 0,
        tx INT NOT NULL DEFAULT 0,
        last_active INT                   -- по нему сессия закрывается
    );
    CREATE INDEX sessions_peer ON sessions(peer_id, start);
    CREATE INDEX sessions_open ON sessions(end) WHERE end IS NULL;

    CREATE TABLE endpoints (
        peer_id INT, ip TEXT, first_seen INT, last_seen INT, count INT NOT NULL DEFAULT 1,
        country TEXT, city TEXT, asn INT, org TEXT,
        PRIMARY KEY (peer_id, ip)
    );

    CREATE TABLE events (
        id INTEGER PRIMARY KEY,
        ts INT NOT NULL,
        peer_id INT,
        kind TEXT NOT NULL,
        detail TEXT,                      -- JSON
        actor TEXT,
        actor_ip TEXT,
        acked INT NOT NULL DEFAULT 0
    );
    CREATE INDEX events_ts ON events(ts);
    CREATE INDEX events_peer ON events(peer_id, ts);
    CREATE INDEX events_kind ON events(kind, ts);

    CREATE TABLE state (key TEXT PRIMARY KEY, value TEXT);

    -- помесячный архив: итоги месяца по клиенту фиксируются 1-го числа в 00:00 (часовой пояс TZ)
    CREATE TABLE monthly_archive (
        month TEXT NOT NULL,              -- 'YYYY-MM'
        peer_id INT NOT NULL,
        name TEXT, username TEXT,
        rx INT NOT NULL DEFAULT 0,        -- клиент отдал
        tx INT NOT NULL DEFAULT 0,        -- клиент скачал
        sessions INT NOT NULL DEFAULT 0,
        online_sec INT NOT NULL DEFAULT 0,
        created_at INT,
        PRIMARY KEY (month, peer_id)
    );

    -- личный кабинет клиента и уведомления
    CREATE TABLE contacts (
        peer_id INT PRIMARY KEY,
        email TEXT, email_verified INT NOT NULL DEFAULT 0, email_code TEXT,
        tg_chat_id INT, tg_name TEXT, tg_code TEXT, tg_code_exp INT,
        daily INT NOT NULL DEFAULT 1, daily_hour INT NOT NULL DEFAULT 21, events INT NOT NULL DEFAULT 1,
        last_daily TEXT,
        lang TEXT,
        cfg_code TEXT, cfg_code_exp INT   -- одноразовая ссылка на бота, по которой клиент получает свой конфиг
    );
    CREATE TABLE notify_log (id INTEGER PRIMARY KEY, ts INT, peer_id INT, channel TEXT, kind TEXT, ok INT, error TEXT);
    CREATE INDEX notify_log_ts ON notify_log(ts);

    -- администраторы (супер-администратор и администраторы групп); учётка из .env — строка с env = 1
    CREATE TABLE admins (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE COLLATE NOCASE,
        pw_hash TEXT NOT NULL DEFAULT '',     -- пусто у учётки из .env: её пароль в .env
        totp_enc TEXT,                        -- Fernet(секрет TOTP); NULL — привязка при первом входе
        totp_step INT NOT NULL DEFAULT -1,    -- последний принятый шаг TOTP: код не проходит дважды
        role TEXT NOT NULL DEFAULT 'group',   -- super | group
        env INT NOT NULL DEFAULT 0,
        disabled INT NOT NULL DEFAULT 0,
        must_change INT NOT NULL DEFAULT 0,   -- временный пароль: сменить при входе
        session_ver INT NOT NULL DEFAULT 0,   -- +1 при сбросе/отключении: открытые сессии закрываются
        created_at INT, last_login INT, last_ip TEXT, note TEXT,
        tg_chat_id INT, tg_name TEXT, tg_code TEXT, tg_code_exp INT,
        notify_alerts INT NOT NULL DEFAULT 1,
        notify_logins INT NOT NULL DEFAULT 0,
        quiet_from INT, quiet_to INT,
        lang TEXT
    );

    -- группы клиентов и их администраторы; клиент без группы — group_id NULL
    CREATE TABLE groups (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL UNIQUE COLLATE NOCASE,
        note TEXT,
        created_at INT,
        quota_bytes INT,
        quota_period TEXT NOT NULL DEFAULT 'month',
        quota_action TEXT NOT NULL DEFAULT 'alert'
    );
    CREATE TABLE admin_groups (
        admin_id INT NOT NULL,
        group_id INT NOT NULL,
        PRIMARY KEY (admin_id, group_id)
    );

    -- бэкапы в Telegram/e-mail: у каждого администратора своё задание (портал — супер, свои группы — админ группы)
    CREATE TABLE backup_jobs (
        admin_id INT PRIMARY KEY,
        enabled INT NOT NULL DEFAULT 0,
        to_telegram INT NOT NULL DEFAULT 1,
        to_email INT NOT NULL DEFAULT 0,
        email TEXT,
        period TEXT NOT NULL DEFAULT 'daily',   -- daily | weekly
        hour INT NOT NULL DEFAULT 3,
        weekday INT NOT NULL DEFAULT 0,         -- 0 — понедельник
        pass_enc TEXT,                          -- Fernet(пароль архива): нужен, чтобы шифровать по расписанию
        last_day TEXT, last_ts INT, last_ok INT, last_status TEXT, last_size INT
    );

    -- доступ к панели администратора только с этих адресов/подсетей; пусто — без ограничения
    CREATE TABLE ip_allow (
        id INTEGER PRIMARY KEY,
        cidr TEXT NOT NULL UNIQUE,
        note TEXT,
        created_at INT,
        actor TEXT
    );
    """,
    # 2: подгруппы — головная организация, филиалы, отделы; NULL — группа верхнего уровня
    """
    ALTER TABLE groups ADD COLUMN parent_id INTEGER REFERENCES groups(id);
    """,
]


def connect(path: Path | str) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), timeout=10, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=10000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def version(conn: sqlite3.Connection) -> int:
    conn.execute("CREATE TABLE IF NOT EXISTS schema_version (v INT NOT NULL)")
    row = conn.execute("SELECT v FROM schema_version").fetchone()
    return row[0] if row else 0


def migrate(conn: sqlite3.Connection) -> int:
    """Доводит схему до последней версии; возвращает итоговую версию."""
    v = version(conn)
    for i, sql in enumerate(MIGRATIONS[v:], start=v + 1):
        conn.execute("BEGIN IMMEDIATE")
        try:
            for stmt in _split(sql):
                conn.execute(stmt)
            conn.execute("DELETE FROM schema_version")
            conn.execute("INSERT INTO schema_version (v) VALUES (?)", (i,))
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    return len(MIGRATIONS)


def _split(sql: str) -> list[str]:
    """Делит скрипт миграции на операторы (executescript нельзя — он коммитит посреди транзакции)."""
    out, buf = [], []
    for line in sql.splitlines():
        line = line.split("--", 1)[0].rstrip()
        if not line:
            continue
        buf.append(line)
        if line.endswith(";"):
            out.append("\n".join(buf))
            buf = []
    if buf:
        out.append("\n".join(buf))
    return out


def open_db(path: Path | str) -> sqlite3.Connection:
    """Открыть и смигрировать БД. Каталог данных и файлы БД — только для владельца: в них история клиентов."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    os.umask(0o077)  # всё, что панель создаёт дальше (БД, -wal/-shm, гео, бэкапы), — 600/700
    conn = connect(path)
    migrate(conn)
    os.chmod(path.parent, 0o700)
    for f in (path, path.with_name(path.name + "-wal"), path.with_name(path.name + "-shm")):
        if f.exists():
            os.chmod(f, 0o600)
    return conn


def peer_filter(peers, col: str = "peer_id") -> tuple[str, tuple]:
    """Условие « AND col …» для выборок по клиентам: None — все; int — один; набор id — только они (пустой — никого)."""
    if peers is None:
        return "", ()
    if isinstance(peers, int):
        return f" AND {col} = ?", (peers,)
    ids = tuple(sorted(peers))
    if not ids:
        return " AND 0", ()
    return f" AND {col} IN ({','.join('?' * len(ids))})", ids


def event(conn: sqlite3.Connection, kind: str, peer_id: int | None = None, detail: dict | None = None,
          actor: str | None = None, actor_ip: str | None = None, ts: int | None = None) -> None:
    conn.execute(
        "INSERT INTO events (ts, peer_id, kind, detail, actor, actor_ip) VALUES (?, ?, ?, ?, ?, ?)",
        (ts or int(time.time()), peer_id, kind,
         json.dumps(detail, ensure_ascii=False) if detail is not None else None, actor, actor_ip),
    )


def get_state(conn: sqlite3.Connection, key: str, default: str | None = None) -> str | None:
    row = conn.execute("SELECT value FROM state WHERE key = ?", (key,)).fetchone()
    return row[0] if row else default


def set_state(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute("INSERT INTO state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                 (key, value))
