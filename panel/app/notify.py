"""Уведомления: клиентам — Telegram-бот, e-mail, ежедневная сводка картинкой, события; администраторам — алерты
панели в Telegram (супер-администратору все, администратору группы — по клиентам его групп).

Каналы включаются сами, когда в .env есть TELEGRAM_BOT_TOKEN / SMTP_HOST; без них всё остальное работает.
"""
from __future__ import annotations

import datetime
import json
import logging
import smtplib
import sqlite3
import ssl
import threading
import time
import urllib.parse
import urllib.request
import uuid
from email.message import EmailMessage

from . import admins, db, fmt, groups, i18n, portal, report
from .i18n import t
from .config import Settings

log = logging.getLogger("notify")

# какие события клиента ему пересылаются
CLIENT_EVENTS = {"alert_new_country", "alert_shared_config", "admin_disable", "admin_enable",
                 "alert_traffic_spike", "alert_quota"}


# ---- Telegram ----

class Telegram:
    def __init__(self, token: str):
        self.token = token
        self.username: str | None = None

    def call(self, method: str, params: dict | None = None, files: dict[str, tuple[str, bytes, str]] | None = None,
             timeout: float = 30) -> dict:
        url = f"https://api.telegram.org/bot{self.token}/{method}"
        if files:
            boundary = uuid.uuid4().hex
            body = b""
            for k, v in (params or {}).items():
                body += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n").encode()
            for k, (name, data, ctype) in files.items():
                body += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"; filename=\"{name}\"\r\n"
                         f"Content-Type: {ctype}\r\n\r\n").encode() + data + b"\r\n"
            body += f"--{boundary}--\r\n".encode()
            req = urllib.request.Request(url, data=body, headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
        else:
            req = urllib.request.Request(url, data=urllib.parse.urlencode(params or {}).encode())
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                out = json.loads(r.read())
        except urllib.error.HTTPError as e:
            out = json.loads(e.read() or b"{}") or {"ok": False, "description": str(e)}
        if not out.get("ok"):
            raise RuntimeError(f"Telegram {method}: {out.get('description')}")
        return out["result"]

    def me(self) -> str:
        if not self.username:
            self.username = self.call("getMe")["username"]
        return self.username

    def send(self, chat_id: int, text: str) -> None:
        self.call("sendMessage", {"chat_id": chat_id, "text": text, "disable_web_page_preview": "true"})

    def send_photo(self, chat_id: int, png: bytes, caption: str) -> None:
        self.call("sendPhoto", {"chat_id": chat_id, "caption": caption[:1000]}, {"photo": ("stats.png", png, "image/png")})

    def send_document(self, chat_id: int, name: str, data: bytes, caption: str = "", ctype: str = "text/plain") -> None:
        self.call("sendDocument", {"chat_id": chat_id, "caption": caption[:1000]}, {"document": (name, data, ctype)},
                  timeout=300)


# ---- e-mail ----

def send_email(s: Settings, to: str, subject: str, text: str, png: bytes | None = None,
               files: list[tuple[str, bytes, str, str]] | None = None) -> None:
    """files — вложения (имя, данные, maintype, subtype)."""
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = s.smtp_from or s.smtp_user, to, subject
    msg.set_content(text)
    if png:
        msg.add_attachment(png, maintype="image", subtype="png", filename="stats.png")
    for name, data, main, sub in files or []:
        msg.add_attachment(data, maintype=main, subtype=sub, filename=name)
    ctx = ssl.create_default_context()
    if s.smtp_ssl or s.smtp_port == 465:
        with smtplib.SMTP_SSL(s.smtp_host, s.smtp_port, context=ctx, timeout=30) as m:
            if s.smtp_user:
                m.login(s.smtp_user, s.smtp_password)
            m.send_message(msg)
    else:
        with smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=30) as m:
            m.starttls(context=ctx)
            if s.smtp_user:
                m.login(s.smtp_user, s.smtp_password)
            m.send_message(msg)


# ---- рассылка ----

class Notifier:
    def __init__(self, settings: Settings, conn: sqlite3.Connection):
        self.s, self.conn = settings, conn
        self.tg = Telegram(settings.telegram_token) if settings.telegram_token else None
        self.config_for = None   # peer_id -> {name, username, conf, vpn} | None; задаёт main (нужен доступ к TrustTunnel)
        self.last_error: str | None = None
        self._lock = threading.Lock()

    @property
    def email_on(self) -> bool:
        return bool(self.s.smtp_host)

    def log(self, peer_id: int, channel: str, kind: str, err: str | None) -> None:
        self.conn.execute("INSERT INTO notify_log (ts, peer_id, channel, kind, ok, error) VALUES (?, ?, ?, ?, ?, ?)",
                          (int(time.time()), peer_id, channel, kind, int(err is None), err))

    def lang(self, peer_id: int) -> str | None:
        row = self.conn.execute("SELECT lang FROM contacts WHERE peer_id = ?", (peer_id,)).fetchone()
        return row[0] if row else None

    def deliver(self, peer_id: int, kind: str, text: str, png: bytes | None = None, subject: str | None = None) -> int:
        """В Telegram и/или на подтверждённый e-mail клиента; возвращает число успешных отправок."""
        c = portal.contact(self.conn, peer_id)
        sent = 0
        if self.tg and c["tg_chat_id"]:
            try:
                self.tg.send_photo(c["tg_chat_id"], png, text) if png else self.tg.send(c["tg_chat_id"], text)
                self.log(peer_id, "telegram", kind, None)
                sent += 1
            except Exception as e:  # noqa: BLE001 — сбой канала не должен мешать другому
                self.log(peer_id, "telegram", kind, str(e)[:300])
        if self.email_on and c["email"] and c["email_verified"]:
            try:
                send_email(self.s, c["email"], subject or t("VPN: notification"), text, png)
                self.log(peer_id, "email", kind, None)
                sent += 1
            except Exception as e:  # noqa: BLE001
                self.log(peer_id, "email", kind, str(e)[:300])
        return sent

    def daily(self, peer_id: int, now: int | None = None) -> int:
        now = int(time.time()) if now is None else now
        with i18n.use(self.lang(peer_id)):
            png, caption = report.daily_png(self.conn, peer_id, now)
            name = self.conn.execute("SELECT name FROM peers WHERE id = ?", (peer_id,)).fetchone()[0]
            return self.deliver(peer_id, "daily", caption, png,
                                subject=t("VPN: statistics for {date} — {name}", date=fmt.dt(now, "%d.%m"), name=name))

    def due_daily(self, now: int) -> None:
        local = datetime.datetime.fromtimestamp(now, fmt.TZ)
        day = local.strftime("%Y-%m-%d")
        for r in self.conn.execute(
                "SELECT c.peer_id FROM contacts c JOIN peers p ON p.id = c.peer_id WHERE p.deleted_at IS NULL AND c.daily = 1 "
                "AND c.daily_hour = ? AND COALESCE(c.last_daily, '') != ? AND (c.tg_chat_id IS NOT NULL OR c.email_verified = 1)",
                (local.hour, day)).fetchall():
            self.conn.execute("UPDATE contacts SET last_daily = ? WHERE peer_id = ?", (day, r[0]))
            self.daily(r[0], now)

    def due_events(self) -> None:
        last = int(db.get_state(self.conn, "notify_event_id", "0") or 0)
        if not last:   # первый запуск — не рассылаем историю
            last = self.conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
        rows = self.conn.execute(
            "SELECT e.id, e.kind, e.detail, e.peer_id FROM events e JOIN contacts c ON c.peer_id = e.peer_id "
            "WHERE e.id > ? AND c.events = 1 ORDER BY e.id LIMIT 200", (last,)).fetchall()
        top = self.conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
        for r in rows:
            if r["kind"] in CLIENT_EVENTS:
                with i18n.use(self.lang(r["peer_id"])):
                    self.deliver(r["peer_id"], r["kind"], "VPN: " + fmt.event_text(r["kind"], r["detail"]))
        db.set_state(self.conn, "notify_event_id", str(max(top, last)))

    # ---- конфиг клиента ----

    def config_text(self, cfg: dict) -> str:
        return "\n".join([t("VPN config for “{name}” (login {username}).", name=cfg["name"], username=cfg["username"]),
                          t("1. Install the TrustTunnel app (trusttunnel.org)."),
                          t("2. Scan the QR code or paste the tt:// link from the next message."),
                          t("The attached .toml file is for the TrustTunnel CLI client.")])

    def config_to_telegram(self, chat_id: int, cfg: dict) -> None:
        from .clientconf import file_name, qr_png
        self.tg.send_document(chat_id, file_name(cfg["name"], cfg["username"]), cfg["conf"].encode(), self.config_text(cfg))
        self.tg.send_photo(chat_id, qr_png(cfg["vpn"]), t("QR code of the config"))
        self.tg.send(chat_id, cfg["vpn"])

    def config_to_email(self, to: str, cfg: dict) -> None:
        from .clientconf import file_name, qr_png
        conf_name = file_name(cfg["name"], cfg["username"])
        send_email(self.s, to, t("VPN config — {name}", name=cfg["name"]),
                   self.config_text(cfg) + "\n\n" + cfg["vpn"] + "\n",
                   files=[(conf_name, cfg["conf"].encode(), "text", "plain"),
                          (conf_name.removesuffix(".toml") + "-qr.png", qr_png(cfg["vpn"]), "image", "png")])

    def send_config(self, peer_id: int, channel: str, to: str = "", actor: str | None = None,
                    actor_ip: str | None = None) -> str:
        """Отправить конфиг клиенту: channel = telegram (в привязанный чат) | email (на адрес to или подтверждённый)."""
        cfg = self.config_for(peer_id) if self.config_for else None
        if not cfg:
            raise ValueError(t("The panel does not know this client's password: issue a new one."))
        c = portal.contact(self.conn, peer_id)
        with i18n.use(self.lang(peer_id)):
            if channel == "telegram":
                if not self.tg or not c["tg_chat_id"]:
                    raise ValueError(t("The client has not connected Telegram yet: send them the bot link."))
                self.config_to_telegram(c["tg_chat_id"], cfg)
                where = c["tg_name"] or "Telegram"
            elif channel == "email":
                to = (to or (c["email"] if c["email_verified"] else "") or "").strip()
                if not self.email_on:
                    raise ValueError(t("E-mail is not configured: add SMTP_* to .env on the server."))
                if not portal.EMAIL_RE.fullmatch(to):
                    raise ValueError(t("Enter a valid e-mail address."))
                self.config_to_email(to, cfg)
                where = to
            else:
                raise ValueError(channel)
        db.event(self.conn, "config_sent", peer_id, {"channel": channel, "to": where}, actor, actor_ip)
        self.log(peer_id, channel, "config", None)
        return where

    # ---- администраторам ----

    def due_admin_events(self, now: int) -> int:
        """Новые алерты (и, по желанию, входы в панель) — в Telegram администраторов с учётом их групп и тихих часов."""
        if not self.tg:
            return 0
        top = self.conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
        last = int(db.get_state(self.conn, "notify_admin_event_id", "0") or 0)
        if not last:   # первый запуск — не рассылаем историю
            db.set_state(self.conn, "notify_admin_event_id", str(top))
            return 0
        rows = self.conn.execute(
            "SELECT e.id, e.ts, e.kind, e.detail, e.peer_id, e.actor, e.actor_ip, p.name FROM events e "
            "LEFT JOIN peers p ON p.id = e.peer_id WHERE e.id > ? AND (e.kind LIKE 'alert_%' OR e.kind = 'admin_login') "
            "ORDER BY e.id LIMIT 200", (last,)).fetchall()
        targets = self.conn.execute("SELECT * FROM admins WHERE tg_chat_id IS NOT NULL AND disabled = 0").fetchall()
        hour = datetime.datetime.fromtimestamp(now, fmt.TZ).hour
        scope: dict[int, set[int]] = {}
        sent = 0
        for e in rows:
            for a in targets:
                if e["kind"] == "admin_login" and not a["notify_logins"]:
                    continue
                if e["kind"].startswith("alert_") and not a["notify_alerts"]:
                    continue
                if e["kind"] != "alert_server" and admins.in_quiet_hours(a, hour):
                    continue
                if a["role"] != "super":   # администратор группы — только события своих клиентов
                    if a["id"] not in scope:
                        scope[a["id"]] = groups.peers_of(self.conn, groups.admin_group_ids(self.conn, a["id"]))
                    if e["peer_id"] is None or e["peer_id"] not in scope[a["id"]]:
                        continue
                with i18n.use(a["lang"]):
                    text = "TrustPanel: " + (f"{e['name']} — " if e["name"] else "") + fmt.event_text(e["kind"], e["detail"])
                    if e["kind"] == "admin_login":
                        text += f" ({e['actor']}, {e['actor_ip']})"
                try:
                    self.tg.send(a["tg_chat_id"], text)
                    sent += 1
                except Exception as ex:  # noqa: BLE001 — один получатель не должен мешать остальным
                    self.conn.execute("INSERT INTO notify_log (ts, peer_id, channel, kind, ok, error) VALUES (?, NULL, ?, ?, 0, ?)",
                                      (now, "telegram-admin", e["kind"], f"{a['username']}: {str(ex)[:250]}"))
        db.set_state(self.conn, "notify_admin_event_id", str(rows[-1]["id"] if len(rows) == 200 else max(top, last)))
        return sent

    def admin_summary(self, a: sqlite3.Row, now: int) -> str:
        """Ответ на /stats администратору: онлайн, трафик за сегодня, непрочитанные алерты — в пределах его групп."""
        peers = None if a["role"] == "super" else groups.peers_of(self.conn, groups.admin_group_ids(self.conn, a["id"]))
        w, args = db.peer_filter(peers, "id")
        tw, targs = db.peer_filter(peers)
        online = self.conn.execute(f"SELECT COUNT(*) FROM peers WHERE deleted_at IS NULL AND disabled = 0 AND last_handshake >= ?{w}",
                                   (now - self.s.online_window, *args)).fetchone()[0]
        total = self.conn.execute(f"SELECT COUNT(*) FROM peers WHERE deleted_at IS NULL{w}", args).fetchone()[0]
        d, u = self.conn.execute(f"SELECT COALESCE(SUM(tx), 0), COALESCE(SUM(rx), 0) FROM traffic_hour WHERE ts >= ?{tw}",
                                 (fmt.day_start(now), *targs)).fetchone()
        alerts = self.conn.execute(f"SELECT COUNT(*) FROM events WHERE kind LIKE 'alert_%' AND acked = 0{tw}", targs).fetchone()[0]
        return "\n".join([t("TrustPanel, {time}", time=fmt.dt(now)),
                          t("Online: {n} of {total}", n=online, total=total),
                          t("Today: ↓ {down} · ↑ {up}", down=fmt.size(d), up=fmt.size(u)),
                          t("Unread alerts: {n}", n=alerts)])

    # ---- бот: привязка и команды ----

    def handle_update(self, u: dict) -> None:
        m = u.get("message") or {}
        chat = (m.get("chat") or {}).get("id")
        text = (m.get("text") or "").strip()
        if not chat or not text:
            return
        who = (m.get("from") or {})
        name = "@" + who["username"] if who.get("username") else who.get("first_name", "")
        if text.startswith("/start"):
            code = text.split(maxsplit=1)[1] if " " in text else ""
            adm = admins.bind_telegram(self.conn, code, chat, name) if code.startswith(admins.TG_PREFIX) else None
            if adm:
                with i18n.use(adm["lang"]):
                    self.tg.send(chat, t("Done: panel alerts for administrator “{name}” will come here.", name=adm["username"])
                                 + "\n" + t("/stats — summary, /stop — disconnect."))
                return
            got = portal.take_config_code(self.conn, code, chat, name) if code.startswith(portal.CFG_PREFIX) else None
            if got:   # ссылка с конфигом: прислать конфиг и подключить уведомления
                with i18n.use(self.lang(got["peer_id"])):
                    cfg = self.config_for(got["peer_id"]) if self.config_for else None
                    if cfg:
                        self.config_to_telegram(chat, cfg)
                        db.event(self.conn, "config_sent", got["peer_id"], {"channel": "telegram", "to": name})
                    else:
                        self.tg.send(chat, t("The config is not available, ask the administrator for a new link."))
                    self.tg.send(chat, t("VPN notifications for “{name}” will come here too.", name=got["name"]) + "\n"
                                 + t("/stats — today's statistics, /stop — disconnect."))
                return
            row = portal.bind_telegram(self.conn, code, chat, name) if code else None
            if row:
                with i18n.use(self.lang(row["peer_id"])):
                    self.tg.send(chat, t("Done: VPN notifications for “{name}” will come here.", name=row["name"]) + "\n"
                                 + t("/stats — today's statistics, /stop — disconnect."))
            else:
                self.tg.send(chat, t("Open your VPN portal and press “Connect Telegram” — the link is valid for an hour."))
        elif text.startswith("/stop"):
            n = portal.unbind_telegram(self.conn, chat) + admins.unbind_telegram(self.conn, chat_id=chat)
            self.tg.send(chat, t("Notifications disabled.") if n else t("This chat was not connected."))
        elif text.startswith("/stats"):
            adm = self.conn.execute("SELECT * FROM admins WHERE tg_chat_id = ? AND disabled = 0", (chat,)).fetchone()
            row = self.conn.execute("SELECT peer_id FROM contacts WHERE tg_chat_id = ?", (chat,)).fetchone()
            if adm:
                with i18n.use(adm["lang"]):
                    self.tg.send(chat, self.admin_summary(adm, int(time.time())))
            if row:
                with i18n.use(self.lang(row[0])):
                    png, caption = report.daily_png(self.conn, row[0], int(time.time()))
                self.tg.send_photo(chat, png, caption)
            elif not adm:
                self.tg.send(chat, t("This chat is not connected to a VPN portal."))

    def bot_loop(self, stop: threading.Event) -> None:
        offset = 0
        while not stop.is_set():
            try:
                for u in self.tg.call("getUpdates", {"offset": offset, "timeout": 50}, timeout=60):
                    offset = u["update_id"] + 1
                    with self._lock:
                        self.handle_update(u)
                self.last_error = None
            except Exception as e:  # noqa: BLE001
                self.last_error = str(e)[:300]
                stop.wait(15)

    def run(self, stop: threading.Event) -> None:
        if self.tg:
            threading.Thread(target=self.bot_loop, args=(stop,), name="telegram", daemon=True).start()
        while not stop.wait(60):
            try:
                with self._lock:
                    now = int(time.time())
                    self.due_events()
                    self.due_admin_events(now)
                    self.due_daily(now)
            except Exception as e:  # noqa: BLE001
                self.last_error = repr(e)
                log.exception("notify")
