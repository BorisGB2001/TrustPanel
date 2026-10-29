"""Веб-приложение панели: вход, страницы, API."""
from __future__ import annotations

import csv
import io
import logging
import os
import re
import secrets
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote, urlsplit

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeTimedSerializer
from starlette.middleware.sessions import SessionMiddleware

from . import __version__, admins, auth, backup, charts, groups, ipallow, quotas, clientconf, db, fmt, i18n, maintenance, monthly, notify, portal, report
from .fmt import N_
from .i18n import t
from .ttctl import TT, TTUnavailable
from .alerts import Alerts
from .config import settings
from .geo import Geo
from .admins import AdminError
from .groups import GroupError
from .quotas import QuotaError
from .manage import Manager, ManageError, load_fernet
from .poller import Poller

BASE = Path(__file__).parent
templates = Jinja2Templates(directory=BASE / "templates")
fmt.register(templates.env)
limiter = auth.RateLimiter()
totp = auth.TOTPGuard(settings.totp_secret) if settings.totp_secret else None


@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    backup.apply_staged(settings.data_dir)          # восстановление из бэкапа, начатое на странице «Бэкапы»
    app.state.db = db.open_db(settings.db_path)
    admins.ensure_env_admin(app.state.db, settings)
    app.state.accounts = admins.Accounts(settings, app.state.db, load_fernet(settings), totp)
    app.state.stop = threading.Event()
    app.state.geo = Geo(settings.data_dir / "geo")
    templates.env.globals["GEO_DATE"] = app.state.geo.built      # дата гео-базы в подвале
    app.state.poller = app.state.alerts = None
    app.state.notifier = None
    app.state.backups = None
    # перезапуск после восстановления базы: процесс завершается, Docker (restart: unless-stopped) поднимает его снова
    app.state.restart = lambda: threading.Timer(2.0, os._exit, (0,)).start()
    if os.environ.get("PANEL_COLLECTORS", "1") == "1":
        threading.Thread(target=app.state.geo.updater, args=(app.state.stop,), name="geo", daemon=True).start()
        app.state.poller = Poller(settings, TT(settings), db.open_db(settings.db_path), app.state.geo, load_fernet(settings))
        threading.Thread(target=app.state.poller.run, args=(app.state.stop,), name="poller", daemon=True).start()
        app.state.alerts = Alerts(settings, db.open_db(settings.db_path), TT(settings))
        threading.Thread(target=app.state.alerts.run, args=(app.state.stop,), name="alerts", daemon=True).start()
        threading.Thread(target=maintenance.run, args=(db.open_db(settings.db_path), settings, app.state.stop),
                         name="maintenance", daemon=True).start()
        threading.Thread(target=monthly.run, args=(db.open_db(settings.db_path), fmt.TZ, app.state.stop),
                         name="monthly", daemon=True).start()
        app.state.notifier = notify.Notifier(settings, db.open_db(settings.db_path))
        attach_config(app.state.notifier)
        threading.Thread(target=app.state.notifier.run, args=(app.state.stop,), name="notify", daemon=True).start()
        app.state.backups = backup.Backups(settings, app.state.notifier.conn, app.state.notifier, load_fernet(settings), TT(settings))
        threading.Thread(target=app.state.backups.loop, args=(app.state.stop,), name="backup", daemon=True).start()
    yield
    app.state.stop.set()
    app.state.db.close()


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "?"


def current_admin(request: Request):
    """Строка admins вошедшего администратора; None — не вошёл, сессия устарела, учётку отключили или сбросили."""
    if "admin" in request.state._state:
        return request.state.admin
    s, row = request.session, None
    if s.get("aid") and s.get("ua") == auth.ua_fingerprint(request.headers.get("user-agent", "")) and \
            time.time() - s.get("at", 0) <= settings.session_hours * 3600:
        row = admins.get(request.app.state.db, s["aid"])
        if row is None or row["disabled"] or row["session_ver"] != s.get("sv"):
            row = None
    if row is None and s.get("aid"):
        s.clear()
    request.state.admin = row
    return row


def current_user(request: Request) -> str | None:
    row = current_admin(request)
    return row["username"] if row else None


def is_super(request: Request) -> bool:
    row = current_admin(request)
    return bool(row) and row["role"] == "super"


def require_super(request: Request) -> None:
    if not is_super(request):
        raise HTTPException(403, t("Only a super administrator can do this."))


def allowed_groups(request: Request) -> set[int] | None:
    """Группы, которые видит администратор: None — все (супер-администратор)."""
    row = current_admin(request)
    if row is None:
        return set()
    if row["role"] == "super":
        return None
    return groups.admin_group_ids(request.app.state.db, row["id"])


def visible_peers(request: Request, group: str = "") -> set[int] | None:
    """Клиенты, которых видно на странице: права администратора ∩ выбранная группа (?group=; 0 — «без группы»).
    None — все клиенты (супер-администратор без фильтра)."""
    conn = request.app.state.db
    allowed = allowed_groups(request)
    sel = int(group) if str(group).isdigit() else None
    if allowed is None:
        if sel is None:
            return None
        return groups.peers_without_group(conn) if sel == 0 else groups.peers_of(conn, {sel})
    return groups.peers_of(conn, allowed if sel is None else allowed & {sel})


def can_see_peer(request: Request, peer_id: int) -> bool:
    v = visible_peers(request)
    return v is None or peer_id in v


def group_choices(request: Request) -> list:
    """Группы для фильтров и форм: все — супер-администратору, свои — администратору группы."""
    allowed = allowed_groups(request)
    return [g for g in groups.all_groups(request.app.state.db) if allowed is None or g["id"] in allowed]


PEER_PATH = re.compile(r"^/peer/(\d+)(?:/|$)")


def csrf_token(request: Request) -> str:
    tok = request.session.get("csrf")
    if not tok:
        tok = request.session["csrf"] = auth.new_csrf()
    return tok


def check_csrf(request: Request, token: str) -> None:
    """Токен из формы + Origin/Referer того же хоста."""
    if not secrets.compare_digest(token or "", request.session.get("csrf", "")):
        raise HTTPException(403, "CSRF")
    origin = request.headers.get("origin") or ""
    if origin == "null":  # приватные режимы и no-referrer: источник скрыт — остаются токен и SameSite=Strict
        origin = ""
    origin = origin or request.headers.get("referer") or ""
    if origin and urlsplit(origin).netloc != request.headers.get("host", ""):
        raise HTTPException(403, "Origin")


def render(request: Request, name: str, **ctx) -> HTMLResponse:
    ctx.setdefault("user", current_user(request))
    ctx.setdefault("admin", current_admin(request))
    ctx.setdefault("flash", request.session.pop("flash", None))
    ctx.setdefault("lang", i18n.get())
    ctx.setdefault("theme", theme_of(request))
    ctx.setdefault("path", request.url.path)
    return templates.TemplateResponse(request, name, {"csrf": csrf_token(request), **ctx})


@app.middleware("http")
async def require_login(request: Request, call_next):
    path = request.url.path
    i18n.set_lang(request.cookies.get("lang"))
    if path.startswith(("/static/", "/me", "/lang/", "/theme/")) or path == "/healthz":
        return await call_next(request)
    if not ipallow.allowed(request.app.state.db, client_ip(request)):
        # админская часть, включая вход, — только с разрешённых адресов (кабинет клиентов /me открыт)
        return Response(t("Access to the panel from your address is not allowed."), status_code=403,
                        media_type="text/plain; charset=utf-8")
    if path in ("/login", "/login/totp"):
        return await call_next(request)
    row = current_admin(request)
    if row:
        if row["must_change"] and path not in ("/account", "/logout"):
            return RedirectResponse("/account", status_code=303)   # временный пароль — сначала сменить
        m = PEER_PATH.match(path)
        if m and not can_see_peer(request, int(m.group(1))):
            # всё, что под /peer/<id>/ (карточка, конфиг, QR, действия), — только клиенты своих групп
            return Response(t("Not found"), status_code=404, media_type="text/plain; charset=utf-8")
        return await call_next(request)
    if path.startswith("/api/"):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return RedirectResponse("/login", status_code=303)


# добавлен последним — значит внешний: сессия уже разобрана, когда работает require_login
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret or secrets.token_urlsafe(48),
    session_cookie="ttp",
    max_age=settings.session_hours * 3600,
    same_site="strict",
    https_only=settings.cookie_secure,
)


THEMES = ("auto", "light", "dark")


def theme_of(request: Request) -> str:
    t = request.cookies.get("theme", "")
    return t if t in THEMES else "auto"


def back_to(request: Request) -> RedirectResponse:
    """Назад на страницу, с которой пришли (только этот же хост)."""
    ref = urlsplit(request.headers.get("referer") or "")
    back = (ref.path or "/") + (f"?{ref.query}" if ref.query else "")
    if ref.netloc and ref.netloc != request.headers.get("host", ""):
        back = "/"
    return RedirectResponse(back if local_path(back) else "/", status_code=303)


@app.get("/theme/{mode}")
def set_theme(request: Request, mode: str):
    """Тема оформления — в cookie на год: светлая, тёмная или как в системе."""
    resp = back_to(request)
    resp.set_cookie("theme", mode if mode in THEMES else "auto", max_age=365 * 86400, httponly=True,
                    secure=settings.cookie_secure, samesite="lax")
    return resp


@app.get("/lang/{code}")
def set_language(request: Request, code: str):
    """Язык интерфейса — в cookie на год; в кабинете клиента он же язык его уведомлений."""
    code = i18n.normalize(code)
    resp = back_to(request)
    resp.set_cookie("lang", code, max_age=365 * 86400, httponly=True, secure=settings.cookie_secure, samesite="lax")
    peer, _ = me_peer(request)
    if peer:
        portal.contact(request.app.state.db, peer["id"])
        request.app.state.db.execute("UPDATE contacts SET lang = ? WHERE peer_id = ?", (code, peer["id"]))
    return resp


@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    if current_user(request):
        return RedirectResponse("/", status_code=303)
    return render(request, "login.html", problems=settings.problems(), error=None)


@app.post("/login", response_class=HTMLResponse)
async def login(request: Request, username: str = Form(""), password: str = Form(""), code: str = Form(""),
                csrf: str = Form("")):
    check_csrf(request, csrf)
    ip = client_ip(request)
    conn = request.app.state.db
    wait = limiter.blocked(ip)
    if wait:
        return render(request, "login.html", problems=[], error=t("Too many attempts. Try again in {n} min.", n=wait // 60 + 1))
    accts = request.app.state.accounts
    row = admins.by_name(conn, username) if not settings.problems() else None
    ok = accts.check_password(row, password)
    enroll = ok and not accts.has_totp(row)
    ok = ok and (enroll or accts.check_totp(row, code))
    if not ok:
        if limiter.fail(ip):
            db.event(conn, "alert_server", detail={"reason": "login_bruteforce"}, actor_ip=ip)
        db.event(conn, "admin_login_failed", detail={"username": username[:64]}, actor_ip=ip)
        return render(request, "login.html", problems=settings.problems(), error=t("Wrong username, password or code."))
    limiter.success(ip)
    request.session.clear()
    if enroll:
        # первый вход: пароль верный, TOTP ещё не привязан — привязка на отдельной странице, сессии пока нет
        tok = secrets.token_urlsafe(24)
        ENROLL[tok] = (row["id"], accts.new_totp_secret(), time.time() + 600)
        request.session.update(enroll=tok, csrf=auth.new_csrf())
        return RedirectResponse("/login/totp", status_code=303)
    start_session(request, row, ip)
    return RedirectResponse("/", status_code=303)


ENROLL: dict[str, tuple[int, str, float]] = {}   # токен → (admin id, секрет TOTP, срок); в памяти, не в cookie


def start_session(request: Request, row, ip: str) -> None:
    request.session.clear()
    request.session.update(aid=row["id"], sv=row["session_ver"], ua=auth.ua_fingerprint(request.headers.get("user-agent", "")),
                           at=int(time.time()), csrf=auth.new_csrf())
    request.app.state.accounts.logged_in(row, ip)
    db.event(request.app.state.db, "admin_login", actor=row["username"], actor_ip=ip)


def enrollment(request: Request):
    tok = request.session.get("enroll", "")
    item = ENROLL.get(tok)
    for k, v in list(ENROLL.items()):
        if v[2] < time.time():
            ENROLL.pop(k, None)
    if not item or item[2] < time.time():
        return None, None, None
    return tok, admins.get(request.app.state.db, item[0]), item[1]


@app.get("/login/totp", response_class=HTMLResponse)
def totp_form(request: Request):
    tok, row, secret = enrollment(request)
    if not row:
        return RedirectResponse("/login", status_code=303)
    uri = request.app.state.accounts.provisioning_uri(row["username"], secret)
    return render(request, "totp_setup.html", username=row["username"], secret=secret, error=None,
                  qr=clientconf.qr_svg(uri).decode())


@app.post("/login/totp", response_class=HTMLResponse)
def totp_bind(request: Request, code: str = Form(""), csrf: str = Form("")):
    check_csrf(request, csrf)
    ip = client_ip(request)
    tok, row, secret = enrollment(request)
    if not row or row["disabled"]:
        return RedirectResponse("/login", status_code=303)
    if limiter.blocked(ip):
        return RedirectResponse("/login", status_code=303)
    if not request.app.state.accounts.bind_totp(row, secret, code, ip):
        limiter.fail(ip)
        uri = request.app.state.accounts.provisioning_uri(row["username"], secret)
        return render(request, "totp_setup.html", username=row["username"], secret=secret,
                      error=t("Wrong code. Check the time on the phone and try again."), qr=clientconf.qr_svg(uri).decode())
    ENROLL.pop(tok, None)
    start_session(request, admins.get(request.app.state.db, row["id"]), ip)
    return RedirectResponse("/", status_code=303)


@app.post("/logout")
async def logout(request: Request, csrf: str = Form("")):
    check_csrf(request, csrf)
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


CLIENTS_SQL = """
SELECT p.id, p.name, p.username, p.disabled, p.created_at, p.last_handshake, p.last_endpoint, p.rx_total, p.tx_total,
       e.country, e.city, e.org,
       COALESCE(t.rx, 0) AS rx_today, COALESCE(t.tx, 0) AS tx_today,
       s.start AS session_start, g.name AS group_name
FROM peers p
LEFT JOIN groups g ON g.id = p.group_id
LEFT JOIN endpoints e ON e.peer_id = p.id AND e.ip = p.last_endpoint
LEFT JOIN (SELECT peer_id, SUM(rx) rx, SUM(tx) tx FROM traffic_hour WHERE ts >= ? GROUP BY peer_id) t ON t.peer_id = p.id
LEFT JOIN sessions s ON s.peer_id = p.id AND s.end IS NULL
WHERE p.deleted_at IS NULL
ORDER BY (s.start IS NULL), COALESCE(p.last_handshake, 0) DESC, p.name
"""


@app.get("/", response_class=HTMLResponse)
def index(request: Request, days: int = 1, group: str = ""):
    conn = request.app.state.db
    now = int(time.time())
    days = days if days in charts.RANGES else 1
    bucket, label = charts.RANGES[days]
    vp = visible_peers(request, group)
    pw, pa = db.peer_filter(vp, "p.id")
    tw, ta = db.peer_filter(vp, "peer_id")
    rows = conn.execute(CLIENTS_SQL.replace("WHERE p.deleted_at IS NULL", "WHERE p.deleted_at IS NULL" + pw),
                        (fmt.day_start(now), *pa)).fetchall()
    clients = [dict(r) | {"status": fmt.status(r, now, settings.online_window)} for r in rows]
    online = sum(c["status"] == "online" for c in clients)
    day_ago = now - 86400 - now % 3600
    totals = conn.execute(f"SELECT COALESCE(SUM(rx), 0), COALESCE(SUM(tx), 0) FROM traffic_hour WHERE ts >= ?{tw}",
                          (day_ago, *ta)).fetchone()
    ew, ea = db.peer_filter(vp, "ev.peer_id")
    events = conn.execute(
        "SELECT ev.ts, ev.kind, ev.detail, p.name FROM events ev LEFT JOIN peers p ON p.id = ev.peer_id "
        f"WHERE 1{ew} ORDER BY ev.id DESC LIMIT 20", ea).fetchall()
    poller = request.app.state.poller
    since = now - days * 86400
    if vp is None:
        peak = conn.execute("SELECT COALESCE(MAX(online), 0) FROM online_min WHERE ts >= ?", (now - 86400,)).fetchone()[0]
        online_series = charts.online_series(conn, since, now, bucket)
    else:   # онлайн по группе — клиенты с трафиком в эту минуту
        peak = max((v for _, v, _ in charts.active_series(conn, now - 86400, now, 60, vp)), default=0)
        online_series = charts.active_series(conn, since, now, bucket, vp)
    alerts = conn.execute(f"SELECT COUNT(*) FROM events WHERE kind LIKE 'alert_%' AND acked = 0{tw}", ta).fetchone()[0]
    top_clients = conn.execute(
        "SELECT p.id, p.name, SUM(t.tx) d, SUM(t.rx) u FROM traffic_hour t JOIN peers p ON p.id = t.peer_id "
        f"WHERE t.ts >= ?{pw} GROUP BY p.id ORDER BY SUM(t.tx + t.rx) DESC LIMIT 10", (day_ago, *pa)).fetchall()
    month = monthly.current_month(now, fmt.TZ)
    m_start, _ = monthly.month_bounds(month, fmt.TZ)

    def top10(start: int) -> str:
        rows = conn.execute("SELECT p.id, p.name, SUM(t.tx) d FROM traffic_hour t JOIN peers p ON p.id = t.peer_id "
                            f"WHERE t.ts >= ?{pw} GROUP BY p.id ORDER BY d DESC LIMIT 10", (start, *pa)).fetchall()
        return charts.hbars([(r["name"], r["d"], f"/peer/{r['id']}") for r in rows if r["d"]])
    return render(request, "index.html", clients=clients, online=online, rx24=totals[0], tx24=totals[1],
                  top_today=top10(fmt.day_start(now)), top_month=top10(m_start), month=month,
                  events=events, poll=poller.status if poller else None, now=now, days=days, peak=peak, alerts=alerts,
                  top_clients=top_clients, group=group, group_list=group_choices(request),
                  traffic_chart=charts.bars(charts.traffic_series(conn, since, now, bucket, vp), fmt.TZ, label),
                  online_chart=charts.bars(online_series, fmt.TZ, label, bytes_axis=False, legend=(t("online"), "")))


def manager(request: Request) -> Manager:
    m = getattr(request.app.state, "manager", None)
    if m is None:
        m = request.app.state.manager = Manager(settings, TT(settings), request.app.state.db)
    return m


def flash(request: Request, text: str, kind: str = "ok") -> None:
    request.session["flash"] = {"text": text, "kind": kind}


def manage_action(request: Request, csrf: str, fn, ok: str, back: str, done=None) -> RedirectResponse:
    """POST-действие управления: CSRF, автор, сообщение об успехе или причине отказа.
    back — куда вернуться при ошибке; done(result) — куда при успехе (по умолчанию тоже back)."""
    check_csrf(request, csrf)
    try:
        res = fn(actor=current_user(request), actor_ip=client_ip(request))
    except (ManageError, TTUnavailable) as e:
        flash(request, str(e), "error")
        return RedirectResponse(back, status_code=303)
    flash(request, ok)
    return RedirectResponse(done(res) if done else back, status_code=303)


def target_group(request: Request, group_id: str) -> int | None:
    """Группа из формы с проверкой прав: супер-администратор — любая или «без группы»; администратор группы — только своя."""
    allowed = allowed_groups(request)
    gid = int(group_id) if group_id.isdigit() and group_id != "0" else None
    if gid is not None and groups.get(request.app.state.db, gid) is None:
        raise ManageError(t("Group not found."))
    if allowed is not None and gid not in allowed:
        raise ManageError(t("Choose one of your groups."))
    return gid


@app.post("/peers/add")
def peer_add(request: Request, name: str = Form(""), note: str = Form(""), username: str = Form(""), group_id: str = Form(""),
             csrf: str = Form("")):
    def go(**kw):
        gid = target_group(request, group_id)          # права — до создания клиента
        pid = manager(request).add(name, note, username, **kw)
        if gid is not None:
            groups.set_peer_group(request.app.state.db, pid, gid, **kw)
        return pid
    return manage_action(request, csrf, go, t("Client “{name}” added.", name=name.strip()), "/", lambda pid: f"/peer/{pid}/config")


@app.post("/peer/{peer_id}/quota")
def peer_quota(request: Request, peer_id: int, gib: str = Form(""), period: str = Form("month"), action: str = Form("alert"),
               csrf: str = Form("")):
    def go(**kw):
        try:
            quotas.set_peer_quota(request.app.state.db, peer_id, gib, period, action, **kw)
        except QuotaError as e:
            raise ManageError(str(e)) from e
    return manage_action(request, csrf, go, t("Quota saved."), f"/peer/{peer_id}")


@app.post("/peer/{peer_id}/group")
def peer_group(request: Request, peer_id: int, group_id: str = Form(""), csrf: str = Form("")):
    def go(**kw):
        try:
            groups.set_peer_group(request.app.state.db, peer_id, target_group(request, group_id), **kw)
        except GroupError as e:
            raise ManageError(str(e)) from e
    return manage_action(request, csrf, go, t("Group changed."), f"/peer/{peer_id}")


@app.get("/peer/{peer_id}", response_class=HTMLResponse)
def peer_page(request: Request, peer_id: int, days: int = 1):
    conn = request.app.state.db
    now = int(time.time())
    row = conn.execute(CLIENTS_SQL.replace("WHERE p.deleted_at IS NULL", "WHERE p.id = ?"),
                       (fmt.day_start(now), peer_id)).fetchone()
    if row is None:
        raise HTTPException(404)
    peer = dict(row) | {"status": fmt.status(row, now, settings.online_window)}
    extra = conn.execute("SELECT username, note, source, deleted_at, group_id, quota_bytes, quota_period, quota_action, "
                         "quota_blocked, password_enc IS NOT NULL AS has_key FROM peers WHERE id = ?", (peer_id,)).fetchone()
    pg = groups.get(conn, extra["group_id"]) if extra["group_id"] else None
    quota = quotas.status(conn, extra["quota_bytes"], extra["quota_period"], peer_id, now)
    group_quota = quotas.status(conn, pg["quota_bytes"], pg["quota_period"], groups.peers_of(conn, {pg["id"]}), now) if pg else None
    sessions = conn.execute("SELECT s.*, e.country, e.org FROM sessions s LEFT JOIN endpoints e "
                            "ON e.peer_id = s.peer_id AND e.ip = s.endpoint_ip WHERE s.peer_id = ? ORDER BY s.start DESC LIMIT 50",
                            (peer_id,)).fetchall()
    endpoints = conn.execute("SELECT * FROM endpoints WHERE peer_id = ? ORDER BY last_seen DESC", (peer_id,)).fetchall()
    events = conn.execute("SELECT ts, kind, detail, actor FROM events WHERE peer_id = ? ORDER BY id DESC LIMIT 50",
                          (peer_id,)).fetchall()
    days = days if days in (1, 7, 30) else 1
    bucket, label = charts.RANGES[days]
    contact = portal.contact(conn, peer_id)
    return render(request, "peer.html", contact=contact, portal_on=extra_portal(conn, peer_id),
                  group_list=group_choices(request), peer_group=pg, quota=quota, group_quota=group_quota,
                  portal_config=conn.execute("SELECT portal_config FROM peers WHERE id = ?", (peer_id,)).fetchone()[0],
                  notifier=request.app.state.notifier, peer=peer, extra=extra, sessions=sessions, endpoints=endpoints,
                  events=events, now=now, days=days,
                  traffic_chart=charts.bars(charts.traffic_series(conn, now - days * 86400, now, bucket, peer_id), fmt.TZ, label),
                  heat=charts.heatmap(charts.activity_cells(conn, peer_id, now - 30 * 86400, fmt.TZ)))


def build_config(m: Manager, peer_id: int) -> dict | None:
    """tt:// (приложения TrustTunnel) и TOML (CLI-клиент) или None, если пароля клиента у панели нет."""
    row = m.conn.execute("SELECT name, username, deleted_at, disabled FROM peers WHERE id = ?", (peer_id,)).fetchone()
    password = m.password(peer_id) if row and not row["deleted_at"] else None
    if not password:
        return None
    return {"name": row["name"], "username": row["username"], "disabled": row["disabled"],
            "vpn": m.tt.export(row["username"], password, "deeplink"), "conf": m.tt.export(row["username"], password, "toml"),
            "address": settings.tt_address}


def client_config(request: Request, peer_id: int) -> dict:
    """Конфиг клиента; пароль панель знает для всех, кого видела в credentials.toml или создала сама."""
    try:
        cfg = build_config(manager(request), peer_id)
    except TTUnavailable as e:
        raise HTTPException(503, t("TrustTunnel could not export the config: {error}", error=e)) from e
    if not cfg:
        raise HTTPException(404, t("The panel does not know this client's password: issue a new one."))
    return cfg


def content_disposition(name: str, username: str) -> str:
    """Заголовки HTTP — только latin-1: ASCII-имя tt-<логин>.toml плюс имя клиента в filename* (RFC 5987)."""
    keep = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in name).strip("_")[:40] or "client"
    return f"attachment; filename=\"tt-{username}.toml\"; filename*=UTF-8''{quote(keep)}.toml"


@app.get("/peer/{peer_id}/config", response_class=HTMLResponse)
def peer_config(request: Request, peer_id: int):
    cfg = client_config(request, peer_id)
    conn = request.app.state.db
    db.event(conn, "admin_config_view", peer_id, None, current_user(request), client_ip(request))
    link = request.session.pop("botlink", None)
    n = notifier(request)
    return render(request, "config.html", peer_id=peer_id, cfg=cfg, contact=portal.contact(conn, peer_id),
                  tg_bot=tg_bot_name(request), email_on=n.email_on,
                  botlink=link["url"] if link and link.get("peer") == peer_id else None)


@app.post("/peer/{peer_id}/rekey")
def peer_rekey(request: Request, peer_id: int, csrf: str = Form("")):
    return manage_action(request, csrf, lambda **kw: manager(request).rekey(peer_id, **kw),
                         t("New password issued: the old config no longer works, send the new one to the client."),
                         f"/peer/{peer_id}", lambda _: f"/peer/{peer_id}/config")


@app.post("/peer/{peer_id}/contacts")
def peer_contacts(request: Request, peer_id: int, tg_id: str = Form(""), email: str = Form(""), with_email: str = Form(""),
                  csrf: str = Form("")):
    """Telegram ID и e-mail клиента — вводит администратор. Новый Telegram ID проверяется пробным сообщением:
    бот может писать только тем, кто хоть раз нажал у него «Старт»."""
    check_csrf(request, csrf)
    conn = request.app.state.db
    c = portal.contact(conn, peer_id)
    raw = tg_id.strip().removeprefix("id").strip()
    tg, tg_name = c["tg_chat_id"], c["tg_name"]
    try:
        if not raw:
            tg = tg_name = None
        elif not re.fullmatch(r"-?\d{3,20}", raw):
            raise ValueError(t("Telegram ID is a number, e.g. 123456789 (the client can get it from @userinfobot)."))
        elif int(raw) != c["tg_chat_id"]:
            n = notifier(request)
            if not n.tg:
                raise ValueError(t("The Telegram bot is not configured: add TELEGRAM_BOT_TOKEN to .env on the server."))
            name = conn.execute("SELECT name FROM peers WHERE id = ?", (peer_id,)).fetchone()[0]
            try:
                with i18n.use(n.lang(peer_id)):
                    n.tg.send(int(raw), t("VPN notifications for “{name}” will come here.", name=name))
            except Exception as e:  # noqa: BLE001
                raise ValueError(t("The bot cannot write to this ID ({error}). The client must open @{bot} and press “Start” once.",
                                   error=str(e).removeprefix("Telegram sendMessage: "), bot=n.tg.me())) from e
            tg, tg_name = int(raw), f"id {raw}"
        portal.set_contacts_by_admin(conn, peer_id, tg, tg_name, email if with_email else None,   # нет поля почты — не трогаем
                                     current_user(request), client_ip(request))
        flash(request, t("Contacts saved."))
    except ValueError as e:
        flash(request, str(e), "error")
    back = request.headers.get("referer", "")
    return RedirectResponse(f"/peer/{peer_id}/config#send" if back.endswith("/config") else f"/peer/{peer_id}#contacts",
                            status_code=303)


@app.post("/peer/{peer_id}/send")
def peer_send(request: Request, peer_id: int, channel: str = Form(""), to: str = Form(""), csrf: str = Form("")):
    check_csrf(request, csrf)
    try:
        where = notifier(request).send_config(peer_id, channel, to, current_user(request), client_ip(request))
        flash(request, t("Config sent: {to}.", to=where))
    except Exception as e:  # noqa: BLE001 — показать причину (нет Telegram, ошибка SMTP и т. п.)
        flash(request, t("Not sent: {error}", error=e), "error")
    return RedirectResponse(f"/peer/{peer_id}/config", status_code=303)


@app.post("/peer/{peer_id}/botlink")
def peer_botlink(request: Request, peer_id: int, csrf: str = Form("")):
    check_csrf(request, csrf)
    bot = tg_bot_name(request)
    if not bot:
        raise HTTPException(404)
    code = portal.config_link_code(request.app.state.db, peer_id)
    db.event(request.app.state.db, "config_link_issued", peer_id, None, current_user(request), client_ip(request))
    request.session["botlink"] = {"peer": peer_id, "url": f"https://t.me/{bot}?start={code}"}   # показывается один раз
    return RedirectResponse(f"/peer/{peer_id}/config#send", status_code=303)


@app.get("/peer/{peer_id}/config.toml")
def peer_config_file(request: Request, peer_id: int):
    cfg = client_config(request, peer_id)
    return Response(cfg["conf"], media_type="text/plain; charset=utf-8",
                    headers={"Content-Disposition": content_disposition(cfg["name"], cfg["username"]), "Cache-Control": "no-store"})


@app.get("/peer/{peer_id}/qr/{kind}.svg")
def peer_qr(request: Request, peer_id: int, kind: str):
    if kind != "vpn":       # TOML с сертификатом в QR не помещается — только tt://
        raise HTTPException(404)
    cfg = client_config(request, peer_id)
    try:
        svg = clientconf.qr_svg(cfg[kind])
    except Exception:  # qrcode.exceptions.DataOverflowError — не помещается в один QR
        raise HTTPException(422, t("Too long for a single QR code"))
    return Response(svg, media_type="image/svg+xml", headers={"Cache-Control": "no-store"})


@app.post("/peer/{peer_id}/rename")
def peer_rename(request: Request, peer_id: int, name: str = Form(""), csrf: str = Form("")):
    return manage_action(request, csrf, lambda **kw: manager(request).rename(peer_id, name, **kw), t("Name changed."), f"/peer/{peer_id}")


@app.post("/peer/{peer_id}/disable")
def peer_disable(request: Request, peer_id: int, csrf: str = Form("")):
    return manage_action(request, csrf, lambda **kw: manager(request).disable(peer_id, **kw), t("Client disabled."), f"/peer/{peer_id}")


@app.post("/peer/{peer_id}/enable")
def peer_enable(request: Request, peer_id: int, csrf: str = Form("")):
    return manage_action(request, csrf, lambda **kw: manager(request).enable(peer_id, **kw), t("Client enabled again."), f"/peer/{peer_id}")


@app.post("/peer/{peer_id}/delete")
def peer_delete(request: Request, peer_id: int, confirm: str = Form(""), csrf: str = Form("")):
    return manage_action(request, csrf, lambda **kw: manager(request).delete(peer_id, confirm, **kw),
                         t("Client deleted. History is kept."), f"/peer/{peer_id}", lambda _: "/")


def local_path(path: str) -> bool:
    """Путь на этом же сайте: «/\\evil.com» и «//evil.com» браузер понимает как другой хост."""
    return path.startswith("/") and not path.startswith(("//", "/\\")) and not any(c in path for c in "\\\r\n")


EVENTS_SQL = """SELECT e.id, e.ts, e.kind, e.detail, e.actor, e.actor_ip, e.acked, e.peer_id, p.name
FROM events e LEFT JOIN peers p ON p.id = e.peer_id WHERE e.ts >= ? {filters} ORDER BY e.id DESC"""


def events_query(conn, days: int, kind: str, peer_id: str, limit: int | None, peers=None):
    """peers — видимые клиенты (None — все); у администратора группы нет событий без клиента (сервер, админы)."""
    filters, args = db.peer_filter(peers, "e.peer_id")
    args = [int(time.time()) - days * 86400, *args]
    if kind:
        filters += " AND e.kind LIKE ?"
        args.append(kind.rstrip("*") + "%" if kind.endswith("*") else kind)
    if peer_id.isdigit():
        filters += " AND e.peer_id = ?"
        args.append(int(peer_id))
    sql = EVENTS_SQL.format(filters=filters) + (f" LIMIT {int(limit)}" if limit else "")
    return conn.execute(sql, args).fetchall()


EVENT_GROUPS = {"": N_("all"), "connect": N_("connections"), "disconnect": N_("disconnections"), "endpoint_change": N_("IP changes"),
                "alert_*": N_("alerts"), "admin_*": N_("administrator actions"),
                "peer_*": N_("client changes outside the panel")}


@app.get("/events", response_class=HTMLResponse)
def events_page(request: Request, days: int = 7, kind: str = "", peer_id: str = "", group: str = ""):
    conn = request.app.state.db
    days = max(1, min(days, 365))
    vp = visible_peers(request, group)
    rows = events_query(conn, days, kind, peer_id, 1000, vp)
    pw, pa = db.peer_filter(vp, "id")
    peers = conn.execute(f"SELECT id, name FROM peers WHERE 1{pw} ORDER BY name", pa).fetchall()
    return render(request, "events.html", rows=rows, days=days, kind=kind, peer_id=peer_id, peers=peers, groups=EVENT_GROUPS,
                  group=group, group_list=group_choices(request))


@app.get("/events.csv")
def events_csv(request: Request, days: int = 7, kind: str = "", peer_id: str = "", group: str = ""):
    rows = events_query(request.app.state.db, max(1, min(days, 365)), kind, peer_id, None, visible_peers(request, group))
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow([t("time"), t("client"), t("event"), t("description"), t("who"), t("admin IP"), t("details JSON")])
    for r in rows:
        w.writerow(map(csv_cell, [fmt.dt(r["ts"], "%Y-%m-%d %H:%M:%S"), r["name"] or "", fmt.event_name(r["kind"]),
                                  fmt.event_text(r["kind"], r["detail"]), r["actor"] or "", r["actor_ip"] or "",
                                  r["detail"] or ""]))
    return Response("\ufeff" + buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="tt-events-{days}d.csv"', "Cache-Control": "no-store"})


@app.get("/alerts", response_class=HTMLResponse)
def alerts_page(request: Request, days: int = 30):
    ew, ea = db.peer_filter(visible_peers(request), "e.peer_id")
    rows = request.app.state.db.execute(
        "SELECT e.*, p.name FROM events e LEFT JOIN peers p ON p.id = e.peer_id WHERE e.kind LIKE 'alert_%' AND e.ts >= ?"
        f"{ew} ORDER BY e.acked, e.id DESC LIMIT 500", (int(time.time()) - max(1, min(days, 365)) * 86400, *ea)).fetchall()
    return render(request, "alerts.html", rows=rows, days=days)


@app.post("/alerts/ack")
def alerts_ack(request: Request, alert_id: str = Form(""), csrf: str = Form("")):
    check_csrf(request, csrf)
    conn = request.app.state.db
    ew, ea = db.peer_filter(visible_peers(request), "peer_id")
    if alert_id.isdigit():
        conn.execute(f"UPDATE events SET acked = 1 WHERE id = ? AND kind LIKE 'alert_%'{ew}", (int(alert_id), *ea))
    else:
        conn.execute(f"UPDATE events SET acked = 1 WHERE kind LIKE 'alert_%' AND acked = 0{ew}", ea)
    return RedirectResponse("/alerts", status_code=303)


def server_info(request: Request) -> dict:
    """Состояние сервера и панели для страницы «Сервер». Пароли клиентов не показываются."""
    st = request.app.state
    info: dict = {"errors": []}
    try:
        tt = TT(settings)
        svc = tt.service()
        info["pid"] = svc["pid"]
        info["state"] = svc["state"]
        info["started"] = int(tt.started_at()) if svc["pid"] else None
        info["version"] = tt.version()
        vpn = tt.vpn_settings()
        info["params"] = {"listen_address": vpn.get("listen_address"), "hosts": ", ".join(tt.hosts()),
                          "listen_protocols": ", ".join(vpn.get("listen_protocols", {})),
                          "ipv6_available": vpn.get("ipv6_available"),
                          "allow_private_network_connections": vpn.get("allow_private_network_connections"),
                          "client address": settings.tt_address}
        m = tt.metrics()
        info["metrics"] = {k: int(v) for k, v in m.items() if k.split("{")[0] in (
            "client_sessions", "outbound_tcp_sockets", "outbound_udp_sockets", "process_resident_memory_bytes",
            "process_open_fds", "process_threads")}
    except Exception as e:  # noqa: BLE001 — страница должна открываться и при недоступном TrustTunnel
        info["errors"].append(f"TrustTunnel: {e}")
    try:
        cnt, mx = (int(open(f"/proc/sys/net/netfilter/nf_conntrack_{k}").read()) for k in ("count", "max"))
        info["conntrack"] = (cnt, mx)
    except (OSError, ValueError):
        pass
    try:
        la = open("/proc/loadavg").read().split()[:3]
        mem = dict(line.split(":", 1) for line in open("/proc/meminfo").read().splitlines() if ":" in line)
        kb = lambda k: int(mem[k].split()[0]) * 1024  # noqa: E731
        info["load"] = la
        info["mem"] = (kb("MemTotal") - kb("MemAvailable"), kb("MemTotal"))
        info["cpus"] = os.cpu_count()
    except (OSError, KeyError, ValueError) as e:
        info["errors"].append(f"/proc: {e}")
    vfs = os.statvfs(settings.data_dir)
    info["disk"] = ((vfs.f_blocks - vfs.f_bavail) * vfs.f_frsize, vfs.f_blocks * vfs.f_frsize)
    info["db_size"] = sum(p.stat().st_size for p in settings.data_dir.glob("panel.db*") if p.exists())
    info["geo"] = st.geo.built() if st.geo else None
    info["collectors"] = {
        N_("TrustTunnel polling"): st.poller and (st.poller.status.last_ok, st.poller.status.last_error),
    }
    root = settings.data_dir / "backups"
    info["backups"] = sorted((p.name for p in root.iterdir() if p.is_dir()), reverse=True)[:15] if root.exists() else []
    info["backups_total"] = len(list(root.iterdir())) if root.exists() else 0
    return info


# ---- группы ----

def group_rows(request: Request) -> list[dict]:
    """Видимые группы с итогами: клиенты, онлайн, трафик сегодня и за месяц, администраторы."""
    conn = request.app.state.db
    now = int(time.time())
    m_start, _ = monthly.month_bounds(monthly.current_month(now, fmt.TZ), fmt.TZ)
    admins_by = groups.admins_of(conn)
    online_since = now - settings.online_window
    out = []
    for g in group_choices(request):
        stat = conn.execute(
            "SELECT COALESCE(SUM(CASE WHEN t.ts >= ? THEN t.tx END), 0) d_today, COALESCE(SUM(CASE WHEN t.ts >= ? THEN t.rx END), 0) "
            "u_today, COALESCE(SUM(t.tx), 0) d_month, COALESCE(SUM(t.rx), 0) u_month FROM traffic_hour t "
            "JOIN peers p ON p.id = t.peer_id WHERE p.group_id = ? AND t.ts >= ?",
            (fmt.day_start(now), fmt.day_start(now), g["id"], m_start)).fetchone()
        online = conn.execute("SELECT COUNT(*) FROM peers WHERE group_id = ? AND deleted_at IS NULL AND disabled = 0 "
                              "AND last_handshake >= ?", (g["id"], online_since)).fetchone()[0]
        quota = quotas.status(conn, g["quota_bytes"], g["quota_period"], groups.peers_of(conn, {g["id"]}), now)
        out.append(dict(g) | dict(stat) | {"online": online, "admins": admins_by.get(g["id"], []), "quota": quota})
    return out


@app.get("/groups", response_class=HTMLResponse)
def groups_page(request: Request):
    conn = request.app.state.db
    nogroup = conn.execute("SELECT COUNT(*) FROM peers WHERE group_id IS NULL AND deleted_at IS NULL").fetchone()[0]
    rows = group_rows(request)
    chart = charts.hbars(sorted(((g["name"], g["d_month"] + g["u_month"], f"/?group={g['id']}") for g in rows
                                 if g["d_month"] + g["u_month"]), key=lambda x: -x[1]))
    return render(request, "groups.html", rows=rows, nogroup=nogroup, chart=chart)


@app.get("/groups.csv")
def groups_csv(request: Request):
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow([t("group"), t("clients"), t("online"), t("downloaded today, bytes"), t("uploaded today, bytes"),
                t("downloaded this month, bytes"), t("uploaded this month, bytes"), t("quota, bytes"), t("quota period"),
                t("quota used, %"), t("administrators")])
    for g in group_rows(request):
        q = g["quota"]
        w.writerow(map(csv_cell, [g["name"], g["clients"], g["online"], g["d_today"], g["u_today"], g["d_month"], g["u_month"],
                                  q["limit"] if q else "", q["period"] if q else "", q["pct"] if q else "",
                                  ", ".join(g["admins"])]))
    return Response("\ufeff" + buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="tt-groups.csv"', "Cache-Control": "no-store"})


def group_action(request: Request, csrf: str, fn, ok: str) -> RedirectResponse:
    require_super(request)
    check_csrf(request, csrf)
    try:
        fn(actor=current_user(request), actor_ip=client_ip(request))
    except (GroupError, QuotaError) as e:
        flash(request, str(e), "error")
        return RedirectResponse("/groups", status_code=303)
    flash(request, ok)
    return RedirectResponse("/groups", status_code=303)


@app.post("/groups/add")
def groups_add(request: Request, name: str = Form(""), note: str = Form(""), csrf: str = Form("")):
    return group_action(request, csrf, lambda **kw: groups.create(request.app.state.db, name, note, **kw),
                        t("Group “{name}” created.", name=" ".join(name.split())))


@app.post("/groups/{group_id}/update")
def groups_update(request: Request, group_id: int, name: str = Form(""), note: str = Form(""), csrf: str = Form("")):
    return group_action(request, csrf, lambda **kw: groups.update(request.app.state.db, group_id, name, note, **kw),
                        t("Group saved."))


@app.post("/groups/{group_id}/quota")
def groups_quota(request: Request, group_id: int, gib: str = Form(""), period: str = Form("month"),
                 action: str = Form("alert"), csrf: str = Form("")):
    return group_action(request, csrf, lambda **kw: quotas.set_group_quota(request.app.state.db, group_id, gib, period, action, **kw),
                        t("Quota saved."))


@app.post("/groups/{group_id}/delete")
def groups_delete(request: Request, group_id: int, csrf: str = Form("")):
    return group_action(request, csrf, lambda **kw: groups.delete(request.app.state.db, group_id, **kw),
                        t("Group deleted; its clients now have no group."))


# ---- бэкапы ----

def backups(request: Request) -> backup.Backups:
    b = request.app.state.backups
    if b is None:
        n = notifier(request)
        b = request.app.state.backups = backup.Backups(settings, request.app.state.db, n, load_fernet(settings), TT(settings))
    return b


@app.get("/backups", response_class=HTMLResponse)
def backups_page(request: Request):
    row = current_admin(request)
    conn = request.app.state.db
    return render(request, "backups.html", job=backup.job(conn, row["id"]), tg_bot=tg_bot_name(request),
                  email_on=notifier(request).email_on,
                  my_groups=[g["name"] for g in group_choices(request)] if row["role"] != "super" else [],
                  history=conn.execute("SELECT ts, kind, detail FROM events WHERE kind IN ('backup_sent', 'alert_backup') "
                                       "AND detail LIKE ? ORDER BY id DESC LIMIT 10",
                                       (f'%"username": "{row["username"]}"%',)).fetchall())


@app.post("/backups/save")
def backups_save(request: Request, enabled: str = Form(""), to_telegram: str = Form(""), to_email: str = Form(""),
                 email: str = Form(""), period: str = Form("daily"), hour: str = Form("3"), weekday: str = Form("0"),
                 password: str = Form(""), csrf: str = Form("")):
    check_csrf(request, csrf)
    try:
        backup.save_job(request.app.state.db, load_fernet(settings), current_admin(request)["id"], enabled == "1",
                        to_telegram == "1", to_email == "1", email, period, hour, weekday, password)
        flash(request, t("Backup settings saved."))
    except backup.BackupError as e:
        flash(request, str(e), "error")
    return RedirectResponse("/backups", status_code=303)


@app.post("/backups/restore")
async def backups_restore(request: Request):
    """Восстановление на этом сервере (супер-администратор): настройки TrustTunnel — сразу, база — с перезапуском панели."""
    require_super(request)
    form = await request.form()
    check_csrf(request, str(form.get("csrf", "")))
    parts = {p for p in backup.PARTS if form.get(f"part_{p}") == "1"} - {"env"}
    try:
        if str(form.get("confirm", "")).strip().upper() != "RESTORE":
            raise backup.BackupError(t("Type RESTORE to confirm."))
        upload = form.get("file")
        if not parts or upload is None or not hasattr(upload, "read"):
            raise backup.BackupError(t("Choose the backup file and what to restore."))
        files = backup.read_archive(await upload.read(), str(form.get("password", "")))
        done = backup.restore(files, settings, TT(settings), parts, live=True)
    except (backup.BackupError, TTUnavailable, OSError) as e:
        flash(request, t("Not restored: {error}", error=e), "error")
        return RedirectResponse("/backups#restore", status_code=303)
    db.event(request.app.state.db, "backup_restored", None, {"parts": sorted(parts), "done": done},
             current_user(request), client_ip(request))
    if "db" in parts:
        request.session.clear()   # сессии — из старой базы
        request.app.state.restart()
        return render(request, "restoring.html", done=done)
    flash(request, t("Restored: {items}.", items="; ".join(done)))
    return RedirectResponse("/backups", status_code=303)


@app.post("/backups/run")
def backups_run(request: Request, csrf: str = Form("")):
    check_csrf(request, csrf)
    status = backups(request).run(current_admin(request)["id"])
    j = backup.job(request.app.state.db, current_admin(request)["id"])
    flash(request, t("Backup: {status}", status=status), "ok" if j["last_ok"] else "error")
    return RedirectResponse("/backups", status_code=303)


# ---- учётки администраторов ----

def tg_bot_name(request: Request) -> str | None:
    n = notifier(request)
    try:
        return n.tg.me() if n and n.tg else None
    except Exception:  # noqa: BLE001 — страница открывается и без Telegram
        return None


@app.get("/account", response_class=HTMLResponse)
def account_page(request: Request):
    return render(request, "account.html", error=None, tg_bot=tg_bot_name(request))


@app.post("/account/telegram")
def account_telegram(request: Request, csrf: str = Form("")):
    check_csrf(request, csrf)
    bot = tg_bot_name(request)
    if not bot:
        raise HTTPException(404)
    code = admins.telegram_code(request.app.state.db, current_admin(request)["id"], i18n.get())
    return RedirectResponse(f"https://t.me/{bot}?start={code}", status_code=303)


@app.post("/account/telegram/unlink")
def account_telegram_unlink(request: Request, csrf: str = Form("")):
    check_csrf(request, csrf)
    admins.unbind_telegram(request.app.state.db, current_admin(request)["id"])
    flash(request, t("Telegram disconnected."))
    return RedirectResponse("/account", status_code=303)


@app.post("/account/notify")
def account_notify(request: Request, alerts: str = Form(""), logins: str = Form(""), quiet_from: str = Form(""),
                   quiet_to: str = Form(""), csrf: str = Form("")):
    check_csrf(request, csrf)
    admins.set_notify(request.app.state.db, current_admin(request)["id"], alerts == "1", logins == "1", quiet_from, quiet_to)
    flash(request, t("Notification settings saved."))
    return RedirectResponse("/account", status_code=303)


@app.post("/account", response_class=HTMLResponse)
def account_password(request: Request, current: str = Form(""), new: str = Form(""), repeat: str = Form(""),
                     csrf: str = Form("")):
    check_csrf(request, csrf)
    row = current_admin(request)
    try:
        request.app.state.accounts.change_password(row, current, new, repeat, client_ip(request))
    except AdminError as e:
        return render(request, "account.html", error=str(e), tg_bot=tg_bot_name(request))
    flash(request, t("Password changed."))
    return RedirectResponse("/", status_code=303)


@app.get("/admins", response_class=HTMLResponse)
def admins_page(request: Request):
    require_super(request)
    conn = request.app.state.db
    return render(request, "admins.html", rows=admins.all_admins(conn), roles=admins.creatable_roles(),
                  ip_rows=ipallow.entries(conn), my_ip=client_ip(request),
                  group_list=groups.all_groups(conn),
                  member={a["id"]: groups.admin_group_ids(conn, a["id"]) for a in admins.all_admins(conn)},
                  new_password=request.session.pop("new_password", None))


def admin_action(request: Request, csrf: str, fn, ok: str) -> RedirectResponse:
    require_super(request)
    check_csrf(request, csrf)
    try:
        res = fn(actor=current_user(request), actor_ip=client_ip(request))
    except AdminError as e:
        flash(request, str(e), "error")
        return RedirectResponse("/admins", status_code=303)
    if isinstance(res, tuple):   # (логин, временный пароль) — показать один раз
        request.session["new_password"] = {"username": res[0], "password": res[1]}
    flash(request, ok)
    return RedirectResponse("/admins", status_code=303)


@app.post("/admins/add")
def admins_add(request: Request, username: str = Form(""), role: str = Form("super"), note: str = Form(""),
               csrf: str = Form("")):
    accts = request.app.state.accounts
    return admin_action(request, csrf, lambda **kw: (username.strip(), accts.create(username, role, note, **kw)),
                        t("Administrator “{name}” added.", name=username.strip()))


@app.post("/admins/{admin_id}/reset")
def admins_reset(request: Request, admin_id: int, csrf: str = Form("")):
    accts = request.app.state.accounts
    row = admins.get(request.app.state.db, admin_id)
    name = row["username"] if row else "?"
    return admin_action(request, csrf, lambda **kw: (name, accts.reset(admin_id, **kw)),
                        t("Password and authenticator of “{name}” reset.", name=name))


@app.post("/admins/{admin_id}/disable")
def admins_disable(request: Request, admin_id: int, csrf: str = Form("")):
    return admin_action(request, csrf, lambda **kw: request.app.state.accounts.set_disabled(admin_id, True, **kw),
                        t("Administrator disabled."))


@app.post("/admins/{admin_id}/enable")
def admins_enable(request: Request, admin_id: int, csrf: str = Form("")):
    return admin_action(request, csrf, lambda **kw: request.app.state.accounts.set_disabled(admin_id, False, **kw),
                        t("Administrator enabled."))


@app.post("/admins/{admin_id}/role")
def admins_role(request: Request, admin_id: int, role: str = Form(""), csrf: str = Form("")):
    return admin_action(request, csrf, lambda **kw: request.app.state.accounts.set_role(admin_id, role, **kw),
                        t("Role changed."))


@app.post("/admins/{admin_id}/groups")
def admins_groups(request: Request, admin_id: int, group_ids: list[str] = Form([]), csrf: str = Form("")):
    ids = {int(g) for g in group_ids if g.isdigit()}
    return admin_action(request, csrf, lambda **kw: groups.set_admin_groups(request.app.state.db, admin_id, ids, **kw),
                        t("Groups of the administrator saved."))


@app.post("/admins/ip/add")
def admins_ip_add(request: Request, cidr: str = Form(""), note: str = Form(""), csrf: str = Form("")):
    require_super(request)
    check_csrf(request, csrf)
    try:
        added = ipallow.add(request.app.state.db, cidr, note, current_user(request), client_ip(request), keep_ip=client_ip(request))
        flash(request, t("{cidr} added: the panel opens only from the listed addresses.", cidr=added))
    except ipallow.IPAllowError as e:
        flash(request, str(e), "error")
    return RedirectResponse("/admins#ip", status_code=303)


@app.post("/admins/ip/{entry_id}/delete")
def admins_ip_delete(request: Request, entry_id: int, csrf: str = Form("")):
    require_super(request)
    check_csrf(request, csrf)
    try:
        removed = ipallow.remove(request.app.state.db, str(entry_id), current_user(request), client_ip(request),
                                 keep_ip=client_ip(request))
        flash(request, t("{cidr} removed.", cidr=removed))
    except ipallow.IPAllowError as e:
        flash(request, str(e), "error")
    return RedirectResponse("/admins#ip", status_code=303)


@app.post("/admins/{admin_id}/delete")
def admins_delete(request: Request, admin_id: int, csrf: str = Form("")):
    return admin_action(request, csrf, lambda **kw: request.app.state.accounts.delete(admin_id, **kw),
                        t("Administrator deleted."))


@app.get("/server", response_class=HTMLResponse)
def server_page(request: Request):
    require_super(request)
    return render(request, "server.html", info=server_info(request), now=int(time.time()))


@app.get("/archive", response_class=HTMLResponse)
def archive_page(request: Request, month: str = "", group: str = ""):
    conn = request.app.state.db
    months = [r[0] for r in conn.execute("SELECT DISTINCT month FROM monthly_archive ORDER BY month DESC")]
    month = month if month in months else (months[0] if months else "")
    pw, pa = db.peer_filter(visible_peers(request, group))
    rows = conn.execute(f"SELECT * FROM monthly_archive WHERE month = ?{pw} ORDER BY tx DESC", (month, *pa)).fetchall()
    chart = charts.hbars([(r["name"] or r["username"], r["tx"], f"/peer/{r['peer_id']}") for r in rows[:10] if r["tx"]])
    gname = {g["id"]: g["name"] for g in group_choices(request)}
    member = {r[0]: r[1] for r in conn.execute("SELECT id, group_id FROM peers")}
    by_group: dict[str, list[int]] = {}
    for r in rows:
        key = gname.get(member.get(r["peer_id"]), t("no group"))
        a = by_group.setdefault(key, [0, 0, 0])
        a[0] += r["tx"]
        a[1] += r["rx"]
        a[2] += 1
    group_totals = sorted(by_group.items(), key=lambda x: -x[1][0])
    return render(request, "archive.html", months=months, month=month, rows=rows, chart=chart,
                  group=group, group_list=group_choices(request), group_totals=group_totals,
                  total=(sum(r["tx"] for r in rows), sum(r["rx"] for r in rows)))


def csv_cell(v):
    """Ячейка CSV без формул: имя клиента вида «=HYPERLINK(…)» Excel иначе выполнит при открытии."""
    return "'" + v if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r") else v


@app.get("/archive/{month}.csv")
def archive_csv(request: Request, month: str, group: str = ""):
    if not re.fullmatch(r"\d{4}-\d{2}", month):
        raise HTTPException(404)
    pw, pa = db.peer_filter(visible_peers(request, group))
    rows = request.app.state.db.execute(f"SELECT * FROM monthly_archive WHERE month = ?{pw} ORDER BY tx DESC",
                                        (month, *pa)).fetchall()
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow([t("month"), t("client"), t("login"), t("downloaded, bytes"), t("uploaded, bytes"), t("sessions"), t("online, h")])
    for r in rows:
        w.writerow(map(csv_cell, [r["month"], r["name"], r["username"], r["tx"], r["rx"], r["sessions"],
                                  round(r["online_sec"] / 3600, 1)]))
    return Response("\ufeff" + buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="tt-{month}.csv"'})


def extra_portal(conn, peer_id: int) -> bool:
    return bool(conn.execute("SELECT portal_hash FROM peers WHERE id = ?", (peer_id,)).fetchone()[0])


def notifier(request: Request) -> notify.Notifier:
    n = request.app.state.notifier
    if n is None:
        n = request.app.state.notifier = notify.Notifier(settings, request.app.state.db)
        attach_config(n)
    return n


def attach_config(n: notify.Notifier) -> None:
    """Боту и отправке нужен конфиг клиента — его экспортирует TrustTunnel (соединение уведомлений)."""
    n.config_for = lambda peer_id: build_config(Manager(settings, TT(settings), n.conn), peer_id)


@app.post("/peer/{peer_id}/portal")
def peer_portal(request: Request, peer_id: int, action: str = Form(""), csrf: str = Form("")):
    """Личный кабинет клиента: выдать/отозвать ссылку, разрешить скачивание конфига, тестовое уведомление."""
    check_csrf(request, csrf)
    conn, who, ip = request.app.state.db, current_user(request), client_ip(request)
    if action == "issue":
        token = portal.issue_link(conn, peer_id, who, ip)
        flash(request, t("Personal link (shown once, the old one no longer works): {url}", url=f"{settings.base_url}/me/k/{token}"))
    elif action == "revoke":
        portal.revoke_link(conn, peer_id, who, ip)
        flash(request, t("Link revoked: the client portal is closed."))
    elif action in ("config_on", "config_off"):
        conn.execute("UPDATE peers SET portal_config = ? WHERE id = ?", (int(action == "config_on"), peer_id))
        flash(request, t("Config download in the portal is allowed.") if action == "config_on" else t("Config download in the portal is forbidden."))
    elif action == "test":
        n = notifier(request).daily(peer_id)
        flash(request, t("Report sent: channels {n}.", n=n) if n else t("Not sent: the client has no connected channels or they are not configured."),
              "ok" if n else "error")
    return RedirectResponse(f"/peer/{peer_id}#portal", status_code=303)


# ---- личный кабинет клиента ----

ME_COOKIE = "ttme"
me_signer = URLSafeTimedSerializer((settings.session_secret or secrets.token_urlsafe(48)) + ":me", salt="portal")
me_limiter = auth.RateLimiter(per_ip=10, window=900, block=900, global_limit=200, global_window=3600)


def me_peer(request: Request):
    """Клиент из cookie кабинета; ссылка отозвана или перевыпущена — сессия недействительна."""
    try:
        data = me_signer.loads(request.cookies.get(ME_COOKIE, ""), max_age=30 * 86400)
    except BadSignature:
        return None, None
    row = request.app.state.db.execute("SELECT * FROM peers WHERE id = ? AND deleted_at IS NULL", (data.get("p"),)).fetchone()
    if not row or not row["portal_hash"] or not row["portal_hash"].startswith(data.get("h", "-")):
        return None, None
    return row, data


def me_redirect(path: str = "/me") -> RedirectResponse:
    return RedirectResponse(path, status_code=303)


def me_check(request: Request, data: dict, csrf: str) -> None:
    if not secrets.compare_digest(csrf or "", data.get("c", "")):
        raise HTTPException(403, "CSRF")


@app.get("/me/k/{token}")
def me_login(request: Request, token: str):
    ip = client_ip(request)
    if me_limiter.blocked(ip):
        raise HTTPException(429, t("Too many attempts, try again later."))
    row = portal.peer_by_token(request.app.state.db, token)
    if not row:
        me_limiter.fail(ip)
        raise HTTPException(404, t("The link is invalid — ask the administrator for a new one."))
    db.event(request.app.state.db, "client_view", row["id"], {"via": "link"}, actor_ip=ip)
    resp = me_redirect()
    resp.set_cookie(ME_COOKIE, me_signer.dumps({"p": row["id"], "h": row["portal_hash"][:16], "c": secrets.token_urlsafe(24)}),
                    max_age=30 * 86400, httponly=True, secure=settings.cookie_secure, samesite="lax", path="/me")  # lax: вход по ссылке из Telegram/почты — переход с чужого сайта
    return resp


@app.get("/me", response_class=HTMLResponse)
def me_page(request: Request, days: int = 1):
    peer, data = me_peer(request)
    if not peer:
        return HTMLResponse(f"<h1>{t('Sign in with a personal link')}</h1><p>{t('Open the link given to you by the VPN administrator.')}</p>", status_code=401)
    conn, now = request.app.state.db, int(time.time())
    days = days if days in charts.RANGES else 1
    bucket, label = charts.RANGES[days]
    row = conn.execute(CLIENTS_SQL.replace("WHERE p.deleted_at IS NULL", "WHERE p.id = ?"), (fmt.day_start(now), peer["id"])).fetchone()
    me = dict(row) | {"status": fmt.status(row, now, settings.online_window)}
    sessions = conn.execute("SELECT s.*, e.country, e.org FROM sessions s LEFT JOIN endpoints e ON e.peer_id = s.peer_id "
                            "AND e.ip = s.endpoint_ip WHERE s.peer_id = ? ORDER BY s.start DESC LIMIT 30", (peer["id"],)).fetchall()
    endpoints = conn.execute("SELECT * FROM endpoints WHERE peer_id = ? ORDER BY last_seen DESC LIMIT 20", (peer["id"],)).fetchall()
    n = request.app.state.notifier
    tg_name = None
    if n and n.tg:
        try:
            tg_name = n.tg.me()
        except Exception:  # noqa: BLE001 — кабинет открывается и без Telegram
            tg_name = None
    return templates.TemplateResponse(request, "me.html", {
        "me": me, "now": now, "days": days, "sessions": sessions, "endpoints": endpoints,
        "quota": quotas.status(conn, peer["quota_bytes"], peer["quota_period"], peer["id"], now),
        "contact": portal.contact(conn, peer["id"]), "csrf": data["c"], "tg_bot": tg_name, "email_on": bool(n and n.email_on),
        "can_config": bool(peer["portal_config"] and peer["password_enc"]),
        "traffic_chart": charts.bars(charts.traffic_series(conn, now - days * 86400, now, bucket, peer["id"]), fmt.TZ, label),
        "flash": None, "user": None, "lang": i18n.get(), "theme": theme_of(request), "path": request.url.path})


@app.post("/me/prefs")
def me_prefs(request: Request, daily: str = Form(""), hour: int = Form(21), events: str = Form(""), csrf: str = Form("")):
    peer, data = me_peer(request)
    if not peer:
        return me_redirect()
    me_check(request, data, csrf)
    portal.set_prefs(request.app.state.db, peer["id"], daily == "1", hour, events == "1")
    return me_redirect("/me#notify")


@app.post("/me/telegram")
def me_telegram(request: Request, csrf: str = Form("")):
    peer, data = me_peer(request)
    if not peer:
        return me_redirect()
    me_check(request, data, csrf)
    n = notifier(request)
    if not n.tg:
        raise HTTPException(404)
    code = portal.telegram_code(request.app.state.db, peer["id"])
    return RedirectResponse(f"https://t.me/{n.tg.me()}?start={code}", status_code=303)


@app.post("/me/telegram/unlink")
def me_telegram_unlink(request: Request, csrf: str = Form("")):
    peer, data = me_peer(request)
    if not peer:
        return me_redirect()
    me_check(request, data, csrf)
    request.app.state.db.execute("UPDATE contacts SET tg_chat_id = NULL, tg_name = NULL WHERE peer_id = ?", (peer["id"],))
    return me_redirect("/me#notify")


@app.post("/me/email")
def me_email(request: Request, email: str = Form(""), csrf: str = Form("")):
    peer, data = me_peer(request)
    if not peer:
        return me_redirect()
    me_check(request, data, csrf)
    n = notifier(request)
    try:
        code = portal.set_email(request.app.state.db, peer["id"], email)
    except ValueError:
        return me_redirect("/me?bad_email=1#notify")
    if code and n.email_on:
        try:
            notify.send_email(settings, email.strip(), t("VPN: confirm your address"),
                              t("To receive VPN notifications at this address, open the link:") + f"\n{settings.base_url}/me/verify/{code}")
        except Exception as e:  # noqa: BLE001
            db.event(request.app.state.db, "alert_server", None, {"reason": "smtp", "error": str(e)[:200]})
    return me_redirect("/me#notify")


@app.get("/me/verify/{code}")
def me_verify(request: Request, code: str):
    pid = portal.verify_email(request.app.state.db, code)
    if not pid:
        raise HTTPException(404, t("The confirmation link is invalid."))
    return HTMLResponse(f"<h1>{t('Address confirmed')}</h1><p>{t('VPN notifications will be sent to this e-mail. You can close this window.')}</p>")


@app.get("/me/config.toml")
def me_config(request: Request):
    peer, _ = me_peer(request)
    if not peer or not peer["portal_config"]:
        raise HTTPException(404)
    cfg = client_config(request, peer["id"])
    db.event(request.app.state.db, "client_view", peer["id"], {"via": "config"}, actor_ip=client_ip(request))
    return Response(cfg["conf"], media_type="text/plain; charset=utf-8",
                    headers={"Content-Disposition": content_disposition(cfg["name"], cfg["username"]), "Cache-Control": "no-store"})


@app.get("/me/qr/{kind}.svg")
def me_qr(request: Request, kind: str):
    peer, _ = me_peer(request)
    if not peer or not peer["portal_config"] or kind != "vpn":
        raise HTTPException(404)
    return Response(clientconf.qr_svg(client_config(request, peer["id"])[kind]), media_type="image/svg+xml",
                    headers={"Cache-Control": "no-store"})


@app.get("/me/stats.png")
def me_stats_png(request: Request):
    peer, _ = me_peer(request)
    if not peer:
        raise HTTPException(404)
    png, _ = report.daily_png(request.app.state.db, peer["id"], int(time.time()))
    return Response(png, media_type="image/png", headers={"Cache-Control": "no-store"})


@app.post("/me/logout")
def me_logout(request: Request):
    resp = me_redirect()
    resp.delete_cookie(ME_COOKIE, path="/me")
    return resp


@app.get("/healthz")
async def healthz(request: Request):
    if client_ip(request) not in ("127.0.0.1", "::1"):
        raise HTTPException(404)
    p = request.app.state.poller
    return {"ok": bool(p and p.status.last_ok and time.time() - p.status.last_ok < 3 * settings.poll_interval),
            "version": __version__, "schema": db.version(request.app.state.db),
            "poller": p and {"last_ok": int(p.status.last_ok), "error": p.status.last_error,
                             "online": p.status.online, "peers": p.status.peers},
            "geo": request.app.state.geo.built()}
