"""Форматирование для шаблонов: байты, время, статусы, тексты событий — на текущем языке (i18n)."""
from __future__ import annotations

import datetime
import json
import time
from zoneinfo import ZoneInfo

from . import __version__, i18n
from .config import settings
from .i18n import t

TZ = ZoneInfo(settings.tz)


def N_(s: str) -> str:
    """Пометка фразы для перевода без перевода на месте (переводится при показе через t)."""
    return s


EVENT_NAMES = {
    "connect": N_("connected"), "disconnect": N_("disconnected"), "endpoint_change": N_("IP changed"),
    "peer_discovered": N_("new client"), "peer_removed_external": N_("client removed outside the panel"),
    "peer_renamed": N_("renamed"), "peers_imported": N_("clients imported"), "alert_server": N_("server"),
    "admin_login": N_("panel sign-in"), "admin_login_failed": N_("failed sign-in"),
    "admin_add": N_("added in the panel"), "admin_delete": N_("deleted in the panel"), "admin_rename": N_("renamed in the panel"),
    "admin_disable": N_("disabled in the panel"), "admin_enable": N_("enabled in the panel"), "admin_config_view": N_("config viewed"),
    "alert_shared_config": N_("looks like the config is used on several devices"),
    "alert_new_country": N_("connection from a new country"),
    "month_archived": N_("month archived"), "alert_traffic_spike": N_("traffic spike"),
    "alert_never_connected": N_("never connected"), "alert_inactive": N_("inactive for a long time"),
    "portal_link_issued": N_("portal link issued"), "portal_link_revoked": N_("portal link revoked"),
    "acct_created": N_("administrator added"), "acct_deleted": N_("administrator deleted"),
    "acct_disabled": N_("administrator disabled"), "acct_enabled": N_("administrator enabled"),
    "acct_reset": N_("administrator password reset"), "acct_role": N_("administrator role changed"),
    "acct_password": N_("administrator changed password"), "acct_totp_bound": N_("administrator set up the authenticator"),
    "group_created": N_("group created"), "group_renamed": N_("group renamed"), "group_deleted": N_("group deleted"),
    "group_member": N_("moved to a group"), "group_moved": N_("group moved"), "acct_groups": N_("administrator groups changed"),
    "acct_telegram": N_("administrator connected Telegram"),
    "alert_quota": N_("traffic quota"), "quota_set": N_("quota changed"),
    "contacts_set": N_("contacts changed"), "backup_sent": N_("backup sent"), "ip_allow_add": N_("panel access allowed from"),
    "ip_allow_remove": N_("panel access removed for"), "ip_allow_clear": N_("panel IP restriction removed"), "backup_restored": N_("restored from a backup"), "alert_backup": N_("backup failed"), "admin_rekey": N_("new password issued"), "config_sent": N_("config sent"), "config_link_issued": N_("bot link for the config created"),
    "client_view": N_("client portal opened"), "contact_telegram": N_("Telegram connected"), "contact_email": N_("e-mail confirmed"),
}

PERIOD_NAMES = {"month": N_("month"), "day": N_("day")}
ACTION_NAMES = {"alert": N_("alert only"), "disable": N_("disable clients until the period ends")}
WEEKDAYS = (N_("Monday"), N_("Tuesday"), N_("Wednesday"), N_("Thursday"), N_("Friday"), N_("Saturday"), N_("Sunday"))
ROLE_NAMES = {"super": N_("super administrator"), "group": N_("group administrator")}

STATUS_KEYS = ("online", "recent", "idle", "never", "disabled")
STATUS_NAMES = {"online": N_("online"), "recent": N_("today"), "idle": N_("long ago"), "never": N_("not seen"),
                "disabled": N_("disabled")}


def status_name(key: str) -> str:
    return t(STATUS_NAMES.get(key, key))


def size(n: int | None) -> str:
    n = n or 0
    for unit in (N_("B"), N_("KiB"), N_("MiB"), N_("GiB")):
        if n < 1024:
            return f"{n:.0f} {t(unit)}" if unit == "B" else f"{n:.1f} {t(unit)}"
        n /= 1024
    return f"{n:.2f} {t('TiB')}"


def tz_label() -> str:
    """Часовой пояс панели для подписей — смещение от UTC сейчас: «UTC», «UTC+01:00»."""
    off = datetime.datetime.now(TZ).utcoffset()
    if not off:
        return "UTC"
    m = int(off.total_seconds()) // 60
    return f"UTC{'+' if m > 0 else '-'}{abs(m) // 60:02d}:{abs(m) % 60:02d}"


def dt(ts: int | None, fmt: str = "%d.%m %H:%M") -> str:
    return datetime.datetime.fromtimestamp(ts, TZ).strftime(fmt) if ts else "—"


def ago(ts: int | None, now: int | None = None) -> str:
    if not ts:
        return t("not seen")
    d = int((now or time.time()) - ts)
    if d < 60:
        return t("{n} s ago", n=d)
    if d < 3600:
        return t("{n} min ago", n=d // 60)
    if d < 86400:
        return t("{h} h {m} min ago", h=d // 3600, m=d % 3600 // 60)
    return t("{n} d ago", n=d // 86400)


def duration(sec: int | None) -> str:
    sec = int(sec or 0)
    h, m = sec // 3600, sec % 3600 // 60
    return t("{h} h {m} min", h=h, m=m) if h else t("{m} min", m=m)


def day_start(now: int) -> int:
    d = datetime.datetime.fromtimestamp(now, TZ).replace(hour=0, minute=0, second=0, microsecond=0)
    return int(d.timestamp())


def status(row, now: int, window: int) -> str:
    if row["disabled"]:
        return "disabled"
    hs = row["last_handshake"]
    if row["session_start"] or (hs and now - hs <= window):
        return "online"
    if not hs:
        return "never"
    return "recent" if now - hs <= 86400 else "idle"


def flag(cc: str | None) -> str:
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in cc.upper()) if cc and len(cc) == 2 else ""


def event_name(kind: str) -> str:
    return t(EVENT_NAMES[kind]) if kind in EVENT_NAMES else kind


def event_text(kind: str, detail: str | None) -> str:
    d = json.loads(detail) if detail else {}
    name = event_name(kind)
    if kind == "connect":
        return t("{name} from {ip} {flag} {org}", name=name, ip=d.get("endpoint") or "?", flag=flag(d.get("country")),
                 org=d.get("org") or "").strip()
    if kind == "disconnect":
        return f"{name}, {duration(d.get('duration'))}, ↓{size(d.get('tx'))} ↑{size(d.get('rx'))}"
    if kind == "endpoint_change":
        return f"{name}: {d.get('from')} → {d.get('to')} {flag(d.get('country'))} {d.get('org') or ''}".strip()
    if kind in ("ip_allow_add", "ip_allow_remove"):
        return f"{name} {d.get('cidr')}" + (f" ({d['note']})" if d.get("note") else "")
    if kind in ("backup_sent", "alert_backup"):
        return f"{name}: {d.get('username')} — {d.get('status')}"
    if kind == "config_sent":
        return f"{name}: {d.get('channel')} → {d.get('to')}"
    if kind in ("admin_add", "admin_delete", "admin_disable", "admin_enable", "admin_rekey"):
        return f"{name}: {d.get('name')} ({d.get('username')})"
    if kind in ("group_created", "group_deleted"):
        return f"{name}: «{d.get('group')}»" + (f" ⊂ «{d['parent']}»" if d.get("parent") else "") + \
            (" + " + ", ".join(d["subgroups"]) if d.get("subgroups") else "")
    if kind == "group_moved":
        return f"{name}: «{d.get('group')}» → " + (f"«{d['parent']}»" if d.get("parent") else t("top level"))
    if kind in ("peer_renamed", "admin_rename"):
        return f"{name}: «{d.get('from')}» → «{d.get('to')}»"
    if kind == "month_archived":
        return f"{name}: {d.get('month')}"
    if kind == "peers_imported":
        return f"{name}: {d.get('count')}"
    if kind == "alert_server":
        reasons = {"tt_restarted": t("TrustTunnel endpoint restarted"), "tt_unavailable": t("TrustTunnel unavailable"),
                   "login_bruteforce": t("password guessing, sign-in blocked for 15 min"),
                   "disk": t("disk is {n} % full", n=d.get("used")),
                   "conntrack": t("connection table {count}/{max}", count=d.get("count"), max=d.get("max")),
                   "smtp": t("e-mail sending failed: {error}", error=d.get("error"))}
        return f"{name}: {reasons.get(d.get('reason'), d.get('reason'))}"
    if kind == "alert_quota":
        text = t("{who}: {used} of {limit} per {period} ({level} %)", who=(t("group «{name}»", name=d.get("name"))
                 if d.get("scope") == "group" else d.get("name")), used=size(d.get("used")), limit=size(d.get("limit")),
                 period=t(PERIOD_NAMES.get(d.get("period"), "month")), level=d.get("level"))
        if d.get("level") == 100 and d.get("action") == "disable":
            text += " — " + t("clients disabled until the next period")
        return f"{name}: {text}"
    if kind == "quota_set":
        if not d.get("limit"):
            return f"{name}: " + (t("group «{name}»", name=d["group"]) + " — " if d.get("group") else "") + t("no quota")
        return f"{name}: " + (t("group «{name}»", name=d["group"]) + " — " if d.get("group") else "") + \
            t("{limit} per {period}", limit=size(d.get("limit")), period=t(PERIOD_NAMES.get(d.get("period"), "month")))
    if kind == "alert_shared_config":
        return f"{name}: " + t("{n} IP changes in 30 min, providers: {providers}", n=d.get("changes"),
                               providers=", ".join(d.get("providers", [])))
    if kind == "alert_new_country":
        return f"{name}: " + t("{flag} {country} ({ip}), before: {known}", flag=flag(d.get("country")), country=d.get("country"),
                               ip=d.get("ip"), known=", ".join(d.get("known", [])))
    if kind == "alert_traffic_spike":
        return f"{name}: " + t("{bytes} in an hour, usually {median}", bytes=size(d.get("bytes")), median=size(d.get("median")))
    if kind in ("alert_never_connected", "alert_inactive"):
        return f"{name}: {d.get('count')} — {', '.join(d.get('names', []))}"
    return name


SECOND_LEVEL = {"co.uk", "com.ua", "co.jp", "com.au", "com.br", "com.tr",
                "co.kr", "com.cn", "com.kz", "co.il", "github.io", "cloudfront.net", "amazonaws.com", "appspot.com"}


def base_domain(name: str) -> str:
    """Базовый домен для группировки: rr3---sn-abc.googlevideo.com → googlevideo.com, a.b.co.uk → b.co.uk."""
    parts = name.lower().rstrip(".").split(".")
    if len(parts) <= 2 or all(p.isdigit() for p in parts):
        return name.lower()
    n = 3 if ".".join(parts[-2:]) in SECOND_LEVEL else 2
    return ".".join(parts[-n:])


def register(env) -> None:
    env.filters.update(size=size, dt=dt, ago=ago, duration=duration, flag=flag, base_domain=base_domain)
    env.globals.update(TZ_LABEL=tz_label, event_text=event_text, status_name=status_name, STATUS_KEYS=STATUS_KEYS, _=t, N_=N_, VERSION=__version__, ROLE_NAMES=ROLE_NAMES, WEEKDAYS=WEEKDAYS, GEO_DATE=lambda: None, PERIOD_NAMES=PERIOD_NAMES, ACTION_NAMES=ACTION_NAMES,
                       languages=i18n.languages)
