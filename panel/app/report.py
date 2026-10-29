"""Ежедневная сводка клиента картинкой: трафик за сегодня по часам и подключения за день (откуда, сколько)."""
from __future__ import annotations

import datetime
import io
import sqlite3
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

from . import fmt
from .i18n import t

FONT_DIRS = ["/usr/share/fonts/dejavu", "/usr/share/fonts/truetype/dejavu", "/Library/Fonts", "/System/Library/Fonts/Supplemental"]
BG, FG, MUTED, GRID, A1, A2 = "#ffffff", "#1b1f24", "#5f6b7a", "#e3e6ea", "#2f6fdd", "#f0a33a"
W, H = 1000, 900


def font(size: int, bold: bool = False) -> ImageFont.ImageFont:
    names = ["DejaVuSans-Bold.ttf", "Arial Bold.ttf"] if bold else ["DejaVuSans.ttf", "Arial.ttf"]
    for d in FONT_DIRS:
        for n in names:
            p = Path(d) / n
            if p.exists():
                return ImageFont.truetype(str(p), size)
    return ImageFont.load_default(size)


def collect(conn: sqlite3.Connection, peer_id: int, now: int) -> dict:
    start = fmt.day_start(now)
    hours = [[0, 0] for _ in range(24)]
    for r in conn.execute("SELECT ts, tx, rx FROM traffic_hour WHERE peer_id = ? AND ts >= ? AND ts <= ?", (peer_id, start, now)):
        h = datetime.datetime.fromtimestamp(r["ts"], fmt.TZ).hour
        hours[h][0] += r["tx"]
        hours[h][1] += r["rx"]
    top = [(f"{fmt.dt(r['start'], '%H:%M')}  {fmt.flag(r['country'])} {r['endpoint_ip'] or '?'}  {r['org'] or ''}".strip(),
            (r["tx"], r["end"] is None))
           for r in conn.execute("SELECT s.start, s.end, s.endpoint_ip, s.tx, e.country, e.org FROM sessions s LEFT JOIN endpoints e "
                                 "ON e.peer_id = s.peer_id AND e.ip = s.endpoint_ip WHERE s.peer_id = ? AND COALESCE(s.end, ?) >= ? "
                                 "ORDER BY s.start DESC LIMIT 10", (peer_id, now, start))]
    online = conn.execute(
        "SELECT COALESCE(SUM(MIN(COALESCE(end, last_active, start), ?) - MAX(start, ?)), 0) FROM sessions "
        "WHERE peer_id = ? AND start <= ? AND COALESCE(end, last_active, start) >= ?", (now, start, peer_id, now, start)).fetchone()[0]
    name = conn.execute("SELECT name FROM peers WHERE id = ?", (peer_id,)).fetchone()[0]
    return {"name": name, "hours": hours, "top": top, "online": online, "date": fmt.dt(now, "%d.%m.%Y"),
            "down": sum(h[0] for h in hours), "up": sum(h[1] for h in hours)}


def render(d: dict) -> bytes:
    img = Image.new("RGB", (W, H), BG)
    g = ImageDraw.Draw(img)
    f_title, f_big, f, f_small = font(34, True), font(26, True), font(20), font(16)
    g.text((40, 30), f"{d['name']} — {d['date']}", font=f_title, fill=FG)
    g.text((40, 82), t("Downloaded {down}   ·   uploaded {up}   ·   online {online}", down=fmt.size(d["down"]), up=fmt.size(d["up"]),
                       online=fmt.duration(d["online"])),
           font=f, fill=MUTED)
    # трафик по часам
    x0, y0, cw, ch = 90, 140, 860, 300
    g.text((40, y0 - 6), t("Traffic by hour"), font=f_big, fill=FG)
    y0 += 40
    top = max((a + b for a, b in d["hours"]), default=0) or 1
    for i in range(5):
        y = y0 + ch * i / 4
        g.line((x0, y, x0 + cw, y), fill=GRID, width=1)
        g.text((x0 - 10, y), fmt.size(int(top * (4 - i) / 4)), font=f_small, fill=MUTED, anchor="rm")
    bw = cw / 24
    for h, (a, b) in enumerate(d["hours"]):
        x = x0 + h * bw
        ha, hb = ch * a / top, ch * b / top
        if ha:
            g.rectangle((x + 3, y0 + ch - ha, x + bw - 3, y0 + ch), fill=A1)
        if hb:
            g.rectangle((x + 3, y0 + ch - ha - hb, x + bw - 3, y0 + ch - ha), fill=A2)
        if h % 3 == 0:
            g.text((x + bw / 2, y0 + ch + 14), f"{h:02d}", font=f_small, fill=MUTED, anchor="mm")
    g.rectangle((x0, y0 + ch + 32, x0 + 14, y0 + ch + 46), fill=A1)
    g.text((x0 + 22, y0 + ch + 39), t("downloaded"), font=f_small, fill=MUTED, anchor="lm")
    g.rectangle((x0 + 120, y0 + ch + 32, x0 + 134, y0 + ch + 46), fill=A2)
    g.text((x0 + 142, y0 + ch + 39), t("uploaded"), font=f_small, fill=MUTED, anchor="lm")
    # подключения за день
    y = y0 + ch + 80
    g.text((40, y), t("Connections today"), font=f_big, fill=FG)
    y += 44
    if not d["top"]:
        g.text((40, y), t("No connections today."), font=f, fill=MUTED)
    mx = max((v[0] for _, v in d["top"]), default=0) or 1
    for i, (label, (down, active)) in enumerate(d["top"]):
        yy = y + i * 30
        g.text((40, yy), label if len(label) <= 44 else label[:43] + "…", font=f, fill=FG)
        bwid = 200 * down / mx
        if bwid:
            g.rectangle((580, yy + 5, 580 + bwid, yy + 21), fill=A1)
        g.text((W - 40, yy), (t("now") + " · " if active else "") + fmt.size(down), font=f, fill=FG, anchor="ra")
    g.text((40, H - 30), t("TrustPanel · traffic counted by the TrustTunnel endpoint"), font=f_small, fill=MUTED)
    buf = io.BytesIO()
    img.save(buf, "PNG", optimize=True)
    return buf.getvalue()


def daily_png(conn: sqlite3.Connection, peer_id: int, now: int) -> tuple[bytes, str]:
    d = collect(conn, peer_id, now)
    caption = f"VPN · {d['name']} · {d['date']}\n" + t("Downloaded {down}, uploaded {up}, online {online}.", down=fmt.size(d["down"]),
                                                            up=fmt.size(d["up"]), online=fmt.duration(d["online"]))
    return render(d), caption
