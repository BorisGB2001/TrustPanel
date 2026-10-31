"""Графики в SVG на сервере: без JS-библиотек, CSP остаётся строгой. Цвета — через CSS-классы (тёмная/светлая тема)."""
from __future__ import annotations

import datetime
import json
from html import escape
from zoneinfo import ZoneInfo

from . import db
from .fmt import N_, size
from .i18n import t

W, H, PAD_L, PAD_B, PAD_T = 720, 180, 68, 22, 8   # PAD_L: подписи вида «953.7 MiB» не обрезаются


def _nice_max(v: float) -> float:
    if v <= 0:
        return 1
    import math
    p = 10 ** math.floor(math.log10(v))
    for m in (1, 2, 2.5, 5, 10):
        if v <= m * p:
            return m * p
    return 10 * p


def bars(points: list[tuple[int, float, float]], tz: ZoneInfo, label_fmt: str, *, bytes_axis: bool = True,
         legend: tuple[str, str] | None = None) -> str:
    """Столбики по интервалам: (начало интервала, серия A, серия B) — A снизу, B сверху (стек)."""
    legend = legend or (t("downloaded"), t("uploaded"))
    if not points:
        return f'<p class="muted small">{t("No data for this period.")}</p>'
    n = len(points)
    top = _nice_max(max(a + b for _, a, b in points))
    pw, ph = W - PAD_L - 4, H - PAD_B - PAD_T
    bw = pw / n
    out = [f'<svg class="chart" viewBox="0 0 {W} {H}" role="img" preserveAspectRatio="none">']
    for i in range(5):
        y = PAD_T + ph * i / 4
        val = top * (4 - i) / 4
        out.append(f'<line class="grid" x1="{PAD_L}" x2="{W}" y1="{y:.1f}" y2="{y:.1f}"/>')
        out.append(f'<text class="axis" x="{PAD_L - 6}" y="{y + 4:.1f}" text-anchor="end">{size(int(val)) if bytes_axis else int(val)}</text>')
    step = max(1, n // 8)
    for i, (ts, a, b) in enumerate(points):
        x = PAD_L + i * bw
        ha, hb = ph * a / top, ph * b / top
        when = datetime.datetime.fromtimestamp(ts, tz).strftime(label_fmt)
        tip = f"{when}: {legend[0]} {size(int(a)) if bytes_axis else int(a)}" + (f", {legend[1]} {size(int(b))}" if bytes_axis else "")
        out.append(f'<g><title>{escape(tip)}</title>'
                   f'<rect class="s1" x="{x + 0.5:.1f}" y="{PAD_T + ph - ha:.1f}" width="{max(bw - 1, 0.5):.1f}" height="{ha:.1f}"/>'
                   f'<rect class="s2" x="{x + 0.5:.1f}" y="{PAD_T + ph - ha - hb:.1f}" width="{max(bw - 1, 0.5):.1f}" height="{hb:.1f}"/></g>')
        if i % step == 0 and i + step // 2 < n:   # подпись у самого правого края обрезалась бы — пропускаем
            out.append(f'<text class="axis" x="{x + bw / 2:.1f}" y="{H - 6}" text-anchor="middle">{escape(when)}</text>')
    out.append("</svg>")
    if bytes_axis:
        out.append(f'<div class="legend"><span class="sw s1"></span>{legend[0]} <span class="sw s2"></span>{legend[1]}</div>')
    return "".join(out)


def heatmap(cells: dict[tuple[int, int], float]) -> str:
    """Активность: строки — дни недели (пн…вс), столбцы — часы 0…23; значение — байты."""
    days = [t(d) for d in (N_("Mon"), N_("Tue"), N_("Wed"), N_("Thu"), N_("Fri"), N_("Sat"), N_("Sun"))]
    top = max(cells.values(), default=0) or 1
    cw, chh, left, topp = 26, 18, 28, 16
    out = [f'<svg class="heat" viewBox="0 0 {left + 24 * cw} {topp + 7 * chh + 2}" role="img">']
    for h in range(0, 24, 3):
        out.append(f'<text class="axis" x="{left + h * cw + cw / 2}" y="11" text-anchor="middle">{h:02d}</text>')
    for d in range(7):
        out.append(f'<text class="axis" x="{left - 6}" y="{topp + d * chh + 13}" text-anchor="end">{days[d]}</text>')
        for h in range(24):
            v = cells.get((d, h), 0)
            op = 0.06 + 0.94 * (v / top) ** 0.5 if v else 0.04
            out.append(f'<rect class="hc" x="{left + h * cw + 1}" y="{topp + d * chh + 1}" width="{cw - 2}" height="{chh - 2}" '
                       f'rx="2" fill-opacity="{op:.2f}"><title>{days[d]} {h:02d}:00 — {size(int(v))}</title></rect>')
    out.append("</svg>")
    return "".join(out)


# ---- выборки ----

def traffic_series(conn, since: int, now: int, bucket: int, peers=None) -> list[tuple[int, float, float]]:
    """(начало, скачано, отдано) по интервалам bucket секунд; ≤ суток — из traffic_min, дальше — из traffic_hour.
    peers — клиент, набор клиентов или None (все), как в db.peer_filter."""
    table = "traffic_min" if bucket < 3600 else "traffic_hour"
    where, args = db.peer_filter(peers)
    rows = conn.execute(f"SELECT ts, SUM(tx) d, SUM(rx) u FROM {table} WHERE ts >= ?{where} GROUP BY ts", (since, *args)).fetchall()
    agg: dict[int, list[float]] = {}
    for r in rows:
        k = r["ts"] - r["ts"] % bucket
        a = agg.setdefault(k, [0, 0])
        a[0] += r["d"]
        a[1] += r["u"]
    start = since - since % bucket
    return [(t, *agg.get(t, (0, 0))) for t in range(start, now + 1, bucket)]


def online_series(conn, since: int, now: int, bucket: int) -> list[tuple[int, float, float]]:
    rows = conn.execute("SELECT ts, online FROM online_min WHERE ts >= ?", (since,)).fetchall()
    agg: dict[int, int] = {}
    for r in rows:
        k = r["ts"] - r["ts"] % bucket
        agg[k] = max(agg.get(k, 0), r["online"])
    start = since - since % bucket
    return [(t, agg.get(t, 0), 0) for t in range(start, now + 1, bucket)]


def active_series(conn, since: int, now: int, bucket: int, peers) -> list[tuple[int, float, float]]:
    """Сколько клиентов из набора были активны (был трафик) — максимум по минутам внутри интервала."""
    where, args = db.peer_filter(peers)
    rows = conn.execute(f"SELECT ts, COUNT(DISTINCT peer_id) n FROM traffic_min WHERE ts >= ? AND (rx + tx) > 0{where} "
                        "GROUP BY ts", (since, *args)).fetchall()
    agg: dict[int, int] = {}
    for r in rows:
        k = r["ts"] - r["ts"] % bucket
        agg[k] = max(agg.get(k, 0), r["n"])
    start = since - since % bucket
    return [(t, agg.get(t, 0), 0) for t in range(start, now + 1, bucket)]


def activity_cells(conn, peers, since: int, tz: ZoneInfo) -> dict[tuple[int, int], float]:
    where, args = db.peer_filter(peers)
    cells: dict[tuple[int, int], float] = {}
    for r in conn.execute(f"SELECT ts, SUM(rx + tx) b FROM traffic_hour WHERE ts >= ?{where} GROUP BY ts", (since, *args)):
        t = datetime.datetime.fromtimestamp(r["ts"], tz)
        cells[(t.weekday(), t.hour)] = cells.get((t.weekday(), t.hour), 0) + r["b"]
    return cells


RANGES = {1: (600, "%H:%M"), 7: (6 * 3600, "%d.%m %H"), 30: (86400, "%d.%m")}


def traffic_bars(rows: list[dict], period: str = "", hint: str = "") -> str:
    """Топ по трафику: полоска скачано (синяя) + отдано (оранжевая), мелкая подпись.
    rows = {name, down, up, href, series: [(подпись, скачано, отдано), …] | None}. Данные для всплывающей карточки
    (app.js) — в data-tip каждой строки: клиент крупно и его график за период."""
    if not rows:
        return f'<p class="muted small">{t("No data.")}</p>'
    top = max(r["down"] + r["up"] for r in rows) or 1
    # полоска от левого края, за ней ↓/↑, имя — по правому краю
    rh, w, left, vals, names = 24, 520, 2, 116, 140
    span = w - left - vals - names
    lbl = {"down": t("downloaded"), "up": t("uploaded"), "total": t("total"), "period": period}
    out = [f'<svg class="hbars tbars" viewBox="0 0 {w} {len(rows) * rh + 4}" role="img" data-labels="{escape(json.dumps(lbl, ensure_ascii=False))}">']
    for i, r in enumerate(rows):
        y = i * rh + 2
        dw = max(span * r["down"] / top, 0.5 if r["down"] else 0)
        uw = max(span * r["up"] / top, 0.5 if r["up"] else 0)
        name = r["name"] if len(r["name"]) <= 24 else "…" + r["name"][-23:]
        tip = {"name": r["name"], "down": size(int(r["down"])), "up": size(int(r["up"])), "total": size(int(r["down"] + r["up"])),
               "d": int(r["down"]), "u": int(r["up"]),
               "series": [[lab, int(a), int(b)] for lab, a, b in (r.get("series") or [])]}
        out.append(f'<a href="{escape(r["href"])}" class="trow" data-tip="{escape(json.dumps(tip, ensure_ascii=False))}">'
                   f'<rect class="hit" x="0" y="{y}" width="{w}" height="{rh}"/>'
                   f'<rect class="s1" x="{left}" y="{y + 4}" width="{dw:.1f}" height="{rh - 8}" rx="2"/>'
                   f'<rect class="s2" x="{left + dw:.1f}" y="{y + 4}" width="{uw:.1f}" height="{rh - 8}" rx="2"/>'
                   f'<text class="axis val" x="{left + dw + uw + 6:.1f}" y="{y + 16}">↓{size(int(r["down"]))} ↑{size(int(r["up"]))}</text>'
                   f'<text class="axis lbl" x="{w - 2}" y="{y + 16}" text-anchor="end">{escape(name)}</text></a>')
    out.append("</svg>")
    out.append(f'<div class="legend"><span class="sw s1"></span>{t("downloaded")} <span class="sw s2"></span>{t("uploaded")}'
               f' <span class="muted">· {hint or t("hover over a client for details")}</span></div>')
    return "".join(out)


def hbars(rows: list[tuple[str, float, str]], unit_bytes: bool = True) -> str:
    """Горизонтальные столбики «имя — значение»: rows = (подпись, значение, ссылка)."""
    if not rows:
        return f'<p class="muted small">{t("No data.")}</p>'
    top = max(v for _, v, _ in rows) or 1
    rh, w, left, right = 24, 520, 150, 80
    out = [f'<svg class="hbars" viewBox="0 0 {w} {len(rows) * rh + 4}" role="img">']
    for i, (label, v, href) in enumerate(rows):
        y = i * rh + 2
        bw = max((w - left - right) * v / top, 1)
        name = label if len(label) <= 20 else label[:19] + "…"
        out.append(f'<a href="{escape(href)}"><text class="axis lbl" x="{left - 8}" y="{y + 16}" text-anchor="end">{escape(name)}<title>{escape(label)}</title></text>'
                   f'<rect class="s1" x="{left}" y="{y + 4}" width="{bw:.1f}" height="{rh - 8}" rx="2"/>'
                   f'<text class="axis" x="{left + bw + 6:.1f}" y="{y + 16}">{size(int(v)) if unit_bytes else int(v)}</text></a>')
    out.append("</svg>")
    return "".join(out)
