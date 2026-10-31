"""Топ по трафику: скачано + отдано, данные для всплывающей карточки, экранирование имён."""
import html
import json
import re

from app import charts


def test_traffic_bars_stack_and_tip_data():
    svg = charts.traffic_bars([
        {"name": 'Анна "<b>"', "down": 10 << 30, "up": 1 << 30, "href": "/peer/1",
         "series": [("09", 5 << 30, 0), ("10", 5 << 30, 1 << 30)]},
        {"name": "Борис", "down": 0, "up": 2 << 20, "href": "/peer/2", "series": None},
    ], "by hour, today")
    assert svg.count('class="s1"') == 2 and svg.count('class="s2"') == 2
    assert "<b>" not in svg.split("data-tip")[0] + svg.split("</svg>")[1]          # имя не попадает в разметку
    tips = [json.loads(html.unescape(m)) for m in re.findall(r'data-tip="([^"]*)"', svg)]
    assert tips[0]["name"] == 'Анна "<b>"' and tips[0]["d"] == 10 << 30 and tips[0]["u"] == 1 << 30
    assert tips[0]["series"] == [["09", 5 << 30, 0], ["10", 5 << 30, 1 << 30]] and tips[1]["series"] == []
    labels = json.loads(html.unescape(re.search(r'data-labels="([^"]*)"', svg).group(1)))
    assert labels["period"] == "by hour, today"
    assert charts.traffic_bars([]).startswith('<p class="muted small">')
