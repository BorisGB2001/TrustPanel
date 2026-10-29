"""Гео по IP: базы DB-IP Lite (CC BY 4.0) — страна/город и ASN/провайдер."""
from __future__ import annotations

import datetime
import gzip
import ipaddress
import logging
import os
import shutil
import threading
import time
import urllib.request
from functools import lru_cache
from pathlib import Path

import maxminddb

log = logging.getLogger("geo")

URL = "https://download.db-ip.com/free/dbip-{kind}-lite-{ym}.mmdb.gz"
KINDS = ("city", "asn")
MAX_AGE = 32 * 86400


class Geo:
    def __init__(self, directory: Path):
        self.dir = directory
        self._readers: dict[str, maxminddb.Reader | None] = {k: None for k in KINDS}
        self._lock = threading.Lock()
        self.open()

    def path(self, kind: str) -> Path:
        return self.dir / f"dbip-{kind}-lite.mmdb"

    def open(self) -> None:
        with self._lock:
            for k in KINDS:
                p = self.path(k)
                old = self._readers.get(k)
                self._readers[k] = maxminddb.open_database(str(p)) if p.exists() else None
                if old:
                    old.close()
            self.lookup.cache_clear()

    def built(self) -> str | None:
        """Дата сборки базы городов (для страницы сервера)."""
        r = self._readers.get("city")
        return datetime.date.fromtimestamp(r.metadata().build_epoch).isoformat() if r else None

    @lru_cache(maxsize=20000)  # noqa: B019 — один объект на процесс
    def lookup(self, ip: str) -> dict:
        out = {"country": None, "city": None, "asn": None, "org": None}
        try:
            if not ipaddress.ip_address(ip).is_global:
                return out
        except ValueError:
            return out
        with self._lock:
            city, asn = self._readers["city"], self._readers["asn"]
            c = city.get(ip) if city else None
            a = asn.get(ip) if asn else None
        if isinstance(c, dict):
            out["country"] = (c.get("country") or {}).get("iso_code")
            names = (c.get("city") or {}).get("names") or {}
            out["city"] = names.get("ru") or names.get("en")
        if isinstance(a, dict):
            out["asn"] = a.get("autonomous_system_number")
            out["org"] = a.get("autonomous_system_organization")
        return out

    # ---- обновление баз ----

    def stale(self) -> list[str]:
        now = time.time()
        return [k for k in KINDS if not self.path(k).exists() or now - self.path(k).stat().st_mtime > MAX_AGE]

    def update(self) -> bool:
        """Скачивает устаревшие базы (текущий месяц, иначе предыдущий); True — если что-то обновилось."""
        self.dir.mkdir(parents=True, exist_ok=True)
        changed = False
        today = datetime.date.today()
        months = [today.strftime("%Y-%m"), (today.replace(day=1) - datetime.timedelta(days=1)).strftime("%Y-%m")]
        for kind in self.stale():
            for ym in months:
                tmp = self.path(kind).with_suffix(".tmp")
                try:
                    req = urllib.request.Request(URL.format(kind=kind, ym=ym), headers={"User-Agent": "trust-panel"})
                    with urllib.request.urlopen(req, timeout=120) as r, open(tmp, "wb") as f:
                        shutil.copyfileobj(gzip.GzipFile(fileobj=r), f)
                    maxminddb.open_database(str(tmp)).close()  # файл целый
                    os.replace(tmp, self.path(kind))
                    log.info("geo %s %s обновлена", kind, ym)
                    changed = True
                    break
                except Exception as e:  # noqa: BLE001 — сеть/формат: пробуем другой месяц, потом завтра
                    log.warning("geo %s %s: %s", kind, ym, e)
                    tmp.unlink(missing_ok=True)
        if changed:
            self.open()
        return changed

    def updater(self, stop: threading.Event) -> None:
        """Фоновый поток: при старте и раз в сутки."""
        while not stop.is_set():
            try:
                self.update()
            except Exception:  # noqa: BLE001
                log.exception("geo update")
            stop.wait(86400)
