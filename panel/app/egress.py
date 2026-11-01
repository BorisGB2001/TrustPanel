"""Путь клиентов в интернет и адреса выхода: traceroute до тестовых узлов и «мой IP» у внешних сервисов.

Адрес сервера и адрес выхода могут не совпадать, а при split routing выходов несколько (российские адреса — напрямую,
остальные — через другой сервер или WARP), поэтому разные сервисы видят клиента с разных адресов. Замер идёт из
сетевого контекста клиентов: wrap(argv) — nsenter в namespace VPN-контейнера или argv как есть, если клиенты выходят
из сети хоста. Имена разрешаются панелью, команды получают уже IP: внутри namespace своего DNS может не быть.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
import socket
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

log = logging.getLogger("egress")

DEFAULT_TARGETS = ("yandex.ru", "vk.com", "google.com", "github.com", "cloudflare.com")
# сервисы «мой IP»; до их адресов тоже строится маршрут — так выход попадает в конец своей ветки
WHOAMI = (
    ("Yandex", "https://yandex.ru/internet"),
    ("ipinfo.io", "https://ipinfo.io/json"),
    ("Cloudflare", "https://www.cloudflare.com/cdn-cgi/trace"),
    ("ipify", "https://api.ipify.org/?format=json"),
)
MAX_HOPS = 20
SILENT = 3                # столько безответных хопов подряд — конец маршрута
STALE = 6 * 3600          # результат старше — при открытии страницы замер запускается заново
IPINFO_TTL = 86400

Wrap = Callable[[list[str]], list[str]]


def resolve(host: str) -> str:
    """IPv4 узла (или сам адрес)."""
    try:
        return str(ipaddress.IPv4Address(host))
    except ValueError:
        return socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]


def parse_traceroute(text: str) -> list[dict]:
    """Хопы `traceroute -n -q 1`: [{"ttl", "ip" (None — нет ответа), "rtt"}]; хвост из звёздочек сворачивается в один."""
    hops = []
    for line in text.splitlines():
        m = re.match(r"\s*(\d+)\s+(?:(\*)|(\S+)\s+([\d.]+)\s*ms)", line)
        if m:
            hops.append({"ttl": int(m[1]), "ip": None if m[2] else m[3], "rtt": None if m[2] else float(m[4])})
    while len(hops) > 1 and hops[-1]["ip"] is None and hops[-2]["ip"] is None:
        hops.pop()
    return hops


def parse_whoami(service: str, body: str) -> dict:
    """Ответ сервиса «мой IP» → {"ip", ...подробности}."""
    if service == "Yandex":
        out = {}
        if m := re.search(r'"ipv4":\{"value":"([^"]*)"', body):
            out["ip"] = m[1]
        if m := re.search(r'"isp":(\{[^{}]*\})', body):
            isp = json.loads(m[1])
            out["asn"] = ", ".join(f"AS{a}" for a in isp.get("asn") or [])
            out["isVpn"] = isp.get("isVpn")
        return out
    if service == "Cloudflare":
        kv = dict(line.split("=", 1) for line in body.splitlines() if "=" in line)
        return {"ip": kv.get("ip"), "loc": kv.get("loc"), "colo": kv.get("colo"), "warp": kv.get("warp")}
    data = json.loads(body)
    return {k: data[k] for k in ("ip", "country", "city", "org") if data.get(k)}


def build_tree(paths: list[dict]) -> list[dict]:
    """Ветки маршрутов, слитые по общим хопам: узел {"ip", "rtt", "children", "leaves": [{"host", "exit"}]}."""
    root: dict = {"children": {}}
    for p in paths:
        node = root
        for i, h in enumerate(p["hops"]):
            # безответные хопы различаются по номеру, чтобы ветки разных маршрутов не сливались по «*»
            key = h["ip"] or f"*{h['ttl']}"
            node = node["children"].setdefault(key, {"ip": h["ip"], "ttl": h["ttl"], "rtt": h["rtt"], "children": {}, "leaves": []})
        node.setdefault("leaves", []).append({"host": p["host"], "ip": p.get("ip"), "exit": p.get("exit"),
                                              "service": p.get("service"), "error": p.get("error")})

    def flat(n: dict) -> list[dict]:
        return [{**c, "children": flat(c)} for c in n["children"].values()]
    return flat(root)


class Egress:
    def __init__(self, wrap: Wrap, targets: list[str] | None = None, token: str = ""):
        self.wrap = wrap
        self.targets = list(targets or DEFAULT_TARGETS)    # меняются из настроек страницы «Сервер»
        self.token = token                                 # ключ ipinfo.io; пусто — сведения ipinfo не запрашиваются
        self.result: dict | None = None
        self.running = False
        self._lock = threading.Lock()
        self._trace_lock = threading.Lock()
        self._cache: dict[str, tuple[float, dict]] = {}

    # ---- замер ----

    def start(self) -> bool:
        """Запускает замер в фоне; False — уже идёт."""
        with self._lock:
            if self.running:
                return False
            self.running = True
        threading.Thread(target=self._run, name="egress", daemon=True).start()
        return True

    def ensure_fresh(self) -> None:
        if not self.running and (not self.result or time.time() - self.result["ts"] > STALE):
            self.start()

    def _run(self) -> None:
        t0 = time.time()
        try:
            jobs = [{"host": h} for h in self.targets]
            jobs += [{"host": urllib.parse.urlsplit(u).hostname, "service": s, "url": u} for s, u in WHOAMI]
            with ThreadPoolExecutor(max_workers=len(jobs) or 1) as pool:
                paths = list(pool.map(self._probe, jobs))
            exits: dict[str, dict] = {}
            for p in paths:
                if p.get("exit", {}).get("ip"):
                    exits.setdefault(p["exit"]["ip"], {"ip": p["exit"]["ip"], "seen_by": {}})["seen_by"][p["service"]] = p["exit"]
            self.result = {"ts": int(t0), "duration": round(time.time() - t0, 1), "tree": build_tree(paths),
                           "exits": list(exits.values()), "errors": [f"{p['host']}: {p['error']}" for p in paths if p.get("error")]}
        except Exception as e:  # noqa: BLE001 — ошибка замера показывается на странице, панель продолжает работать
            log.exception("egress")
            self.result = {"ts": int(t0), "duration": 0, "tree": [], "exits": [], "errors": [str(e)]}
        finally:
            self.running = False

    def _cmd(self, args: list[str], timeout: float) -> str:
        r = subprocess.run(self.wrap(args), capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0 and not r.stdout:
            raise RuntimeError((r.stderr.strip() or f"exit {r.returncode}")[:200])
        return r.stdout

    def _traceroute(self, ip: str) -> list[dict]:
        """traceroute по одному за раз: параллельные запуски путают ICMP-ответы друг друга. Останавливается после
        SILENT безответных хопов подряд — дальше (за WARP, у файрволов) ответов обычно уже нет."""
        with self._trace_lock:
            proc = subprocess.Popen(self.wrap(["traceroute", "-n", "-q", "1", "-w", "1", "-m", str(MAX_HOPS), ip]),
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            lines, silent = [], 0
            try:
                for line in proc.stdout:
                    lines.append(line)
                    silent = silent + 1 if re.match(r"\s*\d+\s+\*", line) else 0
                    if silent >= SILENT:
                        break
            finally:
                proc.kill()
                err = proc.stderr.read()
                proc.wait()
        hops = parse_traceroute("".join(lines))
        if not hops and err.strip():
            raise RuntimeError(err.strip()[:200])
        return hops

    def _probe(self, job: dict) -> dict:
        out = {**job, "hops": []}
        try:
            out["ip"] = ip = resolve(job["host"])
            out["hops"] = self._traceroute(ip)
            if job.get("url"):
                hdr = []
                if job["service"] == "ipinfo.io" and (tok := self.token):
                    hdr = ["-H", f"Authorization: Bearer {tok}"]
                body = self._cmd(["curl", "-sS", "-m", "12", "-A", "Mozilla/5.0", "--resolve", f"{job['host']}:443:{ip}",
                                  *hdr, job["url"]], timeout=20)
                out["exit"] = parse_whoami(job["service"], body)
                if not out["exit"].get("ip"):
                    # например, 429 у ipinfo.io без ключа: общий адрес WARP быстро исчерпывает бесплатный лимит
                    out["error"] = re.sub(r"\s+", " ", body)[:160] or "empty response"
        except Exception as e:  # noqa: BLE001
            out["error"] = str(e)
        return out

    # ---- сведения об адресе ----

    def ipinfo(self, ip: str) -> dict:
        """ipinfo.io Lite по адресу (нужен ключ в настройках); ответы кешируются на сутки."""
        tok = self.token
        if not tok:
            return {"error": "no key"}
        hit = self._cache.get(ip)
        if hit and time.time() - hit[0] < IPINFO_TTL:
            return hit[1]
        req = urllib.request.Request(f"https://api.ipinfo.io/lite/{ip}", headers={"Authorization": f"Bearer {tok}"})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.loads(r.read())
        except Exception as e:  # noqa: BLE001
            return {"error": str(e)[:200]}
        self._cache[ip] = (time.time(), data)
        return data

    def yandex(self, ip: str) -> dict | None:
        """Что Яндекс сказал про этот адрес — только если это выход, с которого клиенты приходят на Яндекс."""
        for e in (self.result or {}).get("exits", []):
            if e["ip"] == ip and "Yandex" in e["seen_by"]:
                return e["seen_by"]["Yandex"]
        return None
