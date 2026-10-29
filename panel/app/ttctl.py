"""Доступ к TrustTunnel endpoint на хосте.

Каталог endpoint'а (/opt/trusttunnel) смонтирован в контейнер по тому же пути; бинарник собран статически и
запускается прямо из контейнера (экспорт конфигов, версия). Служба systemd перезапускается через nsenter в
namespace'ы PID 1 хоста (контейнер с pid: host и privileged). Онлайн и трафик — из метрик endpoint'а
(`[metrics] per_client_metrics = true`, эндпоинт /clients).
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import subprocess
import tempfile
import threading
import tomllib
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .config import Settings


class TTUnavailable(RuntimeError):
    """Endpoint не запущен, метрики недоступны или команда завершилась ошибкой."""


@dataclass(frozen=True)
class ClientStat:
    username: str
    ip: str | None            # адрес клиента, пока он подключён
    sessions: int
    rx: int                   # байт от клиента (клиент отдал) — outbound у endpoint'а
    tx: int                   # байт клиенту (клиент скачал) — inbound у endpoint'а

    @property
    def endpoint_ip(self) -> str | None:
        return self.ip


def parse_clients(text: str) -> list[ClientStat]:
    """Ответ /clients: [{"username", "ip", "sessions", "inbound", "outbound"}, …]; пустое имя — до авторизации."""
    out = []
    for c in json.loads(text or "[]"):
        name = c.get("username") or ""
        if not name:
            continue
        ip = c.get("ip") or None
        if ip and ip.count(":") == 1:          # "1.2.3.4:5678" → адрес без порта
            ip = ip.rsplit(":", 1)[0]
        out.append(ClientStat(name, ip.strip("[]") if ip else None, int(c.get("sessions") or 0),
                              int(c.get("outbound") or 0), int(c.get("inbound") or 0)))
    return out


def parse_metrics(text: str) -> dict[str, float]:
    """Prometheus-текст → {имя{метки}: значение}; нужны только общие счётчики процесса."""
    out = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        key, _, val = line.rpartition(" ")
        try:
            out[key] = float(val)
        except ValueError:
            continue
    return out


# ---- credentials.toml ----

def parse_credentials(text: str) -> list[dict]:
    """[[client]] username/password → список словарей (порядок файла)."""
    data = tomllib.loads(text or "")
    return [{"username": str(c.get("username", "")), "password": str(c.get("password", ""))}
            for c in data.get("client", []) if c.get("username")]


def _toml_str(s: str) -> str:
    return json.dumps(s, ensure_ascii=False)     # строка JSON — допустимая базовая строка TOML


def render_credentials(clients: list[dict], header: str = "") -> str:
    lines = [header.rstrip()] if header.strip() else []
    for c in clients:
        lines += ["", "[[client]]", f"username = {_toml_str(c['username'])}", f"password = {_toml_str(c['password'])}"]
    return "\n".join(lines).lstrip("\n") + "\n"


def leading_comments(text: str) -> str:
    """Комментарии в начале файла (пометки администратора) — сохраняются при перезаписи."""
    out = []
    for line in (text or "").splitlines():
        if line.startswith("#") or not line.strip():
            out.append(line)
        else:
            break
    return "\n".join(out).strip()


USERNAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class TT:
    def __init__(self, settings: Settings):
        self.s = settings
        self._lock = threading.Lock()

    # ---- файлы ----

    @property
    def dir(self) -> Path:
        return Path(self.s.tt_dir)

    def vpn_settings(self) -> dict:
        try:
            return tomllib.loads((self.dir / "vpn.toml").read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as e:
            raise TTUnavailable(f"vpn.toml: {e}") from e

    def cred_path(self) -> Path:
        p = Path(self.vpn_settings().get("credentials_file", "credentials.toml"))
        return p if p.is_absolute() else self.dir / p

    def read_credentials_raw(self) -> str:
        try:
            return self.cred_path().read_text(encoding="utf-8")
        except FileNotFoundError:
            return ""

    def read_credentials(self) -> list[dict]:
        try:
            return parse_credentials(self.read_credentials_raw())
        except tomllib.TOMLDecodeError as e:
            raise TTUnavailable(f"credentials.toml: {e}") from e

    def write_credentials_raw(self, text: str) -> None:
        atomic_write(self.cred_path(), text)

    def write_credentials(self, clients: list[dict]) -> None:
        self.write_credentials_raw(render_credentials(clients, leading_comments(self.read_credentials_raw())))

    def hosts(self) -> list[str]:
        try:
            data = tomllib.loads((self.dir / "hosts.toml").read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError):
            return []
        return [h.get("hostname", "") for h in data.get("main_hosts", []) if h.get("hostname")]

    # ---- endpoint ----

    def binary(self) -> str:
        return str(self.dir / "trusttunnel_endpoint")

    def version(self) -> str:
        return self._run([self.binary(), "-v"]).strip()

    def export(self, username: str, password: str, fmt: str = "deeplink") -> str:
        """Конфиг клиента от самого endpoint'а: временный vpn.toml с одним этим клиентом в credentials —
        так работает и для отключённых (их нет в рабочем credentials.toml)."""
        vpn = (self.dir / "vpn.toml").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory(prefix="tt-export-") as tmp:
            creds = Path(tmp) / "credentials.toml"
            creds.write_text(render_credentials([{"username": username, "password": password}]), encoding="utf-8")
            vpn = re.sub(r'(?m)^credentials_file\s*=.*$', f"credentials_file = {_toml_str(str(creds))}", vpn)
            (Path(tmp) / "vpn.toml").write_text(vpn, encoding="utf-8")
            args = [self.binary(), str(Path(tmp) / "vpn.toml"), "hosts.toml", "-c", username, "-a", self.s.tt_address,
                    "-f", fmt]
            if fmt == "deeplink" and self.s.tt_name:
                args += ["-n", self.s.tt_name]
            for d in self.s.tt_dns:
                args += ["-d", d]
            out = self._run(args).strip()
        if fmt == "deeplink":
            link = next((line.strip() for line in out.splitlines() if line.strip().startswith("tt://")), "")
            if not link:
                raise TTUnavailable("export: no tt:// link in the output")
            return link
        return out + "\n"

    def _run(self, args: list[str], timeout: float = 20) -> str:
        try:
            r = subprocess.run(args, cwd=self.dir, capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise TTUnavailable(f"{Path(args[0]).name}: {e}") from e
        if r.returncode != 0:
            raise TTUnavailable(f"{Path(args[0]).name}: {(r.stderr or r.stdout).strip()[:300]}")
        return r.stdout

    # ---- служба на хосте ----

    def host_argv(self, args: list[str]) -> list[str]:
        return ["nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "--", *args]

    def systemctl(self, *args: str) -> str:
        try:
            r = subprocess.run(self.host_argv(["systemctl", *args]), capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise TTUnavailable(f"systemctl {args[0]}: {e}") from e
        if r.returncode != 0 and args[0] != "show":
            raise TTUnavailable(f"systemctl {' '.join(args)}: {(r.stderr or r.stdout).strip()[:300]}")
        return r.stdout

    def restart(self) -> None:
        """Endpoint читает credentials.toml только при старте (SIGHUP перечитывает лишь TLS-хосты)."""
        self.systemctl("restart", self.s.tt_service)

    def service(self) -> dict:
        out = self.systemctl("show", self.s.tt_service, "-p", "MainPID,ActiveState,ActiveEnterTimestampMonotonic,ExecMainStartTimestamp")
        kv = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
        return {"pid": int(kv.get("MainPID") or 0), "state": kv.get("ActiveState", "?"),
                "started": kv.get("ExecMainStartTimestamp", "")}

    def pid(self) -> int:
        pid = self.service()["pid"]
        if not pid:
            raise TTUnavailable(f"service {self.s.tt_service} is not running")
        return pid

    def started_at(self) -> float:
        pid = self.pid()
        ticks = int(Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19])
        boot = next(float(line.split()[1]) for line in Path("/proc/stat").read_text().splitlines() if line.startswith("btime "))
        return boot + ticks / os.sysconf("SC_CLK_TCK")

    # ---- метрики ----

    def _get(self, path: str) -> str:
        try:
            with urllib.request.urlopen(self.s.tt_metrics.rstrip("/") + path, timeout=5) as r:
                return r.read().decode()
        except OSError as e:
            raise TTUnavailable(f"metrics {path}: {e}") from e

    def clients(self) -> list[ClientStat]:
        return parse_clients(self._get("/clients"))

    def metrics(self) -> dict[str, float]:
        return parse_metrics(self._get("/metrics"))

    @contextmanager
    def locked(self):
        """Одна операция изменения за раз — и между потоками, и между процессами панели."""
        with self._lock:
            self.s.data_dir.mkdir(parents=True, exist_ok=True)
            with open(self.s.data_dir / "tt.lock", "w") as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(f, fcntl.LOCK_UN)


def atomic_write(path: Path, text: str) -> None:
    """Временный файл рядом → fsync → rename; права и владелец — как у исходного файла (по умолчанию 600)."""
    st = path.stat() if path.exists() else None
    tmp = path.with_name(f".{path.name}.panel-tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        if st:
            os.chmod(tmp, st.st_mode & 0o7777)
            try:
                os.chown(tmp, st.st_uid, st.st_gid)
            except PermissionError:
                pass
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
