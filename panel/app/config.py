"""Настройки из переменных окружения (.env)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    return default if v is None else v.strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    v = os.environ.get(name, "").strip()
    return int(v) if v else default


@dataclass(frozen=True)
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(os.environ.get("PANEL_DATA", "/data")))
    panel_host: str = field(default_factory=lambda: os.environ.get("PANEL_HOST", ""))
    panel_port: int = field(default_factory=lambda: _int("PANEL_PORT", 15443))
    admin_user: str = field(default_factory=lambda: os.environ.get("ADMIN_USER", "admin"))
    admin_password_hash: str = field(default_factory=lambda: os.environ.get("ADMIN_PASSWORD_HASH", ""))
    totp_secret: str = field(default_factory=lambda: os.environ.get("TOTP_SECRET", ""))
    session_secret: str = field(default_factory=lambda: os.environ.get("SESSION_SECRET", ""))
    data_key: str = field(default_factory=lambda: os.environ.get("DATA_KEY", ""))
    cookie_secure: bool = field(default_factory=lambda: _bool("COOKIE_SECURE", True))
    session_hours: int = field(default_factory=lambda: _int("SESSION_HOURS", 12))

    public_host: str = field(default_factory=lambda: os.environ.get("PUBLIC_HOST", ""))
    tt_dir: str = field(default_factory=lambda: os.environ.get("TT_DIR", "/opt/trusttunnel"))
    tt_service: str = field(default_factory=lambda: os.environ.get("TT_SERVICE", "trusttunnel"))
    tt_metrics: str = field(default_factory=lambda: os.environ.get("TT_METRICS", "http://127.0.0.1:1987"))
    # адрес подключения в конфигах клиентов: ip, ip:port, домен или домен:порт (по умолчанию PUBLIC_HOST)
    tt_address_env: str = field(default_factory=lambda: os.environ.get("TT_ADDRESS", ""))
    tt_name: str = field(default_factory=lambda: os.environ.get("TT_NAME", "TrustTunnel"))
    tt_dns: tuple[str, ...] = field(default_factory=lambda: tuple(os.environ.get("CLIENT_DNS", "").replace(",", " ").split()))

    telegram_token: str = field(default_factory=lambda: os.environ.get("TELEGRAM_BOT_TOKEN", "").strip())
    smtp_host: str = field(default_factory=lambda: os.environ.get("SMTP_HOST", "").strip())
    smtp_port: int = field(default_factory=lambda: _int("SMTP_PORT", 587))
    smtp_user: str = field(default_factory=lambda: os.environ.get("SMTP_USER", ""))
    smtp_password: str = field(default_factory=lambda: os.environ.get("SMTP_PASSWORD", ""))
    smtp_from: str = field(default_factory=lambda: os.environ.get("SMTP_FROM", ""))
    smtp_ssl: bool = field(default_factory=lambda: _bool("SMTP_SSL", False))

    tz: str = field(default_factory=lambda: os.environ.get("TZ", "Europe/Moscow"))
    poll_interval: int = field(default_factory=lambda: _int("POLL_INTERVAL", 30))
    online_window: int = field(default_factory=lambda: _int("ONLINE_WINDOW", 180))
    retention_raw_days: int = field(default_factory=lambda: _int("RETENTION_RAW_DAYS", 30))
    retention_min_days: int = field(default_factory=lambda: _int("RETENTION_MIN_DAYS", 7))
    retention_events_days: int = field(default_factory=lambda: _int("RETENTION_EVENTS_DAYS", 365))

    @property
    def tt_address(self) -> str:
        return self.tt_address_env or self.public_host or self.panel_host

    @property
    def base_url(self) -> str:
        port = "" if self.panel_port == 443 else f":{self.panel_port}"
        return f"https://{self.panel_host or self.public_host}{port}"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "panel.db"

    def problems(self) -> list[str]:
        """Что не настроено для безопасного запуска веб-интерфейса."""
        out = []
        if not self.admin_password_hash:
            out.append("ADMIN_PASSWORD_HASH")
        if not self.totp_secret:
            out.append("TOTP_SECRET")
        if len(self.session_secret) < 32:
            out.append("SESSION_SECRET (32+ characters)")
        return out


settings = Settings()
