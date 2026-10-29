"""Вход администратора: пароль (scrypt) + TOTP, защита от перебора, CSRF.

CLI: python -m app.auth init [--env FILE]   — задать пароль и привязать TOTP; с --env записывает их в FILE
     python -m app.auth hash [--env FILE]   — только сменить пароль
     python -m app.auth totp [--env FILE]   — только перевыпустить TOTP (старые коды перестанут работать)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import sys
import threading
import time
from collections import defaultdict, deque

import pyotp

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**15, 8, 1


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, maxmem=64 * 1024 * 1024, dklen=32)
    b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731
    # без «$»: docker compose подставляет переменные в .env и испортил бы хеш
    return f"scrypt:{SCRYPT_N}:{SCRYPT_R}:{SCRYPT_P}:{b64(salt)}:{b64(dk)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, want = stored.replace("$", ":").split(":")
        if algo != "scrypt":
            return False
        dk = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                            maxmem=64 * 1024 * 1024, dklen=len(base64.b64decode(want)))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(dk, base64.b64decode(want))


# хеш случайного пароля: проверка для несуществующего логина занимает столько же, сколько для настоящего
DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


def totp_step(secret: str, code: str, last_step: int, now: float | None = None) -> int | None:
    """Шаг TOTP, которому соответствует код (окно ±1 шаг), если он новее last_step; иначе None."""
    code = "".join(ch for ch in code if ch.isdigit())
    if len(code) != 6:
        return None
    totp = pyotp.TOTP(secret)
    now = time.time() if now is None else now
    step = int(now // totp.interval)
    for s in (step - 1, step, step + 1):
        if s > last_step and hmac.compare_digest(totp.at(s * totp.interval), code):
            return s
    return None


class TOTPGuard:
    """Проверка TOTP с окном ±1 шаг и запретом повторного использования одного кода."""

    def __init__(self, secret: str):
        self.secret = secret
        self._last_step = -1
        self._lock = threading.Lock()

    def verify(self, code: str, now: float | None = None) -> bool:
        with self._lock:
            step = totp_step(self.secret, code, self._last_step, now)
            if step is None:
                return False
            self._last_step = step
            return True


class RateLimiter:
    """5 неудач с одного IP за 15 мин → блок IP на 15 мин; >30 неудач за час со всех IP → блок входа для всех на 15 мин."""

    def __init__(self, per_ip: int = 5, window: int = 900, block: int = 900, global_limit: int = 30, global_window: int = 3600):
        self.per_ip, self.window, self.block = per_ip, window, block
        self.global_limit, self.global_window = global_limit, global_window
        self._fails: dict[str, deque[float]] = defaultdict(deque)
        self._blocked: dict[str, float] = {}
        self._global: deque[float] = deque()
        self._global_until = 0.0
        self._lock = threading.Lock()

    def blocked(self, ip: str, now: float | None = None) -> int:
        """Сколько секунд ещё действует блок (0 — можно пробовать)."""
        now = time.time() if now is None else now
        with self._lock:
            until = max(self._blocked.get(ip, 0.0), self._global_until)
            return max(0, int(until - now))

    def fail(self, ip: str, now: float | None = None) -> bool:
        """Учитывает неудачу; True — если только что сработал глобальный блок (повод для alert_server)."""
        now = time.time() if now is None else now
        with self._lock:
            q = self._fails[ip]
            q.append(now)
            while q and q[0] < now - self.window:
                q.popleft()
            if len(q) >= self.per_ip:
                self._blocked[ip] = now + self.block
                q.clear()
            self._global.append(now)
            while self._global and self._global[0] < now - self.global_window:
                self._global.popleft()
            if len(self._global) > self.global_limit and self._global_until <= now:
                self._global_until = now + self.block
                self._global.clear()
                return True
            return False

    def success(self, ip: str) -> None:
        with self._lock:
            self._fails.pop(ip, None)


def new_csrf() -> str:
    return secrets.token_urlsafe(32)


def ua_fingerprint(user_agent: str) -> str:
    return hashlib.sha256(user_agent.encode()).hexdigest()[:16]


def _cli() -> None:
    import getpass

    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd not in ("init", "hash", "totp"):
        sys.exit(__doc__)
    values: dict[str, str] = {}
    while cmd != "totp":
        pw = getpass.getpass("New administrator password (12+ characters): ")
        if len(pw) < 12:
            print("Too short.")
            continue
        if pw != getpass.getpass("Repeat: "):
            print("Does not match.")
            continue
        values["ADMIN_PASSWORD_HASH"] = hash_password(pw)
        break
    if cmd in ("init", "totp"):
        import qrcode

        secret = pyotp.random_base32()
        values["TOTP_SECRET"] = secret
        print("\nScan the QR code in your authenticator app (or enter the secret manually: " + secret + "):\n")
        qr = qrcode.QRCode(border=1)
        qr.add_data(pyotp.TOTP(secret).provisioning_uri(name="admin", issuer_name="TrustPanel"))
        qr.print_ascii(invert=True)
    env = sys.argv[sys.argv.index("--env") + 1] if "--env" in sys.argv else None
    if env:
        _update_env(env, values)
        print(f"\nSaved to {env}. Restart the panel: docker compose up -d panel")
    else:
        print("\n" + "\n".join(f"{k}={v}" for k, v in values.items()))
        print("\nAdd the lines above to .env (mode 600) and restart: docker compose up -d panel")


def _update_env(path: str, values: dict[str, str]) -> None:
    """Заменяет или дописывает KEY=value в .env, остальные строки (и комментарии) не трогает."""
    try:
        lines = open(path, encoding="utf-8").read().splitlines()
    except FileNotFoundError:
        lines = []
    seen = set()
    for i, line in enumerate(lines):
        key = line.split("=", 1)[0].strip()
        if key in values:
            lines[i] = f"{key}={values[key]}"
            seen.add(key)
    lines += [f"{k}={v}" for k, v in values.items() if k not in seen]
    with open(path, "w", encoding="utf-8") as f:  # bind-mount: перезапись на месте, без rename
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    _cli()
