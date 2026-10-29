"""Общие фикстуры: TrustTunnel на временном каталоге — настоящие файлы, служба и метрики в памяти."""
import pytest
from cryptography.fernet import Fernet

from app import db
from app.config import Settings
from app.manage import Manager
from app.ttctl import TT, ClientStat, render_credentials

CREDS = [{"username": "anna", "password": "pw-anna"}, {"username": "boris", "password": "pw-boris"}]
VPN = 'listen_address = "0.0.0.0:443"\ncredentials_file = "credentials.toml"\nrules_file = "rules.toml"\n'
HOSTS = '[[main_hosts]]\nhostname = "vpn.example.com"\ncert_chain_path = "certs/cert.pem"\nprivate_key_path = "certs/key.pem"\n'


class FakeTT(TT):
    """Файлы — настоящие (tmp), перезапуск службы, метрики и экспорт конфига — в памяти."""

    def __init__(self, s):
        super().__init__(s)
        self.restarts = 0
        self.fail_restart = False
        self.stats: dict[str, ClientStat] = {}
        self.svc_pid = 100

    def restart(self):
        self.restarts += 1
        if self.fail_restart:
            raise RuntimeError("systemctl restart упал")
        self.svc_pid += 1
        self.stats = {}            # счётчики endpoint'а обнуляются при старте

    def service(self):
        return {"pid": self.svc_pid, "state": "active", "started": ""}

    def started_at(self):
        return 1_700_000_000.0

    def clients(self):
        return list(self.stats.values())

    def metrics(self):
        return {"client_sessions": float(sum(c.sessions for c in self.stats.values()))}

    def version(self):
        return "1.1.0"

    def export(self, username, password, fmt="deeplink"):
        return f"tt://?{username}:{password}" if fmt == "deeplink" else f'username = "{username}"\npassword = "{password}"\n'

    def set_stat(self, user, sessions=1, rx=0, tx=0, ip="203.0.113.5"):
        self.stats[user] = ClientStat(user, ip if sessions else None, sessions, rx, tx)


def make_tt_dir(path, creds=CREDS):
    path.mkdir(parents=True, exist_ok=True)
    (path / "vpn.toml").write_text(VPN)
    (path / "hosts.toml").write_text(HOSTS)
    (path / "rules.toml").write_text("")
    (path / "certs").mkdir(exist_ok=True)
    (path / "certs" / "cert.pem").write_text("CERT")
    (path / "certs" / "key.pem").write_text("KEY")
    (path / "credentials.toml").write_text("# admin note\n" + render_credentials(creds))
    (path / "credentials.toml").chmod(0o640)
    return path


@pytest.fixture
def env(tmp_path):
    """(Manager, FakeTT, каталог endpoint'а, БД) с двумя клиентами из credentials.toml."""
    d = make_tt_dir(tmp_path / "tt")
    s = Settings(data_dir=tmp_path / "data", tt_dir=str(d), public_host="vpn.example.com")
    conn = db.open_db(s.data_dir / "p.db")
    f = Fernet(Fernet.generate_key())
    for c, name in zip(CREDS, ("Анна", "Борис")):
        conn.execute("INSERT INTO peers (username, name, source, password_enc) VALUES (?, ?, 'endpoint', ?)",
                     (c["username"], name, f.encrypt(c["password"].encode())))
    tt = FakeTT(s)
    return Manager(s, tt, conn, f), tt, d, conn
