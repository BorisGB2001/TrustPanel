import os
import stat

import pytest

from app.manage import ManageError, suggest_username
from app.ttctl import parse_credentials, parse_clients, render_credentials


def creds(d):
    return {c["username"]: c["password"] for c in parse_credentials((d / "credentials.toml").read_text())}


def pid_of(conn, name):
    return conn.execute("SELECT id FROM peers WHERE name = ?", (name,)).fetchone()[0]


def test_credentials_roundtrip_and_quoting():
    clients = [{"username": "a", "password": 'p"q\\r'}, {"username": "b", "password": "ё"}]
    text = render_credentials(clients, "# note")
    assert text.startswith("# note\n") and parse_credentials(text) == clients


def test_parse_clients_directions_and_ports():
    got = parse_clients('[{"username":"boris","ip":"1.2.3.4:5555","sessions":2,"inbound":500,"outbound":20},'
                        '{"username":"","ip":null,"sessions":0,"inbound":0,"outbound":0}]')
    assert len(got) == 1 and got[0].ip == "1.2.3.4" and got[0].tx == 500 and got[0].rx == 20   # inbound — клиенту


def test_suggest_username():
    assert suggest_username("John iPhone", set()) == "john-iphone"
    assert suggest_username("Анна", set()) == "user-1"
    assert suggest_username("john", {"john"}) == "john-1"


def test_add_writes_credentials_and_restarts(env):
    m, tt, d, conn = env
    pid = m.add("Вика", "заметка", actor="admin")
    row = conn.execute("SELECT * FROM peers WHERE id = ?", (pid,)).fetchone()
    assert row["username"] == "user-1" and row["source"] == "panel"
    assert creds(d)["user-1"] == m.password(pid) and len(m.password(pid)) >= 20
    assert tt.restarts == 1
    text = (d / "credentials.toml").read_text()
    assert text.startswith("# admin note")                                  # пометки администратора остаются
    assert stat.S_IMODE(os.stat(d / "credentials.toml").st_mode) == 0o640  # права — как были
    assert conn.execute("SELECT kind FROM events WHERE peer_id = ?", (pid,)).fetchone()[0] == "admin_add"


def test_add_with_login_and_rejects(env):
    m, tt, d, conn = env
    m.add("iPad", username="ipad.home")
    assert "ipad.home" in creds(d)
    for kw, err in ((dict(name="Анна"), "already exists"), (dict(name=""), "1 to 64"),
                    (dict(name="X", username="anna"), "taken"), (dict(name="Y", username="bad login"), "Latin")):
        with pytest.raises(ManageError, match=err):
            m.add(**kw)


def test_add_rollback_on_restart_failure(env):
    m, tt, d, conn = env
    before = (d / "credentials.toml").read_text()
    tt.fail_restart = True
    with pytest.raises(ManageError, match="restored"):
        m.add("Вика")
    assert (d / "credentials.toml").read_text() == before
    assert conn.execute("SELECT COUNT(*) FROM peers").fetchone()[0] == 2


def test_rename_only_in_panel(env):
    m, tt, d, conn = env
    m.rename(pid_of(conn, "Анна"), "Анна Петровна")
    assert pid_of(conn, "Анна Петровна") and tt.restarts == 0 and "anna" in creds(d)


def test_disable_enable_keeps_password(env):
    m, tt, d, conn = env
    pid = pid_of(conn, "Анна")
    m.disable(pid)
    assert "anna" not in creds(d) and tt.restarts == 1
    m.enable(pid)
    assert creds(d)["anna"] == "pw-anna" and tt.restarts == 2


def test_enable_refuses_login_taken_outside(env):
    m, tt, d, conn = env
    pid = pid_of(conn, "Анна")
    m.disable(pid)
    (d / "credentials.toml").write_text(render_credentials([{"username": "anna", "password": "other"}]))
    with pytest.raises(ManageError, match="outside the panel"):
        m.enable(pid)


def test_delete_needs_exact_name_and_frees_login(env):
    m, tt, d, conn = env
    pid = pid_of(conn, "Борис")
    with pytest.raises(ManageError):
        m.delete(pid, "борис")
    m.delete(pid, "Борис")
    assert "boris" not in creds(d)
    row = conn.execute("SELECT * FROM peers WHERE id = ?", (pid,)).fetchone()
    assert row["deleted_at"] and row["password_enc"] is None and row["username"] != "boris"
    m.add("Новый Борис", username="boris")                        # логин свободен для нового клиента


def test_rekey_changes_password(env):
    m, tt, d, conn = env
    pid = pid_of(conn, "Анна")
    m.rekey(pid)
    assert creds(d)["anna"] == m.password(pid) != "pw-anna"
    m.disable(pid)
    n = tt.restarts
    m.rekey(pid)                                                   # отключённому — только в БД
    assert tt.restarts == n and "anna" not in creds(d)
    m.enable(pid)
    assert creds(d)["anna"] == m.password(pid)


def test_backups_are_private_and_rotated(env, monkeypatch):
    m, tt, d, conn = env
    monkeypatch.setattr("app.manage.KEEP_BACKUPS", 2)
    for i in range(4):
        m.add(f"c{i}")
    root = m.s.data_dir / "backups"
    dirs = [p for p in root.iterdir() if p.is_dir()]
    assert len(dirs) == 2 and stat.S_IMODE(os.stat(root).st_mode) == 0o700
    f = dirs[0] / "credentials.toml"
    assert stat.S_IMODE(os.stat(f).st_mode) == 0o600
