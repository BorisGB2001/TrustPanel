import re
import time

import pyotp

from tests.test_auth import _csrf, _login, client  # noqa: F401 — фикстура


def _new_admin(client, name="anna.k"):
    _login(client)
    page = client.get("/admins").text
    page = client.post("/admins/add", data={"username": name, "role": "super", "csrf": _csrf(page)}).text
    pw = re.search(r"<code>([^<]+)</code>", page).group(1)
    assert client.get("/admins").text.count(pw) == 0            # временный пароль показан один раз
    client.post("/logout", data={"csrf": _csrf(page)})
    return pw


def _first_login(client, name, pw):
    from app import main
    r = client.post("/login", data={"username": name, "password": pw, "code": "", "csrf": _csrf(client.get("/login").text)},
                    follow_redirects=False)
    assert r.headers["location"] == "/login/totp"
    secret = next(v[1] for v in main.ENROLL.values())
    page = client.get("/login/totp").text
    assert secret in page and "<svg" in page
    return secret, page


def test_first_login_binds_totp_and_forces_password_change(client):
    pw = _new_admin(client)
    secret, page = _first_login(client, "anna.k", pw)
    assert "Wrong code" in client.post("/login/totp", data={"code": "000000", "csrf": _csrf(page)}).text
    r = client.post("/login/totp", data={"code": pyotp.TOTP(secret).now(), "csrf": _csrf(page)}, follow_redirects=False)
    assert r.headers["location"] == "/"
    assert client.get("/", follow_redirects=False).headers["location"] == "/account"   # временный пароль
    page = client.get("/account").text
    bad = client.post("/account", data={"current": pw, "new": "short", "repeat": "short", "csrf": _csrf(page)})
    assert "at least 12" in bad.text
    client.post("/account", data={"current": pw, "new": "a-new-long-password", "repeat": "a-new-long-password",
                                  "csrf": _csrf(page)})
    assert client.get("/", follow_redirects=False).status_code == 200
    assert client.get("/admins").status_code == 200              # роль super


def test_totp_code_not_accepted_twice_and_wrong_password(client):
    from app import admins, main
    pw = _new_admin(client)
    secret, page = _first_login(client, "anna.k", pw)
    code = pyotp.TOTP(secret).now()
    client.post("/login/totp", data={"code": code, "csrf": _csrf(page)})
    client.post("/logout", data={"csrf": _csrf(client.get("/account").text)})
    acc = main.app.state.accounts
    row = admins.by_name(main.app.state.db, "anna.k")
    assert not acc.check_totp(row, code)                          # тот же код второй раз не проходит
    r = client.post("/login", data={"username": "anna.k", "password": "wrong-password", "code": "",
                                    "csrf": _csrf(client.get("/login").text)})
    assert "Wrong username" in r.text
    r = client.post("/login", data={"username": "nobody", "password": pw, "code": "", "csrf": _csrf(client.get("/login").text)})
    assert "Wrong username" in r.text


def test_reset_and_disable_end_sessions(client):
    from app import admins, main
    pw = _new_admin(client)
    secret, page = _first_login(client, "anna.k", pw)
    client.post("/login/totp", data={"code": pyotp.TOTP(secret).now(), "csrf": _csrf(page)})
    assert client.get("/account").status_code == 200
    conn, acc = main.app.state.db, main.app.state.accounts
    aid = admins.by_name(conn, "anna.k")["id"]
    acc.set_disabled(aid, True)
    assert client.get("/account", follow_redirects=False).headers["location"] == "/login"   # сессия закрыта
    r = client.post("/login", data={"username": "anna.k", "password": pw, "code": "", "csrf": _csrf(client.get("/login").text)})
    assert "Wrong username" in r.text                                                   # отключённый не входит
    acc.set_disabled(aid, False)
    new = acc.reset(aid)
    row = admins.get(conn, aid)
    assert row["totp_enc"] is None and row["must_change"] == 1 and new != pw


def test_env_admin_protected_and_role_checks(client):
    from app import admins, main
    conn, acc = main.app.state.db, main.app.state.accounts
    env = conn.execute("SELECT * FROM admins WHERE env = 1").fetchone()
    assert env["username"] == "admin" and env["role"] == "super"
    for fn in (lambda: acc.reset(env["id"]), lambda: acc.set_disabled(env["id"], True), lambda: acc.delete(env["id"])):
        try:
            fn()
            raise AssertionError("env admin must not be editable")
        except admins.AdminError:
            pass
    try:
        acc.create("x.admin", "owner")                            # неизвестная роль
        raise AssertionError
    except admins.AdminError:
        pass
    pw = _new_admin(client, "bob.m")
    conn.execute("UPDATE admins SET role = 'group', must_change = 0 WHERE username = 'bob.m'")
    secret, page = _first_login(client, "bob.m", pw)
    client.post("/login/totp", data={"code": pyotp.TOTP(secret).now(), "csrf": _csrf(page)})
    assert client.get("/admins").status_code == 403 and client.get("/server").status_code == 403
    assert 'href="/admins"' not in client.get("/").text


def test_enrollment_expires(client):
    from app import main
    pw = _new_admin(client)
    _first_login(client, "anna.k", pw)
    for k, v in list(main.ENROLL.items()):
        main.ENROLL[k] = (v[0], v[1], time.time() - 1)
    assert client.get("/login/totp", follow_redirects=False).headers["location"] == "/login"
