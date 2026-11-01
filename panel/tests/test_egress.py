import io
import json

from app import egress
from tests.test_auth import _csrf, _login, client  # noqa: F401 — фикстура

TRACE = """traceroute to 192.0.2.50 (192.0.2.50), 20 hops max, 46 byte packets
 1  172.16.0.1  0.068 ms
 2  10.0.0.2  42.951 ms
 3  *
 4  *
 5  *
"""


def test_parse_traceroute_folds_silent_tail():
    hops = egress.parse_traceroute(TRACE)
    assert hops == [{"ttl": 1, "ip": "172.16.0.1", "rtt": 0.068}, {"ttl": 2, "ip": "10.0.0.2", "rtt": 42.951},
                    {"ttl": 3, "ip": None, "rtt": None}]


def test_parse_whoami():
    ya = 'x"ipv4":{"value":"8.8.4.4"},"isp":{"asn":[64500],"localName":null,"isVpn":false}y'
    assert egress.parse_whoami("Yandex", ya) == {"ip": "8.8.4.4", "asn": "AS64500", "isVpn": False}
    cf = "fl=1\nip=198.51.100.20\ncolo=AMS\nloc=NL\nwarp=off\n"
    assert egress.parse_whoami("Cloudflare", cf) == {"ip": "198.51.100.20", "loc": "NL", "colo": "AMS", "warp": "off"}
    assert egress.parse_whoami("ipinfo.io", json.dumps({"ip": "198.51.100.21", "country": "NL", "readme": "x"})) == \
        {"ip": "198.51.100.21", "country": "NL"}


def test_tree_merges_common_hops():
    gw = {"ttl": 1, "ip": "172.16.0.1", "rtt": 0.1}
    tree = egress.build_tree([
        {"host": "google.com", "hops": [gw, {"ttl": 2, "ip": "10.0.0.2", "rtt": 40}, {"ttl": 3, "ip": None, "rtt": None}]},
        {"host": "ipinfo.io", "service": "ipinfo.io", "exit": {"ip": "198.51.100.21"},
         "hops": [gw, {"ttl": 2, "ip": "10.0.0.2", "rtt": 41}, {"ttl": 3, "ip": None, "rtt": None}]},
        {"host": "yandex.ru", "hops": [gw, {"ttl": 2, "ip": "192.0.2.3", "rtt": 0.9}]},
    ])
    assert len(tree) == 1 and tree[0]["ip"] == "172.16.0.1"
    vx, direct = tree[0]["children"]
    assert vx["ip"] == "10.0.0.2" and direct["leaves"][0]["host"] == "yandex.ru"
    assert [l["host"] for l in vx["children"][0]["leaves"]] == ["google.com", "ipinfo.io"]


def test_probe_runs_in_wrapped_context(monkeypatch):
    calls = []

    def fake_run(argv, **kw):
        calls.append(argv)
        out = TRACE if "traceroute" in argv else "ip=1.2.3.4\nloc=NL\n"
        return type("R", (), {"returncode": 0, "stdout": out, "stderr": ""})()

    class FakePopen:
        def __init__(self, argv, **kw):
            calls.append(argv)
            self.stdout = iter((TRACE + " 6  *\n 7  *\n 8  10.0.0.9  1 ms\n").splitlines(True))
            self.stderr = io.StringIO("")

        def kill(self):
            pass

        def wait(self):
            pass

    monkeypatch.setattr(egress.subprocess, "run", fake_run)
    monkeypatch.setattr(egress.subprocess, "Popen", FakePopen)
    monkeypatch.setattr(egress, "resolve", lambda h: "9.9.9.9")
    eg = egress.Egress(lambda a: ["nsenter", "-n", "--", *a], targets=["example.com"])
    p = eg._probe({"host": "www.cloudflare.com", "service": "Cloudflare", "url": "https://www.cloudflare.com/cdn-cgi/trace"})
    assert p["exit"]["ip"] == "1.2.3.4" and len(p["hops"]) == 3
    assert all(c[:3] == ["nsenter", "-n", "--"] for c in calls)
    assert "www.cloudflare.com:443:9.9.9.9" in calls[1]
    assert [h["ttl"] for h in p["hops"]] == [1, 2, 3]       # после трёх безответных хопов traceroute остановлен


def test_whoami_error_is_reported(monkeypatch):
    monkeypatch.setattr(egress.subprocess, "run", lambda argv, **kw: type("R", (), {
        "returncode": 0, "stdout": '{"status": 429, "error": {"title": "Rate limit hit"}}', "stderr": ""})())
    monkeypatch.setattr(egress, "resolve", lambda h: "9.9.9.9")
    eg = egress.Egress(lambda a: a)
    monkeypatch.setattr(eg, "_traceroute", lambda ip: [])
    p = eg._probe({"host": "ipinfo.io", "service": "ipinfo.io", "url": "https://ipinfo.io/json"})
    assert "Rate limit" in p["error"] and not p["exit"]


def test_server_page_settings_and_ip(client, monkeypatch):  # noqa: F811
    from app import main
    _login(client)
    eg = main.app.state.egress
    eg.result = {"ts": 1, "duration": 3.2, "errors": [],
                 "exits": [{"ip": "8.8.4.4", "seen_by": {"Yandex": {"ip": "8.8.4.4", "asn": "AS64500", "isVpn": False}}}],
                 "tree": egress.build_tree([{"host": "yandex.ru", "service": "Yandex", "exit": {"ip": "8.8.4.4"},
                                             "hops": [{"ttl": 1, "ip": "172.16.0.1", "rtt": 0.1}]}])}
    page = client.get("/server").text
    assert "Client path to the internet" in page and "8.8.4.4" in page and "AS64500" in page

    r = client.post("/server/egress/settings", data={"targets": "ya.ru, github.com", "labels": "10.0.0.2 = ams\nbad = x",
                                                    "token": "tok123", "csrf": _csrf(page)}, follow_redirects=False)
    assert r.status_code == 303
    assert eg.targets == ["ya.ru", "github.com"] and eg.token == "tok123"
    conn = main.app.state.db
    assert "tok123" not in (main.db.get_state(conn, "ipinfo_token") or "")       # ключ хранится зашифрованным
    page = client.get("/server").text
    assert "10.0.0.2 = ams" in page and "tok123" not in page

    monkeypatch.setattr(eg, "ipinfo", lambda ip: {"country_code": "RU"})
    d = client.get("/server/ip/8.8.4.4").json()
    assert d["ipinfo"] == {"country_code": "RU"} and d["yandex"]["isVpn"] is False
    assert client.get("/server/ip/10.0.0.2").json()["private"] is True
    assert client.get("/server/ip/not-an-ip").status_code == 400

    bad = client.post("/server/egress/settings", data={"targets": "rm -rf;", "csrf": _csrf(page)})
    assert "Invalid" in bad.text and eg.targets == ["ya.ru", "github.com"]
    client.post("/server/egress/settings", data={"targets": "", "clear_token": "1", "csrf": _csrf(page)})
    assert eg.token == "" and eg.targets == list(egress.DEFAULT_TARGETS)
