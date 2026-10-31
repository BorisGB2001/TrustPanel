"""Подгруппы: дерево, права администратора головной группы, итоги и квоты по поддереву, удаление."""
import pytest

from tests.test_auth import _csrf, _login, client  # noqa: F401 — фикстура
from tests.test_groups import world  # noqa: F401 — фикстура


def test_tree_and_cycles():
    from app import db, groups
    conn = db.open_db(":memory:")
    head = groups.create(conn, "Головная")
    kzn = groups.create(conn, "Казань", parent_id=head)
    sales = groups.create(conn, "Продажи", parent_id=kzn)
    other = groups.create(conn, "Другая")
    tree = groups.all_groups(conn)
    assert [(g["name"], g["depth"]) for g in tree] == [("Головная", 0), ("Казань", 1), ("Продажи", 2), ("Другая", 0)]
    assert next(g for g in tree if g["id"] == sales)["path"] == "Головная / Казань / Продажи"
    assert groups.subtree(conn, {head}) == {head, kzn, sales}
    for bad in (head, sales):                                     # в себя и в свою подгруппу — нельзя
        with pytest.raises(groups.GroupError):
            groups.update(conn, head, "Головная", "", bad)
    groups.update(conn, sales, "Продажи", "", other)
    assert groups.get(conn, sales)["parent_id"] == other
    groups.update(conn, sales, "Продажи", "", kzn)
    conn.execute("INSERT INTO peers (id, username, name, group_id) VALUES (1, 'k', 'Анна', ?)", (sales,))
    groups.delete(conn, kzn)                                      # подгруппы переходят к родителю
    assert groups.get(conn, sales)["parent_id"] == head
    assert groups.get(conn, sales) is not None
    assert groups.delete(conn, head, with_subgroups=True) == {head, sales}
    assert [g["name"] for g in groups.all_groups(conn)] == ["Другая"]
    assert conn.execute("SELECT group_id FROM peers WHERE id = 1").fetchone()[0] is None


def test_group_admin_manages_subgroups(client, world):
    from app import groups, quotas
    conn, ga, gb = world
    tok = _csrf(client.get("/groups").text)
    client.post("/groups/add", data={"csrf": tok, "name": "A-филиал", "parent_id": str(ga)})
    sub = next(g["id"] for g in groups.all_groups(conn) if g["name"] == "A-филиал")
    assert groups.get(conn, sub)["parent_id"] == ga
    # верхний уровень и чужая группа — нельзя
    assert client.post("/groups/add", data={"csrf": tok, "name": "X", "parent_id": ""}).status_code == 403
    assert client.post("/groups/add", data={"csrf": tok, "name": "Y", "parent_id": str(gb)}).status_code == 403
    # клиента — в подгруппу; он виден в фильтре головной группы, его трафик — в итогах головной группы и её квоте
    client.post("/peer/2/group", data={"csrf": tok, "group_id": str(sub)})
    assert groups.get(conn, sub) and conn.execute("SELECT group_id FROM peers WHERE id = 2").fetchone()[0] == sub
    page = client.get(f"/?group={ga}").text
    assert "Анна" in page and "Борис" in page
    assert 2 in quotas.group_peers(conn, ga)
    gp = client.get("/groups").text
    assert f'href="/groups?edit={sub}#edit"' in gp and f'href="/groups?edit={ga}#edit"' not in gp   # свою группу меняет супер
    assert "A-филиал" in gp and 'class="gname depth1"' in gp
    # подгруппу переименовать можно, назначенную группу и квоту — нет
    client.post(f"/groups/{sub}/update", data={"csrf": tok, "name": "A-Казань", "note": "", "parent_id": str(ga)})
    assert groups.get(conn, sub)["name"] == "A-Казань"
    assert client.post(f"/groups/{ga}/update", data={"csrf": tok, "name": "AA", "parent_id": ""}).status_code == 403
    assert client.post(f"/groups/{sub}/quota", data={"csrf": tok, "gib": "5"}).status_code == 403
    assert client.post(f"/groups/{ga}/delete", data={"csrf": tok}).status_code == 403
    client.post(f"/groups/{sub}/delete", data={"csrf": tok})
    assert groups.get(conn, sub) is None and conn.execute("SELECT group_id FROM peers WHERE id = 2").fetchone()[0] is None


def test_delete_with_subgroups_and_clients(client, monkeypatch):
    from app import groups, main
    conn = main.app.state.db
    head = groups.create(conn, "H")
    sub = groups.create(conn, "S", parent_id=head)
    for pid, name, g in ((1, "Анна", head), (2, "Вера", sub)):
        conn.execute("INSERT INTO peers (id, username, name, group_id) VALUES (?, ?, ?, ?)", (pid, f"k{pid}", name, g))
    deleted = []
    fake = type("M", (), {"delete_many": lambda self, ids, **kw: deleted.extend(ids)})()
    monkeypatch.setattr(main, "manager", lambda request: fake)
    _login(client)
    page = client.get(f"/groups?delete={head}").text
    assert 'name="with_subgroups"' in page and 'name="with_clients"' in page
    tok = _csrf(page)
    client.post(f"/groups/{head}/delete", data={"csrf": tok, "with_subgroups": "1", "with_clients": "1", "confirm": "H"})
    assert sorted(deleted) == [1, 2] and groups.all_groups(conn) == []


def test_breadcrumbs(client, world):
    from app import groups
    conn, ga, gb = world
    sub = groups.create(conn, "A-Казань", parent_id=ga)
    groups.set_peer_group(conn, 2, sub)
    page = client.get("/peer/2").text
    crumbs = page.split('class="crumbs"')[1].split("</nav>")[0]
    assert '<a href="/">' in crumbs and f'href="/?group={ga}"' in crumbs and f'href="/?group={sub}"' in crumbs
    assert 'aria-current="page">Борис' in crumbs
    over = client.get(f"/?group={ga}").text
    assert f'<a href="/?group={sub}">A-Казань</a>' in over                        # ссылки на подгруппы
