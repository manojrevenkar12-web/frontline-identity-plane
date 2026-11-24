from __future__ import annotations

from fip.protocols.scim import ENTERPRISE, PATCH_OP, ScimPolicy, ScimService


def svc(**kw: bool) -> tuple[ScimService, str, str]:
    s = ScimService(ScimPolicy(**kw))
    return s, s.issue_token("a"), s.issue_token("b")


def user(s: ScimService, t: str, name: str) -> str:
    st, body = s.create_user(t, {"userName": name, ENTERPRISE: {"department": "Production", "division": "Augsburg", "employeeNumber": "B1"}})
    assert st == 201
    return str(body["id"])


def test_the_tenant_comes_from_the_token_not_the_path() -> None:
    s, ta, tb = svc()
    user(s, "a", "x@a.example")
    assert s.tenant_for(tb, "a") == "b"
    weak, _, tb2 = svc(tenant_from_token=False)
    assert weak.tenant_for(tb2, "a") == "a"
    assert s.tenant_for("scim_unknown") is None


def test_entra_quirks_are_understood() -> None:
    s, _, _ = svc()
    uid = user(s, "a", "x@a.example")
    st, body = s.patch_user("a", uid, {"schemas": [PATCH_OP], "Operations": [{"op": "Replace", "path": "active", "value": "False"}]})
    assert st == 200 and body["active"] is False


def test_a_spec_strict_server_refuses_them_and_the_deactivation_is_lost() -> None:
    s, _, _ = svc(lenient_ops=False)
    uid = user(s, "a", "x@a.example")
    st, _ = s.patch_user("a", uid, {"schemas": [PATCH_OP], "Operations": [{"op": "Replace", "path": "active", "value": "False"}]})
    assert st == 400
    assert s.stores["a"].users[uid]["active"] is True


def test_group_membership_add_remove_and_unknown_members() -> None:
    s, _, _ = svc()
    u1, u2 = user(s, "a", "x@a.example"), user(s, "a", "y@a.example")
    st, g = s.create_group("a", {"displayName": "AUG-Operators", "externalId": "g1", "members": [{"value": u1}]})
    assert st == 201
    s.patch_group("a", g["id"], {"Operations": [{"op": "Add", "path": "members", "value": [{"value": u2}]}]})
    assert {m["value"] for m in s.stores["a"].groups[g["id"]]["members"]} == {u1, u2}
    s.patch_group("a", g["id"], {"Operations": [{"op": "remove", "path": f'members[value eq "{u1}"]'}]})
    assert {m["value"] for m in s.stores["a"].groups[g["id"]]["members"]} == {u2}
    assert s.patch_group("a", g["id"], {"Operations": [{"op": "add", "path": "members", "value": [{"value": "nope"}]}]})[0] == 404


def test_users_only_mode_answers_501_for_groups() -> None:
    s, _, _ = svc(groups=False)
    assert s.create_group("a", {"displayName": "x"})[0] == 501


def test_filters_uniqueness_and_etags() -> None:
    s, _, _ = svc()
    uid = user(s, "a", "X@a.example")
    assert s.create_user("a", {"userName": "x@a.example"})[0] == 409
    assert s.list_users("a", 'userName eq "x@a.example"')[1]["totalResults"] == 1
    assert s.list_users("a", 'userName eq "x" or 1 eq 1')[0] == 400
    v = s.stores["a"].users[uid]["meta"]["version"]
    s.put_user("a", uid, {"userName": "X@a.example", "active": True})
    assert s.put_user("a", uid, {"userName": "X@a.example"}, if_match=v)[0] == 412
