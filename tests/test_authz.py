from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from fip.authz.agents import AgentPolicy, AgentTokens
from fip.authz.engine import AccessEngine
from fip.authz.model import MappingRule
from fip.authz.stations import StationPolicy, Stations
from fip.protocols import oidc
from fip.protocols.scim import ENTERPRISE, PATCH_OP, ScimPolicy, ScimService


@pytest.fixture()
def world(key: rsa.RSAPrivateKey) -> dict[str, Any]:
    scim = ScimService(ScimPolicy())
    scim.issue_token("a")
    scim.issue_token("b")
    ids = {}
    for name, badge, dept in (("op@a.example", "B1", "Production"), ("qa@a.example", "B2", "Quality")):
        ids[name] = scim.create_user("a", {"userName": name, ENTERPRISE: {"department": dept, "division": "Augsburg", "employeeNumber": badge}})[1]["id"]
    scim.create_group("a", {"displayName": "AUG-Operators", "externalId": "g-op", "members": [{"value": ids["op@a.example"]}]})
    scim.create_group("a", {"displayName": "AUG-QS", "externalId": "g-qa", "members": [{"value": ids["qa@a.example"]}]})
    engine = AccessEngine(scim, rules={"a": [MappingRule("g-op", "a/aug", "operator", "t"), MappingRule("g-qa", "a/aug", "approver", "t")]})
    prov = oidc.Provider("https://login.a.example", key, kid="k")
    agents = AgentTokens(AgentPolicy(), engine, oidc.OidcPolicy())
    cfg = oidc.TenantOidc("a", prov.issuer, "c", "r")
    agents.idp["a"] = (cfg, prov.jwks)
    secret = agents.register("a", "bot", frozenset({"app.view", "app.run", "app.edit", "record.write", "record.approve"}))
    return {"scim": scim, "engine": engine, "prov": prov, "agents": agents, "secret": secret, "ids": ids}


def deactivate(w: dict[str, Any], name: str) -> None:
    w["scim"].patch_user("a", w["ids"][name], {"schemas": [PATCH_OP], "Operations": [{"op": "replace", "path": "active", "value": False}]})


def test_groups_and_rules_give_roles_and_a_deactivation_removes_them(world: dict[str, Any]) -> None:
    e = world["engine"]
    assert e.decide("a", "op@a.example", "app.run", "a/aug").allow
    assert not e.decide("a", "op@a.example", "record.approve", "a/aug").allow
    assert not e.decide("b", "op@a.example", "app.run", "a/aug").allow  # another tenant does not know them
    deactivate(world, "op@a.example")
    assert not e.decide("a", "op@a.example", "app.run", "a/aug").allow


def exchange(w: dict[str, Any], who: str, scopes: set[str], now: float = 100.0, **kw: Any) -> str:
    sub = w["prov"].id_token({"sub": who, "email": who}, "c", now)
    return w["agents"].exchange(client_id="bot", client_secret=w["secret"], subject_token=sub, tenant=kw.get("tenant", "a"), scopes=scopes, workspaces={"a/aug"}, now=now)


def test_an_agent_gets_no_more_than_the_person(world: dict[str, Any]) -> None:
    tok = exchange(world, "op@a.example", {"app.run", "record.approve"})
    a = world["agents"]
    assert a.check(tok, "a", "app.run", "a/aug", 101).allow
    assert not a.check(tok, "a", "record.approve", "a/aug", 101).allow
    with pytest.raises(PermissionError, match="invalid_scope"):
        exchange(world, "op@a.example", {"record.approve"})


def test_an_agent_token_dies_with_the_persons_access(world: dict[str, Any]) -> None:
    tok = exchange(world, "op@a.example", {"app.run"})
    deactivate(world, "op@a.example")
    assert not world["agents"].check(tok, "a", "app.run", "a/aug", 101).allow


def test_an_agent_token_is_bound_to_its_tenant_and_expires(world: dict[str, Any]) -> None:
    tok = exchange(world, "op@a.example", {"app.run"})
    assert not world["agents"].check(tok, "b", "app.run", "a/aug", 101).allow
    assert not world["agents"].check(tok, "a", "app.run", "a/aug", 100 + 601).allow
    with pytest.raises(PermissionError, match="invalid_client"):
        exchange(world, "op@a.example", {"app.run"}, tenant="b")


def test_without_down_scoping_or_live_checks_the_agent_overreaches(world: dict[str, Any]) -> None:
    world["agents"].policy = AgentPolicy(down_scope=False, live_check=False)
    tok = exchange(world, "op@a.example", {"record.approve"})
    deactivate(world, "op@a.example")
    assert world["agents"].check(tok, "a", "record.approve", "a/aug", 101).allow


def test_stations_lock_when_idle_and_a_signature_needs_the_pin(world: dict[str, Any]) -> None:
    st = Stations(StationPolicy(), world["engine"])
    st.register("s1", "a", "a/aug")
    st.pins[("a", "qa@a.example")] = "1234"
    assert st.badge("s1", "B1", 0) is not None
    assert st.act("s1", "record.write", 60)[0].allow
    assert not st.act("s1", "record.write", 60 + 301 + 60)[0].allow  # walked away: locked
    st.badge("s1", "B2", 1000)
    assert not st.act("s1", "record.approve", 1001)[0].allow
    d, who = st.act("s1", "record.approve", 1002, pin="1234")
    assert d.allow and who == "qa@a.example"


def test_a_badge_works_only_for_an_active_person_with_a_role_at_that_plant(world: dict[str, Any]) -> None:
    st = Stations(StationPolicy(), world["engine"])
    st.register("s1", "a", "a/aug")
    st.register("s2", "a", "a/other")
    assert st.badge("s2", "B1", 0) is None
    deactivate(world, "op@a.example")
    assert st.badge("s1", "B1", 0) is None
