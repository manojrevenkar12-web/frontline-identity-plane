from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from fip.authz.model import MappingRule
from fip.protocols import oidc, saml
from fip.protocols.scim import ENTERPRISE
from fip.service.api import IdentityPlane, create_app

NOW = 1_800_000_000.0


@pytest.fixture()
def env(key: rsa.RSAPrivateKey, other_key: rsa.RSAPrivateKey) -> dict:
    plane = IdentityPlane.from_config()
    prov = oidc.Provider("https://login.a.example", other_key, kid="a1")
    tok_a = plane.add_tenant("a", saml_issuer="https://idp.a.example", saml_key=key.public_key(), oidc_provider=prov)
    tok_b = plane.add_tenant("b", saml_issuer="https://idp.b.example", saml_key=other_key.public_key(), oidc_provider=oidc.Provider("https://login.b.example", key, kid="b1"))
    plane.engine.rules["a"] = [MappingRule("g-op", "a/aug", "operator", "t")]
    plane.stations.register("st1", "a", "a/aug")
    secret = plane.agents.register("a", "bot", frozenset({"app.run", "app.edit"}))
    client = TestClient(create_app(plane, clock=lambda: NOW))
    return {"c": client, "a": tok_a, "b": tok_b, "plane": plane, "prov": prov, "secret": secret, "idp": saml.IdentityProvider("https://idp.a.example", key)}


def h(tok: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {tok}"}


def provision(env: dict) -> str:
    c = env["c"]
    r = c.post("/scim/v2/Users", json={"userName": "op@a.example", ENTERPRISE: {"department": "Production", "division": "Augsburg", "employeeNumber": "B7"}}, headers=h(env["a"]))
    assert r.status_code == 201
    uid = r.json()["id"]
    assert c.post("/scim/v2/Groups", json={"displayName": "AUG-Operators", "externalId": "g-op", "members": [{"value": uid}]}, headers=h(env["a"])).status_code == 201
    return str(uid)


def test_scim_needs_a_token_and_never_crosses_tenants(env: dict) -> None:
    provision(env)
    c = env["c"]
    assert c.get("/scim/v2/Users").status_code == 401
    assert c.get("/scim/v2/Users", headers=h(env["b"])).json()["totalResults"] == 0
    assert c.get("/scim/v2/Users", headers=h(env["a"])).json()["totalResults"] == 1


def test_saml_sign_in_returns_the_grants(env: dict) -> None:
    provision(env)
    c = env["c"]
    rid = c.get("/t/a/saml/login").json()["request_id"]
    now = NOW - saml.EPOCH.timestamp()
    resp = env["idp"].response(now=now, name_id="op@a.example", audience="https://identity.frontline.example/sp", acs_url="https://identity.frontline.example/a/saml/acs", in_response_to=rid)
    form = {"SAMLResponse": base64.b64encode(saml.serialize(resp)).decode()}
    r = c.post("/t/a/saml/acs", data=form)
    assert r.status_code == 200 and r.json()["grants"] == ["a/aug:operator"]
    assert c.post("/t/a/saml/acs", data=form).status_code == 403  # the same response again
    assert "fip_saml_ok_total 1" in c.get("/metrics").text


def test_token_exchange_and_authorize(env: dict) -> None:
    uid = provision(env)
    c = env["c"]
    sub = env["prov"].id_token({"sub": "op", "email": "op@a.example"}, "frontline-a", NOW)
    body = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token": sub,
        "client_id": "bot",
        "client_secret": env["secret"],
        "tenant": "a",
        "scope": "app.run app.edit",
        "workspaces": ["a/aug"],
    }
    r = c.post("/oauth/token", json=body)
    assert r.status_code == 200
    tok = r.json()["access_token"]
    assert c.post("/t/a/authorize", json={"action": "app.run", "workspace": "a/aug"}, headers=h(tok)).json()["allow"] is True
    assert c.post("/t/a/authorize", json={"action": "app.edit", "workspace": "a/aug"}, headers=h(tok)).json()["allow"] is False
    c.patch(f"/scim/v2/Users/{uid}", json={"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "Replace", "path": "active", "value": "False"}]}, headers=h(env["a"]))
    assert c.post("/t/a/authorize", json={"action": "app.run", "workspace": "a/aug"}, headers=h(tok)).json()["allow"] is False


def test_badge_and_act(env: dict) -> None:
    provision(env)
    c = env["c"]
    assert c.post("/stations/st1/badge", json={"badge": "B7"}).json()["user"] == "op@a.example"
    assert c.post("/stations/st1/act", json={"action": "record.write"}).json()["allow"] is True
    assert c.post("/stations/st1/badge", json={"badge": "nobody"}).status_code == 403


def test_health(env: dict) -> None:
    assert env["c"].get("/healthz").json()["tenants"] == 2
