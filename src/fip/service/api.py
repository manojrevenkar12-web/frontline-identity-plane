"""The identity plane's HTTP API: SCIM 2.0 for the customer's IdP, SAML and OIDC sign-in per tenant, token exchange
for agents, badge sign-in for stations, and one authorization endpoint the product asks before every action.

The tenant always comes from a credential: the SCIM bearer token, the signed assertion's issuer and key, or the agent
token's audience. A tenant in the URL only selects the endpoint; it never widens what a credential may see.
"""

from __future__ import annotations

import base64
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Form, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel

from .. import config
from ..authz.agents import AgentPolicy, AgentTokens
from ..authz.engine import AccessEngine
from ..authz.model import ACTIONS, MappingRule
from ..authz.stations import StationPolicy, Stations
from ..protocols import oidc, saml
from ..protocols.scim import ScimPolicy, ScimService

SP_ENTITY = "https://identity.frontline.example/sp"


@dataclass
class IdentityPlane:
    """The platform's components wired together with the settings in config/platform.yml."""

    cfg: dict[str, Any]
    scim: ScimService
    engine: AccessEngine
    sp: saml.ServiceProvider
    rp: oidc.RelyingParty
    agents: AgentTokens
    stations: Stations
    counters: dict[str, int] = field(default_factory=dict)

    @classmethod
    def from_config(cls, cfg: dict[str, Any] | None = None) -> IdentityPlane:
        cfg = cfg or config.platform()
        scim = ScimService(ScimPolicy(**cfg["scim"]))
        engine = AccessEngine(scim, group_sync=bool(cfg["provisioning"]["group_sync"]), honour_dates=bool(cfg["provisioning"]["honour_dates"]))
        opol = oidc.OidcPolicy(**cfg["oidc"])
        return cls(
            cfg,
            scim,
            engine,
            saml.ServiceProvider(saml.SamlPolicy(**cfg["saml"])),
            oidc.RelyingParty(opol),
            AgentTokens(AgentPolicy(**cfg["agents"]), engine, opol),
            Stations(StationPolicy(**cfg["stations"]), engine),
        )

    def count(self, k: str) -> None:
        self.counters[k] = self.counters.get(k, 0) + 1

    def add_tenant(self, tenant: str, *, saml_issuer: str, saml_key: rsa.RSAPublicKey, oidc_provider: oidc.Provider) -> str:
        """Register a customer: its IdP for SAML and OIDC. Returns the SCIM bearer token for its IdP."""
        self.sp.tenants[tenant] = saml.TenantSaml(tenant, saml_issuer, saml_key, SP_ENTITY, f"https://identity.frontline.example/{tenant}/saml/acs")
        self.rp.providers[oidc_provider.issuer] = oidc_provider
        tcfg = oidc.TenantOidc(tenant, oidc_provider.issuer, f"frontline-{tenant}", f"https://identity.frontline.example/{tenant}/oidc/cb")
        self.rp.tenants[tenant] = tcfg
        self.agents.idp[tenant] = (tcfg, oidc_provider.jwks)
        return self.scim.issue_token(tenant)


class ExchangeBody(BaseModel):
    grant_type: str
    subject_token: str
    client_id: str
    client_secret: str
    tenant: str
    scope: str
    workspaces: list[str]


class AuthorizeBody(BaseModel):
    action: str
    workspace: str


class BadgeBody(BaseModel):
    badge: str


class ActBody(BaseModel):
    action: str
    pin: str | None = None


def _bearer(authz: str | None) -> str:
    if not authz or not authz.lower().startswith("bearer "):
        raise HTTPException(401, "bearer token required")
    return authz.split(" ", 1)[1]


def create_app(plane: IdentityPlane, clock: Any = time.time) -> FastAPI:
    app = FastAPI(title="frontline-identity-plane", version="1.0.0")
    app.state.plane = plane

    def scim_tenant(authz: str | None) -> str:
        t = plane.scim.tenant_for(_bearer(authz))
        if t is None:
            raise HTTPException(401, "unknown SCIM token")
        return t

    def scim_out(res: tuple[int, dict[str, Any]]) -> Response:
        status, body = res
        plane.count(f"scim_{status}")
        if status == 204:
            return Response(status_code=204)
        return JSONResponse(body, status_code=status, media_type="application/scim+json")

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        return {"ok": True, "tenants": len(plane.sp.tenants)}

    @app.get("/metrics", response_class=PlainTextResponse)
    def metrics() -> str:
        return "".join(f"fip_{k}_total {v}\n" for k, v in sorted(plane.counters.items()))

    # ------------------------------------------------------------------------------ SCIM 2.0
    @app.post("/scim/v2/Users")
    async def create_user(request: Request, authorization: str | None = Header(None)) -> Response:
        return scim_out(plane.scim.create_user(scim_tenant(authorization), await request.json()))

    @app.get("/scim/v2/Users")
    def list_users(filter: str | None = None, authorization: str | None = Header(None)) -> Response:  # noqa: A002 - SCIM name
        return scim_out(plane.scim.list_users(scim_tenant(authorization), filter))

    @app.get("/scim/v2/Users/{uid}")
    def get_user(uid: str, authorization: str | None = Header(None)) -> Response:
        return scim_out(plane.scim.get_user(scim_tenant(authorization), uid))

    @app.put("/scim/v2/Users/{uid}")
    async def put_user(uid: str, request: Request, authorization: str | None = Header(None), if_match: str | None = Header(None)) -> Response:
        return scim_out(plane.scim.put_user(scim_tenant(authorization), uid, await request.json(), if_match))

    @app.patch("/scim/v2/Users/{uid}")
    async def patch_user(uid: str, request: Request, authorization: str | None = Header(None), if_match: str | None = Header(None)) -> Response:
        return scim_out(plane.scim.patch_user(scim_tenant(authorization), uid, await request.json(), if_match))

    @app.delete("/scim/v2/Users/{uid}")
    def delete_user(uid: str, authorization: str | None = Header(None)) -> Response:
        return scim_out(plane.scim.delete_user(scim_tenant(authorization), uid))

    @app.post("/scim/v2/Groups")
    async def create_group(request: Request, authorization: str | None = Header(None)) -> Response:
        return scim_out(plane.scim.create_group(scim_tenant(authorization), await request.json()))

    @app.get("/scim/v2/Groups")
    def list_groups(filter: str | None = None, authorization: str | None = Header(None)) -> Response:  # noqa: A002
        return scim_out(plane.scim.list_groups(scim_tenant(authorization), filter))

    @app.patch("/scim/v2/Groups/{gid}")
    async def patch_group(gid: str, request: Request, authorization: str | None = Header(None)) -> Response:
        return scim_out(plane.scim.patch_group(scim_tenant(authorization), gid, await request.json()))

    # ------------------------------------------------------------------------------ sign-in
    @app.get("/t/{tenant}/saml/login")
    def saml_login(tenant: str) -> dict[str, str]:
        if tenant not in plane.sp.tenants:
            raise HTTPException(404, "unknown tenant")
        return {"request_id": plane.sp.authn_request(tenant, clock() - _epoch()), "idp": plane.sp.tenants[tenant].idp_entity_id}

    @app.post("/t/{tenant}/saml/acs")
    def saml_acs(tenant: str, SAMLResponse: str = Form(...)) -> dict[str, Any]:  # noqa: N803 - SAML binding name
        try:
            login = plane.sp.consume(tenant, base64.b64decode(SAMLResponse), clock() - _epoch())
        except saml.SamlError as e:
            plane.count(f"saml_rejected_{e.code}")
            raise HTTPException(403, f"sign-in refused: {e.code}") from e
        plane.count("saml_ok")
        return {"user": login.name_id, "grants": sorted(f"{g.workspace}:{g.role}" for g in plane.engine.grants(tenant, login.name_id))}

    @app.get("/t/{tenant}/oidc/login")
    def oidc_login(tenant: str) -> dict[str, str]:
        if tenant not in plane.rp.tenants:
            raise HTTPException(404, "unknown tenant")
        return plane.rp.start(tenant, clock())

    @app.get("/t/{tenant}/oidc/callback")
    def oidc_callback(tenant: str, code: str, state: str, iss: str | None = None) -> dict[str, Any]:
        try:
            login = plane.rp.callback(tenant, {"code": code, "state": state, "iss": iss or ""}, clock())
        except oidc.OidcError as e:
            plane.count(f"oidc_rejected_{e.code}")
            raise HTTPException(403, f"sign-in refused: {e.code}") from e
        plane.count("oidc_ok")
        return {"user": login.email, "grants": sorted(f"{g.workspace}:{g.role}" for g in plane.engine.grants(tenant, login.email))}

    # ------------------------------------------------------------------------------ agents
    @app.post("/oauth/token")
    def token_exchange(body: ExchangeBody) -> dict[str, Any]:
        if body.grant_type != "urn:ietf:params:oauth:grant-type:token-exchange":
            raise HTTPException(400, "unsupported_grant_type")
        try:
            tok = plane.agents.exchange(
                client_id=body.client_id,
                client_secret=body.client_secret,
                subject_token=body.subject_token,
                tenant=body.tenant,
                scopes=set(body.scope.split()) & ACTIONS,
                workspaces=set(body.workspaces),
                now=clock(),
            )
        except PermissionError as e:
            plane.count("exchange_refused")
            raise HTTPException(400, str(e)) from e
        plane.count("exchange_ok")
        return {"access_token": tok, "issued_token_type": "urn:ietf:params:oauth:token-type:jwt", "token_type": "Bearer", "expires_in": int(plane.agents.policy.ttl_s)}

    @app.post("/t/{tenant}/authorize")
    def authorize(tenant: str, body: AuthorizeBody, authorization: str | None = Header(None)) -> dict[str, Any]:
        d = plane.agents.check(_bearer(authorization), tenant, body.action, body.workspace, clock())
        plane.count("authorize_allow" if d.allow else "authorize_deny")
        return {"allow": d.allow, "reason": d.reason}

    # ------------------------------------------------------------------------------ stations
    @app.post("/stations/{station}/badge")
    def badge(station: str, body: BadgeBody) -> dict[str, Any]:
        s = plane.stations.badge(station, body.badge, clock())
        if s is None:
            raise HTTPException(403, "badge not accepted at this station")
        return {"session": s.id, "user": s.user, "workspace": s.workspace}

    @app.post("/stations/{station}/act")
    def act(station: str, body: ActBody) -> dict[str, Any]:
        d, who = plane.stations.act(station, body.action, clock(), pin=body.pin)
        return {"allow": d.allow, "reason": d.reason, "as": who}

    return app


def _epoch() -> float:
    return saml.EPOCH.timestamp()


def create_demo_app() -> FastAPI:
    """A demo tenant with its own IdP keys, a SCIM token printed to the log, and one rule."""
    plane = IdentityPlane.from_config()
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    prov = oidc.Provider("https://login.demo.example", rsa.generate_private_key(public_exponent=65537, key_size=2048), kid="demo-k1")
    token = plane.add_tenant("demo", saml_issuer="https://login.demo.example", saml_key=k.public_key(), oidc_provider=prov)
    plane.engine.rules["demo"] = [MappingRule("demo-operators", "demo/augsburg", "operator", "demo")]
    plane.stations.register("demo/augsburg/st0", "demo", "demo/augsburg")
    print(f"demo SCIM token: {token}  (agent secret: {plane.agents.register('demo', 'assistant-demo', frozenset(ACTIONS))})")
    _ = secrets
    return create_app(plane)
