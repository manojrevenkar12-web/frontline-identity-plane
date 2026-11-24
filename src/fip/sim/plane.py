"""Builds one design of the identity plane for a site: the platform's components with the design's settings,
connected to the site's identity providers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.asymmetric import rsa

from .. import config
from ..authz.agents import AgentPolicy, AgentTokens
from ..authz.engine import AccessEngine
from ..authz.model import Grant
from ..authz.stations import StationPolicy, Stations
from ..onboarding import OnboardingPolicy, Proposal, decide
from ..protocols import oidc, saml
from ..protocols.scim import ScimPolicy, ScimService
from ..world.idp import IdP
from ..world.world import Site, read_groups

SP_ENTITY = "https://identity.frontline.example/sp"
_KEYS: dict[tuple[int, str, str, str], rsa.RSAPrivateKey] = {}


def idp_key(site: Site, tenant: str, use: str) -> rsa.RSAPrivateKey:
    k = (site.seed, site.variant, tenant, use)
    if k not in _KEYS:
        _KEYS[k] = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return _KEYS[k]


def acs(tenant: str) -> str:
    return f"https://identity.frontline.example/{tenant}/saml/acs"


def issuer(tenant: str) -> str:
    return f"https://login.{tenant}.example"


@dataclass
class Plane:
    name: str
    kind: str
    cfg: dict[str, Any]
    site: Site
    scim: ScimService
    engine: AccessEngine
    sp: saml.ServiceProvider
    rp: oidc.RelyingParty
    agents: AgentTokens
    stations: Stations
    saml_idps: dict[str, saml.IdentityProvider] = field(default_factory=dict)
    idps: dict[str, IdP] = field(default_factory=dict)
    onboarding: dict[str, Any] = field(default_factory=dict)
    agent_secrets: dict[str, str] = field(default_factory=dict)


def build(site: Site, name: str, d: dict[str, Any]) -> Plane:
    cfg = config.merged(config.platform(), d.get("set", {}))
    kind = d["kind"]
    sq = kind == "status_quo"
    scim_pol = ScimPolicy(**{**cfg["scim"], "groups": False if sq else cfg["scim"]["groups"]})
    scim = ScimService(scim_pol)
    engine = AccessEngine(scim, group_sync=not sq and bool(cfg["provisioning"]["group_sync"]), honour_dates=not sq and bool(cfg["provisioning"]["honour_dates"]))
    sp = saml.ServiceProvider(saml.SamlPolicy(**cfg["saml"]))
    opol = oidc.OidcPolicy(**cfg["oidc"])
    rp = oidc.RelyingParty(opol)
    agents = AgentTokens(AgentPolicy(**cfg["agents"]), engine, opol)
    stations = Stations(StationPolicy(**cfg["stations"]), engine)
    plane = Plane(name, kind, cfg, site, scim, engine, sp, rp, agents, stations)
    for tn, t in site.tenants.items():
        k = idp_key(site, tn, "saml")
        plane.saml_idps[tn] = saml.IdentityProvider(issuer(tn), k, clock_skew_s=t.clock_skew_s, sign_response_only=t.idp == "adfs")
        sp.tenants[tn] = saml.TenantSaml(tn, issuer(tn), k.public_key(), SP_ENTITY, acs(tn))
        prov = oidc.Provider(issuer(tn), idp_key(site, tn, "oidc"), kid=f"{tn}-k1", clock_skew_s=t.clock_skew_s)
        rp.providers[prov.issuer] = prov
        tcfg = oidc.TenantOidc(tn, prov.issuer, f"frontline-{tn}", f"https://identity.frontline.example/{tn}/oidc/cb")
        rp.tenants[tn] = tcfg
        agents.idp[tn] = (tcfg, prov.jwks)
        token = scim.issue_token(tn)
        plane.idps[tn] = IdP(site, t, scim, token)
        plane.agent_secrets[tn] = agents.register(tn, f"assistant-{tn}", frozenset({"app.view", "app.run", "app.edit", "record.write", "record.approve"}))
        for p in t.plants:
            for i in range(int(site.cfg["stations"]["per_plant"])):
                stations.register(f"{tn}/{p.lower()}/st{i}", tn, f"{tn}/{p.lower()}")
    return plane


def connect(plane: Plane) -> None:
    """Day zero: the IdP's initial sync, then the group-to-role mapping (or, today, roles set by hand)."""
    site = plane.site
    for tn, t in site.tenants.items():
        idp = plane.idps[tn]
        idp.seed([pid for pid, p in t.people.items() if p.start <= 0])
        attempt = 0
        while idp.queue:  # the initial sync retries until done
            attempt += 1
            idp.deliver(-1.0 - attempt / 1000.0)
        ob = plane.cfg["onboarding"]
        real = [g for g in t.groups if g.workspace is not None]
        if plane.kind == "status_quo":
            # roles set by hand per person; no groups
            for pid, acc in t.initial.items():
                p = t.people[pid]
                if p.start <= 0:
                    plane.engine.manual[(tn, p.email.lower())] = {Grant(w, r) for w, r in acc}
            plane.onboarding[tn] = {
                "auto": 0,
                "queued": 0,
                "wrong_auto": 0,
                "admin_minutes": sum(1 for p in t.people.values() if p.start <= 0) * float(site.cfg["status_quo"].get("admin_minutes_per_user", 2.0)),
            }
            continue
        if not ob["use_model"]:
            plane.engine.rules[tn] = [_rule(g) for g in real]
            plane.onboarding[tn] = {"auto": 0, "queued": len(t.groups), "wrong_auto": 0, "admin_minutes": len(t.groups) * float(ob["admin_minutes_per_queued_group"])}
            continue
        proposals = [Proposal(gx, ws, role, conf) for gx, ws, role, conf in read_groups(site, tn)]
        store = plane.scim.stores[tn]
        by_ext = {g.get("externalId"): g for g in store.groups.values()}

        def members_of(gx: str, store: Any = store, by_ext: Any = by_ext) -> list[dict[str, Any]]:
            g = by_ext.get(gx)
            return [store.users[m["value"]] for m in g["members"] if m["value"] in store.users] if g else []

        out = decide(proposals, members_of, {w: p for w, p in t.workspaces.items()}, OnboardingPolicy(float(ob["min_confidence"]), float(ob["member_agreement"]), bool(ob["check_members"])))
        truth = {g.external_id: (g.workspace, g.role) for g in t.groups}
        wrong = [r for r in out.rules if truth[r.group_external_id] != (r.workspace, r.role)]
        auto = {r.group_external_id for r in out.rules}
        # a person maps every queued group correctly (or dismisses it) at a cost in minutes
        rules = list(out.rules) + [_rule(g) for g in real if g.external_id not in auto]
        plane.engine.rules[tn] = rules
        plane.onboarding[tn] = {
            "auto": len(out.rules),
            "queued": len(out.queued),
            "wrong_auto": len(wrong),
            "admin_minutes": len(out.queued) * float(ob["admin_minutes_per_queued_group"]),
            "groups": len(t.groups),
        }


def _rule(g: Any) -> Any:
    from ..authz.model import MappingRule

    return MappingRule(g.external_id, g.workspace, g.role, "plant-admin")
