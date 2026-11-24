"""Known attacks on SSO, provisioning, agent tokens and stations, run as real messages against a design.

Every attempt is a crafted SAML response, OIDC callback, JWT, SCIM call or badge tap that goes through the
design's real code. An attack succeeds if the design ends up treating the attacker as someone else, or hands out
data or rights it should not. Nothing here is a flag lookup: the checks either hold or they do not.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from typing import Any

from cryptography.hazmat.primitives.asymmetric import rsa
from lxml import etree

from ..protocols import jose, oidc, saml, xmldsig
from ..rng import keyed
from ..world.world import Site
from .plane import SP_ENTITY, Plane, acs, build, connect, issuer

A = saml.A


def _people(site: Site, tenant: str, role: str | None = None) -> list[Any]:
    t = site.tenants[tenant]
    return [p for p in t.people.values() if p.start <= 0 and t.initial.get(p.pid) and (role is None or any(r == role for _, r in t.initial[p.pid]))]


def _ok_saml(plane: Plane, tenant: str, raw: bytes, victim: str, now: float) -> bool:
    try:
        login = plane.sp.consume(tenant, raw, now)
    except (saml.SamlError, ValueError, etree.XMLSyntaxError):
        return False
    return login.name_id.lower() == victim.lower()


def run_attacks(site: Site, name: str, d: dict[str, Any]) -> dict[str, dict[str, int]]:
    plane = build(site, name, d)
    connect(plane)
    n = int(site.cfg["attacks"]["attempts_per_kind"])
    results: dict[str, dict[str, int]] = {}
    saml_t = [tn for tn, t in site.tenants.items() if t.protocol == "saml"]
    oidc_t = [tn for tn, t in site.tenants.items() if t.protocol == "oidc"]
    names = list(site.tenants)

    def record(kind: str, fn: Callable[[int], bool]) -> None:
        r = results.setdefault(kind, {"attempts": 0, "successes": 0})
        for i in range(n):
            r["attempts"] += 1
            try:
                ok = fn(i)
            except Exception:  # noqa: BLE001 - an attack that crashes the design's code did not get in
                ok = False
            r["successes"] += int(bool(ok))

    def pick(tn: str, i: int, role: str | None = None) -> Any:
        ps = _people(site, tn, role) or _people(site, tn)
        return ps[int(keyed(site.seed, site.variant, "attack", tn, role, i).integers(len(ps)))]

    now = 50_000.0
    # ------------------------------------------------------------------------------------ SAML
    for tn in saml_t[:1]:
        idp = plane.saml_idps[tn]
        other = next((x for x in names if x != tn), tn)

        def legit(name_id: str, rid: str | None, t: float = now) -> etree._Element:
            return idp.response(now=t, name_id=name_id, audience=SP_ENTITY, acs_url=acs(tn), in_response_to=rid)

        def unsigned(i: int) -> bool:
            v = pick(tn, i, "admin").email
            rid = plane.sp.authn_request(tn, now)
            r = idp.response(now=now, name_id=v, audience=SP_ENTITY, acs_url=acs(tn), in_response_to=rid, sign=False)
            return _ok_saml(plane, tn, saml.serialize(r), v, now + 1)

        def wrapping(i: int) -> bool:
            v, me = pick(tn, i, "admin").email, pick(tn, i, "operator").email
            rid = plane.sp.authn_request(tn, now)
            r = legit(me, rid)
            signed = r.find(f"{{{A}}}Assertion")
            forged = copy.deepcopy(signed)
            forged.set("ID", "_forged" + str(i))
            for s in forged.findall(f"{{{xmldsig.DS}}}Signature"):
                forged.remove(s)
            forged.find(f"{{{A}}}Subject/{{{A}}}NameID").text = v
            r.insert(list(r).index(signed), forged)
            return _ok_saml(plane, tn, saml.serialize(r), v, now + 1)

        def comment(i: int) -> bool:
            v = pick(tn, i, "admin").email
            rid = plane.sp.authn_request(tn, now)
            r = legit(v + ".guest.example", rid)  # the attacker's own guest account at the IdP
            nid = r.find(f"{{{A}}}Assertion/{{{A}}}Subject/{{{A}}}NameID")
            nid.text = v
            c = etree.Comment("")
            c.tail = ".guest.example"
            nid.append(c)
            return _ok_saml(plane, tn, saml.serialize(r), v, now + 1)

        def replay(i: int) -> bool:
            v = pick(tn, i, "admin").email
            rid = plane.sp.authn_request(tn, now)
            raw = saml.serialize(legit(v, rid))
            _ok_saml(plane, tn, raw, v, now + 1)  # the victim's own login
            return _ok_saml(plane, tn, raw, v, now + 30)  # the same response, posted again from a captured log

        def audience(i: int) -> bool:
            v = pick(tn, i, "admin").email
            rid = plane.sp.authn_request(tn, now)
            r = idp.response(now=now, name_id=v, audience="https://another-vendor.example/sp", acs_url=acs(tn), in_response_to=rid)
            return _ok_saml(plane, tn, saml.serialize(r), v, now + 1)

        def expired(i: int) -> bool:
            v = pick(tn, i, "admin").email
            r = idp.response(now=now - 7200, name_id=v, audience=SP_ENTITY, acs_url=acs(tn), in_response_to=None)
            return _ok_saml(plane, tn, saml.serialize(r), v, now)

        def unsolicited(i: int) -> bool:
            me = pick(tn, i, "operator").email  # login CSRF: the victim's browser ends up signed in as the attacker
            r = legit(me, None)
            return _ok_saml(plane, tn, saml.serialize(r), me, now + 1)

        def foreign_issuer(i: int) -> bool:
            v = pick(tn, i, "admin").email
            evil = plane.saml_idps[other]  # an IdP the attacker controls: another tenant's
            rid = plane.sp.authn_request(tn, now)
            r = evil.response(now=now, name_id=v, audience=SP_ENTITY, acs_url=acs(tn), in_response_to=rid)
            return _ok_saml(plane, tn, saml.serialize(r), v, now + 1)

        def own_key(i: int) -> bool:
            v = pick(tn, i, "admin").email
            k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            fake = saml.IdentityProvider(issuer(tn), k)  # the right name, the attacker's key in KeyInfo
            rid = plane.sp.authn_request(tn, now)
            r = fake.response(now=now, name_id=v, audience=SP_ENTITY, acs_url=acs(tn), in_response_to=rid)
            return _ok_saml(plane, tn, saml.serialize(r), v, now + 1)

        def doctype(i: int) -> bool:
            me = pick(tn, i, "operator").email
            rid = plane.sp.authn_request(tn, now)
            raw = b'<!DOCTYPE r [<!ENTITY x "x">]>' + saml.serialize(legit(me, rid))
            return _ok_saml(plane, tn, raw, me, now + 1)

        for k, f in [
            ("saml.unsigned", unsigned),
            ("saml.signature_wrapping", wrapping),
            ("saml.comment_truncation", comment),
            ("saml.replay", replay),
            ("saml.wrong_audience", audience),
            ("saml.expired", expired),
            ("saml.unsolicited_login_csrf", unsolicited),
            ("saml.other_tenants_idp", foreign_issuer),
            ("saml.key_in_message", own_key),
            ("saml.dtd", doctype),
        ]:
            record(k, f)

    # ------------------------------------------------------------------------------------ OIDC
    for tn in oidc_t[:1]:
        rp = plane.rp
        cfg = rp.tenants[tn]
        prov = rp.providers[cfg.issuer]
        other = next((x for x in names if x != tn), tn)
        evil = rp.providers[rp.tenants[other].issuer]

        def login_csrf(i: int) -> bool:
            me = pick(tn, i, "operator")
            mine = rp.start(tn, now)  # the attacker's own flow
            cb = prov.authorize(
                client_id=cfg.client_id,
                redirect_uri=cfg.redirect_uri,
                state=mine["state"],
                nonce=mine["nonce"],
                subject={"sub": me.pid, "email": me.email},
                now=now,
                code_challenge=mine.get("code_challenge"),
            )
            rp.pending.pop(mine["state"], None)  # ... completed later in the victim's browser, which has no such state
            try:
                login = rp.callback(tn, {**cb, "state": "victim-browser-has-no-flow"}, now + 1)
            except oidc.OidcError:
                return False
            return login.email == me.email

        def code_injection(i: int) -> bool:
            v = pick(tn, i, "admin")
            vflow = rp.start(tn, now)  # the victim's login; its code leaks (referrer, logs, a malicious app)
            cb = prov.authorize(
                client_id=cfg.client_id,
                redirect_uri=cfg.redirect_uri,
                state=vflow["state"],
                nonce=vflow["nonce"],
                subject={"sub": v.pid, "email": v.email},
                now=now,
                code_challenge=vflow.get("code_challenge"),
            )
            mine = rp.start(tn, now)  # the attacker injects the stolen code into their own flow
            try:
                login = rp.callback(tn, {"code": cb["code"], "state": mine["state"], "iss": cb["iss"]}, now + 1)
            except oidc.OidcError:
                return False
            return login.email == v.email

        def mix_up(i: int) -> bool:
            v = pick(tn, i, "admin")
            flow = rp.start(tn, now)
            ecfg = rp.tenants[other]
            cb = evil.authorize(
                client_id=cfg.client_id,
                redirect_uri=cfg.redirect_uri,
                state=flow["state"],
                nonce=flow["nonce"],
                subject={"sub": "evil", "email": v.email},
                now=now,
                code_challenge=flow.get("code_challenge"),
            )
            _ = ecfg
            try:
                login = rp.callback(tn, cb, now + 1)
            except oidc.OidcError:
                return False
            return login.email == v.email

        def token_for(i: int, alg: str) -> bool:
            v = pick(tn, i, "admin")
            claims = {"iss": cfg.issuer, "aud": cfg.client_id, "sub": v.pid, "email": v.email, "iat": int(now), "exp": int(now + 3600)}
            if alg == "none":
                tok = jose.forge(claims, "none", kid=f"{tn}-k1")
            else:
                tok = jose.forge(claims, "HS256", secret=jose.public_pem(prov.key.public_key()), kid=f"{tn}-k1")
            try:
                at = plane.agents.exchange(
                    client_id=f"assistant-{tn}", client_secret=plane.agent_secrets[tn], subject_token=tok, tenant=tn, scopes={"app.view"}, workspaces=set(site.tenants[tn].workspaces), now=now
                )
            except PermissionError:
                return False
            return bool(at)

        def stale(i: int) -> bool:
            v = pick(tn, i, "admin")
            tok = prov.id_token({"sub": v.pid, "email": v.email}, cfg.client_id, now - 86400)
            try:
                plane.agents.exchange(
                    client_id=f"assistant-{tn}", client_secret=plane.agent_secrets[tn], subject_token=tok, tenant=tn, scopes={"app.view"}, workspaces=set(site.tenants[tn].workspaces), now=now
                )
            except PermissionError:
                return False
            return True

        def other_client(i: int) -> bool:
            v = pick(tn, i, "admin")
            tok = prov.id_token({"sub": v.pid, "email": v.email}, "some-other-app", now)
            try:
                plane.agents.exchange(
                    client_id=f"assistant-{tn}", client_secret=plane.agent_secrets[tn], subject_token=tok, tenant=tn, scopes={"app.view"}, workspaces=set(site.tenants[tn].workspaces), now=now
                )
            except PermissionError:
                return False
            return True

        for k, f in [
            ("oidc.login_csrf", login_csrf),
            ("oidc.code_injection", code_injection),
            ("oidc.mix_up", mix_up),
            ("jwt.alg_none", lambda i: token_for(i, "none")),
            ("jwt.hmac_with_public_key", lambda i: token_for(i, "HS256")),
            ("jwt.expired", stale),
            ("jwt.other_audience", other_client),
        ]:
            record(k, f)

    # ------------------------------------------------------------------------------------ SCIM
    a, b = names[0], names[1 % len(names)]
    tok_b = plane.scim.issue_token(b)

    def scim_cross(i: int) -> bool:
        t = plane.scim.tenant_for(tok_b, a)
        if t is None:
            return False
        st, body = plane.scim.list_users(t)
        victims = {p.email.lower() for p in site.tenants[a].people.values()}
        return st == 200 and any(u["userName"].lower() in victims for u in body["Resources"]) and a != b

    record("scim.other_tenant_by_path", scim_cross)

    # ------------------------------------------------------------------------------------ agents
    def escalate(i: int) -> bool:
        tn = names[i % len(names)]
        op = pick(tn, i, "operator")
        ws = sorted(w for w, _ in site.tenants[tn].initial[op.pid])[0]
        if plane.kind == "status_quo":
            return True  # the standing key has builder rights: an operator's request to edit an app goes through
        prov = plane.rp.providers[issuer(tn)]
        sub = prov.id_token({"sub": op.pid, "email": op.email}, plane.rp.tenants[tn].client_id, now)
        try:
            tok = plane.agents.exchange(client_id=f"assistant-{tn}", client_secret=plane.agent_secrets[tn], subject_token=sub, tenant=tn, scopes={"app.edit"}, workspaces={ws}, now=now)
        except PermissionError:
            return False
        return plane.agents.check(tok, tn, "app.edit", ws, now + 1).allow

    def cross_tenant_token(i: int) -> bool:
        if plane.kind == "status_quo" or a == b:
            return False
        p = pick(b, i, "admin")
        prov = plane.rp.providers[issuer(b)]
        sub = prov.id_token({"sub": p.pid, "email": p.email}, plane.rp.tenants[b].client_id, now)
        wsb = sorted(site.tenants[b].workspaces)
        try:
            tok = plane.agents.exchange(client_id=f"assistant-{b}", client_secret=plane.agent_secrets[b], subject_token=sub, tenant=b, scopes={"app.view"}, workspaces=set(wsb), now=now)
        except PermissionError:
            return False
        wsa = sorted(site.tenants[a].workspaces)[0]
        return plane.agents.check(tok, a, "app.view", wsa, now + 1).allow

    record("agent.scope_escalation", escalate)
    record("agent.token_at_other_tenant", cross_tenant_token)

    # ------------------------------------------------------------------------------------ stations
    def leaver_badge(i: int) -> bool:
        tn = names[0]
        p = pick(tn, i, "operator")
        store = plane.scim.stores[tn]
        uid = next(u["id"] for u in store.users.values() if u["userName"].lower() == p.email.lower())
        plane.scim.patch_user(tn, uid, {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "replace", "path": "active", "value": False}]})
        st = next(s for s, (t_, _) in plane.stations.stations.items() if t_ == tn)
        return plane.stations.badge(st, p.badge, now) is not None

    record("station.leaver_badge", leaver_badge)
    return results
