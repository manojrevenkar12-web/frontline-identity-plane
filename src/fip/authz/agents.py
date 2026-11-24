"""Identities for AI agents acting for a person: OAuth 2.0 Token Exchange (RFC 8693).

An agent never holds a standing credential to a tenant. It presents the person's token (an ID token from the
tenant's IdP) and its own client credentials, and gets back a token that:
- names both (`sub` the person, `act.sub` the agent);
- is limited to the scopes the agent is allowed AND the person has, in the workspaces asked for;
- is bound to one tenant (`aud`), lives minutes, and
- is checked against the person's current access on every use, so a deactivation or group change ends it at once.

The status quo it replaces is a long-lived API key per tenant with builder rights, shared by automations.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from ..protocols import jose
from ..protocols.oidc import OidcError, OidcPolicy, TenantOidc, validate_id_token
from .engine import AccessEngine, Decision
from .model import ACTIONS, permissions


@dataclass(frozen=True)
class AgentPolicy:
    down_scope: bool = True  # never more than the person may do
    ttl_s: float = 600.0
    live_check: bool = True  # every use re-checks the person's current access, so a leaver's agent stops at once
    audience_bound: bool = True


@dataclass
class AgentClient:
    client_id: str
    tenant: str
    secret_hash: str
    allowed_scopes: frozenset[str]


@dataclass
class AgentTokens:
    policy: AgentPolicy
    engine: AccessEngine
    oidc_policy: OidcPolicy
    idp: dict[str, tuple[TenantOidc, dict[str, Any]]] = field(default_factory=dict)  # tenant -> (config, jwks)
    clients: dict[str, AgentClient] = field(default_factory=dict)
    key: ec.EllipticCurvePrivateKey = field(default_factory=lambda: ec.generate_private_key(ec.SECP256R1()))
    issuer: str = "https://identity.frontline.example"

    def register(self, tenant: str, client_id: str, scopes: frozenset[str]) -> str:
        secret = secrets.token_urlsafe(24)
        self.clients[client_id] = AgentClient(client_id, tenant, hashlib.sha256(secret.encode()).hexdigest(), scopes & ACTIONS)
        return secret

    def exchange(self, *, client_id: str, client_secret: str, subject_token: str, tenant: str, scopes: set[str], workspaces: set[str], now: float) -> str:
        c = self.clients.get(client_id)
        if c is None or c.secret_hash != hashlib.sha256(client_secret.encode()).hexdigest():
            raise PermissionError("invalid_client")
        if c.tenant != tenant:
            raise PermissionError("invalid_client: agent belongs to another tenant")
        cfg, jwks = self.idp[tenant]
        try:
            claims = validate_id_token(subject_token, cfg, jwks, self.oidc_policy, now, nonce=None)
        except OidcError as e:
            raise PermissionError(f"invalid_grant: {e}") from e
        person = str(claims.get("email") or claims.get("sub"))
        if self.engine.user(tenant, person) is None:
            raise PermissionError("invalid_grant: unknown person")
        granted = set(scopes) & set(c.allowed_scopes)
        if self.policy.down_scope:
            mine = self.engine.grants(tenant, person, now)
            granted = {s for s in granted if any(s in permissions(mine, w) for w in workspaces)}
        if not granted:
            raise PermissionError("invalid_scope: nothing left after down-scoping")
        body = {
            "iss": self.issuer,
            "aud": f"tenant:{tenant}",
            "sub": person,
            "act": {"sub": client_id},
            "scope": " ".join(sorted(granted)),
            "ws": sorted(workspaces),
            "iat": int(now),
            "exp": int(now + self.policy.ttl_s),
            "ver": self.engine.version(tenant),
            "jti": secrets.token_hex(8),
        }
        return jose.sign(body, self.key, "agent-1")

    def check(self, token: str, tenant: str, action: str, workspace: str, now: float) -> Decision:
        try:
            c = jose.verify(token, {"agent-1": self.key.public_key()}, frozenset({"ES256"}))
        except jose.JoseError as e:
            return Decision(False, f"token: {e}")
        if self.policy.audience_bound and c.get("aud") != f"tenant:{tenant}":
            return Decision(False, "token is for another tenant")
        if c["exp"] < now:
            return Decision(False, "token expired")
        if action not in c["scope"].split() or workspace not in c["ws"]:
            return Decision(False, "outside the token's scope")
        if self.policy.live_check:
            d = self.engine.decide(tenant, c["sub"], action, workspace, now)
            if not d.allow:
                return Decision(False, f"the person cannot do this now: {d.reason}")
        return Decision(True, f"agent {c['act']['sub']} for {c['sub']}")
