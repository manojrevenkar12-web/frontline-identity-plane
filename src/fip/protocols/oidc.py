"""OpenID Connect authorization code flow: a provider (for the simulated IdPs) and the relying party (the platform).

The relying party binds everything to the login it started: state names the flow, the flow names the issuer,
PKCE binds the code to the browser that started it, the `iss` response parameter (RFC 9207) stops mix-up between the
many IdPs a multi-tenant product trusts, and the ID token is checked for issuer, audience, expiry and nonce with
algorithms fixed per issuer.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec, rsa

from . import jose


class OidcError(ValueError):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


def s256(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


# ------------------------------------------------------------------------------------------------- provider
@dataclass
class Provider:
    issuer: str
    key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
    kid: str = "k1"
    clock_skew_s: float = 0.0
    codes: dict[str, dict[str, Any]] = field(default_factory=dict)

    @property
    def jwks(self) -> dict[str, Any]:
        return {self.kid: self.key.public_key()}

    def authorize(self, *, client_id: str, redirect_uri: str, state: str, nonce: str, subject: dict[str, Any], now: float, code_challenge: str | None = None) -> dict[str, str]:
        code = secrets.token_urlsafe(24)
        self.codes[code] = {"client_id": client_id, "redirect_uri": redirect_uri, "nonce": nonce, "subject": subject, "challenge": code_challenge, "exp": now + 60}
        return {"code": code, "state": state, "iss": self.issuer}

    def token(self, *, code: str, client_id: str, redirect_uri: str, now: float, code_verifier: str | None = None) -> dict[str, str]:
        c = self.codes.pop(code, None)  # single use
        if c is None or c["exp"] < now or c["client_id"] != client_id or c["redirect_uri"] != redirect_uri:
            raise OidcError("invalid_grant", "code unknown, used, expired or for another client")
        if c["challenge"] is not None and (code_verifier is None or s256(code_verifier) != c["challenge"]):
            raise OidcError("invalid_grant", "PKCE verifier does not match")
        return {"id_token": self.id_token(c["subject"], client_id, now, nonce=c["nonce"])}

    def id_token(self, subject: dict[str, Any], audience: str, now: float, *, nonce: str | None = None, lifetime_s: float = 300.0) -> str:
        t = now + self.clock_skew_s
        claims = {"iss": self.issuer, "aud": audience, "iat": int(t), "exp": int(t + lifetime_s), "jti": secrets.token_hex(8), **subject}
        if nonce:
            claims["nonce"] = nonce
        return jose.sign(claims, self.key, self.kid)


# ------------------------------------------------------------------------------------------------- relying party
@dataclass(frozen=True)
class OidcPolicy:
    use_pkce: bool = True
    check_state: bool = True
    check_iss_param: bool = True
    fixed_algs: bool = True
    check_claims: bool = True  # iss, aud, exp, nonce
    max_skew_s: float = 120.0


@dataclass
class TenantOidc:
    tenant: str
    issuer: str
    client_id: str
    redirect_uri: str
    algs: frozenset[str] = frozenset({"RS256"})


@dataclass
class OidcLogin:
    tenant: str
    subject: str
    email: str
    claims: dict[str, Any]


@dataclass
class RelyingParty:
    policy: OidcPolicy
    tenants: dict[str, TenantOidc] = field(default_factory=dict)
    providers: dict[str, Provider] = field(default_factory=dict)  # issuer -> provider (the network)
    pending: dict[str, dict[str, Any]] = field(default_factory=dict)  # state -> flow

    def start(self, tenant: str, now: float) -> dict[str, str]:
        cfg = self.tenants[tenant]
        flow: dict[str, Any] = {"tenant": tenant, "issuer": cfg.issuer, "nonce": secrets.token_urlsafe(16), "verifier": secrets.token_urlsafe(32), "exp": now + 600}
        state = secrets.token_urlsafe(16)
        self.pending[state] = flow
        out: dict[str, str] = {"state": state, "nonce": flow["nonce"], "client_id": cfg.client_id, "redirect_uri": cfg.redirect_uri}
        if self.policy.use_pkce:
            out["code_challenge"] = s256(flow["verifier"])
        return out

    def callback(self, tenant: str, params: dict[str, str], now: float) -> OidcLogin:
        pol = self.policy
        cfg = self.tenants.get(tenant)
        if cfg is None:
            raise OidcError("tenant")
        flow = self.pending.pop(params.get("state", ""), None)
        if pol.check_state:
            if flow is None or flow["exp"] < now or flow["tenant"] != tenant:
                raise OidcError("state", "no login in progress with this state")
        issuer = cfg.issuer
        if pol.check_iss_param:
            if params.get("iss") != issuer:
                raise OidcError("mix_up", "response came from another issuer")
        elif params.get("iss") in self.providers:
            issuer = params["iss"]  # what an RP that trusts the response does: redeem the code where it says
        prov = self.providers[issuer]
        verifier = flow["verifier"] if (flow and pol.use_pkce) else None
        try:
            tok = prov.token(code=params.get("code", ""), client_id=cfg.client_id, redirect_uri=cfg.redirect_uri, now=now, code_verifier=verifier)
        except OidcError as e:
            raise OidcError("token", str(e)) from e
        # an RP that redeemed the code elsewhere validates against wherever it redeemed it: the mix-up
        check = cfg if issuer == cfg.issuer else TenantOidc(tenant, issuer, cfg.client_id, cfg.redirect_uri, cfg.algs)
        claims = validate_id_token(tok["id_token"], check, prov.jwks, pol, now, nonce=flow["nonce"] if flow else None)
        return OidcLogin(tenant, str(claims.get("sub")), str(claims.get("email", "")), claims)


def validate_id_token(token: str, cfg: TenantOidc, jwks: dict[str, Any], pol: OidcPolicy, now: float, *, nonce: str | None) -> dict[str, Any]:
    try:
        claims = jose.verify(token, jwks, cfg.algs, trust_header_alg=not pol.fixed_algs)
    except jose.JoseError as e:
        raise OidcError("signature", str(e)) from e
    if pol.check_claims:
        if claims.get("iss") != cfg.issuer:
            raise OidcError("issuer", "token from another issuer")
        aud = claims.get("aud")
        if cfg.client_id not in (aud if isinstance(aud, list) else [aud]):
            raise OidcError("audience", "token for another client")
        if not isinstance(claims.get("exp"), int) or claims["exp"] + pol.max_skew_s < now:
            raise OidcError("expired")
        if claims.get("iat", 0) - pol.max_skew_s > now:
            raise OidcError("time", "issued in the future")
        if nonce is not None and claims.get("nonce") != nonce:
            raise OidcError("nonce", "token is from another login")
    return claims
