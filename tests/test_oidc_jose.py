from __future__ import annotations

from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from fip.protocols import jose, oidc


def setup(key: rsa.RSAPrivateKey, other_key: rsa.RSAPrivateKey, pol: oidc.OidcPolicy = oidc.OidcPolicy()) -> tuple[oidc.RelyingParty, oidc.Provider, oidc.Provider]:
    good = oidc.Provider("https://login.a.example", key, kid="a1")
    evil = oidc.Provider("https://login.evil.example", other_key, kid="e1")
    rp = oidc.RelyingParty(pol, providers={good.issuer: good, evil.issuer: evil})
    rp.tenants["a"] = oidc.TenantOidc("a", good.issuer, "client-a", "https://sp/a/cb")
    return rp, good, evil


def login(rp: oidc.RelyingParty, prov: oidc.Provider, who: str, now: float = 10.0) -> oidc.OidcLogin:
    s = rp.start("a", now)
    cb = prov.authorize(client_id="client-a", redirect_uri="https://sp/a/cb", state=s["state"], nonce=s["nonce"], subject={"sub": who, "email": who}, now=now, code_challenge=s.get("code_challenge"))
    return rp.callback("a", cb, now + 1)


def test_the_code_flow_signs_in(key: rsa.RSAPrivateKey, other_key: rsa.RSAPrivateKey) -> None:
    rp, good, _ = setup(key, other_key)
    assert login(rp, good, "a@x.example").email == "a@x.example"


def test_a_code_is_used_once(key: rsa.RSAPrivateKey, other_key: rsa.RSAPrivateKey) -> None:
    rp, good, _ = setup(key, other_key)
    s = rp.start("a", 10)
    cb = good.authorize(client_id="client-a", redirect_uri="https://sp/a/cb", state=s["state"], nonce=s["nonce"], subject={"sub": "x", "email": "x"}, now=10, code_challenge=s["code_challenge"])
    rp.callback("a", cb, 11)
    s2 = rp.start("a", 12)
    with pytest.raises(oidc.OidcError):
        rp.callback("a", {**cb, "state": s2["state"]}, 13)


def test_mix_up_is_refused_by_the_iss_parameter_and_works_without_it(key: rsa.RSAPrivateKey, other_key: rsa.RSAPrivateKey) -> None:
    rp, _, evil = setup(key, other_key)
    with pytest.raises(oidc.OidcError, match="mix_up"):
        login(rp, evil, "boss@a.example")
    weak, _, evil2 = setup(key, other_key, replace(oidc.OidcPolicy(), check_iss_param=False))
    assert login(weak, evil2, "boss@a.example").email == "boss@a.example"


def test_pkce_binds_the_code_to_its_flow(key: rsa.RSAPrivateKey, other_key: rsa.RSAPrivateKey) -> None:
    rp, good, _ = setup(key, other_key)
    victim = rp.start("a", 10)
    cb = good.authorize(
        client_id="client-a", redirect_uri="https://sp/a/cb", state=victim["state"], nonce=victim["nonce"], subject={"sub": "v", "email": "v"}, now=10, code_challenge=victim["code_challenge"]
    )
    mine = rp.start("a", 10)
    with pytest.raises(oidc.OidcError, match="token"):
        rp.callback("a", {**cb, "state": mine["state"]}, 11)


def test_alg_none_and_hmac_with_the_public_key_are_refused_unless_the_header_is_trusted(key: rsa.RSAPrivateKey) -> None:
    claims = {"iss": "i", "aud": "c", "exp": 99, "sub": "boss"}
    keys = {"k": key.public_key()}
    for tok in (jose.forge(claims, "none", kid="k"), jose.forge(claims, "HS256", secret=jose.public_pem(key.public_key()), kid="k")):
        with pytest.raises(jose.JoseError):
            jose.verify(tok, keys, frozenset({"RS256"}))
        assert jose.verify(tok, keys, frozenset({"RS256"}), trust_header_alg=True)["sub"] == "boss"


def test_es256_round_trip_and_tamper() -> None:
    k = ec.generate_private_key(ec.SECP256R1())
    tok = jose.sign({"a": 1}, k, "e")
    assert jose.verify(tok, {"e": k.public_key()}, frozenset({"ES256"})) == {"a": 1}
    h, b, s = tok.split(".")
    with pytest.raises(jose.JoseError):
        jose.verify(f"{h}.{jose.b64u(b'{"a":2}')}.{s}", {"e": k.public_key()}, frozenset({"ES256"}))


def test_id_token_claims(key: rsa.RSAPrivateKey, other_key: rsa.RSAPrivateKey) -> None:
    _, good, _ = setup(key, other_key)
    cfg = oidc.TenantOidc("a", good.issuer, "client-a", "x")
    pol = oidc.OidcPolicy()
    with pytest.raises(oidc.OidcError, match="audience"):
        oidc.validate_id_token(good.id_token({"sub": "s"}, "other", 0), cfg, good.jwks, pol, 1, nonce=None)
    with pytest.raises(oidc.OidcError, match="expired"):
        oidc.validate_id_token(good.id_token({"sub": "s"}, "client-a", 0), cfg, good.jwks, pol, 10_000, nonce=None)
    with pytest.raises(oidc.OidcError, match="nonce"):
        oidc.validate_id_token(good.id_token({"sub": "s"}, "client-a", 0, nonce="n1"), cfg, good.jwks, pol, 1, nonce="n2")
