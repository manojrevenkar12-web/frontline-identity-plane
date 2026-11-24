"""JWS compact serialization: RS256 and ES256 sign and verify, and nothing else.

The verifier never takes the algorithm from the token: the caller says which algorithms the issuer uses, and the key
comes from the issuer's key set by `kid`. `alg: none` and HMAC with a public key as the secret are the classic breaks.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


class JoseError(ValueError):
    pass


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def public_pem(key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey) -> bytes:
    return key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


def sign(claims: dict[str, Any], key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey, kid: str) -> str:
    alg = "RS256" if isinstance(key, rsa.RSAPrivateKey) else "ES256"
    head = b64u(json.dumps({"alg": alg, "kid": kid, "typ": "JWT"}, separators=(",", ":")).encode())
    body = b64u(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    msg = f"{head}.{body}".encode()
    if isinstance(key, rsa.RSAPrivateKey):
        sig = key.sign(msg, padding.PKCS1v15(), hashes.SHA256())
    else:
        r, s = decode_dss_signature(key.sign(msg, ec.ECDSA(hashes.SHA256())))
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{head}.{body}.{b64u(sig)}"


def forge(claims: dict[str, Any], alg: str, secret: bytes = b"", kid: str = "") -> str:
    """Tokens an attacker can make without a private key: `none`, or HMAC keyed with a public key."""
    head = b64u(json.dumps({"alg": alg, "kid": kid, "typ": "JWT"}, separators=(",", ":")).encode())
    body = b64u(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    if alg == "none":
        return f"{head}.{body}."
    mac = hmac.new(secret, f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{b64u(mac)}"


def peek(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        h, b, _ = token.split(".")
        return json.loads(unb64u(h)), json.loads(unb64u(b))
    except (ValueError, json.JSONDecodeError) as e:
        raise JoseError("malformed token") from e


def verify(token: str, keys: dict[str, Any], allowed_algs: frozenset[str], *, trust_header_alg: bool = False) -> dict[str, Any]:
    """Return the claims if the signature is valid under one of `keys` (kid -> public key). Checks nothing else."""
    head, claims = peek(token)
    alg = head.get("alg")
    if not trust_header_alg and alg not in allowed_algs:
        raise JoseError(f"algorithm {alg!r} not allowed for this issuer")
    key = keys.get(head.get("kid", ""))
    if key is None:
        if trust_header_alg and len(keys) == 1:
            key = next(iter(keys.values()))
        else:
            raise JoseError("unknown key id")
    h, b, s = token.split(".")
    msg, sig = f"{h}.{b}".encode(), unb64u(s) if s else b""
    try:
        if alg == "none":
            if not trust_header_alg:
                raise JoseError("unsigned token")
            return claims
        if alg == "HS256":
            # what a library that trusts the header does with an RSA public key: use its bytes as the secret
            if not hmac.compare_digest(hmac.new(public_pem(key), msg, hashlib.sha256).digest(), sig):
                raise JoseError("bad signature")
            return claims
        if alg == "RS256" and isinstance(key, rsa.RSAPublicKey):
            key.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
            return claims
        if alg == "ES256" and isinstance(key, ec.EllipticCurvePublicKey):
            if len(sig) != 64:
                raise JoseError("bad signature length")
            key.verify(encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")), msg, ec.ECDSA(hashes.SHA256()))
            return claims
    except InvalidSignature as e:
        raise JoseError("bad signature") from e
    raise JoseError("algorithm and key type do not match")
