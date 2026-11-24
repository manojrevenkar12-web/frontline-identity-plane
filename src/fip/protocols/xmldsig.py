"""XML Signature (enveloped, exclusive C14N, RSA-SHA256), the subset SAML uses.

The verifier returns the element the signature covers, and nothing else: whoever consumes the message must read that
element and only that element. Most SAML breaks (signature wrapping, comment truncation, trusting the key in the
message) come from verifying one thing and reading another.
"""

from __future__ import annotations

import base64
import copy
import hashlib
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key
from lxml import etree
from lxml.builder import ElementMaker

DS = "http://www.w3.org/2000/09/xmldsig#"
EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
ALLOWED_TRANSFORMS = {ENVELOPED, EXC_C14N}


class SignatureError(ValueError):
    pass


def c14n(el: etree._Element) -> bytes:
    return etree.tostring(el, method="c14n", exclusive=True, with_comments=False)


def _digest(el: etree._Element) -> str:
    body = copy.deepcopy(el)
    for sig in body.findall(f"{{{DS}}}Signature"):
        body.remove(sig)
    return base64.b64encode(hashlib.sha256(c14n(body)).digest()).decode()


def public_key_b64(key: rsa.RSAPrivateKey | rsa.RSAPublicKey) -> str:
    pub = key.public_key() if isinstance(key, rsa.RSAPrivateKey) else key
    return base64.b64encode(pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).decode()


def sign(el: etree._Element, key: rsa.RSAPrivateKey, after: etree._Element | None = None, include_key: bool = True) -> None:
    """Sign `el` (it needs an ID attribute) with an enveloped signature, inserted after `after` or first."""
    ref = el.get("ID")
    if not ref:
        raise SignatureError("element to sign has no ID")
    E = ElementMaker(namespace=DS, nsmap={"ds": DS})
    signed_info = E.SignedInfo(
        E.CanonicalizationMethod(Algorithm=EXC_C14N),
        E.SignatureMethod(Algorithm=RSA_SHA256),
        E.Reference(E.Transforms(E.Transform(Algorithm=ENVELOPED), E.Transform(Algorithm=EXC_C14N)), E.DigestMethod(Algorithm=SHA256), E.DigestValue(_digest(el)), URI=f"#{ref}"),
    )
    sig = E.Signature(signed_info, E.SignatureValue(""))
    if include_key:
        sig.append(E.KeyInfo(E.KeyValue(public_key_b64(key))))
    idx = list(el).index(after) + 1 if after is not None else 0
    el.insert(idx, sig)
    si = sig.find(f"{{{DS}}}SignedInfo")
    value = key.sign(c14n(si), padding.PKCS1v15(), hashes.SHA256())
    sig.find(f"{{{DS}}}SignatureValue").text = base64.b64encode(value).decode()


@dataclass(frozen=True)
class VerifyOptions:
    """Every switch here is a known way to get it wrong; the platform runs with all of them on."""

    bind_reference: bool = True  # the reference must point at the signature's parent and at a unique ID
    trusted_key_only: bool = True  # verify with the configured key, never the key inside the message


def verify(root: etree._Element, trusted_key: rsa.RSAPublicKey, opts: VerifyOptions = VerifyOptions()) -> list[etree._Element]:
    """Verify every signature in the document; return the elements they cover. Raises SignatureError."""
    covered = []
    sigs = root.iter(f"{{{DS}}}Signature")
    for sig in list(sigs):
        si = sig.find(f"{{{DS}}}SignedInfo")
        if si is None:
            raise SignatureError("signature without SignedInfo")
        if si.find(f"{{{DS}}}SignatureMethod").get("Algorithm") != RSA_SHA256:
            raise SignatureError("signature method not allowed")
        refs = si.findall(f"{{{DS}}}Reference")
        if len(refs) != 1:
            raise SignatureError("exactly one reference is allowed")
        ref = refs[0]
        uri = ref.get("URI", "")
        if not uri.startswith("#"):
            raise SignatureError("only same-document references are allowed")
        for t in ref.iter(f"{{{DS}}}Transform"):
            if t.get("Algorithm") not in ALLOWED_TRANSFORMS:
                raise SignatureError("transform not allowed")
        target_id = uri[1:]
        targets = [e for e in root.iter() if isinstance(e.tag, str) and e.get("ID") == target_id]
        if opts.bind_reference:
            if len(targets) != 1:
                raise SignatureError("reference ID is missing or not unique")
            if sig.getparent() is not targets[0]:
                raise SignatureError("signature is not enveloped in the element it references")
        if not targets:
            raise SignatureError("reference not found")
        target = targets[0]
        if _digest(target) != ref.findtext(f"{{{DS}}}DigestValue"):
            raise SignatureError("digest mismatch")
        key = trusted_key
        if not opts.trusted_key_only:
            kv = sig.findtext(f"{{{DS}}}KeyInfo/{{{DS}}}KeyValue")
            if kv:
                key = load_der_public_key(base64.b64decode(kv))  # type: ignore[assignment]
        try:
            key.verify(base64.b64decode(sig.findtext(f"{{{DS}}}SignatureValue") or ""), c14n(si), padding.PKCS1v15(), hashes.SHA256())
        except (InvalidSignature, ValueError) as e:
            raise SignatureError("signature value invalid") from e
        covered.append(target)
    return covered
