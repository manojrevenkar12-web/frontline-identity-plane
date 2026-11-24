"""SAML 2.0 Web SSO: the identity provider side (for the simulated IdPs) and the service provider side (the platform).

The service provider checks what SAML Core and the Web SSO profile require, plus the lessons of known breaks:
signed assertion consumed as signed (signature wrapping), NameID read whole (comment truncation), no DTDs,
issuer and key per tenant, audience, recipient, time window with bounded skew, InResponseTo for SP-initiated
logins, and a replay cache that lives as long as the assertion could be valid.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.asymmetric import rsa
from lxml import etree
from lxml.builder import ElementMaker

from . import xmldsig

P = "urn:oasis:names:tc:SAML:2.0:protocol"
A = "urn:oasis:names:tc:SAML:2.0:assertion"
SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
EPOCH = datetime(2026, 1, 5, tzinfo=UTC)


def iso(t: float) -> str:
    return (EPOCH + timedelta(seconds=t)).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s: str | None) -> float | None:
    if not s:
        return None
    return (datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC) - EPOCH).total_seconds()


class SamlError(ValueError):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


# --------------------------------------------------------------------------------------------- identity provider
@dataclass
class IdentityProvider:
    entity_id: str
    key: rsa.RSAPrivateKey
    clock_skew_s: float = 0.0  # this IdP's clock against true time
    sign_response_only: bool = False  # some IdPs sign the Response, not the Assertion

    def response(
        self,
        *,
        now: float,
        name_id: str,
        audience: str,
        acs_url: str,
        in_response_to: str | None,
        attributes: dict[str, list[str]] | None = None,
        lifetime_s: float = 300.0,
        sign: bool = True,
    ) -> etree._Element:
        t = now + self.clock_skew_s
        E = ElementMaker(namespace=A, nsmap={"saml": A, "samlp": P})
        Pm = ElementMaker(namespace=P, nsmap={"saml": A, "samlp": P})
        aid = "_a" + secrets.token_hex(12)
        conf = {"NotOnOrAfter": iso(t + lifetime_s), "Recipient": acs_url}
        if in_response_to:
            conf["InResponseTo"] = in_response_to
        assertion = E.Assertion(
            E.Issuer(self.entity_id),
            E.Subject(
                E.NameID(name_id, Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),
                E.SubjectConfirmation(E.SubjectConfirmationData(**conf), Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"),
            ),
            E.Conditions(E.AudienceRestriction(E.Audience(audience)), NotBefore=iso(t - 5), NotOnOrAfter=iso(t + lifetime_s)),
            E.AuthnStatement(AuthnInstant=iso(t), SessionIndex="_s" + secrets.token_hex(6)),
            ID=aid,
            IssueInstant=iso(t),
            Version="2.0",
        )
        if attributes:
            st = E.AttributeStatement()
            for k, vs in attributes.items():
                st.append(E.Attribute(*[E.AttributeValue(v) for v in vs], Name=k))
            assertion.append(st)
        rattrs = {"ID": "_r" + secrets.token_hex(12), "Version": "2.0", "IssueInstant": iso(t), "Destination": acs_url}
        if in_response_to:
            rattrs["InResponseTo"] = in_response_to
        resp = Pm.Response(E.Issuer(self.entity_id), Pm.Status(Pm.StatusCode(Value=SUCCESS)), assertion, **rattrs)
        if sign:
            if self.sign_response_only:
                xmldsig.sign(resp, self.key, after=resp[0])
            else:
                xmldsig.sign(assertion, self.key, after=assertion[0])
        return resp


def serialize(el: etree._Element) -> bytes:
    return etree.tostring(el)


# --------------------------------------------------------------------------------------------- service provider
@dataclass(frozen=True)
class SamlPolicy:
    require_signature: bool = True
    consume_signed_only: bool = True  # read the assertion the signature covers, and require exactly one
    whole_nameid: bool = True  # reject comments inside NameID; never read .text alone
    reject_doctype: bool = True
    check_audience: bool = True
    check_recipient: bool = True
    check_time: bool = True
    max_skew_s: float = 180.0
    require_in_response_to: bool = True  # SP-initiated only, unless the tenant allows IdP-initiated
    replay_cache: bool = True
    bind_reference: bool = True
    trusted_key_only: bool = True


@dataclass
class TenantSaml:
    tenant: str
    idp_entity_id: str
    idp_key: rsa.RSAPublicKey
    sp_entity_id: str
    acs_url: str
    allow_idp_initiated: bool = False


@dataclass
class SamlLogin:
    tenant: str
    name_id: str
    attributes: dict[str, list[str]]
    assertion_id: str
    session_index: str | None


@dataclass
class ServiceProvider:
    policy: SamlPolicy
    tenants: dict[str, TenantSaml] = field(default_factory=dict)
    outstanding: dict[str, tuple[str, float]] = field(default_factory=dict)  # request ID -> (tenant, expiry)
    seen: dict[str, float] = field(default_factory=dict)  # assertion ID -> expiry

    def authn_request(self, tenant: str, now: float, ttl_s: float = 600.0) -> str:
        rid = "_q" + secrets.token_hex(12)
        self.outstanding[rid] = (tenant, now + ttl_s)
        return rid

    def _parse(self, raw: bytes) -> etree._Element:
        if self.policy.reject_doctype:
            parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False, huge_tree=False, remove_pis=True)
            root = etree.fromstring(raw, parser)
            if root.getroottree().docinfo.doctype:
                raise SamlError("doctype", "DTDs are not accepted")
            return root
        return etree.fromstring(raw, etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=True))

    def consume(self, tenant: str, raw: bytes, now: float) -> SamlLogin:
        """Validate a posted SAMLResponse at the tenant's ACS URL. Raises SamlError with a stable code."""
        cfg = self.tenants.get(tenant)
        if cfg is None:
            raise SamlError("tenant", "unknown tenant")
        pol = self.policy
        try:
            root = self._parse(raw)
        except etree.XMLSyntaxError as e:
            raise SamlError("parse", str(e)) from e
        if root.tag != f"{{{P}}}Response":
            raise SamlError("parse", "not a Response")
        sc = root.find(f"{{{P}}}Status/{{{P}}}StatusCode")
        if sc is None or sc.get("Value") != SUCCESS:
            raise SamlError("status", "IdP did not report success")
        if root.findtext(f"{{{A}}}Issuer") != cfg.idp_entity_id:
            raise SamlError("issuer", "response issuer is not this tenant's IdP")
        assertions = list(root.iter(f"{{{A}}}Assertion"))
        opts = xmldsig.VerifyOptions(bind_reference=pol.bind_reference, trusted_key_only=pol.trusted_key_only)
        has_sig = any(True for _ in root.iter(f"{{{xmldsig.DS}}}Signature"))
        covered: list[etree._Element] = []
        if has_sig:
            try:
                covered = xmldsig.verify(root, cfg.idp_key, opts)
            except xmldsig.SignatureError as e:
                raise SamlError("signature", str(e)) from e
        elif pol.require_signature:
            raise SamlError("signature", "unsigned response")
        if pol.consume_signed_only:
            if len(assertions) != 1:
                raise SamlError("assertion", "exactly one assertion is allowed")
            a = assertions[0]
            if not any(c is a or (c is root and a.getparent() is root) for c in covered):
                raise SamlError("signature", "the assertion read is not the one signed")
        else:
            if not assertions:
                raise SamlError("assertion", "no assertion")
            a = assertions[0]  # what a hand-rolled parser does: the first assertion in document order
        if a.findtext(f"{{{A}}}Issuer") != cfg.idp_entity_id:
            raise SamlError("issuer", "assertion issuer is not this tenant's IdP")
        nid = a.find(f"{{{A}}}Subject/{{{A}}}NameID")
        if nid is None:
            raise SamlError("subject", "no NameID")
        if pol.whole_nameid:
            if any(isinstance(c, etree._Comment) for c in nid.iter()) or len(nid):
                raise SamlError("subject", "NameID must be plain text")
            name_id = "".join(nid.itertext()).strip()
        else:
            name_id = (nid.text or "").strip()
        scd = a.find(f"{{{A}}}Subject/{{{A}}}SubjectConfirmation/{{{A}}}SubjectConfirmationData")
        cond = a.find(f"{{{A}}}Conditions")
        if pol.check_audience:
            auds = [x.text for x in a.iter(f"{{{A}}}Audience")]
            if cfg.sp_entity_id not in auds:
                raise SamlError("audience", "assertion is for another service")
        if pol.check_recipient:
            if scd is None or scd.get("Recipient") != cfg.acs_url or root.get("Destination") not in (None, cfg.acs_url):
                raise SamlError("recipient", "assertion was sent to another endpoint")
        expiry = now + 600
        if pol.check_time:
            nb = parse_iso(cond.get("NotBefore")) if cond is not None else None
            na = parse_iso(cond.get("NotOnOrAfter")) if cond is not None else None
            sna = parse_iso(scd.get("NotOnOrAfter")) if scd is not None else None
            if na is None or sna is None:
                raise SamlError("time", "assertion has no expiry")
            if nb is not None and now + pol.max_skew_s < nb:
                raise SamlError("time", "not yet valid")
            if now - pol.max_skew_s >= min(na, sna):
                raise SamlError("time", "expired")
            expiry = min(na, sna) + pol.max_skew_s
        irt = scd.get("InResponseTo") if scd is not None else None
        if pol.require_in_response_to:
            if irt is None:
                if not cfg.allow_idp_initiated:
                    raise SamlError("in_response_to", "unsolicited response")
            else:
                req = self.outstanding.pop(irt, None)
                if req is None or req[0] != tenant or req[1] < now:
                    raise SamlError("in_response_to", "no outstanding request with this ID")
        aid = a.get("ID", "")
        if pol.replay_cache:
            self.seen = {k: v for k, v in self.seen.items() if v > now} if len(self.seen) > 5000 else self.seen
            if aid in self.seen and self.seen[aid] > now:
                raise SamlError("replay", "assertion already used")
            self.seen[aid] = expiry
        attrs: dict[str, list[str]] = {}
        for at in a.iter(f"{{{A}}}Attribute"):
            attrs[at.get("Name", "")] = ["".join(v.itertext()) for v in at.iter(f"{{{A}}}AttributeValue")]
        authn = a.find(f"{{{A}}}AuthnStatement")
        return SamlLogin(tenant, name_id, attrs, aid, authn.get("SessionIndex") if authn is not None else None)
