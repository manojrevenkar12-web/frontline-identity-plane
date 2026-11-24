"""Each known SAML break, against the service provider with the platform's policy and with the check switched off."""

from __future__ import annotations

import copy
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from lxml import etree

from fip.protocols import saml, xmldsig

A = saml.A
SP, ACS = "https://sp.example", "https://sp.example/t/acs"


def make(key: rsa.RSAPrivateKey, policy: saml.SamlPolicy = saml.SamlPolicy()) -> tuple[saml.IdentityProvider, saml.ServiceProvider]:
    idp = saml.IdentityProvider("https://idp.example", key)
    sp = saml.ServiceProvider(policy, {"t": saml.TenantSaml("t", "https://idp.example", key.public_key(), SP, ACS)})
    return idp, sp


def resp(idp: saml.IdentityProvider, sp: saml.ServiceProvider, who: str, now: float = 100.0, **kw: object) -> etree._Element:
    rid = sp.authn_request("t", now)
    return idp.response(now=now, name_id=who, audience=kw.pop("audience", SP), acs_url=ACS, in_response_to=kw.pop("irt", rid), **kw)  # type: ignore[arg-type]


def test_a_valid_login_passes_and_reads_attributes(key: rsa.RSAPrivateKey) -> None:
    idp, sp = make(key)
    r = idp.response(now=100, name_id="a@x.example", audience=SP, acs_url=ACS, in_response_to=sp.authn_request("t", 100), attributes={"groups": ["g1", "g2"]})
    login = sp.consume("t", saml.serialize(r), 101)
    assert login.name_id == "a@x.example" and login.attributes["groups"] == ["g1", "g2"]


def test_a_response_signed_on_the_response_element_also_passes(key: rsa.RSAPrivateKey) -> None:
    idp, sp = make(key)
    idp.sign_response_only = True
    assert sp.consume("t", saml.serialize(resp(idp, sp, "a@x.example")), 101).name_id == "a@x.example"


def wrap(r: etree._Element, victim: str) -> etree._Element:
    signed = r.find(f"{{{A}}}Assertion")
    forged = copy.deepcopy(signed)
    forged.set("ID", "_forged")
    for s in forged.findall(f"{{{xmldsig.DS}}}Signature"):
        forged.remove(s)
    forged.find(f"{{{A}}}Subject/{{{A}}}NameID").text = victim
    r.insert(list(r).index(signed), forged)
    return r


def test_signature_wrapping_is_refused_and_works_without_the_defence(key: rsa.RSAPrivateKey) -> None:
    idp, sp = make(key)
    with pytest.raises(saml.SamlError):
        sp.consume("t", saml.serialize(wrap(resp(idp, sp, "me@x.example"), "boss@x.example")), 101)
    idp2, weak = make(key, replace(saml.SamlPolicy(), consume_signed_only=False))
    assert weak.consume("t", saml.serialize(wrap(resp(idp2, weak, "me@x.example"), "boss@x.example")), 101).name_id == "boss@x.example"


def test_a_comment_in_the_nameid_does_not_truncate_it(key: rsa.RSAPrivateKey) -> None:
    def attack(sp: saml.ServiceProvider, idp: saml.IdentityProvider) -> str:
        r = resp(idp, sp, "boss@x.example.guest.example")
        nid = r.find(f"{{{A}}}Assertion/{{{A}}}Subject/{{{A}}}NameID")
        nid.text = "boss@x.example"
        c = etree.Comment("")
        c.tail = ".guest.example"
        nid.append(c)
        return sp.consume("t", saml.serialize(r), 101).name_id

    idp, sp = make(key)
    with pytest.raises(saml.SamlError, match="subject"):
        attack(sp, idp)
    idp2, weak = make(key, replace(saml.SamlPolicy(), whole_nameid=False))
    assert attack(weak, idp2) == "boss@x.example"  # the signature still verifies: comments are not signed


def test_the_key_in_the_message_is_never_trusted(key: rsa.RSAPrivateKey, other_key: rsa.RSAPrivateKey) -> None:
    _, sp = make(key)
    fake = saml.IdentityProvider("https://idp.example", other_key)
    with pytest.raises(saml.SamlError, match="signature"):
        sp.consume("t", saml.serialize(resp(fake, sp, "boss@x.example")), 101)


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (lambda idp, sp: resp(idp, sp, "a@x.example", sign=False), "signature"),
        (lambda idp, sp: resp(idp, sp, "a@x.example", audience="https://other.example"), "audience"),
        (lambda idp, sp: idp.response(now=-9000, name_id="a@x.example", audience=SP, acs_url=ACS, in_response_to=None), "time"),
        (lambda idp, sp: idp.response(now=100, name_id="a@x.example", audience=SP, acs_url=ACS, in_response_to=None), "in_response_to"),
        (lambda idp, sp: idp.response(now=100, name_id="a@x.example", audience=SP, acs_url=ACS, in_response_to="_never_sent"), "in_response_to"),
        (lambda idp, sp: idp.response(now=100, name_id="a@x.example", audience=SP, acs_url="https://elsewhere/acs", in_response_to=sp.authn_request("t", 100)), "recipient"),
    ],
)
def test_each_check_refuses_its_attack(key: rsa.RSAPrivateKey, mutate: object, code: str) -> None:
    idp, sp = make(key)
    r = mutate(idp, sp)  # type: ignore[operator]
    with pytest.raises(saml.SamlError) as e:
        sp.consume("t", saml.serialize(r), 101)
    assert e.value.code == code


def test_replay_is_refused_even_for_idp_initiated_logins(key: rsa.RSAPrivateKey) -> None:
    idp, sp = make(key)
    sp.tenants["t"].allow_idp_initiated = True
    raw = saml.serialize(idp.response(now=100, name_id="a@x.example", audience=SP, acs_url=ACS, in_response_to=None))
    sp.consume("t", raw, 101)
    with pytest.raises(saml.SamlError, match="replay"):
        sp.consume("t", raw, 130)


def test_dtds_are_refused(key: rsa.RSAPrivateKey) -> None:
    idp, sp = make(key)
    with pytest.raises(saml.SamlError, match="doctype"):
        sp.consume("t", b'<!DOCTYPE r [<!ENTITY x "x">]>' + saml.serialize(resp(idp, sp, "a@x.example")), 101)


def test_clock_skew_within_tolerance_passes_and_beyond_it_fails(key: rsa.RSAPrivateKey) -> None:
    idp, sp = make(key)
    idp.clock_skew_s = 150
    assert sp.consume("t", saml.serialize(resp(idp, sp, "a@x.example")), 101)
    idp.clock_skew_s = 400
    with pytest.raises(saml.SamlError, match="time"):
        sp.consume("t", saml.serialize(resp(idp, sp, "a@x.example")), 101)


def test_a_response_for_another_tenant_is_refused(key: rsa.RSAPrivateKey, other_key: rsa.RSAPrivateKey) -> None:
    idp, sp = make(key)
    sp.tenants["u"] = saml.TenantSaml("u", "https://idp.u.example", other_key.public_key(), SP, "https://sp.example/u/acs")
    with pytest.raises(saml.SamlError):
        sp.consume("u", saml.serialize(resp(idp, sp, "a@x.example")), 101)
