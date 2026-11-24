from __future__ import annotations

from typing import Any

from fip.onboarding import OnboardingPolicy, Proposal, agreement, decide
from fip.protocols.scim import ENTERPRISE


def member(dept: str, site: str) -> dict[str, Any]:
    return {ENTERPRISE: {"department": dept, "division": site}}


MEMBERS = {
    "ops": [member("Production", "Augsburg")] * 19 + [member("Quality", "Augsburg")],
    "all": [member("Production", "Augsburg")] * 17 + [member("Quality", "Augsburg"), member("IT", "Augsburg"), member("Management", "Augsburg")],
    "vpn": [member("Production", "Augsburg"), member("IT", "Pilsen"), member("Quality", "Augsburg"), member("Management", "Pilsen")],
    "it": [member("IT", "Augsburg")] * 3,
}
SITES = {"t/aug": "Augsburg", "t/plz": "Pilsen"}


def run(props: list[Proposal], **kw: Any) -> Any:
    return decide(props, lambda g: MEMBERS.get(g, []), SITES, OnboardingPolicy(**kw))


def test_a_clear_confident_proposal_whose_members_fit_becomes_a_rule() -> None:
    out = run([Proposal("ops", "t/aug", "operator", 0.95)])
    assert [(r.group_external_id, r.role) for r in out.rules] == [("ops", "operator")]


def test_privileged_roles_always_go_to_a_person() -> None:
    out = run([Proposal("it", "t/aug", "admin", 0.99)])
    assert not out.rules and "privileged" in out.queued[0][1]


def test_a_name_never_decides_alone() -> None:
    p = Proposal("vpn", "t/aug", "operator", 0.93)
    assert not run([p]).rules
    assert run([p], check_members=False).rules  # the ablation: a confident name is enough


def test_a_group_of_everyone_is_not_an_operators_group_even_if_most_are_operators() -> None:
    assert not run([Proposal("all", "t/aug", "operator", 0.97)]).rules


def test_low_confidence_and_no_proposal_are_queued() -> None:
    out = run([Proposal("ops", "t/aug", "operator", 0.5), Proposal("x", None, None, 0.2)])
    assert not out.rules and len(out.queued) == 2


def test_agreement_counts_site_and_department() -> None:
    assert agreement(MEMBERS["ops"], "Augsburg", "operator") == 0.95
    assert agreement([], "Augsburg", "operator") == 0.0
