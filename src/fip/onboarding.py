"""Onboarding a customer's identity provider: which IdP group should give which role in which plant?

A model reads the group names and descriptions (often a mix of German and English, site codes and line numbers)
and proposes a mapping with a confidence. Code decides what happens to each proposal:

- a privileged role (approver, admin) always goes to a person;
- a low-confidence proposal goes to a person;
- a name never decides alone: the group's members must agree with the proposal. At least `member_agreement`
  of them must work at the plant's site, in a department that fits the role (from the SCIM user attributes);
- everything else becomes a rule, recorded as approved by the assistant and reviewable later.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .authz.model import PRIVILEGED, MappingRule
from .protocols.scim import ENTERPRISE

ROLE_DEPARTMENTS = {
    "operator": {"Production"},
    "approver": {"Quality"},
    "builder": {"Engineering", "Digital"},
    "admin": {"IT", "Digital"},
    "viewer": {"Management"},
}


@dataclass(frozen=True)
class Proposal:
    group: str  # externalId
    workspace: str | None
    role: str | None
    confidence: float


@dataclass(frozen=True)
class OnboardingPolicy:
    min_confidence: float = 0.8
    member_agreement: float = 0.95
    check_members: bool = True


@dataclass
class Outcome:
    rules: list[MappingRule]
    queued: list[tuple[Proposal, str]]  # (proposal, why a person must look)


def agreement(members: list[dict[str, Any]], site: str, role: str) -> float:
    if not members:
        return 0.0
    ok = sum(1 for u in members if u.get(ENTERPRISE, {}).get("division") == site and u.get(ENTERPRISE, {}).get("department") in ROLE_DEPARTMENTS[role])
    return ok / len(members)


def decide(
    proposals: list[Proposal],
    members_of: Callable[[str], list[dict[str, Any]]],
    site_of: dict[str, str],
    policy: OnboardingPolicy,
) -> Outcome:
    rules, queued = [], []
    for p in proposals:
        if p.workspace is None or p.role is None:
            queued.append((p, "the model found no role"))
            continue
        if p.role in PRIVILEGED:
            queued.append((p, "privileged role: a person decides"))
            continue
        if p.confidence < policy.min_confidence:
            queued.append((p, "low confidence"))
            continue
        if policy.check_members:
            a = agreement(members_of(p.group), site_of.get(p.workspace, ""), p.role)
            if a < policy.member_agreement:
                queued.append((p, f"members do not fit the proposal ({a:.0%})"))
                continue
        rules.append(MappingRule(p.group, p.workspace, p.role, "onboarding-assistant"))
    return Outcome(rules, queued)
