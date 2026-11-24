"""Who may do what, decided in one place.

Effective access is computed from the identity provider's current state (users and groups pushed by SCIM),
the tenant's approved mapping rules, and any manual grants an admin added. Nothing about access is stored in a
session: every decision reads the current state, so a deactivation or a group change takes effect on the next
request, for people, shared stations and agents alike.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..protocols.saml import parse_iso
from ..protocols.scim import ENTERPRISE, FRONTLINE, ScimService
from .model import Grant, MappingRule, permissions


@dataclass(frozen=True)
class Decision:
    allow: bool
    reason: str


@dataclass
class AccessEngine:
    scim: ScimService
    rules: dict[str, list[MappingRule]] = field(default_factory=dict)  # tenant -> rules
    manual: dict[tuple[str, str], set[Grant]] = field(default_factory=dict)  # (tenant, userName) -> grants
    group_sync: bool = True
    honour_dates: bool = True  # no access before the start date or after the end date the IdP sent
    _index: dict[str, tuple[int, dict[str, dict], dict[str, set[str]]]] = field(default_factory=dict)

    def _idx(self, tenant: str) -> tuple[dict[str, dict], dict[str, set[str]]]:
        """userName -> user and user id -> group keys, rebuilt only when the tenant's SCIM data changed."""
        st = self.scim.stores[tenant]
        cached = self._index.get(tenant)
        if cached is None or cached[0] != st.version:
            users = {u["userName"].lower(): u for u in st.users.values()}
            groups: dict[str, set[str]] = {}
            for g in st.groups.values():
                k = g.get("externalId") or g["displayName"]
                for m in g["members"]:
                    groups.setdefault(m["value"], set()).add(k)
            cached = (st.version, users, groups)
            self._index[tenant] = cached
        return cached[1], cached[2]

    def user(self, tenant: str, user_name: str) -> dict | None:
        if tenant not in self.scim.stores:
            return None
        return self._idx(tenant)[0].get(user_name.lower())

    def user_by_badge(self, tenant: str, badge: str) -> dict | None:
        st = self.scim.stores.get(tenant)
        for u in st.users.values() if st else []:
            if u.get(ENTERPRISE, {}).get("employeeNumber") == badge:
                return u
        return None

    def in_dates(self, u: dict, now: float | None) -> bool:
        """`now` in seconds on the protocol clock (saml.EPOCH); None skips the check."""
        if now is None or not self.honour_dates:
            return True
        d = u.get(FRONTLINE, {})
        start, end = parse_iso(d.get("startDate")), parse_iso(d.get("endDate"))
        return (start is None or now >= start) and (end is None or now < end)

    def grants(self, tenant: str, user_name: str, now: float | None = None) -> set[Grant]:
        u = self.user(tenant, user_name)
        if u is None or not u.get("active", False) or not self.in_dates(u, now):
            return set()
        out = set(self.manual.get((tenant, user_name.lower()), set()))
        if self.group_sync:
            ext = self._idx(tenant)[1].get(u["id"], set())
            for r in self.rules.get(tenant, []):
                if r.group_external_id in ext:
                    out.add(Grant(r.workspace, r.role))
        return out

    def version(self, tenant: str) -> int:
        st = self.scim.stores.get(tenant)
        return st.version if st else 0

    def decide(self, tenant: str, user_name: str, action: str, workspace: str, now: float | None = None) -> Decision:
        u = self.user(tenant, user_name)
        if u is None:
            return Decision(False, "no such user in this tenant")
        if not u.get("active", False):
            return Decision(False, "user is deactivated")
        if not self.in_dates(u, now):
            return Decision(False, "outside the person's start and end dates")
        if action in permissions(self.grants(tenant, user_name, now), workspace):
            return Decision(True, "granted")
        return Decision(False, "no role in this workspace allows it")
