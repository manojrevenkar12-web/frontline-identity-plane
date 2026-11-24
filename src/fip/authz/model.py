"""Roles, permissions, grants and the mapping rules that turn IdP groups into grants."""

from __future__ import annotations

from dataclasses import dataclass

# What each role may do in a workspace. Approve is an electronic signature on a production record.
PERMISSIONS: dict[str, frozenset[str]] = {
    "viewer": frozenset({"app.view"}),
    "operator": frozenset({"app.view", "app.run", "record.write"}),
    "approver": frozenset({"app.view", "app.run", "record.write", "record.approve"}),
    "builder": frozenset({"app.view", "app.edit", "app.run"}),
    "admin": frozenset({"app.view", "app.run", "app.edit", "record.write", "users.manage"}),
}
ROLES = tuple(PERMISSIONS)
PRIVILEGED = frozenset({"approver", "admin"})  # never granted by a model's proposal alone
ACTIONS = frozenset().union(*PERMISSIONS.values())


@dataclass(frozen=True)
class Grant:
    workspace: str
    role: str

    def allows(self, action: str, workspace: str) -> bool:
        return self.workspace == workspace and action in PERMISSIONS[self.role]


@dataclass(frozen=True)
class MappingRule:
    """An IdP group (by its stable externalId) gives a role in a workspace. Approved by a person."""

    group_external_id: str
    workspace: str
    role: str
    approved_by: str


def permissions(grants: set[Grant], workspace: str) -> frozenset[str]:
    out: set[str] = set()
    for g in grants:
        if g.workspace == workspace:
            out |= PERMISSIONS[g.role]
    return frozenset(out)
