"""A customer's identity provider, pushing SCIM to whatever service it is pointed at.

It behaves like the real ones: Microsoft Entra sends `"op": "Replace"` and `"active": "False"` on a polling cycle,
Okta sends a whole user with PUT within minutes, ADFS-era connectors send strings for booleans. A network error is
retried on the next cycle, in order. A 4xx answer is logged and the change is dropped, as IdPs do after their retries.
A 501 on groups makes the IdP stop pushing groups, which is what customers are told to configure today.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any, Protocol

from ..protocols.saml import iso
from ..rng import keyed
from .world import FUNCTIONS, Change, Site, Tenant

PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
FRONT = "urn:ietf:params:scim:schemas:extension:frontline:2.0:User"
ENT = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"


class ScimEndpoint(Protocol):
    def tenant_for(self, token: str, path_tenant: str | None = None) -> str | None: ...
    def create_user(self, tenant: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]: ...
    def put_user(self, tenant: str, uid: str, body: dict[str, Any], if_match: str | None = None) -> tuple[int, dict[str, Any]]: ...
    def patch_user(self, tenant: str, uid: str, body: dict[str, Any], if_match: str | None = None) -> tuple[int, dict[str, Any]]: ...
    def create_group(self, tenant: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]: ...
    def patch_group(self, tenant: str, gid: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]: ...


def junk_groups(site: Site, t: Tenant, pid: str) -> set[str]:
    rng = keyed(site.seed, site.variant, "junk", pid)
    out = set()
    for g in t.groups:
        if g.workspace is not None:
            continue
        p = 1.0 if g.name == "All-Staff" else 0.35 if g.name in ("VPN-Users", "SAP-Users", "Teams-Licence") else 0.03
        if rng.random() < p:
            out.add(g.external_id)
    return out


@dataclass
class IdP:
    site: Site
    tenant: Tenant
    scim: ScimEndpoint
    token: str
    users: dict[str, dict[str, Any]] = field(default_factory=dict)  # pid -> IdP state
    ids: dict[str, str] = field(default_factory=dict)  # pid / group externalId -> SCIM id
    queue: deque[tuple[str, Any]] = field(default_factory=deque)
    groups_on: bool = True
    dropped: list[dict[str, Any]] = field(default_factory=list)
    touched: set[str] = field(default_factory=set)  # pids whose access may have changed in the last delivery
    group_ops: int = 0

    @property
    def cfg(self) -> dict[str, Any]:
        return self.site.idp_cfg(self.tenant.name)

    # ---------------------------------------------------------------------------------- state
    def _groups_for(self, pid: str, access: frozenset[tuple[str, str]]) -> set[str]:
        return {self.tenant.group_for(ws, role).external_id for ws, role in access} | junk_groups(self.site, self.tenant, pid)

    def _user_body(self, pid: str) -> dict[str, Any]:
        u = self.users[pid]
        p = self.tenant.people[pid]
        active: Any = u["active"]
        if self.cfg["bool_strings"]:
            active = "True" if active else "False"
        return {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User", ENT],
            "externalId": pid,
            "userName": p.email,
            "name": {"givenName": p.first.title(), "familyName": p.last.title()},
            "emails": [{"value": p.email, "type": "work", "primary": True}],
            "active": active,
            ENT: {"department": u["department"], "division": u["site"], "employeeNumber": p.badge},
            FRONT: {k: v for k, v in (("startDate", iso(p.start * 3600) if p.start > 0 else None), ("endDate", iso(p.contractor_end * 3600) if p.contractor_end else None)) if v},
        }

    def _op(self, name: str) -> str:
        return name.capitalize() if self.cfg["capitalised_ops"] else name

    def seed(self, people: list[str]) -> None:
        """The initial sync when the customer connects the IdP: users first, then groups with members."""
        for pid in people:
            p = self.tenant.people[pid]
            self.users[pid] = {"active": True, "department": p.department, "site": p.site, "groups": self._groups_for(pid, self.tenant.initial[pid])}
            self.queue.append(("create_user", pid))
        for g in self.tenant.groups:
            self.queue.append(("create_group", g.external_id))

    def change(self, c: Change) -> None:
        if c.kind == "join":
            self.users[c.pid] = {"active": True, "department": c.department, "site": c.site, "groups": self._groups_for(c.pid, c.access)}
            self.queue.append(("create_user", c.pid))
            for gx in self.users[c.pid]["groups"]:
                self.queue.append(("add_member", (gx, c.pid)))
            return
        u = self.users.get(c.pid)
        if u is None:
            return
        if c.kind in ("leave", "contractor_end"):
            u["active"] = False
            self.queue.append(("update_user", c.pid))
            return
        new = self._groups_for(c.pid, c.access)
        for gx in sorted(u["groups"] - new):
            self.queue.append(("remove_member", (gx, c.pid)))
        for gx in sorted(new - u["groups"]):
            self.queue.append(("add_member", (gx, c.pid)))
        u["groups"] = new
        if (c.department, c.site) != (u["department"], u["site"]):
            u["department"], u["site"] = c.department, c.site
            self.queue.append(("update_user", c.pid))

    # ---------------------------------------------------------------------------------- push
    def deliver(self, now: float) -> int:
        tenant = self.scim.tenant_for(self.token, self.tenant.name)
        if tenant is None:
            return 0
        n = 0
        self.touched = set()
        rng = keyed(self.site.seed, self.site.variant, "push", self.tenant.name, round(now, 4))
        while self.queue:
            kind, arg = self.queue[0]
            if rng.random() < float(self.cfg["failure_rate"]):
                break  # network error: the rest waits for the next cycle, in order
            self.queue.popleft()
            status, body = self._send(tenant, kind, arg)
            n += 1
            if status >= 400:
                if status == 501 and kind in ("create_group", "add_member", "remove_member"):
                    self.groups_on = False
                    continue
                self.dropped.append({"t": now, "op": kind, "arg": str(arg), "status": status, "detail": body.get("detail")})
        return n

    def _send(self, tenant: str, kind: str, arg: Any) -> tuple[int, dict[str, Any]]:
        s = self.scim
        if kind == "create_user":
            st, body = s.create_user(tenant, self._user_body(arg))
            if st == 201:
                self.ids[arg] = body["id"]
            self.touched.add(arg)
            return st, body
        if kind == "update_user":
            uid = self.ids.get(arg)
            if uid is None:
                return 404, {"detail": "not provisioned"}
            self.touched.add(arg)
            if self.cfg["user_update"] == "put":
                return s.put_user(tenant, uid, self._user_body(arg))
            u = self.users[arg]
            active: Any = u["active"]
            if self.cfg["bool_strings"]:
                active = "True" if active else "False"
            ops = [
                {"op": self._op("replace"), "path": "active", "value": active},
                {"op": self._op("replace"), "path": f"{ENT}:department", "value": u["department"]},
                {"op": self._op("replace"), "path": f"{ENT}:division", "value": u["site"]},
            ]
            return s.patch_user(tenant, uid, {"schemas": [PATCH], "Operations": ops})
        if not self.groups_on:
            return 200, {}
        self.group_ops += 1
        if kind == "create_group":
            g = next(x for x in self.tenant.groups if x.external_id == arg)
            members = [{"value": self.ids[pid]} for pid, u in self.users.items() if arg in u["groups"] and pid in self.ids]
            gbody: dict[str, Any] = {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "externalId": g.external_id, "displayName": g.name, "members": members}
            st, body = s.create_group(tenant, gbody)
            if st == 201:
                self.ids[arg] = body["id"]
                self.touched |= {pid for pid, u in self.users.items() if arg in u["groups"]}
            return st, body
        gx, pid = arg
        gid, uid = self.ids.get(gx), self.ids.get(pid)
        if gid is None or uid is None:
            return 404, {"detail": "group or user not provisioned"}
        self.touched.add(pid)
        if kind == "add_member":
            return s.patch_group(tenant, gid, {"schemas": [PATCH], "Operations": [{"op": self._op("add"), "path": "members", "value": [{"value": uid}]}]})
        if self.tenant.idp in ("okta", "ping"):
            op: dict[str, Any] = {"op": self._op("remove"), "path": f'members[value eq "{uid}"]'}
        else:
            op = {"op": self._op("remove"), "path": "members", "value": [{"value": uid}]}
        return s.patch_group(tenant, gid, {"schemas": [PATCH], "Operations": [op]})


def functions_of(role: str) -> str:
    return next(d for d, r in FUNCTIONS.values() if r == role)
