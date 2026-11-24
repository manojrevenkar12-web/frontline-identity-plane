"""SCIM 2.0 service provider (RFC 7643/7644): Users and Groups, with the subset of filters and PATCH that real
identity providers send, including their quirks.

- The tenant comes from the bearer token, never from the URL.
- PATCH accepts what Microsoft Entra sends (`"op": "Replace"`, `"active": "False"`, member removal by value filter)
  and what Okta sends (PUT of the whole user), and answers anything else with a 400 the IdP can act on.
- Every write bumps `meta.version`; `If-Match` with a stale version is refused (412).
- Membership changes for a user who does not exist are refused (404), not silently created.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass, field
from typing import Any

USER = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group"
ENTERPRISE = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
FRONTLINE = "urn:ietf:params:scim:schemas:extension:frontline:2.0:User"  # startDate, endDate (ISO 8601)
PATCH_OP = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
ERROR = "urn:ietf:params:scim:api:messages:2.0:Error"


@dataclass(frozen=True)
class ScimPolicy:
    tenant_from_token: bool = True
    lenient_ops: bool = True  # accept the case and boolean-as-string quirks of real IdPs
    groups: bool = True  # sync groups (the status quo provisions users only)
    strict_members: bool = True  # 404 on members that do not exist instead of ignoring them


def err(status: int, detail: str, scim_type: str | None = None) -> tuple[int, dict[str, Any]]:
    body: dict[str, Any] = {"schemas": [ERROR], "status": str(status), "detail": detail}
    if scim_type:
        body["scimType"] = scim_type
    return status, body


_FILTER = re.compile(r'^\s*(userName|externalId|displayName|emails\.value|id)\s+eq\s+"((?:[^"\\]|\\.)*)"\s*$')


def _bool(v: Any, lenient: bool) -> bool | None:
    if isinstance(v, bool):
        return v
    if lenient and isinstance(v, str) and v.lower() in ("true", "false"):
        return v.lower() == "true"
    return None


@dataclass
class Store:
    users: dict[str, dict[str, Any]] = field(default_factory=dict)
    groups: dict[str, dict[str, Any]] = field(default_factory=dict)
    version: int = 0  # bumps on every write; the access layer caches on it


@dataclass
class ScimService:
    policy: ScimPolicy
    tokens: dict[str, str] = field(default_factory=dict)  # sha256(token) -> tenant
    stores: dict[str, Store] = field(default_factory=dict)
    log: list[dict[str, Any]] = field(default_factory=list)

    # ---------------------------------------------------------------------------------------- auth
    def issue_token(self, tenant: str) -> str:
        tok = "scim_" + secrets.token_urlsafe(24)
        self.tokens[hashlib.sha256(tok.encode()).hexdigest()] = tenant
        self.stores.setdefault(tenant, Store())
        return tok

    def tenant_for(self, token: str, path_tenant: str | None = None) -> str | None:
        t = self.tokens.get(hashlib.sha256(token.encode()).hexdigest())
        if t is None:
            return None
        if not self.policy.tenant_from_token and path_tenant:
            return path_tenant if path_tenant in self.stores else None
        return t

    # ---------------------------------------------------------------------------------------- helpers
    def _bump(self, st: Store, res: dict[str, Any]) -> None:
        st.version += 1
        res["meta"]["version"] = f'W/"{st.version}"'

    @staticmethod
    def _match(res: dict[str, Any], attr: str, value: str) -> bool:
        if attr == "emails.value":
            return any(e.get("value", "").lower() == value.lower() for e in res.get("emails", []))
        v = res.get(attr)
        return isinstance(v, str) and (v.lower() == value.lower() if attr == "userName" else v == value)

    def _list(self, items: dict[str, dict[str, Any]], flt: str | None) -> tuple[int, dict[str, Any]]:
        out = list(items.values())
        if flt:
            m = _FILTER.match(flt)
            if not m:
                return err(400, "filter not supported", "invalidFilter")
            out = [r for r in out if self._match(r, m.group(1), m.group(2).replace('\\"', '"'))]
        return 200, {"schemas": [LIST], "totalResults": len(out), "Resources": out, "startIndex": 1, "itemsPerPage": len(out)}

    # ---------------------------------------------------------------------------------------- users
    def create_user(self, tenant: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        st = self.stores[tenant]
        un = body.get("userName")
        if not isinstance(un, str) or not un:
            return err(400, "userName is required", "invalidValue")
        if any(u["userName"].lower() == un.lower() for u in st.users.values()):
            return err(409, "userName already exists", "uniqueness")
        uid = secrets.token_hex(8)
        user = {
            "schemas": [USER, ENTERPRISE],
            "id": uid,
            "externalId": body.get("externalId"),
            "userName": un,
            "name": body.get("name", {}),
            "emails": body.get("emails", []),
            "title": body.get("title"),
            "active": _bool(body.get("active", True), self.policy.lenient_ops) is not False,
            ENTERPRISE: dict(body.get(ENTERPRISE, {})),
            FRONTLINE: {k: v for k, v in dict(body.get(FRONTLINE, {})).items() if k in ("startDate", "endDate")},
            "meta": {"resourceType": "User"},
        }
        st.users[uid] = user
        self._bump(st, user)
        return 201, user

    def get_user(self, tenant: str, uid: str) -> tuple[int, dict[str, Any]]:
        u = self.stores[tenant].users.get(uid)
        return (200, u) if u else err(404, "user not found")

    def list_users(self, tenant: str, flt: str | None = None) -> tuple[int, dict[str, Any]]:
        return self._list(self.stores[tenant].users, flt)

    def put_user(self, tenant: str, uid: str, body: dict[str, Any], if_match: str | None = None) -> tuple[int, dict[str, Any]]:
        st = self.stores[tenant]
        u = st.users.get(uid)
        if u is None:
            return err(404, "user not found")
        if if_match and if_match != u["meta"]["version"]:
            return err(412, "version mismatch")
        active = _bool(body.get("active", True), self.policy.lenient_ops)
        if active is None:
            return err(400, "active must be a boolean", "invalidValue")
        for k in ("userName", "externalId", "name", "emails", "title"):
            if k in body:
                u[k] = body[k]
        u["active"] = active
        u[ENTERPRISE] = dict(body.get(ENTERPRISE, u[ENTERPRISE]))
        if FRONTLINE in body:
            u[FRONTLINE] = {k: v for k, v in dict(body[FRONTLINE]).items() if k in ("startDate", "endDate")}
        self._bump(st, u)
        return 200, u

    def patch_user(self, tenant: str, uid: str, body: dict[str, Any], if_match: str | None = None) -> tuple[int, dict[str, Any]]:
        st = self.stores[tenant]
        u = st.users.get(uid)
        if u is None:
            return err(404, "user not found")
        if if_match and if_match != u["meta"]["version"]:
            return err(412, "version mismatch")
        ops = body.get("Operations")
        if PATCH_OP not in body.get("schemas", []) or not isinstance(ops, list):
            return err(400, "not a PatchOp", "invalidSyntax")
        staged = dict(u)
        for op in ops:
            kind = op.get("op", "")
            kind = kind.lower() if self.policy.lenient_ops else kind
            if kind not in ("add", "replace", "remove"):
                return err(400, f"unsupported op {op.get('op')!r}", "invalidSyntax")
            path, value = op.get("path"), op.get("value")
            updates = {path: value} if path else (value if isinstance(value, dict) else None)
            if kind == "remove":
                if path in ("title",):
                    staged[path] = None
                    continue
                return err(400, f"cannot remove {path!r}", "mutability")
            if updates is None:
                return err(400, "replace without path needs an object value", "invalidValue")
            for k, v in updates.items():
                if k == "active":
                    b = _bool(v, self.policy.lenient_ops)
                    if b is None:
                        return err(400, "active must be a boolean", "invalidValue")
                    staged["active"] = b
                elif k in ("userName", "externalId", "title", "displayName"):
                    staged[k] = v
                elif k.startswith(ENTERPRISE + ":"):
                    staged[ENTERPRISE] = {**staged[ENTERPRISE], k.split(":")[-1]: v}
                elif k in (f"{FRONTLINE}:startDate", f"{FRONTLINE}:endDate"):
                    staged[FRONTLINE] = {**staged.get(FRONTLINE, {}), k.split(":")[-1]: v}
                elif k == "name.givenName" or k == "name.familyName":
                    staged["name"] = {**staged.get("name", {}), k.split(".")[1]: v}
                elif k == 'emails[type eq "work"].value':
                    staged["emails"] = [{"value": v, "type": "work", "primary": True}]
                else:
                    return err(400, f"unsupported path {k!r}", "invalidPath")
        u.update(staged)
        self._bump(st, u)
        return 200, u

    def delete_user(self, tenant: str, uid: str) -> tuple[int, dict[str, Any]]:
        st = self.stores[tenant]
        if st.users.pop(uid, None) is None:
            return err(404, "user not found")
        for g in st.groups.values():
            g["members"] = [m for m in g["members"] if m["value"] != uid]
        st.version += 1
        return 204, {}

    # ---------------------------------------------------------------------------------------- groups
    def _members(self, st: Store, value: Any) -> list[dict[str, str]] | None:
        out = []
        for m in value or []:
            mid = m.get("value") if isinstance(m, dict) else None
            if mid not in st.users:
                if self.policy.strict_members:
                    return None
                continue
            out.append({"value": mid})
        return out

    def create_group(self, tenant: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        if not self.policy.groups:
            return err(501, "groups are not provisioned through SCIM")
        st = self.stores[tenant]
        name = body.get("displayName")
        if not isinstance(name, str) or not name:
            return err(400, "displayName is required", "invalidValue")
        members = self._members(st, body.get("members"))
        if members is None:
            return err(404, "a member does not exist")
        gid = secrets.token_hex(8)
        g = {"schemas": [GROUP], "id": gid, "externalId": body.get("externalId"), "displayName": name, "members": members, "meta": {"resourceType": "Group"}}
        st.groups[gid] = g
        self._bump(st, g)
        return 201, g

    def list_groups(self, tenant: str, flt: str | None = None) -> tuple[int, dict[str, Any]]:
        if not self.policy.groups:
            return err(501, "groups are not provisioned through SCIM")
        return self._list(self.stores[tenant].groups, flt)

    def patch_group(self, tenant: str, gid: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        if not self.policy.groups:
            return err(501, "groups are not provisioned through SCIM")
        st = self.stores[tenant]
        g = st.groups.get(gid)
        if g is None:
            return err(404, "group not found")
        members = {m["value"] for m in g["members"]}
        name = g["displayName"]
        for op in body.get("Operations", []):
            kind = op.get("op", "")
            kind = kind.lower() if self.policy.lenient_ops else kind
            path, value = op.get("path"), op.get("value")
            if kind == "add" and path == "members":
                add = self._members(st, value)
                if add is None:
                    return err(404, "a member does not exist")
                members |= {m["value"] for m in add}
            elif kind == "remove" and path == "members" and isinstance(value, list):
                members -= {m.get("value") for m in value}
            elif kind == "remove" and isinstance(path, str) and (m := re.fullmatch(r'members\[value eq "([^"]+)"\]', path)):
                members.discard(m.group(1))
            elif kind == "replace" and path == "members":
                rep = self._members(st, value)
                if rep is None:
                    return err(404, "a member does not exist")
                members = {m["value"] for m in rep}
            elif kind == "replace" and (path == "displayName" or (path is None and isinstance(value, dict) and "displayName" in value)):
                name = value if path else value["displayName"]
            else:
                return err(400, f"unsupported group operation {op.get('op')!r} {path!r}", "invalidSyntax")
        g["members"] = [{"value": m} for m in sorted(members)]
        g["displayName"] = name
        self._bump(st, g)
        return 200, g

    def delete_group(self, tenant: str, gid: str) -> tuple[int, dict[str, Any]]:
        st = self.stores[tenant]
        if st.groups.pop(gid, None) is None:
            return err(404, "group not found")
        st.version += 1
        return 204, {}
