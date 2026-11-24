"""The simulated customers and what really happens to them. Designs never read this module's truth.

A site is a set of tenants (manufacturers). Each has plants, a workforce with functions and shifts, an identity
provider (IdP) with its own push habits, IdP groups named the way that company names things, and a stream of HR
events: joiners, leavers, transfers between plants, promotions, temporary assignments, contractors whose end date
arrives. The truth is who should be able to do what, at every moment.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from functools import cache
from typing import Any

import yaml

from .. import config
from ..rng import keyed

FUNCTIONS = {"operators": ("Production", "operator"), "quality": ("Quality", "approver"), "engineers": ("Engineering", "builder"), "plant_it": ("IT", "admin"), "managers": ("Management", "viewer")}
SHIFTS = (6, 14, 22)  # shift starts, hour of day
FIRST_NAMES = [
    "anna",
    "jonas",
    "mia",
    "lukas",
    "lea",
    "felix",
    "emma",
    "paul",
    "sofia",
    "ben",
    "lena",
    "elias",
    "marie",
    "noah",
    "hanna",
    "tom",
    "eva",
    "max",
    "ida",
    "leon",
    "petra",
    "jan",
    "karin",
    "ole",
]
LAST_NAMES = [
    "mueller",
    "schmidt",
    "novak",
    "fischer",
    "weber",
    "horvath",
    "wagner",
    "becker",
    "kovac",
    "hofmann",
    "schulz",
    "keller",
    "lang",
    "berger",
    "vogel",
    "kraus",
    "dvorak",
    "frank",
    "huber",
    "brandt",
]


@cache
def world_config(variant: str) -> dict[str, Any]:
    raw = yaml.safe_load((config.CONFIG / "world.yml").read_text(encoding="utf-8"))
    return raw["dev"] if variant == "dev" else config.merged(raw["dev"], raw[variant])


def ws_id(tenant: str, plant: str) -> str:
    return f"{tenant}/{plant.lower()}"


@dataclass
class Person:
    pid: str
    tenant: str
    email: str
    first: str
    last: str
    department: str
    site: str  # home plant
    badge: str
    shift: int | None  # hour the person's shift starts; None for day workers
    start: float  # hour the job starts
    contractor_end: float | None = None


@dataclass(frozen=True)
class Group:
    external_id: str
    name: str
    tenant: str
    workspace: str | None  # truth: what the group means in the product, None for junk
    role: str | None


@dataclass(frozen=True)
class Change:
    """Something HR decided. `access` is the truth from `t` on; the IdP learns about it at `t_idp`."""

    t: float
    t_idp: float
    pid: str
    kind: str  # join | leave | transfer | promote | temp_start | temp_end | contractor_end
    access: frozenset[tuple[str, str]]  # (workspace, role)
    department: str
    site: str


@dataclass
class Tenant:
    name: str
    idp: str
    protocol: str
    plants: list[str]
    naming: str
    clock_skew_s: float
    people: dict[str, Person] = field(default_factory=dict)
    groups: list[Group] = field(default_factory=list)
    initial: dict[str, frozenset[tuple[str, str]]] = field(default_factory=dict)  # truth at t=0
    changes: list[Change] = field(default_factory=list)

    @property
    def workspaces(self) -> dict[str, str]:
        return {ws_id(self.name, p): p for p in self.plants}

    def group_for(self, ws: str, role: str) -> Group:
        return next(g for g in self.groups if g.workspace == ws and g.role == role)


@dataclass
class Site:
    seed: int
    variant: str
    cfg: dict[str, Any]
    tenants: dict[str, Tenant]

    @property
    def hours(self) -> float:
        return float(self.cfg["weeks"]) * 168.0

    def idp_cfg(self, tenant: str) -> dict[str, Any]:
        return dict(self.cfg["idp"][self.tenants[tenant].idp])


# ------------------------------------------------------------------------------------------------ naming
_CODES = {
    "Augsburg": "AUG",
    "Pilsen": "PLZ",
    "Basel": "BSL",
    "Visp": "VSP",
    "Linz": "LNZ",
    "Chemnitz": "CHE",
    "Ingolstadt": "ING",
    "Győr": "GYR",
    "Zwickau": "ZWI",
    "Tuttlingen": "TUT",
    "Lüdenscheid": "LDS",
    "Pirna": "PIR",
    "Ludwigshafen": "LUH",
}
_DE = {"operator": "Werker", "approver": "QS-Freigabe", "builder": "Prozessentwicklung", "admin": "IT-Admins", "viewer": "Leitung"}
_EN = {"operator": "Operators", "approver": "Quality-Approvers", "builder": "Engineering", "admin": "Plant-IT", "viewer": "Managers"}
JUNK = [
    "All-Staff",
    "VPN-Users",
    "Admins-Test",
    "Leavers-2025",
    "Teams-Licence",
    "Canteen-Menu",
    "Printer-Admins",
    "Ex-Contractors",
    "SAP-Users",
    "Badge-Office",
    "Works-Council",
    "MFA-Pilot",
    "Laptop-Rollout",
    "Visitors",
]


def group_name(style: str, site: str, role: str, i: int) -> str:
    code = _CODES.get(site, site[:3].upper())
    if style == "site_func":
        return f"{code}-{_EN[role]}"
    if style == "grp_func_site":
        return f"GRP_{_EN[role].replace('-', '_')}_{site}"
    return f"SG-{1000 + 37 * i} {code} {_DE[role]}"


# ------------------------------------------------------------------------------------------------ build
def _lognormal(rng: Any, median: float, sigma: float) -> float:
    return float(median * math.exp(rng.normal() * sigma))


def build_site(seed: int, variant: str = "dev") -> Site:
    cfg = world_config(variant)
    tenants: dict[str, Tenant] = {}
    for tc in cfg["tenants"]:
        t = Tenant(tc["name"], tc["idp"], tc["protocol"], list(tc["plants"]), tc["naming"], float(tc["clock_skew_s"]))
        _populate(t, seed, variant, cfg)
        tenants[t.name] = t
    return Site(seed, variant, cfg, tenants)


def _new_person(t: Tenant, rng: Any, dept: str, site: str, start: float, shift: int | None, contractor_end: float | None) -> Person:
    n = len(t.people)
    first, last = FIRST_NAMES[int(rng.integers(len(FIRST_NAMES)))], LAST_NAMES[int(rng.integers(len(LAST_NAMES)))]
    pid = f"{t.name}:{n:05d}"
    return Person(pid, t.name, f"{first}.{last}.{n}@{t.name}.example", first, last, dept, site, f"B{int(rng.integers(10**7, 10**8))}", shift, start, contractor_end)


def _populate(t: Tenant, seed: int, variant: str, cfg: dict[str, Any]) -> None:
    rng = keyed(seed, variant, "people", t.name)
    wf = cfg["workforce"]
    hours = float(cfg["weeks"]) * 168.0
    # groups: one per (plant, role), named the company's way, plus junk
    i = 0
    for p in t.plants:
        for _fn, (_, role) in FUNCTIONS.items():
            t.groups.append(Group(f"{t.name}-g{i:03d}", group_name(t.naming, p, role, i), t.name, ws_id(t.name, p), role))
            i += 1
    for j in range(int(cfg["groups"]["junk_per_tenant"])):
        t.groups.append(Group(f"{t.name}-j{j:03d}", JUNK[j % len(JUNK)], t.name, None, None))
    # people
    for p in t.plants:
        for fn, (dept, role) in FUNCTIONS.items():
            lo, hi = wf[fn]
            for _ in range(int(rng.integers(lo, hi + 1))):
                contractor = fn == "operators" and rng.random() < float(wf.get("contractor_share", 0.0))
                end = float(rng.uniform(24, hours)) if contractor else None
                person = _new_person(t, rng, dept, p, -1000.0, SHIFTS[int(rng.integers(3))] if fn == "operators" else None, end)
                t.people[person.pid] = person
                access = {(ws_id(t.name, p), role)}
                if fn in ("quality", "engineers") and len(t.plants) > 1 and rng.random() < float(wf.get("multi_plant_share", 0.0)):
                    other = [x for x in t.plants if x != p][int(rng.integers(len(t.plants) - 1))]
                    access.add((ws_id(t.name, other), role))
                t.initial[person.pid] = frozenset(access)
                if end is not None:
                    lag = _lognormal(rng, 6.0, 1.0)  # contractor end dates are known: the IdP disables on a schedule
                    t.changes.append(Change(end, end + lag, person.pid, "contractor_end", frozenset(), dept, p))
    _hr_events(t, rng, cfg, hours)
    t.changes.sort(key=lambda c: (c.t, c.pid))


def _hr_events(t: Tenant, rng: Any, cfg: dict[str, Any], hours: float) -> None:
    hr = cfg["hr"]
    lag = hr["idp_lag_hours"]
    current = dict(t.initial)
    ended = {c.pid for c in t.changes}
    cur_site = {pid: p.site for pid, p in t.people.items()}
    cur_dept = {pid: p.department for pid, p in t.people.items()}
    weeks = int(cfg["weeks"])
    for w in range(weeks):
        people = [pid for pid in current if current[pid] and pid not in ended]
        n = len(people)
        for kind, rate in (("leave", hr["leave_rate"]), ("transfer", hr["transfer_rate"]), ("promote", hr["promotion_rate"]), ("temp_start", hr["temp_assignment_rate"])):
            for _ in range(int(rng.poisson(float(rate) * n))):
                pid = people[int(rng.integers(n))]
                if pid in ended or not current.get(pid):
                    continue
                person = t.people[pid]
                at = w * 168.0 + float(rng.uniform(0, 168))
                t_idp = at + _lognormal(rng, float(lag["median"]), float(lag["sigma"]))
                acc = set(current[pid])
                dept, site = cur_dept[pid], cur_site[pid]
                if kind == "leave":
                    acc = set()
                    ended.add(pid)
                    t.changes.append(Change(at, t_idp, pid, "leave", frozenset(), dept, site))
                elif kind == "transfer" and len(t.plants) > 1:
                    site = [x for x in t.plants if x != cur_site[pid]][int(rng.integers(len(t.plants) - 1))]
                    acc = {(ws_id(t.name, site), r) for (_, r) in acc}
                    cur_site[pid] = site
                    t.changes.append(Change(at, t_idp, pid, "transfer", frozenset(acc), dept, site))
                elif kind == "promote" and dept == "Production":
                    dept = "Quality"
                    cur_dept[pid] = dept
                    acc = {(w_, "approver") for (w_, _) in acc}
                    t.changes.append(Change(at, t_idp, pid, "promote", frozenset(acc), dept, site))
                elif kind == "temp_start" and len(t.plants) > 1:
                    role = next(iter(acc))[1]
                    other = [x for x in t.plants if ws_id(t.name, x) not in {a[0] for a in acc}]
                    if not other:
                        continue
                    extra = (ws_id(t.name, other[int(rng.integers(len(other)))]), role)
                    t.changes.append(Change(at, t_idp, pid, "temp_start", frozenset(acc | {extra}), dept, site))
                    end = at + 168.0 * float(hr["temp_assignment_weeks"])
                    if end < hours:
                        t.changes.append(Change(end, end + _lognormal(rng, float(lag["median"]), float(lag["sigma"])), pid, "temp_end", frozenset(acc), dept, site))
                    continue
                else:
                    continue
                current[pid] = frozenset(acc)
        for _ in range(int(rng.poisson(float(hr["join_rate"]) * max(n, 1)))):
            site = t.plants[int(rng.integers(len(t.plants)))]
            fn = "operators" if rng.random() < 0.75 else ["quality", "engineers", "managers"][int(rng.integers(3))]
            dept, role = FUNCTIONS[fn]
            at = w * 168.0 + float(rng.uniform(0, 168))
            person = _new_person(t, rng, dept, site, at, SHIFTS[int(rng.integers(3))] if fn == "operators" else None, None)
            t.people[person.pid] = person
            t.initial.setdefault(person.pid, frozenset())
            current[person.pid] = frozenset({(ws_id(t.name, site), role)})
            cur_site[person.pid], cur_dept[person.pid] = site, dept
            # HR creates the account a few days before the first day
            t.changes.append(Change(at, at - float(rng.uniform(24, 96)), person.pid, "join", current[person.pid], dept, site))


def truth_at(t: Tenant, pid: str, when: float) -> frozenset[tuple[str, str]]:
    by_pid = t.__dict__.get("_by_pid")
    if by_pid is None:
        by_pid = {}
        for c in t.changes:
            by_pid.setdefault(c.pid, []).append(c)
        t.__dict__["_by_pid"] = by_pid
    acc = t.initial.get(pid, frozenset())
    for c in by_pid.get(pid, ()):
        if c.t > when:
            break
        acc = c.access
    return acc


# ------------------------------------------------------------------------------------------------ the model
def read_groups(site: Site, tenant: str, keyfn: Any = None) -> list[tuple[str, str | None, str | None, float]]:
    """What a language model makes of the tenant's group names: (externalId, workspace, role, confidence).

    Hidden: how often it is right depends on how the company names its groups; junk groups sometimes get a
    confident, wrong proposal ("Admins-Test" -> admin)."""
    t = site.tenants[tenant]
    mm = site.cfg["mapping_model"]
    out: list[tuple[str, str | None, str | None, float]] = []
    roles = list(_EN)
    wss = list(t.workspaces)
    for g in t.groups:
        rng = keyed(site.seed, site.variant, "model", tenant, g.external_id)
        if g.workspace is None:
            m = mm["junk"]
            if rng.random() < float(m["proposes"]):
                role = "admin" if "Admin" in g.name else roles[int(rng.integers(len(roles)))]
                out.append((g.external_id, wss[int(rng.integers(len(wss)))], role, float(rng.uniform(*m["confidence"]))))
            else:
                out.append((g.external_id, None, None, float(rng.uniform(0.1, 0.5))))
            continue
        m = mm[t.naming]
        conf = float(rng.uniform(*m["confidence"]))
        if rng.random() < float(m["correct"]):
            out.append((g.external_id, g.workspace, g.role, conf))
        else:
            # a plausible mistake: the right plant with a neighbouring role, or the right role at another plant
            if rng.random() < 0.6 or len(wss) == 1:
                wrong = [r for r in roles if r != g.role]
                out.append((g.external_id, g.workspace, wrong[int(rng.integers(len(wrong)))], conf))
            else:
                other = [w for w in wss if w != g.workspace]
                out.append((g.external_id, other[int(rng.integers(len(other)))], g.role, conf))
    return out
