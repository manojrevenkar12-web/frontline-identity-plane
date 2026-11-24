"""Runs one design over the site's weeks and grades every moment against the truth.

Events, in time order: HR decisions (the truth changes), the IdP learning about them, the IdP's SCIM pushes,
shift starts (can each person do their job?), tickets to a plant admin being worked (today's process), people asking
the AI assistant to do things, and hand-overs at shared stations. Access is re-evaluated for every person an event
may have touched, so durations are exact, not sampled.
"""

from __future__ import annotations

import heapq
import math
from dataclasses import dataclass, field
from typing import Any

from ..authz.model import PERMISSIONS, Grant
from ..protocols import oidc
from ..rng import keyed
from ..world.world import SHIFTS, Site, Tenant, truth_at
from .plane import Plane, build, connect

NEEDS = {"operator": "app.run", "approver": "record.approve", "builder": "app.edit", "admin": "users.manage", "viewer": "app.view"}


def _working(t: float) -> float:
    """Move a time to the next working hour (Mon-Fri 08-17)."""
    for _ in range(400):
        d, h = int(t // 24) % 7, t % 24
        if d < 5 and 8 <= h < 17:
            return t
        t = math.floor(t) + 1
    return t


@dataclass
class Account:
    """What one person could do versus what they should, integrated over time."""

    since: float = 0.0
    eff: frozenset[tuple[str, str]] = frozenset()
    truth: frozenset[tuple[str, str]] = frozenset()
    idpv: frozenset[tuple[str, str]] = frozenset()  # what the customer's IdP says at this moment
    over_h: float = 0.0
    under_h: float = 0.0


@dataclass
class Metrics:
    over_h: float = 0.0
    over_idp_h: float = 0.0
    under_h: float = 0.0
    leaver_h_from_hr: list[float] = field(default_factory=list)
    leaver_h_from_idp: list[float] = field(default_factory=list)
    shift_starts: int = 0
    blocked: int = 0
    tickets: int = 0
    agent_requests: int = 0
    agent_overreach: int = 0
    agent_overreach_idp: int = 0
    agent_refused_allowed: int = 0
    leaver_agent_actions: int = 0
    station_actions: int = 0
    wrong_identity: int = 0
    signatures: int = 0
    wrong_identity_signatures: int = 0
    signatures_without_second_factor: int = 0
    scim_dropped: int = 0
    scim_ops: int = 0


class Runner:
    def __init__(self, site: Site, name: str, d: dict[str, Any]) -> None:
        self.site = site
        self.plane: Plane = build(site, name, d)
        connect(self.plane)
        self.m = Metrics()
        self.acc: dict[str, Account] = {}
        self.left_at: dict[str, tuple[float, float]] = {}  # pid -> (hr time, idp time)
        self.open_tickets: set[str] = set()
        self.q: list[tuple[float, int, str, Any]] = []
        self.n = 0
        self.agent_cache: dict[str, tuple[str, float]] = {}  # pid -> (token, expiry): what an agent keeps
        self.sq = self.plane.kind == "status_quo"
        self._crew: dict[tuple[str, str, int, str, int], list[str]] = {}

    # ----------------------------------------------------------------------------------- helpers
    def push(self, t: float, kind: str, payload: Any) -> None:
        self.n += 1
        heapq.heappush(self.q, (t, self.n, kind, payload))

    def tenant_of(self, pid: str) -> Tenant:
        return self.site.tenants[pid.split(":")[0]]

    def effective(self, pid: str, now: float) -> frozenset[tuple[str, str]]:
        t = self.tenant_of(pid)
        p = t.people[pid]
        return frozenset((g.workspace, g.role) for g in self.plane.engine.grants(t.name, p.email, now * 3600.0))

    def idp_view(self, pid: str) -> frozenset[tuple[str, str]]:
        t = self.tenant_of(pid)
        u = self.plane.idps[t.name].users.get(pid)
        if u is None or not u["active"]:
            return frozenset()
        real = {g.external_id: (str(g.workspace), str(g.role)) for g in t.groups if g.workspace is not None}
        return frozenset(real[g] for g in u["groups"] if g in real)

    def reeval(self, pid: str, now: float) -> None:
        a = self.acc.setdefault(pid, Account(since=now))
        dt = max(0.0, now - a.since)
        if a.eff - a.truth:
            a.over_h += dt
            self.m.over_h += dt
        if a.eff - a.idpv:
            self.m.over_idp_h += dt
        if a.truth - a.eff:
            a.under_h += dt
            self.m.under_h += dt
        a.since = now
        a.truth = truth_at(self.tenant_of(pid), pid, now)
        a.idpv = self.idp_view(pid)
        a.eff = self.effective(pid, now)
        if pid in self.left_at and not a.eff and pid not in self._closed:
            hr, idp = self.left_at[pid]
            self._closed.add(pid)
            self.m.leaver_h_from_hr.append(max(0.0, now - hr))
            self.m.leaver_h_from_idp.append(max(0.0, now - idp))

    # ----------------------------------------------------------------------------------- run
    def run(self) -> Metrics:
        site, plane = self.site, self.plane
        self._closed: set[str] = set()
        H = site.hours
        for tn, t in site.tenants.items():
            for pid in t.people:
                self.reeval(pid, 0.0)
            for c in t.changes:
                self.push(max(c.t_idp, 0.0), "idp", c)
                self.push(c.t, "truth", c)
            cyc = float(site.idp_cfg(tn)["cycle_min"]) / 60.0
            k = 1
            while k * cyc < H:
                self.push(k * cyc, "scim", tn)
                k += 1
            self._agent_requests(t)
            self._station_days(t)
        for day in range(int(H // 24)):
            if day % 7 >= 5:
                continue
            for h in SHIFTS:
                self.push(day * 24 + h, "shift", h)
            self.push(day * 24 + 8, "shift", None)
        while self.q:
            now, _, kind, payload = heapq.heappop(self.q)
            if now > H:
                break
            getattr(self, f"_on_{kind}")(now, payload)
        for pid in list(self.acc):
            self.reeval(pid, H)
        for pid, (hr, idp) in self.left_at.items():
            if pid not in self._closed:  # still open at the end of the study: count to the end
                self.m.leaver_h_from_hr.append(H - hr)
                self.m.leaver_h_from_idp.append(max(0.0, H - idp))
        for pusher in plane.idps.values():
            self.m.scim_dropped += len(pusher.dropped)
        return self.m

    # ----------------------------------------------------------------------------------- events
    def _on_idp(self, now: float, c: Any) -> None:
        self.plane.idps[c.pid.split(":")[0]].change(c)
        if c.kind in ("leave", "contractor_end"):
            hr, _ = self.left_at.get(c.pid, (c.t, c.t_idp))
            self.left_at[c.pid] = (hr, c.t_idp)
        self.reeval(c.pid, now)

    def _on_truth(self, now: float, c: Any) -> None:
        if c.kind in ("leave", "contractor_end"):
            self.left_at[c.pid] = (c.t, max(c.t_idp, c.t))
        self.reeval(c.pid, now)

    def _on_scim(self, now: float, tn: str) -> None:
        idp = self.plane.idps[tn]
        if not idp.queue:
            return
        self.m.scim_ops += idp.deliver(now)
        touched = set(idp.touched)
        # a group change can touch anyone in it; re-evaluate the people the IdP pushed about
        for pid in touched:
            self.reeval(pid, now)

    def _on_shift(self, now: float, hour: int | None) -> None:
        for t in self.site.tenants.values():
            for pid, p in t.people.items():
                if p.shift != hour or p.start > now:
                    continue
                truth = truth_at(t, pid, now)
                if not truth:
                    continue
                self.m.shift_starts += 1
                eff = self.effective(pid, now)
                perms = {(w, a) for w, r in eff for a in PERMISSIONS[r]}
                missing = [(w, r) for w, r in truth if (w, NEEDS[r]) not in perms]
                if not missing:
                    continue
                self.m.blocked += 1
                if self.sq and pid not in self.open_tickets:
                    self.open_tickets.add(pid)
                    self.m.tickets += 1
                    sq = self.site.cfg["status_quo"]["ticket_hours"]
                    rng = keyed(self.site.seed, self.site.variant, "ticket", pid, round(now, 2))
                    self.push(_working(now + float(sq["median"]) * math.exp(rng.normal() * float(sq["sigma"]))), "ticket", pid)

    def _on_ticket(self, now: float, pid: str) -> None:
        t = self.tenant_of(pid)
        p = t.people[pid]
        truth = truth_at(t, pid, now)
        key = (t.name, p.email.lower())
        cur = self.plane.engine.manual.setdefault(key, set())
        rng = keyed(self.site.seed, self.site.variant, "cleanup", pid, round(now, 2))
        if rng.random() < float(self.site.cfg["status_quo"]["cleanup_share"]):
            cur.clear()
        cur |= {Grant(w, r) for w, r in truth}
        self.open_tickets.discard(pid)
        self.reeval(pid, now)

    # ----------------------------------------------------------------------------------- the AI assistant
    def _agent_requests(self, t: Tenant) -> None:
        ac = self.site.cfg["agent"]
        mix = ac["mix"]
        acts, w = list(mix), [float(x) for x in mix.values()]
        rng = keyed(self.site.seed, self.site.variant, "agent", t.name)
        leaves = {c.pid: c.t for c in t.changes if c.kind in ("leave", "contractor_end")}
        H = self.site.hours
        for pid, p in t.people.items():
            n = int(rng.poisson(float(ac["requests_per_person_week"]) * H / 168.0))
            for _ in range(n):
                at = float(rng.uniform(max(p.start, 0), H))
                action = acts[int(rng.choice(len(acts), p=[x / sum(w) for x in w]))]
                self.push(at, "agent", (pid, action, False))
            if pid in leaves:  # scheduled jobs the person set up keep firing after they leave
                end = leaves[pid] + 168.0 * float(ac["leaver_jobs_weeks"])
                at = leaves[pid] + 6.0
                while at < min(end, H):
                    self.push(at, "agent", (pid, "app.edit" if rng.random() < 0.5 else "record.write", True))
                    at += 24.0

    def _on_agent(self, now: float, payload: tuple[str, str, bool]) -> None:
        pid, action, after_leave = payload
        t = self.tenant_of(pid)
        p = t.people[pid]
        truth = truth_at(t, pid, now)
        ws = next(iter(sorted(w for w, _ in truth)), f"{t.name}/{t.plants[0].lower()}")
        allowed = any(w == ws and action in PERMISSIONS[r] for w, r in truth)
        self.m.agent_requests += 1
        done = self._agent_do(t, pid, p.email, action, ws, now)
        idpv = self.idp_view(pid)
        if done and not any(w == ws and action in PERMISSIONS[r] for w, r in idpv):
            self.m.agent_overreach_idp += 1
        if done and not allowed:
            self.m.agent_overreach += 1
            if after_leave or not truth:
                self.m.leaver_agent_actions += 1
        if allowed and not done:
            self.m.agent_refused_allowed += 1

    def _agent_do(self, t: Tenant, pid: str, email: str, action: str, ws: str, now: float) -> bool:
        plane = self.plane
        if self.sq:
            # today: one API key per tenant with builder rights everywhere, shared by automations
            return action in PERMISSIONS["builder"]
        tok, exp = self.agent_cache.get(pid, ("", -1.0))
        if exp <= now:
            idp_user = plane.idps[t.name].users.get(pid)
            if idp_user is None or not idp_user["active"]:
                return False  # the IdP will not issue a token for a disabled person
            prov = plane.rp.providers[plane.rp.tenants[t.name].issuer]
            subject = prov.id_token({"sub": pid, "email": email}, plane.rp.tenants[t.name].client_id, now * 3600.0)
            try:
                tok = plane.agents.exchange(
                    client_id=f"assistant-{t.name}",
                    client_secret=plane.agent_secrets[t.name],
                    subject_token=subject,
                    tenant=t.name,
                    scopes={action} | ({"app.view", "app.run", "app.edit", "record.write", "record.approve"} if not plane.agents.policy.down_scope else set()),
                    workspaces={ws},
                    now=now * 3600.0,
                )
            except PermissionError:
                return False
            self.agent_cache[pid] = (tok, now + plane.agents.policy.ttl_s / 3600.0)
        return plane.agents.check(tok, t.name, action, ws, now * 3600.0).allow

    # ----------------------------------------------------------------------------------- shared stations
    def _station_days(self, t: Tenant) -> None:
        sc = self.site.cfg["stations"]
        rng = keyed(self.site.seed, self.site.variant, "stations", t.name)
        for day in range(int(self.site.hours // 24)):
            if day % 7 >= 5:
                continue
            for h in SHIFTS:
                for plant in t.plants:
                    for i in range(int(sc["per_plant"])):
                        st = f"{t.name}/{plant.lower()}/st{i}"
                        base = day * 24 + h + float(rng.uniform(0.0, 0.3))
                        self.push(base, "station", (st, plant, h, "start", float(rng.random()), int(rng.integers(1 << 30))))
                        for _k in range(int(sc["changeovers_per_shift"])):
                            at = day * 24 + h + float(rng.uniform(0.5, 7.5))
                            gap = float(rng.uniform(*sc["gap_minutes"])) / 60.0
                            self.push(at, "station", (st, plant, h, "leave", gap, int(rng.integers(1 << 30))))
                        for _k in range(int(sc["signatures_per_shift"])):
                            at = day * 24 + h + float(rng.uniform(0.5, 7.5))
                            self.push(at, "station", (st, plant, h, "sign", float(rng.random()), int(rng.integers(1 << 30))))

    def _shift_people(self, t: Tenant, plant: str, hour: int, now: float, role: str) -> list[str]:
        key = (t.name, plant, hour, role, int(now))
        if key in self._crew:
            return self._crew[key]
        ws = f"{t.name}/{plant.lower()}"
        out: list[str] = []
        self._crew[key] = out
        for pid, p in t.people.items():
            if p.start > now or (role == "operator" and p.shift != hour):
                continue
            if any(w == ws and r == role for w, r in truth_at(t, pid, now)):
                out.append(pid)
        return out

    def _on_station(self, now: float, ev: tuple[str, str, int, str, float, int]) -> None:
        st, plant, hour, kind, x, pick = ev
        t = self.tenant_of(st.split("/")[0] + ":")
        stations = self.plane.stations
        no_tap = float(self.site.cfg["stations"]["no_tap_share"])
        ops = self._shift_people(t, plant, hour, now, "operator")
        if not ops:
            return
        if kind == "start":
            a = ops[pick % len(ops)]
            stations.badge(st, t.people[a].badge, now * 3600.0)
            self._act(t, st, a, "record.write", now)
            return
        if kind == "leave":
            b = ops[(pick // 7) % len(ops)]
            later = now + x
            if keyed(self.site.seed, self.site.variant, "tap", st, round(now, 3)).random() >= no_tap:
                stations.badge(st, t.people[b].badge, later * 3600.0)
            self._act(t, st, b, "record.write", later)
            return
        # an approver comes to sign a record at the station
        qs = self._shift_people(t, plant, hour, now, "approver")
        if not qs:
            return
        q = qs[pick % len(qs)]
        self.m.signatures += 1
        if keyed(self.site.seed, self.site.variant, "sigtap", st, round(now, 3)).random() >= no_tap:
            stations.badge(st, t.people[q].badge, now * 3600.0)
        pin = stations.pins.setdefault((t.name, t.people[q].email.lower()), f"pin-{q}")
        d, who = stations.act(st, "record.approve", now * 3600.0, pin=pin)
        if d.allow:
            if who is not None and who.lower() != t.people[q].email.lower():
                self.m.wrong_identity_signatures += 1
            if not stations.policy.signature_needs_second_factor:
                self.m.signatures_without_second_factor += 1

    def _act(self, t: Tenant, st: str, actor: str, action: str, now: float) -> None:
        self.m.station_actions += 1
        d, who = self.plane.stations.act(st, action, now * 3600.0)
        if d.allow and who is not None and who.lower() != t.people[actor].email.lower():
            self.m.wrong_identity += 1


def legit_logins(site: Site, plane: Plane) -> tuple[int, int]:
    """Real people logging in through their IdP: how many does the plane turn away?"""
    n = bad = 0
    for tn, t in site.tenants.items():
        rng = keyed(site.seed, site.variant, "logins", tn)
        people = [p for p in t.people.values() if p.start <= 0 and t.initial.get(p.pid)]
        for _ in range(int(site.cfg["legit_logins_per_tenant"])):
            p = people[int(rng.integers(len(people)))]
            now = float(rng.uniform(0, 100000))
            n += 1
            try:
                if t.protocol == "saml":
                    rid = plane.sp.authn_request(tn, now)
                    resp = plane.saml_idps[tn].response(
                        now=now + 2, name_id=p.email, audience="https://identity.frontline.example/sp", acs_url=f"https://identity.frontline.example/{tn}/saml/acs", in_response_to=rid
                    )
                    from ..protocols.saml import serialize

                    plane.sp.consume(tn, serialize(resp), now + 3)
                else:
                    start = plane.rp.start(tn, now)
                    prov = plane.rp.providers[plane.rp.tenants[tn].issuer]
                    cb = prov.authorize(
                        client_id=start["client_id"],
                        redirect_uri=start["redirect_uri"],
                        state=start["state"],
                        nonce=start["nonce"],
                        subject={"sub": p.pid, "email": p.email},
                        now=now + 2,
                        code_challenge=start.get("code_challenge"),
                    )
                    plane.rp.callback(tn, cb, now + 4)
            except (ValueError, oidc.OidcError):
                bad += 1
    return n, bad
