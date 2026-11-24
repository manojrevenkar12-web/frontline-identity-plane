"""Shared shop-floor stations: a registered device, a badge tap, and a session that ends when the person walks away.

- A station belongs to one workspace; a badge works only for an active person with a role there.
- A session locks after a few idle minutes, and a new badge tap ends the previous person's session.
- An electronic signature on a record (21 CFR Part 11 §11.200) needs two components: the badge alone is not one.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field

from .engine import AccessEngine, Decision


@dataclass(frozen=True)
class StationPolicy:
    idle_lock_s: float = 300.0
    max_session_s: float = 9 * 3600.0
    signature_needs_second_factor: bool = True
    check_workspace_role: bool = True


@dataclass
class Session:
    id: str
    tenant: str
    workspace: str
    station: str
    user: str
    started: float
    last: float


@dataclass
class Stations:
    policy: StationPolicy
    engine: AccessEngine
    stations: dict[str, tuple[str, str]] = field(default_factory=dict)  # station -> (tenant, workspace)
    active: dict[str, Session] = field(default_factory=dict)  # station -> current session
    pins: dict[tuple[str, str], str] = field(default_factory=dict)  # (tenant, user) -> PIN, the second component

    def register(self, station: str, tenant: str, workspace: str) -> None:
        self.stations[station] = (tenant, workspace)

    def badge(self, station: str, badge: str, now: float) -> Session | None:
        if station not in self.stations:
            return None
        tenant, ws = self.stations[station]
        u = self.engine.user_by_badge(tenant, badge)
        if u is None or not u.get("active"):
            self.active.pop(station, None)
            return None
        if self.policy.check_workspace_role and not self.engine.decide(tenant, u["userName"], "app.run", ws, now).allow:
            return None
        s = Session(secrets.token_hex(6), tenant, ws, station, u["userName"], now, now)
        self.active[station] = s  # a new tap ends the previous person's session
        return s

    def current(self, station: str, now: float) -> Session | None:
        s = self.active.get(station)
        if s is None:
            return None
        if self.policy.idle_lock_s and (now - s.last > self.policy.idle_lock_s or now - s.started > self.policy.max_session_s):
            self.active.pop(station, None)
            return None
        return s

    def act(self, station: str, action: str, now: float, pin: str | None = None) -> tuple[Decision, str | None]:
        """Do `action` at the station as whoever is signed in. Returns the decision and who acted."""
        s = self.current(station, now)
        if s is None:
            return Decision(False, "no one is signed in at this station"), None
        if action == "record.approve" and self.policy.signature_needs_second_factor:
            if pin is None or self.pins.get((s.tenant, s.user.lower())) != pin:
                return Decision(False, "a signature needs the PIN as well as the badge"), s.user
        d = self.engine.decide(s.tenant, s.user, action, s.workspace, now)
        if d.allow:
            s.last = now
        return d, s.user
