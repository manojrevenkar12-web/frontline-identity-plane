from __future__ import annotations

import pytest

from fip import config
from fip.sim.attacks import run_attacks
from fip.sim.run import Runner, legit_logins
from fip.world.world import Site, build_site, read_groups, truth_at


def test_same_seed_same_customers(tiny: Site) -> None:
    again = build_site(5, "tiny")
    for tn in tiny.tenants:
        assert [c.pid for c in again.tenants[tn].changes] == [c.pid for c in tiny.tenants[tn].changes]
        assert read_groups(again, tn) == read_groups(tiny, tn)


def test_truth_follows_hr_changes(tiny: Site) -> None:
    t = next(iter(tiny.tenants.values()))
    leave = next(c for c in t.changes if c.kind in ("leave", "contractor_end"))
    assert truth_at(t, leave.pid, leave.t - 0.01)
    assert not truth_at(t, leave.pid, leave.t + 0.01)


@pytest.fixture(scope="module")
def results(tiny: Site) -> dict[str, object]:
    d = config.designs()["designs"]
    return {n: Runner(tiny, n, d[n]).run() for n in ("status_quo", "naive_build", "platform")}


def test_the_platform_has_less_wrong_access_than_today(results: dict[str, object]) -> None:
    p, sq = results["platform"], results["status_quo"]
    assert p.over_idp_h < sq.over_idp_h  # type: ignore[attr-defined]
    assert p.blocked <= sq.blocked  # type: ignore[attr-defined]


def test_the_platform_closes_leavers_within_the_idp_cycle(results: dict[str, object]) -> None:
    p = results["platform"]
    assert p.leaver_h_from_idp and max(p.leaver_h_from_idp) < 1.0  # type: ignore[attr-defined]


def test_no_signature_under_someone_elses_identity(results: dict[str, object]) -> None:
    assert results["platform"].wrong_identity_signatures == 0  # type: ignore[attr-defined]
    assert results["naive_build"].wrong_identity_signatures > 0  # type: ignore[attr-defined]


def test_every_attack_fails_against_the_platform_and_some_work_against_a_naive_build(tiny: Site) -> None:
    d = config.designs()["designs"]
    plat = run_attacks(tiny, "platform", d["platform"])
    naive = run_attacks(tiny, "naive_build", d["naive_build"])
    assert sum(v["successes"] for v in plat.values()) == 0
    assert naive["saml.signature_wrapping"]["successes"] > 0 and naive["jwt.alg_none"]["successes"] > 0


def test_legitimate_logins_pass(tiny: Site) -> None:
    r = Runner(tiny, "platform", config.designs()["designs"]["platform"])
    n, bad = legit_logins(tiny, r.plane)
    assert n > 0 and bad == 0
