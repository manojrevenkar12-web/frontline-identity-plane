"""Runs every design on a split's sites, grades them, checks the gates and writes reports/<split>.json."""

from __future__ import annotations

import hashlib
import json
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any

import numpy as np

from .. import config
from ..sim.attacks import run_attacks
from ..sim.run import Runner, legit_logins
from ..world.world import build_site

REPORTS = config.REPORTS
LOCK = REPORTS / "heldout.lock"
CROSS_TENANT = ("saml.other_tenants_idp", "scim.other_tenant_by_path", "agent.token_at_other_tenant")


class HeldOutLocked(RuntimeError):
    pass


def _round(x: Any) -> Any:
    if isinstance(x, np.floating | float):
        x = float(x)
        return None if x != x else round(x, 4)
    if isinstance(x, np.integer):
        return int(x)
    if isinstance(x, dict):
        return {str(k): _round(v) for k, v in x.items()}
    if isinstance(x, list | tuple):
        return [_round(v) for v in x]
    return x


def config_hash() -> str:
    h = hashlib.sha256()
    for p in sorted(config.CONFIG.glob("*.yml")):
        h.update(p.name.encode())
        h.update(p.read_bytes())
    return h.hexdigest()


def _p95(xs: list[float]) -> float:
    return float(np.percentile(xs, 95)) if xs else 0.0


def design_metrics(site: Any, name: str, d: dict[str, Any]) -> dict[str, Any]:
    r = Runner(site, name, d)
    m = r.run()
    attacks = run_attacks(site, name, d)
    n, bad = legit_logins(site, r.plane)
    ob = r.plane.onboarding.values()
    groups = sum(x.get("groups", 0) for x in ob)
    sq = site.cfg["status_quo"]
    weeks = float(site.cfg["weeks"])
    people = sum(len(t.people) for t in site.tenants.values())
    return {
        "people": people,
        "over_privileged_h": m.over_h,
        "over_idp_h": m.over_idp_h,
        "under_privileged_h": m.under_h,
        "leavers": len(m.leaver_h_from_idp),
        "leaver_h_after_idp_p95": _p95(m.leaver_h_from_idp),
        "leaver_h_after_idp_mean": float(np.mean(m.leaver_h_from_idp)) if m.leaver_h_from_idp else 0.0,
        "leaver_h_after_hr_p95": _p95(m.leaver_h_from_hr),
        "shift_starts": m.shift_starts,
        "blocked_shift_starts": m.blocked,
        "tickets": m.tickets,
        "admin_hours_onboarding": sum(x["admin_minutes"] for x in ob) / 60.0,
        "admin_hours_per_week": m.tickets * float(sq["admin_minutes_per_ticket"]) / 60.0 / weeks,
        "lost_work_hours": m.blocked * float(sq["blocked_minutes_per_ticket"]) / 60.0 if r.sq else 0.0,
        "groups": groups,
        "groups_auto_mapped": sum(x["auto"] for x in ob),
        "wrong_auto_grants": sum(x["wrong_auto"] for x in ob),
        "agent_requests": m.agent_requests,
        "agent_overreach": m.agent_overreach,
        "agent_overreach_idp": m.agent_overreach_idp,
        "agent_refused_allowed": m.agent_refused_allowed,
        "leaver_agent_actions": m.leaver_agent_actions,
        "station_actions": m.station_actions,
        "wrong_identity_actions": m.wrong_identity,
        "signatures": m.signatures,
        "wrong_identity_signatures": m.wrong_identity_signatures,
        "signatures_without_second_factor": m.signatures_without_second_factor,
        "scim_changes_dropped": m.scim_dropped,
        "attack_attempts": sum(v["attempts"] for v in attacks.values()),
        "attack_successes": sum(v["successes"] for v in attacks.values()),
        "cross_tenant_successes": sum(attacks[k]["successes"] for k in CROSS_TENANT if k in attacks),
        "attacks": attacks,
        "legit_logins": n,
        "legit_login_rejections": bad,
    }


def _seed_job(args: tuple[int, str]) -> dict[str, Any]:
    seed, variant = args
    site = build_site(seed, variant)
    dcfg = config.designs()
    out: dict[str, Any] = {
        "seed": seed,
        "designs": {},
        "site": {
            "tenants": len(site.tenants),
            "plants": sum(len(t.plants) for t in site.tenants.values()),
            "people": sum(len(t.people) for t in site.tenants.values()),
            "weeks": site.cfg["weeks"],
            "hr_changes": sum(len(t.changes) for t in site.tenants.values()),
            "idps": sorted({t.idp for t in site.tenants.values()}),
        },
    }
    for name, d in dcfg["designs"].items():
        out["designs"][name] = design_metrics(site, name, d)
    return _round(out)


def _combine(rows: list[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k in rows[0]:
        vals = [r[k] for r in rows]
        if k == "attacks":
            kinds = sorted({x for v in vals for x in v})
            out[k] = {x: {"attempts": sum(v.get(x, {}).get("attempts", 0) for v in vals), "successes": sum(v.get(x, {}).get("successes", 0) for v in vals)} for x in kinds}
        elif k.endswith("_p95") or k.endswith("_mean"):
            out[k] = float(np.mean(vals))
        else:
            out[k] = float(np.sum(vals))
    return out


def check_gates(res: dict[str, Any], g: dict[str, Any]) -> dict[str, Any]:
    p, sq = res["designs"]["platform"], res["designs"]["status_quo"]
    gp = g["platform"]
    rows = [
        ("Attacks that got in", p["attack_successes"], gp["attack_successes_max"], "max"),
        ("Cross-tenant access", p["cross_tenant_successes"], gp["cross_tenant_max"], "max"),
        ("Hours from IdP deactivation to the last access path closed, p95", p["leaver_h_after_idp_p95"], gp["leaver_hours_after_idp_p95_max"], "max"),
        ("Over-privileged person-hours, ratio to today", p["over_privileged_h"] / max(sq["over_privileged_h"], 1e-9), gp["over_privileged_vs_status_quo_max"], "max"),
        ("Blocked shift starts, ratio to today", p["blocked_shift_starts"] / max(sq["blocked_shift_starts"], 1e-9), gp["blocked_shift_starts_vs_status_quo_max"], "max"),
        ("Legitimate logins turned away, share", p["legit_login_rejections"] / max(p["legit_logins"], 1), gp["legit_login_rejection_max"], "max"),
        ("Wrong grants applied from the model's mapping", p["wrong_auto_grants"], gp["wrong_auto_grants_max"], "max"),
        ("AI-assistant actions the IdP did not allow, ratio to today", p["agent_overreach_idp"] / max(sq["agent_overreach_idp"], 1e-9), gp["agent_overreach_vs_status_quo_max"], "max"),
        ("Signatures recorded under someone else's identity", p["wrong_identity_signatures"], gp["wrong_identity_signatures_max"], "max"),
    ]
    out = [{"gate": n, "value": v, "limit": lim, "kind": k, "pass": (v <= lim) if k == "max" else (v >= lim)} for n, v, lim, k in rows]
    return {"platform": out, "platform_pass": all(r["pass"] for r in out)}


def run_split(split: str, workers: int = 3) -> dict[str, Any]:
    seeds: list[int] = config.seeds()[split]
    variant = "heldout" if split == "heldout" else "dev"
    jobs = [(s, variant) for s in seeds]
    if workers > 1:
        with ProcessPoolExecutor(max_workers=min(workers, len(jobs))) as ex:
            per_seed = list(ex.map(_seed_job, jobs))
    else:
        per_seed = [_seed_job(j) for j in jobs]
    dcfg = config.designs()
    res: dict[str, Any] = {
        "split": split,
        "seeds": seeds,
        "designs": {n: _combine([s["designs"][n] for s in per_seed]) for n in dcfg["designs"]},
        "labels": {n: d["label"] for n, d in dcfg["designs"].items()},
        "main": dcfg["main"],
        "ablations": dcfg["ablations"],
        "site": {k: (sum(s["site"][k] for s in per_seed) if isinstance(per_seed[0]["site"][k], int | float) and k != "weeks" else per_seed[0]["site"][k]) for k in per_seed[0]["site"]},
        "per_seed": [
            {"seed": s["seed"], **{n: {"over_privileged_h": s["designs"][n]["over_privileged_h"], "attack_successes": s["designs"][n]["attack_successes"]} for n in dcfg["main"]}} for s in per_seed
        ],
    }
    res["gates"] = check_gates(res, config.gates())
    return _round(res)


def write(split: str, res: dict[str, Any]) -> Path:
    REPORTS.mkdir(exist_ok=True)
    path = REPORTS / f"{split}.json"
    path.write_text(json.dumps(res, indent=1) + "\n", encoding="utf-8")
    return path


def run_heldout_once(workers: int = 3) -> dict[str, Any]:
    if LOCK.exists():
        raise HeldOutLocked(f"{LOCK} exists: the held-out customers have been run. Add new seeds under a new name and an ADR.")
    REPORTS.mkdir(exist_ok=True)
    LOCK.write_text(json.dumps({"seeds": config.seeds()["heldout"], "config_sha256": config_hash()}, indent=1) + "\n", encoding="utf-8")
    res = run_split("heldout", workers)
    write("heldout", res)
    return res
