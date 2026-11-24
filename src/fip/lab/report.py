"""Writes REPORT.md, the README results block and the console data from reports/*.json. Never edited by hand:
CI regenerates them and fails on a diff."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .. import config

ROOT = config.ROOT
START, END = "<!-- results:start -->", "<!-- results:end -->"
NAMES = {"status_quo": "Today's provisioning", "naive_build": "A first in-house build", "platform": "The identity plane"}


def _load(name: str) -> dict[str, Any] | None:
    p = config.REPORTS / f"{name}.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def num(x: float | None, d: int = 0) -> str:
    return "–" if x is None else f"{x:,.{d}f}"


def pct(x: float | None, d: int = 1) -> str:
    return "–" if x is None else f"{100 * x:.{d}f}%"


def rows(d: dict[str, Any]) -> list[tuple[str, str]]:
    return [
        ("Attacks that got in", f"{num(d['attack_successes'])} of {num(d['attack_attempts'])}"),
        ("... of them reaching another tenant", num(d["cross_tenant_successes"])),
        ("Hours from the IdP's deactivation to every access path closed, p95", num(d["leaver_h_after_idp_p95"], 2)),
        ("Person-hours with more access than the IdP gives", num(d["over_idp_h"])),
        ("Person-hours with more access than HR intends (includes the IdP's own lag)", num(d["over_privileged_h"])),
        ("Shift starts where someone could not do their job", num(d["blocked_shift_starts"])),
        ("Access tickets to plant admins", num(d["tickets"])),
        ("Admin hours to connect the customers", num(d["admin_hours_onboarding"], 1)),
        ("AI-assistant actions the person was not allowed", num(d["agent_overreach"])),
        ("... beyond what the IdP said at that moment", num(d["agent_overreach_idp"])),
        ("AI-assistant requests refused although allowed", num(d["agent_refused_allowed"])),
        ("Station records under someone else's name", num(d["wrong_identity_actions"])),
        ("Signatures under someone else's identity", num(d["wrong_identity_signatures"])),
        ("Signatures with the badge alone (no second component)", num(d["signatures_without_second_factor"])),
        ("IdP changes the service refused and lost", num(d["scim_changes_dropped"])),
        ("Legitimate logins turned away", f"{num(d['legit_login_rejections'])} of {num(d['legit_logins'])}"),
    ]


def main_table(r: dict[str, Any], names: list[str]) -> list[str]:
    out = ["| | " + " | ".join(NAMES.get(n, n) for n in names) + " |", "|---|" + "---:|" * len(names)]
    cols = [rows(r["designs"][n]) for n in names]
    for i, (label, _) in enumerate(cols[0]):
        cells = [c[i][1] for c in cols]
        if "platform" in names:
            j = names.index("platform")
            cells[j] = f"**{cells[j]}**"
        out.append(f"| {label} | " + " | ".join(cells) + " |")
    return out


def attack_table(r: dict[str, Any], names: list[str]) -> list[str]:
    kinds = list(r["designs"]["platform"]["attacks"])
    out = ["| Attack (attempts per design) | " + " | ".join(NAMES.get(n, n) for n in names) + " |", "|---|" + ":---:|" * len(names)]
    for k in kinds:
        att = r["designs"]["platform"]["attacks"][k]["attempts"]
        cells = []
        for n in names:
            s = r["designs"][n]["attacks"].get(k, {}).get("successes", 0)
            cells.append(f"**{num(s)} in**" if s else "held")
        out.append(f"| `{k}` ({num(att)}) | " + " | ".join(cells) + " |")
    return out


def ablation_table(r: dict[str, Any]) -> list[str]:
    out = [
        "| Variant | Attacks in | IdP changes lost | Person-hours over HR's intent | Wrong grants from mapping | Assistant actions not allowed | Station records under another name |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for n in ["platform", *r["ablations"]]:
        d = r["designs"][n]
        name = "**The identity plane**" if n == "platform" else r["labels"][n]
        out.append(
            f"| {name} | {num(d['attack_successes'])} | {num(d['scim_changes_dropped'])} | {num(d['over_privileged_h'])} | {num(d['wrong_auto_grants'])} | {num(d['agent_overreach'])} | {num(d['wrong_identity_actions'])} |"
        )
    return out


def gate_table(r: dict[str, Any]) -> list[str]:
    out = ["| Gate | Value | Limit | |", "|---|---:|---:|---|"]
    for g in r["gates"]["platform"]:
        out.append(f"| {g['gate']} | {g['value']:.3f} | {'≤' if g['kind'] == 'max' else '≥'} {g['limit']} | {'pass' if g['pass'] else '**fail**'} |")
    return out


def onboarding_line(r: dict[str, Any]) -> str:
    p = r["designs"]["platform"]
    return (
        f"Connecting the customers' IdPs: a model read {num(p['groups'])} group names; code accepted {num(p['groups_auto_mapped'])} as rules "
        f"({num(p['wrong_auto_grants'])} wrong) and sent the rest to a person: {num(p['admin_hours_onboarding'], 1)} admin hours, against "
        f"{num(r['designs']['naive_build']['admin_hours_onboarding'], 1)} mapping every group by hand and {num(r['designs']['status_quo']['admin_hours_onboarding'], 1)} setting roles person by person today."
    )


def readme_block(dev: dict[str, Any], held: dict[str, Any] | None) -> str:
    s = dev["site"]
    lines = [
        START,
        "",
        f"_Generated by `python -m fip.cli report` from `reports/dev.json`{' and `reports/heldout.json`' if held else ''}. Do not edit by hand._",
        "",
        f"**Development customers:** {len(dev['seeds'])} simulated sets of {s['tenants'] // len(dev['seeds'])} manufacturers, {s['plants']} plants and {num(s['people'])} people in all, "
        f"{s['weeks']} weeks each, with {num(s['hr_changes'])} HR changes (joiners, leavers, transfers, promotions, temporary assignments, contractor ends) "
        f"arriving through {', '.join(s['idps'])}. Every design meets the same people, the same changes, the same attacks and the same shop-floor days.",
        "",
    ]
    lines += main_table(dev, dev["main"])
    lines += ["", "**Known attacks, each a real message through the design's code:**", ""]
    lines += attack_table(dev, dev["main"])
    lines += ["", onboarding_line(dev), "", "**What each safeguard is worth** (one changed at a time):", ""]
    lines += ablation_table(dev)
    lines += ["", f"**Release gates, development customers:** {'all pass' if dev['gates']['platform_pass'] else 'some fail'}", ""]
    lines += gate_table(dev)
    if held:
        hs = held["site"]
        lines += [
            "",
            f"**Held-out customers, run once** ({hs['tenants'] // len(held['seeds'])} manufacturers per set including a Ping IdP that capitalises its operations, an ADFS clock 160 s off, more junk groups, more leavers, more people who skip the badge tap):",
            "",
        ]
        lines += main_table(held, held["main"])
        lines += ["", onboarding_line(held), "", f"Held-out gates: {sum(g['pass'] for g in held['gates']['platform'])} of {len(held['gates']['platform'])} pass.", ""]
        lines += gate_table(held)
    lines += ["", END]
    return "\n".join(lines)


def report_md(dev: dict[str, Any], held: dict[str, Any] | None) -> str:
    out = ["# Results", "", "Generated from `reports/*.json` by `python -m fip.cli report`.", ""]
    for title, r in (("Development customers", dev), ("Held-out customers (run once)", held)):
        if not r:
            continue
        names = r["main"] + r["ablations"]
        out += [f"## {title}: seeds {', '.join(map(str, r['seeds']))}", "", "### Every design, every metric", ""]
        keys = [k for k in r["designs"]["platform"] if k != "attacks"]
        out.append("| metric | " + " | ".join(names) + " |")
        out.append("|---|" + "---:|" * len(names))
        for k in keys:
            out.append(f"| {k} | " + " | ".join(num(r["designs"][n][k], 2) for n in names) + " |")
        out += ["", "### Attacks", ""] + attack_table(r, names) + ["", "### Gates", ""] + gate_table(r) + [""]
    return "\n".join(out) + "\n"


def write_all() -> list[Path]:
    dev = _load("dev")
    if dev is None:
        raise SystemExit("run `python -m fip.cli run dev` first")
    held = _load("heldout")
    paths = []
    p = ROOT / "REPORT.md"
    p.write_text(report_md(dev, held), encoding="utf-8")
    paths.append(p)
    readme = ROOT / "README.md"
    if readme.exists():
        text = readme.read_text(encoding="utf-8")
        if START in text and END in text:
            head, rest = text.split(START, 1)
            _, tail = rest.split(END, 1)
            readme.write_text(head + readme_block(dev, held) + tail, encoding="utf-8")
            paths.append(readme)
    data = ROOT / "web" / "public" / "data" / "report.json"
    data.parent.mkdir(parents=True, exist_ok=True)
    data.write_text(json.dumps({"dev": dev, "heldout": held}, separators=(",", ":")) + "\n", encoding="utf-8")
    paths.append(data)
    return paths
