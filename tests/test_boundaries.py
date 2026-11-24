"""The invariants in AGENTS.md that code can check."""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "fip"
PLATFORM = ["authz", "protocols", "service"]


def _imports(path: Path) -> set[str]:
    mods: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module)
        elif isinstance(node, ast.Import):
            mods.update(a.name for a in node.names)
    return mods


def test_the_platform_never_imports_the_world_the_simulation_or_the_lab() -> None:
    files = [p for d in PLATFORM for p in (SRC / d).rglob("*.py")] + [SRC / "onboarding.py"]
    for p in files:
        bad = [m for m in _imports(p) if m.split(".")[0] in ("world", "sim", "lab") or ".world" in m or ".sim" in m or ".lab" in m]
        assert not bad, f"{p.relative_to(SRC)} imports {bad}"


def test_the_world_does_not_read_the_platforms_settings_or_code() -> None:
    for p in (SRC / "world").rglob("*.py"):
        text = p.read_text(encoding="utf-8")
        for needle in ("config.platform(", "config.designs(", "config.gates(", "platform.yml"):
            assert needle not in text, f"{p.name} reads {needle}"
        bad = [m for m in _imports(p) if any(x in m for x in ("authz", "onboarding", "service", "sim", "lab"))]
        assert not bad, f"{p.name} imports {bad}"


def test_no_scim_handler_takes_the_tenant_from_the_url() -> None:
    text = (SRC / "service" / "api.py").read_text(encoding="utf-8")
    assert "scim_tenant(authorization)" in text
    assert "/t/{tenant}/scim" not in text
