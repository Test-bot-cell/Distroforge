from __future__ import annotations

from pathlib import Path

from distroforge.core.demo_iso import run_demo_iso


def render_demo_iso(root: Path, name: str | None = None, release: str = "26.04", execute: bool = False, json_output: bool = False) -> tuple[str, bool]:
    report = run_demo_iso(root, name=name, release=release, execute=execute)
    return report.render_json() if json_output else report.render_text(), report.blocked
