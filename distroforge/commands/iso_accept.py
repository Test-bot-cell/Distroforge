from __future__ import annotations

from pathlib import Path

from distroforge.core.build import BuildOptions
from distroforge.core.definition import apply_definition, load_definition
from distroforge.core.iso_acceptance import accept_iso
from distroforge.core.project import Project


def render_iso_accept(root: Path, definition: Path | None = None, iso: Path | None = None, output_dir: Path | None = None, json_output: bool = False) -> tuple[str, bool]:
    project = Project.load(root)
    options = apply_definition(project, load_definition(definition)) if definition else BuildOptions()
    report = accept_iso(project, options, iso=iso, output_dir=output_dir)
    return report.render_json() if json_output else report.render_text(), report.blocked
