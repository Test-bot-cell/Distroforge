from __future__ import annotations

from pathlib import Path

from distroforge.core.build import BuildOptions
from distroforge.core.definition import apply_definition, load_definition
from distroforge.core.iso_doctor import diagnose_iso_build
from distroforge.core.project import Project


def render_iso_doctor(root: Path, definition: Path | None = None, json_output: bool = False) -> str:
    project = Project.load(root)
    options = apply_definition(project, load_definition(definition)) if definition else BuildOptions()
    report = diagnose_iso_build(project, options, definition=definition)
    return report.render_json() if json_output else report.render_text()
