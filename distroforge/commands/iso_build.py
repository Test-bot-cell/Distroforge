from __future__ import annotations

from pathlib import Path

from distroforge.core.build import BuildOptions
from distroforge.core.definition import apply_definition, load_definition
from distroforge.core.iso_build import run_iso_build
from distroforge.core.project import Project


def render_iso_build(root: Path, definition: Path | None = None, execute: bool = False, output_iso: Path | None = None, boot_proof: str = "none", json_output: bool = False) -> str:
    project = Project.load(root)
    options = apply_definition(project, load_definition(definition)) if definition else BuildOptions()
    options.output_iso = output_iso or options.output_iso
    report = run_iso_build(project, options, execute=execute, boot_proof_backend=boot_proof, definition=definition)
    return report.render_json() if json_output else report.render_text()
