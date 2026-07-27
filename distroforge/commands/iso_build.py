from __future__ import annotations

from pathlib import Path

from distroforge.core.build import BuildOptions
from distroforge.core.definition import apply_definition, load_definition
from distroforge.core.iso_build import run_iso_build
from distroforge.core.project import Project


def render_iso_build(root: Path, definition: Path | None = None, execute: bool = False, output_iso: Path | None = None, boot_proof: str = "none", json_output: bool = False) -> tuple[str, bool]:
    project = Project.load(root)
    options = apply_definition(project, load_definition(definition)) if definition else BuildOptions()
    options.output_iso = output_iso or options.output_iso
    report = run_iso_build(project, options, execute=execute, boot_proof_backend=boot_proof, definition=definition)
    rendered = report.render_json() if json_output else report.render_text()
    # Only an executing build fails. run_iso_build marks a dry run blocked too, when
    # the doctor refuses the project (core/iso_build.py:90), and a plan that reports
    # why it cannot build has answered correctly rather than failed. With --execute,
    # blocked means the ISO is missing or empty after the build ran, which is the one
    # case that used to print "blocked" in the report and still exit 0.
    #
    # "failed" is the third word and it must be here too: a build that dies inside a
    # command now returns a report instead of raising, and without this the exception
    # that used to exit 1 through a traceback would exit 0 through a tidy report.
    return rendered, (report.blocked or report.failed) and report.execute
