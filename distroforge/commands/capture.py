from __future__ import annotations

import argparse
from pathlib import Path

from distroforge.core.capture import InstalledSystemCaptureService
from distroforge.core.capture_diff import diff_capture_profile
from distroforge.core.definition import (
    apply_definition,
    definition_from_project,
    load_definition,
    write_definition,
)
from distroforge.core.project import Project


def run_capture(
    target: Path,
    output: Path | None = None,
    sanitize: str = "strict",
    include_configs: list[Path] | None = None,
    include_config_globs: list[str] | None = None,
    json_output: bool = False,
) -> str:
    profile = InstalledSystemCaptureService().capture(
        target,
        sanitize=sanitize,
        include_configs=include_configs or [],
        include_config_globs=include_config_globs or [],
    )
    rendered = profile.render_json() if json_output else profile.render_yaml()
    if not output:
        return rendered
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")
    return f"Wrote {output}\n{profile.report.render_text()}\n"


def render_capture_diff(profile: Path, json_output: bool = False) -> str:
    diff = diff_capture_profile(profile)
    return diff.render_json() if json_output else diff.render_text()


def run_rebuild_from_capture(args: argparse.Namespace) -> None:
    data = load_definition(args.profile)
    metadata = data.get("metadata", {})
    release = args.release
    name = args.name
    if isinstance(metadata, dict):
        release = release or str(metadata.get("release", "26.04"))
        name = name or str(metadata.get("name", "Captured System")).replace("Captured ", "")
    project = Project.create(name or "Captured System", args.root, release or "26.04")
    options = apply_definition(project, data)
    project.save()
    preset = project.root / "captured-profile.yaml"
    write_definition(definition_from_project(project, options, {"source": str(args.profile)}), preset)
    print(f"Created {project.root}")
    print(f"Wrote {preset}")
    print("Next: distroforge build " + str(project.root) + " --definition " + str(preset))
