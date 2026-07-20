from __future__ import annotations

from pathlib import Path

from distroforge.core.definition import apply_definition, definition_from_project, write_definition
from distroforge.core.derivative_profile import DerivativeProfileService
from distroforge.core.project import Project


def list_derivative_profiles() -> str:
    lines = []
    for profile in DerivativeProfileService().list_profiles().values():
        lines.append(
            f"{profile.key:14} {profile.label} - "
            f"{profile.base_family} {profile.base_release}, {profile.installer}, {profile.hardware_channel}"
        )
    return "\n".join(lines)


def render_derivative_profile(profile: str, dockerfile: Path | None = None, json_output: bool = False) -> str:
    plan = DerivativeProfileService().plan(profile, dockerfile)
    return plan.render_json() if json_output else plan.render_text()


def export_derivative_profile(
    profile: str,
    target: Path,
    dockerfile: Path | None = None,
    json_output: bool = False,
) -> str:
    plan = DerivativeProfileService().write_definition(profile, target, dockerfile)
    return (plan.render_json() if json_output else plan.render_text()) + f"Wrote {target}\n"


def create_derivative_project(
    profile: str,
    root: Path,
    name: str | None = None,
    dockerfile: Path | None = None,
    json_output: bool = False,
) -> str:
    service = DerivativeProfileService()
    plan = service.plan(profile, dockerfile)
    project = Project.create(name or plan.profile.branding_name, root, plan.profile.base_release)
    options = apply_definition(project, plan.definition())
    project.save()
    target = project.root / f"{profile}-derivative.yaml"
    write_definition(definition_from_project(project, options, {"derivative": profile}), target)
    rendered = plan.render_json() if json_output else plan.render_text()
    return rendered + f"Created {project.root}\nWrote {target}\n"
