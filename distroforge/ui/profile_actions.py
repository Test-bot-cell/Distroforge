from __future__ import annotations

from pathlib import Path

from distroforge.core.definition import (
    apply_definition,
    definition_from_project,
    write_definition,
)
from distroforge.core.derivative_profile import DerivativeProfileService
from distroforge.core.distro_profile import DistroProfileService
from distroforge.core.project import Project
from distroforge.ui.qt import QFileDialog


def _selected_derivative_dockerfile(window) -> Path | None:
    text = window.derivative_dockerfile_edit.text().strip()
    return Path(text) if text else None


def run_profile_diff_action(window) -> None:
    if not window._require_project():
        return
    profile = window.profile_combo.currentData()
    if not profile:
        window.profile_view.setPlainText("No profile selected.")
        return
    window._sync_project_from_ui()
    assert window.project
    plan = DistroProfileService().plan(window.project, str(profile), window._build_options().branding)
    window.profile_view.setPlainText(plan.render_text())
    window._log(f"Profile diff: {profile}")
    window._open_surface("packages")


def export_profile_definition_action(window) -> None:
    if not window._require_project():
        return
    profile = window.profile_combo.currentData()
    if not profile:
        window.profile_view.setPlainText("No profile selected.")
        return
    window._sync_project_from_ui()
    assert window.project
    target = window.project.root / f"{profile}-profile.json"
    plan = DistroProfileService().write_definition(
        window.project,
        str(profile),
        target,
        window._build_options().branding,
    )
    window.profile_view.setPlainText(plan.render_text())
    window._log(f"Profile definition exported to {target}")
    window._open_surface("packages")


def run_derivative_profile_plan_action(window) -> None:
    profile = window.derivative_profile_combo.currentData()
    if not profile:
        window.profile_view.setPlainText("No derivative profile selected.")
        return
    plan = DerivativeProfileService().plan(str(profile), _selected_derivative_dockerfile(window))
    window.profile_view.setPlainText(plan.render_text())
    window._log(f"Derivative profile plan: {profile}")
    window._open_surface("packages")


def export_derivative_profile_definition_action(window) -> None:
    if not window._require_project():
        return
    profile = window.derivative_profile_combo.currentData()
    if not profile:
        window.profile_view.setPlainText("No derivative profile selected.")
        return
    assert window.project
    target = window.project.root / f"{profile}-derivative.yaml"
    plan = DerivativeProfileService().write_definition(
        str(profile),
        target,
        _selected_derivative_dockerfile(window),
    )
    window.profile_view.setPlainText(plan.render_text())
    window._log(f"Derivative profile exported to {target}")
    window._open_surface("packages")


def create_derivative_project_action(window) -> None:
    profile = window.derivative_profile_combo.currentData()
    if not profile:
        window.profile_view.setPlainText("No derivative profile selected.")
        return
    directory = QFileDialog.getExistingDirectory(window, "New derivative project parent")
    if not directory:
        return
    plan = DerivativeProfileService().plan(str(profile), _selected_derivative_dockerfile(window))
    root = Path(directory) / str(profile)
    project = Project.create(plan.profile.branding_name, root, plan.profile.base_release)
    options = apply_definition(project, plan.definition())
    project.save()
    target = project.root / f"{profile}-derivative.yaml"
    write_definition(definition_from_project(project, options, {"derivative": str(profile)}), target)
    window.project = project
    window.loaded_preset_options = options
    window.loaded_preset_path = target
    window._refresh()
    window.profile_view.setPlainText(plan.render_text() + f"\nCreated {root}\nWrote {target}")
    window._log(f"Created derivative project {root}")
    window._open_surface("packages")
