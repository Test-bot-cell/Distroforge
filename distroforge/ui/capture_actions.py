from __future__ import annotations

from pathlib import Path

from distroforge.core.capture import InstalledSystemCaptureService
from distroforge.core.definition import (
    apply_definition,
    definition_from_project,
    load_definition,
    write_definition,
)
from distroforge.core.live_build import LiveBuildPlanner
from distroforge.core.livefs_iso import LivefsIsoPlanner
from distroforge.core.project import Project
from distroforge.core.systemd_image import SystemdImagePlan
from distroforge.core.upgrade_media import UpgradeMediaPreflight
from distroforge.ui.qt import QFileDialog


def _split_values(text: str) -> list[str]:
    values: list[str] = []
    for raw_line in text.replace(",", "\n").splitlines():
        item = raw_line.strip()
        if item and not item.startswith("#"):
            values.append(item)
    return values


def _capture_include_configs(window) -> list[Path]:
    return [Path(value) for value in _split_values(window.capture_include_configs_edit.toPlainText()) if value]


def _capture_include_config_globs(window) -> list[str]:
    return _split_values(window.capture_include_config_globs_edit.toPlainText())


def _capture_output_path(window) -> Path:
    text = window.capture_output_edit.text().strip()
    if text:
        return Path(text)
    return Path.home() / "distroforge-captured-system.yaml"


def _livefs_iso_plan(window):
    profile_path = window.capture_profile_path or _capture_output_path(window)
    work_dir = Path(window.livefs_iso_work_dir_edit.text().strip() or "/tmp/distroforge-livefs-iso")
    dest = Path(window.livefs_iso_dest_edit.text().strip() or "/tmp/distroforge-livefs.iso")
    series = window.livefs_iso_series_edit.text().strip() or None
    components = _split_values(window.livefs_iso_components_edit.text())
    return LivefsIsoPlanner().plan(
        profile_path,
        work_dir,
        dest,
        series=series,
        arch=window.livefs_iso_arch_edit.text().strip() or "amd64",
        mirror=window.livefs_iso_mirror_edit.text().strip() or "http://archive.ubuntu.com/ubuntu",
        components=components or None,
        project=window.livefs_iso_project_edit.text().strip() or None,
        volume_id=window.livefs_iso_volume_id_edit.text().strip() or None,
    )


def browse_capture_output_action(window) -> None:
    path, _ = QFileDialog.getSaveFileName(
        window,
        "Select capture YAML on host",
        str(_capture_output_path(window)),
        filter="YAML files (*.yaml *.yml)",
    )
    if path:
        window.capture_output_edit.setText(path)


def browse_live_build_output_action(window) -> None:
    directory = QFileDialog.getExistingDirectory(window, "Select live-build output directory")
    if directory:
        window.live_build_output_edit.setText(directory)


def browse_livefs_work_dir_action(window) -> None:
    directory = QFileDialog.getExistingDirectory(window, "Select livefs ISO work directory")
    if directory:
        window.livefs_iso_work_dir_edit.setText(directory)


def browse_livefs_dest_iso_action(window) -> None:
    path, _ = QFileDialog.getSaveFileName(
        window,
        "Select livefs destination ISO on host",
        window.livefs_iso_dest_edit.text().strip() or "/tmp/distroforge-livefs.iso",
        filter="ISO images (*.iso)",
    )
    if path:
        window.livefs_iso_dest_edit.setText(path)


def browse_partition_layout_action(window) -> None:
    path, _ = QFileDialog.getOpenFileName(
        window,
        "Select systemd repart layout",
        filter="Repart files (*.conf);;All files (*)",
    )
    if path:
        window.image_partition_layout_edit.setText(path)


def run_capture_scan_action(window) -> None:
    profile = InstalledSystemCaptureService().capture(
        Path(window.capture_target_edit.text().strip() or "/"),
        sanitize=str(window.capture_sanitize_combo.currentData() or "strict"),
        include_configs=_capture_include_configs(window),
        include_config_globs=_capture_include_config_globs(window),
    )
    window.capture_view.setPlainText(profile.render_summary())
    window.capture_profile_path = None
    window._log("Captured installed system intent for review.")


def export_capture_profile_action(window) -> None:
    target = _capture_output_path(window)
    profile = InstalledSystemCaptureService().capture(
        Path(window.capture_target_edit.text().strip() or "/"),
        sanitize=str(window.capture_sanitize_combo.currentData() or "strict"),
        include_configs=_capture_include_configs(window),
        include_config_globs=_capture_include_config_globs(window),
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(profile.render_yaml(), encoding="utf-8")
    window.capture_profile_path = target
    window.capture_view.setPlainText(profile.render_summary() + f"\n\nWrote {target}")
    window._log(f"Exported capture profile {target}")


def rebuild_from_capture_action(window) -> None:
    profile_path = window.capture_profile_path or _capture_output_path(window)
    if not profile_path.exists():
        window._error("Export a capture profile before rebuilding from it.")
        return
    root_text = window.capture_rebuild_root_edit.text().strip()
    if not root_text:
        directory = QFileDialog.getExistingDirectory(window, "New rebuild project parent")
        if not directory:
            return
        root = Path(directory) / "captured-rebuild"
    else:
        root = Path(root_text)
    try:
        data = load_definition(profile_path)
    except Exception as exc:
        window._error(f"Failed to read capture profile: {exc}")
        return
    metadata = data.get("metadata", {}) if isinstance(data, dict) else {}
    release = "26.04"
    name = "Captured Rebuild"
    if isinstance(metadata, dict):
        release = str(metadata.get("release", release))
        name = str(metadata.get("name", name)).replace("Captured ", "")
    window.project = Project.create(name, root, release)
    options = apply_definition(window.project, data)
    window.project.save()
    preset = root / "captured-profile.yaml"
    write_definition(definition_from_project(window.project, options, {"source": str(profile_path)}), preset)
    window.loaded_preset_options = options
    window.loaded_preset_path = preset
    window._refresh()
    window.capture_view.setPlainText(f"Created rebuild project {root}\nPreset: {preset}")
    window._log(f"Created rebuild project from capture: {root}")


def plan_live_build_action(window) -> None:
    profile_path = window.capture_profile_path or _capture_output_path(window)
    output = Path(window.live_build_output_edit.text().strip() or "/tmp/distroforge-live-build")
    plan = LiveBuildPlanner().plan(profile_path, output)
    window.capture_view.setPlainText(plan.render_text())


def write_live_build_plan_action(window) -> None:
    profile_path = window.capture_profile_path or _capture_output_path(window)
    output = Path(window.live_build_output_edit.text().strip() or "/tmp/distroforge-live-build")
    planner = LiveBuildPlanner()
    plan = planner.plan(profile_path, output)
    planner.write_plan(plan)
    window.capture_view.setPlainText(plan.render_text() + f"\n\nWrote {output}")
    window._log(f"Wrote live-build plan {output}")


def plan_livefs_iso_action(window) -> None:
    plan = _livefs_iso_plan(window)
    window.capture_view.setPlainText(plan.render_text())
    window._log("Planned Ubuntu livefs ISO workflow.")


def write_livefs_iso_plan_action(window) -> None:
    planner = LivefsIsoPlanner()
    plan = _livefs_iso_plan(window)
    planner.write_plan(plan)
    window.capture_view.setPlainText(plan.render_text() + f"\n\nWrote {plan.work_dir}")
    window._log(f"Wrote livefs ISO workspace {plan.work_dir}")


def run_upgrade_preflight_action(window) -> None:
    report = UpgradeMediaPreflight().check(
        Path(window.upgrade_target_edit.text().strip() or "/"),
        window.upgrade_from_edit.text().strip() or None,
        window.upgrade_to_edit.text().strip() or None,
    )
    window.capture_view.setPlainText(report.render_text())
    window._log("Ran upgrade media preflight.")


def plan_systemd_image_action(window) -> None:
    layout = window.image_partition_layout_edit.text().strip()
    plan = SystemdImagePlan(
        mode=str(window.image_mode_combo.currentData() or "appliance"),
        partition_layout=Path(layout) if layout else None,
        update_strategy=str(window.image_update_strategy_combo.currentData() or "manual"),
    )
    window.capture_view.setPlainText(plan.render_text())
    window._log("Planned OEM/systemd image workflow.")
