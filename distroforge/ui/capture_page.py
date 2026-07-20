from __future__ import annotations

from distroforge.ui.qt import QVBoxLayout, QWidget
from distroforge.ui.widgets import button as _button
from distroforge.ui.widgets import responsive_form as _responsive_form
from distroforge.ui.widgets import responsive_row as _responsive_row
from distroforge.ui.widgets import section as _section


def build_capture_page(window) -> QWidget:
    page = QWidget()
    layout = QVBoxLayout(page)
    layout.setContentsMargins(18, 18, 18, 18)

    capture_form = _responsive_form()
    capture_form.addRow("Target root", window.capture_target_edit)
    capture_form.addRow(
        "Output YAML",
        _responsive_row(window.capture_output_edit, _button("Select", window._browse_capture_output, "save"), breakpoint=680),
    )
    capture_form.addRow("Rebuild project root", window.capture_rebuild_root_edit)
    capture_form.addRow("Sanitize", window.capture_sanitize_combo)
    capture_form.addRow("Include configs", window.capture_include_configs_edit)
    capture_form.addRow("Include config globs", window.capture_include_config_globs_edit)
    capture_actions = _responsive_row(
        _button("Scan", window._run_capture_scan, "audit"),
        _button("Export YAML", window._export_capture_profile, "save"),
        _button("Build from profile", window._rebuild_from_capture, "start"),
        breakpoint=900,
    )

    live_form = _responsive_form()
    live_form.addRow(
        "live-build output",
        _responsive_row(window.live_build_output_edit, _button("Select", window._browse_live_build_output, "open"), breakpoint=680),
    )
    live_actions = _responsive_row(
        _button("Plan live-build", window._plan_live_build, "plan"),
        _button("Write live-build config", window._write_live_build_plan, "save"),
        breakpoint=820,
    )

    livefs_iso_form = _responsive_form()
    livefs_iso_form.addRow(
        "Work dir",
        _responsive_row(window.livefs_iso_work_dir_edit, _button("Select", window._browse_livefs_work_dir, "open"), breakpoint=680),
    )
    livefs_iso_form.addRow(
        "Destination ISO",
        _responsive_row(window.livefs_iso_dest_edit, _button("Select", window._browse_livefs_dest_iso, "save"), breakpoint=680),
    )
    livefs_iso_form.addRow("Series", window.livefs_iso_series_edit)
    livefs_iso_form.addRow("Architecture", window.livefs_iso_arch_edit)
    livefs_iso_form.addRow("Mirror", window.livefs_iso_mirror_edit)
    livefs_iso_form.addRow("Components", window.livefs_iso_components_edit)
    livefs_iso_form.addRow("Project", window.livefs_iso_project_edit)
    livefs_iso_form.addRow("Volume ID", window.livefs_iso_volume_id_edit)
    livefs_iso_actions = _responsive_row(
        _button("Plan livefs ISO", window._plan_livefs_iso, "plan"),
        _button("Write livefs ISO workspace", window._write_livefs_iso_plan, "save"),
        breakpoint=820,
    )

    upgrade_form = _responsive_form()
    upgrade_form.addRow("Target root", window.upgrade_target_edit)
    upgrade_form.addRow("From release", window.upgrade_from_edit)
    upgrade_form.addRow("To release", window.upgrade_to_edit)
    upgrade_actions = _responsive_row(_button("Run preflight", window._run_upgrade_preflight, "audit"), breakpoint=720)

    image_form = _responsive_form()
    image_form.addRow("Mode", window.image_mode_combo)
    image_form.addRow(
        "Partition layout",
        _responsive_row(window.image_partition_layout_edit, _button("Select", window._browse_partition_layout, "open"), breakpoint=680),
    )
    image_form.addRow("Update strategy", window.image_update_strategy_combo)
    image_actions = _responsive_row(_button("Plan image", window._plan_systemd_image, "plan"), breakpoint=720)

    layout.addWidget(_section("Capture Installed System", capture_form, capture_actions))
    layout.addWidget(_section("Review", window.capture_view), 1)
    layout.addWidget(_section("Debian live-build", live_form, live_actions))
    layout.addWidget(_section("Ubuntu livefs ISO", livefs_iso_form, livefs_iso_actions))
    layout.addWidget(_section("Upgrade Media Preflight", upgrade_form, upgrade_actions))
    layout.addWidget(_section("OEM / systemd Image", image_form, image_actions))
    return page
