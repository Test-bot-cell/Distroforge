from __future__ import annotations

import os

import pytest

from distroforge.ui.qt import QApplication

# Every page/toolbar builder wires its buttons to a window._handler at
# construction time, so simply building MainWindow proves that none of those
# delegators went missing during the action-module extraction. This list is the
# explicit contract for the slots the shell must keep exposing.
WIRED_HANDLERS = [
    "_new_project",
    "_open_project",
    "_save_project",
    "_browse_iso",
    "_browse_output_iso",
    "_browse_wallpaper",
    "_apply_source_starter",
    "_use_previous_project_source",
    "_run_capture_scan",
    "_export_capture_profile",
    "_rebuild_from_capture",
    "_plan_live_build",
    "_write_live_build_plan",
    "_plan_livefs_iso",
    "_write_livefs_iso_plan",
    "_run_upgrade_preflight",
    "_plan_systemd_image",
    "_load_artifact_defaults",
    "_run_release_readiness",
    "_run_release_gate",
    "_run_evidence_status",
    "_create_publish_bundle",
    "_verify_evidence_contract",
    "_run_qemu_smoke_plan",
    "_run_packaging_policy",
    "_run_autopkgtest_doctor",
    "_run_hermetic_build_plan",
    "_render_mirrors",
    "_apply_mirrors",
    "_restore_mirrors",
    "_run_brand_preview",
    "_export_brand_identity",
    "_run_profile_diff",
    "_export_profile_definition",
    "_run_derivative_profile_plan",
    "_export_derivative_profile_definition",
    "_create_derivative_project",
    "_start_terminal",
    "_show_chroot_backend_status",
    "_send_terminal_input",
    "_poll_terminal",
    "_stop_terminal",
    "_mount_terminal_runtime",
    "_unmount_terminal_runtime",
    "_export_recipe",
    "_import_recipe",
    "_export_build_preset",
    "_import_build_preset",
    "_clear_build_preset",
    "_show_guided_recipes",
    "_review_current_plan",
    "_review_manifest_file",
    "_doctor",
    "_run_ux_audit",
    "_run_readiness",
    "_run_branding_compliance",
    "_run_debrand_scan",
    "_run_ai_review",
    "_run_forgeadvisor",
    "_explain_build",
    "_explain_risk",
    "_forgeadvisor_explain_log",
    "_forgeadvisor_doctor_ai",
    "_show_plan",
    "_filter_logs",
    "_refresh_plugins",
]


@pytest.fixture(scope="module")
def qt_app():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    return QApplication.instance() or QApplication([])


def test_main_window_builds_headless(qt_app) -> None:
    from distroforge.ui.main_window import MainWindow

    window = MainWindow()

    # The shell hosts 15 surfaces in a key-based stack reached through the surface
    # router; the journey-spine rail drives navigation hub-and-spoke.
    assert window._pages.count() == 15
    assert set(window._surfaces) == set(window._surface_labels)
    assert window.journey_spine is not None
    assert window.project is None


def test_main_window_exposes_every_wired_handler(qt_app) -> None:
    from distroforge.ui.main_window import MainWindow

    window = MainWindow()

    missing = [name for name in WIRED_HANDLERS if not callable(getattr(window, name, None))]
    assert missing == []
