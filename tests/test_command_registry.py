from __future__ import annotations

import argparse
from pathlib import Path

from distroforge.cli import build_parser
from distroforge.core.command_registry import (
    CLI_GUI_COMMANDS,
    command_names,
    commands_requiring_progress,
    gui_parity_report,
)


def _parser_command_names(parser: argparse.ArgumentParser) -> set[str]:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return set(action.choices)
    return set()


def test_all_known_cli_commands_have_gui_mapping() -> None:
    assert set(command_names()) == _parser_command_names(build_parser())
    assert all(command.gui_surface for command in CLI_GUI_COMMANDS)


def test_long_running_gui_commands_require_progress() -> None:
    progress = set(commands_requiring_progress())

    assert {"build", "validate", "ci", "doctor", "ux-audit"}.issubset(progress)


def test_gui_parity_report_is_human_readable() -> None:
    report = gui_parity_report()

    assert "CLI command -> GUI surface" in report
    assert "build" in report
    assert "progressbar" in report


def test_iso_doctor_is_visible_in_build_gui() -> None:
    build_page = Path("distroforge/ui/build_page.py").read_text(encoding="utf-8")

    assert "ISO Toolchain" in build_page
    assert "ISO Doctor" in build_page
    assert "ISO Build" in build_page
    assert "Accept ISO" in build_page
    assert "Plan Demo ISO" in build_page
    assert "run_iso_toolchain_from_build" in build_page
    assert "run_iso_doctor_from_build" in build_page
    assert "run_iso_build_from_build" in build_page
    assert "run_iso_accept_from_build" in build_page
    assert "run_demo_iso_from_build" in build_page


def test_qemu_virtualization_lab_is_visible_in_gui() -> None:
    source = Path("distroforge/ui/main_window.py").read_text(encoding="utf-8")
    page = Path("distroforge/ui/virtualization_page.py").read_text(encoding="utf-8")
    window_widgets = Path("distroforge/ui/window_widgets.py").read_text(encoding="utf-8")

    assert "Virtualization Lab" in source
    assert "QEMU Virtualization" in page
    assert "prebuild_vm_check" in source
    assert "qemu_screenshot_check" in window_widgets


def test_artifacts_and_derivative_workflows_are_visible_in_gui() -> None:
    source = Path("distroforge/ui/main_window.py").read_text(encoding="utf-8")
    artifacts = Path("distroforge/ui/artifacts_page.py").read_text(encoding="utf-8")
    packages = Path("distroforge/ui/packages_page.py").read_text(encoding="utf-8")
    window_widgets = Path("distroforge/ui/window_widgets.py").read_text(encoding="utf-8")

    assert "Artifacts" in source
    assert "_artifacts_page" in source
    assert "Release Readiness" in artifacts
    assert "Release Gate" in artifacts
    assert "Publish Bundle" in artifacts
    assert "Plan Sign Release" in artifacts
    assert "Release Notes" in artifacts
    assert "Verify Release" in artifacts
    assert "Explain Release" in artifacts
    assert "Publish Drill" in artifacts
    assert "Promote Drill" in artifacts
    assert "Compare Drill" in artifacts
    assert "Release Pipeline" in artifacts
    assert "Boot Proof" in artifacts
    assert "Boot proof backend" in artifacts
    assert "boot_proof_backend_combo" in window_widgets
    assert "QEMU Smoke Plan" in artifacts
    assert "Packaging Policy" in artifacts
    assert "Autopkgtest Doctor" in artifacts
    assert "_run_autopkgtest_doctor" in source
    assert "Hermetic Build" in artifacts
    assert "Verify Evidence" in artifacts
    assert "render_artifacts_command" in Path("distroforge/commands/artifacts.py").read_text(encoding="utf-8")
    assert "render_evidence_command" in Path("distroforge/commands/evidence.py").read_text(encoding="utf-8")
    assert "Create Derivative Project" in packages
    assert "_browse_derivative_dockerfile" in source


def test_build_phases_are_visible_in_command_center_gui() -> None:
    page = Path("distroforge/ui/command_center_page.py").read_text(encoding="utf-8")

    assert "Show build phase contracts" in page
    assert "show_phase_contracts" in page
    assert "render_phase_contracts" in page


def test_forgeadvisor_is_visible_in_maintainer_gui() -> None:
    source = Path("distroforge/ui/main_window.py").read_text(encoding="utf-8")
    page = Path("distroforge/ui/maintainer_page.py").read_text(encoding="utf-8")

    assert "ForgeAdvisor" in page
    assert "Evidence Status" in page
    assert "Verbose Evidence" in page
    assert "Evidence Fix Plan" in page
    assert "Verify Evidence" in page
    assert "FA: evidence" in page
    assert "FA: fix plan" in page
    assert "Maintainer Copilot" in page
    assert "FA: triage log" in page
    assert "FA: review def" in page
    assert "FA: search local" in page
    assert "_run_forgeadvisor" in source
    assert "_run_evidence_status" in source
    assert "_run_evidence_status_verbose" in source
    assert "_run_evidence_fix_plan" in source
    assert "_forgeadvisor_explain_evidence" in source
    assert "_forgeadvisor_fix_plan" in source
    assert "_forgeadvisor_copilot" in source
    assert "_forgeadvisor_triage_log" in source
    assert "_forgeadvisor_review_definition" in source
    assert "_forgeadvisor_search_local" in source


def test_gui_uses_sudo_by_default_and_keeps_pkexec_opt_in() -> None:
    window_widgets = Path("distroforge/ui/window_widgets.py").read_text(encoding="utf-8")
    guidance = Path("distroforge/ui/build_guidance.py").read_text(encoding="utf-8")

    assert 'QCheckBox("Use sudo for system operations")' in window_widgets
    assert 'QCheckBox("Use pkexec for GUI privilege prompts (advanced)")' in window_widgets
    assert "window.pkexec_check.setChecked(False)" in window_widgets
    assert "Rootfs and ISO writes use sudo with askpass when needed" in guidance


def test_recent_pages_are_split_out_of_main_window() -> None:
    for path in (
        "distroforge/ui/packages_page.py",
        "distroforge/ui/capture_page.py",
        "distroforge/ui/artifacts_page.py",
        "distroforge/commands/capture.py",
        "distroforge/commands/livefs.py",
        "distroforge/commands/derivative.py",
        "distroforge/commands/artifacts.py",
    ):
        assert Path(path).exists()
