from __future__ import annotations

from typing import Protocol

from distroforge.ui.path_actions import picker
from distroforge.ui.qt import QLabel, QVBoxLayout, QWidget
from distroforge.ui.step_focus import StepFocusHeader
from distroforge.ui.widgets import button, button_group, responsive_form, responsive_row, section


class BuildPageWindow(Protocol):
    sudo_check: QWidget
    pkexec_check: QWidget
    synaptic_check: QWidget
    preview_check: QWidget
    sanitize_check: QWidget
    prune_packages_check: QWidget
    sanitize_apt_lists_check: QWidget
    sanitize_ssh_keys_check: QWidget
    release_track_combo: QWidget
    devel_suite_edit: QWidget
    backports_check: QWidget
    proposed_check: QWidget
    proposed_pin_edit: QWidget
    rolling_upgrades_check: QWidget
    rolling_full_upgrade_check: QWidget
    system_sync_check: QWidget
    system_sync_strategy_combo: QWidget
    system_sync_hold_edit: QWidget
    system_sync_fallback_check: QWidget
    system_sync_post_install_only_check: QWidget
    system_sync_post_install_tool_check: QWidget
    apt_cache_dir_edit: QWidget
    apt_proxy_edit: QWidget
    apt_cache_check: QWidget
    snapshots_check: QWidget
    auto_recovery_check: QWidget
    workflow_level_status_label: QWidget
    privilege_status_label: QWidget
    snapshot_status_label: QWidget
    plan_steps_list: QWidget
    plan_view: QWidget

    def _show_plan(self) -> None: ...

    def _run_build(self, execute: bool) -> None: ...

    def _cancel_job(self) -> None: ...

    def _build_options(self): ...

    def _log(self, message: str) -> None: ...

    def _require_project(self) -> bool: ...

    def _sync_project_from_ui(self) -> None: ...


def build_build_page(window: BuildPageWindow) -> QWidget:
    page = QWidget()
    layout = QVBoxLayout(page)
    layout.setContentsMargins(18, 18, 18, 18)
    layout.addWidget(StepFocusHeader(window, "dry-run"))
    flags = responsive_row(
        window.sudo_check,
        window.pkexec_check,
        window.synaptic_check,
        window.preview_check,
        breakpoint=900,
    )
    sanitize_flags = responsive_row(
        window.sanitize_check,
        window.prune_packages_check,
        window.sanitize_apt_lists_check,
        window.sanitize_ssh_keys_check,
        breakpoint=980,
    )
    release_form = responsive_form()
    release_form.addRow("Release track", window.release_track_combo)
    release_form.addRow("Devel suite", window.devel_suite_edit)
    release_flags = responsive_row(
        window.backports_check,
        window.proposed_check,
        QLabel("Proposed pin"),
        window.proposed_pin_edit,
        breakpoint=860,
    )
    rolling_flags = responsive_row(
        window.rolling_upgrades_check,
        window.rolling_full_upgrade_check,
        breakpoint=720,
    )
    sync_form = responsive_form()
    sync_form.addRow(window.system_sync_check)
    sync_form.addRow("Strategy", window.system_sync_strategy_combo)
    sync_form.addRow("Fallback holds", window.system_sync_hold_edit)
    sync_flags = responsive_row(
        window.system_sync_fallback_check,
        window.system_sync_post_install_only_check,
        window.system_sync_post_install_tool_check,
        breakpoint=900,
    )
    cache_form = responsive_form()
    cache_form.addRow(
        "Apt cache dir",
        responsive_row(
            window.apt_cache_dir_edit,
            picker(window, window.apt_cache_dir_edit, title="Select apt cache dir", mode="dir"),
            breakpoint=680,
        ),
    )
    cache_form.addRow("Apt proxy", window.apt_proxy_edit)
    cache_flags = responsive_row(
        window.apt_cache_check,
        window.snapshots_check,
        window.auto_recovery_check,
        breakpoint=900,
    )
    plan_actions = button_group(
        "Plan and check",
        button("Plan", window._show_plan, "plan"),
        button("ISO Toolchain", lambda: run_iso_toolchain_from_build(window), "settings"),
        button("ISO Doctor", lambda: run_iso_doctor_from_build(window), "doctor"),
        button("Plan Demo ISO", lambda: run_demo_iso_from_build(window), "image"),
    )
    run_actions = button_group(
        "Build and run",
        button("ISO Build", lambda: run_iso_build_from_build(window), "start"),
        button("Accept ISO", lambda: run_iso_accept_from_build(window), "check"),
        button("Dry-run", lambda: window._run_build(False), "dry"),
        button("Execute", lambda: window._run_build(True), "start", primary=True),
        button("Cancel", window._cancel_job, "cancel"),
    )
    runtime = QVBoxLayout()
    runtime.addWidget(flags)
    runtime.addWidget(window.workflow_level_status_label)
    runtime.addWidget(window.privilege_status_label)
    runtime.addWidget(window.snapshot_status_label)
    runtime.addWidget(sanitize_flags)
    runtime.addWidget(cache_flags)
    release = QVBoxLayout()
    release.addLayout(release_form)
    release.addWidget(release_flags)
    release.addWidget(rolling_flags)
    release.addLayout(sync_form)
    release.addWidget(sync_flags)
    release.addLayout(cache_form)
    layout.addWidget(section("Build Controls", runtime, plan_actions, run_actions))
    layout.addWidget(section("Release and Cache", release))
    plan_row = responsive_row(
        section("Build Steps", window.plan_steps_list),
        section("Plan Detail", window.plan_view),
        breakpoint=980,
    )
    layout.addWidget(plan_row, 1)
    return page


def run_iso_doctor_from_build(window: BuildPageWindow) -> None:
    if not window._require_project():
        return
    from distroforge.core.iso_doctor import diagnose_iso_build

    window._sync_project_from_ui()
    report = diagnose_iso_build(window.project, window._build_options())
    window.plan_view.setPlainText(report.render_text())
    window._log(f"ISO doctor: {report.status}")


def run_iso_toolchain_from_build(window: BuildPageWindow) -> None:
    from distroforge.core.iso_toolchain import check_iso_toolchain

    report = check_iso_toolchain()
    window.plan_view.setPlainText(report.render_text())
    window._log(f"ISO toolchain: {report.status}")


def run_iso_build_from_build(window: BuildPageWindow) -> None:
    window._log("Starting ISO build.")
    window._run_build(True)


def run_iso_accept_from_build(window: BuildPageWindow) -> None:
    if not window._require_project():
        return
    from distroforge.core.iso_acceptance import accept_iso

    window._sync_project_from_ui()
    report = accept_iso(window.project, window._build_options())
    window.plan_view.setPlainText(report.render_text())
    window._log(f"ISO acceptance: {report.status}")


def run_demo_iso_from_build(window: BuildPageWindow) -> None:
    if not window._require_project():
        return
    from distroforge.core.demo_iso import run_demo_iso

    window._sync_project_from_ui()
    report = run_demo_iso(window.project.root, execute=False)
    window.plan_view.setPlainText(report.render_text())
    window._log(f"Demo ISO: {report.status}")
