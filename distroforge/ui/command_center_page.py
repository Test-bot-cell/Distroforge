from __future__ import annotations

import os

from distroforge.core.beginner_iso import (
    explain_beginner_iso_failure,
    prepare_beginner_iso_path,
    repair_beginner_iso_release_artifacts,
    run_beginner_iso_boot_proof,
)
from distroforge.core.build import BuildOrchestrator, BuildProgress
from distroforge.core.build_journey import apply_journey_step, build_journey, check_journey_step
from distroforge.core.build_memory import BuildMemory, default_corpus_path
from distroforge.core.command import CommandRunner
from distroforge.core.command_registry import gui_parity_report
from distroforge.core.definition import (
    apply_definition,
    definition_from_project,
    load_definition,
    write_definition,
)
from distroforge.core.doctor import (
    apt_install_command,
    install_missing,
    install_packages_for,
    missing_required,
    run_doctor,
)
from distroforge.core.phase_contracts import render_phase_contracts
from distroforge.core.poweruser_iso import prepare_poweruser_iso_path
from distroforge.core.publish_bundle import create_publish_bundle
from distroforge.core.workflows import product_capability_text
from distroforge.ui.goal_hub import build_goal_hub
from distroforge.ui.jobs import GuiJob
from distroforge.ui.qt import QMessageBox, QVBoxLayout, QWidget
from distroforge.ui.widgets import button as _button
from distroforge.ui.widgets import responsive_row as _responsive_row
from distroforge.ui.widgets import section as _section

JOURNEY_TARGETS = {
    "open-source": "source",
    "open-packages": "packages",
    "open-build-release": "build",
    "open-advanced": "advanced",
    "open-virtualization-lab": "virtualization",
    "open-artifacts": "artifacts",
    "open-extensions": "extensions",
}


def build_command_center_page(window) -> QWidget:
    page = QWidget()
    layout = QVBoxLayout(page)
    layout.setContentsMargins(18, 18, 18, 18)
    actions = _responsive_row(
        _button("Refresh command map", window._refresh_command_center, "plan"),
        _button("Show build phase contracts", lambda: show_phase_contracts(window), "plan"),
        _button("Show build memory", lambda: show_build_memory(window), "plan"),
        _button("Open current step", lambda: open_current_journey_step(window), "open"),
        _button("Apply current step", lambda: apply_current_journey_step(window), "start"),
        breakpoint=720,
    )
    layout.addWidget(_section("What do you want to achieve?", build_goal_hub(window)))
    layout.addWidget(_section("Build Journey", window.journey_view), 1)
    layout.addWidget(_section("CLI / GUI Parity", actions, window.command_center_view), 1)
    return page


def command_center_text(window) -> tuple[str, str]:
    level = window.mode_combo.currentData() or "beginner"
    journey = build_journey(window.project, window._build_options(), level).render_text()
    parity = (
        gui_parity_report()
        + "\n\n" + product_capability_text()
        + "\n\nCurrent GUI -> CLI equivalent\n"
        + window._cli_equivalent()
    )
    return journey, parity


def show_phase_contracts(window) -> None:
    window.command_center_view.setPlainText(render_phase_contracts())
    window._log("Showed build phase contracts (inputs, artifacts, privileges, rollback).")


def show_build_memory(window) -> None:
    summary = BuildMemory(default_corpus_path()).summarize()
    window.command_center_view.setPlainText(summary.render_text())
    window._log(summary.citation)


def open_current_journey_step(window) -> None:
    if not window._require_project():
        return
    level = window.mode_combo.currentData() or "beginner"
    current = build_journey(window.project, window._build_options(), level).current
    if current is None:
        window._log("Build journey is complete for the selected level.")
        return
    open_journey_target(window, current.step.action_id, current.step.step_id)


def open_journey_target(window, action_id: str, step_id: str = "") -> None:
    if not window._require_project():
        return
    target = JOURNEY_TARGETS.get(action_id)
    if target is None:
        window._error(f"Unknown journey target: {action_id}")
        return
    window._focus_journey_step(target, step_id)
    window._log(f"Opened journey step: {step_id or action_id}")


def apply_current_journey_step(window) -> None:
    if not window._require_project():
        return
    level = window.mode_combo.currentData() or "beginner"
    options = window._build_options()
    current = build_journey(window.project, options, level).current
    if current is None:
        window._log("Build journey is complete for the selected level.")
        return
    apply_journey_step_id(window, current.step.step_id, options)


def prepare_beginner_iso_from_start(window) -> None:
    if not window._require_project():
        return
    report = prepare_beginner_iso_path(window.project, apply_safe_defaults=True, dry_run=True)
    window.journey_view.setPlainText(report.render_text())
    if hasattr(window, "start_journey_status_label"):
        window.start_journey_status_label.setText(f"Beginner ISO path prepared - gate {report.gate_status.upper()}")
    window._refresh()
    window._log("Prepared beginner ISO path with safe defaults and dry-run evidence.")


def prepare_poweruser_iso_from_start(window) -> None:
    if not window._require_project():
        return
    report = prepare_poweruser_iso_path(window.project, apply_safe_defaults=True, dry_run=True)
    window.journey_view.setPlainText(report.render_text())
    if hasattr(window, "start_journey_status_label"):
        window.start_journey_status_label.setText(f"Power user ISO path prepared - gate {report.gate_status.upper()}")
    window._refresh()
    window._log("Prepared power user ISO path with guarded advanced defaults.")


def execute_beginner_iso_from_start(window) -> None:
    if not window._require_project():
        return
    if window.build_job and window.build_job.running:
        window._error("A build job is already running.")
        return
    if QMessageBox.question(window, "Build beginner ISO", "Run the beginner ISO build now?") != QMessageBox.StandardButton.Yes:
        return
    if not window.skip_deps_check.isChecked():
        deps = run_doctor(CommandRunner(dry_run=True))
        missing = missing_required(deps)
        if missing:
            details = "\n".join(f"- {item.binary}: {item.reason}" for item in missing)
            install = apt_install_command(install_packages_for(deps))
            if QMessageBox.question(window, "Install missing tools", f"Missing required host tools:\n{details}\n\nInstall now?\n{install}") == QMessageBox.StandardButton.Yes:
                _install_missing_beginner_tools(window, deps)
            else:
                window._error(f"Missing required host tools:\n{details}\n\nInstall with:\n{install}")
            return
    os.environ["DISTROFORGE_PRIVILEGE"] = "pkexec" if window.pkexec_check.isChecked() else "sudo"
    window._sync_project_from_ui()
    prep = prepare_beginner_iso_path(window.project, apply_safe_defaults=True, dry_run=True)
    options = apply_definition(window.project, load_definition(prep.definition))
    plan_steps = BuildOrchestrator(window.project, CommandRunner(dry_run=True), options).plan()
    window._populate_plan_steps(plan_steps)
    window._job_step_total = len(plan_steps)
    window._job_step_done = 0

    def target(emit) -> None:
        def progress(update: BuildProgress) -> None:
            step = update.step
            emit.progress(
                update.index, update.total, step.phase.value, step.title, step.detail, update.fraction
            )

        report = prepare_beginner_iso_path(
            window.project,
            apply_safe_defaults=True,
            dry_run=True,
            execute=True,
            definition_path=prep.definition,
            dry_run_path=prep.dry_run,
            progress=progress,
            memory=BuildMemory(default_corpus_path()),
        )
        emit.journey(report.render_text())
        if report.build_status == "failed":
            emit.journey(report.render_text() + "\n\n" + explain_beginner_iso_failure(window.project, report.command_log).render_text())
        emit(f"Beginner ISO build {report.build_status}; release gate {report.gate_status}.")

    window.build_job = GuiJob(target)
    window.progress.setRange(0, max(window._job_step_total, 1))
    window.progress.setValue(0)
    window.progress.setFormat("0/%m")
    window.progress.setVisible(True)
    window.build_job.start()
    window.job_timer.start()
    window._open_surface("start")


def _install_missing_beginner_tools(window, deps) -> None:
    if window.build_job and window.build_job.running:
        window._error("A build job is already running.")
        return

    def target(emit) -> None:
        runner = CommandRunner(dry_run=False)
        install_missing(runner, deps)
        after = missing_required(run_doctor(CommandRunner(dry_run=True)))
        if after:
            emit("Host tools installation finished, but preflight still has missing required tools.")
        else:
            emit("Host tools installed. Run Build beginner ISO again.")

    window.build_job = GuiJob(target)
    window.progress.setRange(0, 0)
    window.progress.setVisible(True)
    window.build_job.start()
    window.job_timer.start()
    window._open_surface("start")


def repair_beginner_release_artifacts_from_start(window) -> None:
    if not window._require_project():
        return
    options = window._build_options()
    preset = window.project.root / "beginner-iso.yaml"
    if preset.exists():
        options = apply_definition(window.project, load_definition(preset))
    report = repair_beginner_iso_release_artifacts(window.project, options)
    window.journey_view.setPlainText(report.render_text())
    if hasattr(window, "start_journey_status_label"):
        window.start_journey_status_label.setText(f"Release artifacts repaired - gate {report.gate_status.upper()}")
    window._refresh()
    window._log(f"Repaired beginner release artifacts; release gate {report.gate_status}.")


def run_beginner_boot_proof_from_start(window) -> None:
    if not window._require_project():
        return
    options = window._build_options()
    preset = window.project.root / "beginner-iso.yaml"
    if preset.exists():
        options = apply_definition(window.project, load_definition(preset))
    report = run_beginner_iso_boot_proof(window.project, options, execute=True)
    window.journey_view.setPlainText(report.render_text())
    if hasattr(window, "start_journey_status_label"):
        window.start_journey_status_label.setText(f"Boot proof {report.status} - gate {report.gate_status.upper()}")
    window._refresh()
    window._log(f"Planned beginner boot proof; release gate {report.gate_status}.")


def create_publish_bundle_from_start(window) -> None:
    if not window._require_project():
        return
    preset = window.project.root / "beginner-iso.yaml"
    options = apply_definition(window.project, load_definition(preset)) if preset.exists() else window._build_options()
    report = create_publish_bundle(window.project, options)
    window.journey_view.setPlainText(report.render_text())
    if hasattr(window, "start_journey_status_label"):
        window.start_journey_status_label.setText(f"Publish bundle written - gate {report.status.upper()}")
    window._refresh()
    window._log(f"Created publish bundle with release gate {report.status}.")


def apply_journey_step_id(window, step_id: str, options=None) -> None:
    if not window._require_project():
        return
    level = window.mode_combo.currentData() or "beginner"
    options = options or window._build_options()
    report = apply_journey_step(window.project, options, step_id)
    lines = [report.render_text()]
    if report.changed_options:
        target = window.project.root / f"journey-{step_id}.yaml"
        write_definition(definition_from_project(window.project, options), target)
        lines.append(f"\nWrote build definition: {target}")
    text = "\n".join(lines) + "\n\n" + build_journey(window.project, options, level).render_text()
    window.journey_view.setPlainText(text)
    window._refresh()
    window._log(f"Applied journey step: {step_id}")


def check_journey_step_id(window, step_id: str, options=None) -> None:
    if not window._require_project():
        return
    options = options or window._build_options()
    report = check_journey_step(window.project, options, step_id)
    text = report.render_text()
    window.journey_view.setPlainText(text + "\n\n" + build_journey(window.project, options, window.mode_combo.currentData() or "beginner").render_text())
    if hasattr(window, "start_journey_status_label"):
        window.start_journey_status_label.setText(f"{report.title}: {report.status.upper()} - {report.findings[0] if report.findings else 'No findings'}")
    window._log(f"Checked journey step: {step_id} ({report.status})")
