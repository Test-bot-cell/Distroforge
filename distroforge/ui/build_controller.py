from __future__ import annotations

import os
from pathlib import Path
from typing import Protocol

from distroforge.core.build import BuildOrchestrator
from distroforge.core.command import CommandRunner
from distroforge.core.doctor import (
    apt_install_command,
    install_packages_for,
    missing_required,
    run_doctor,
)
from distroforge.core.iso_build import run_iso_build
from distroforge.core.project import Project
from distroforge.ui.jobs import GuiJob
from distroforge.ui.qt import QCheckBox, QLineEdit, QMessageBox, QProgressBar, QTimer


# See the note on BuildPageWindow: protocol attributes are invariant, so `object` is not
# a permissive annotation but an exact one, and it rejected the window that implements it.
class BuildControllerWindow(Protocol):
    build_job: GuiJob | None
    job_timer: QTimer
    progress: QProgressBar
    project: Project | None
    skip_deps_check: QCheckBox
    pkexec_check: QCheckBox
    log_file_edit: QLineEdit
    _job_step_total: int
    _job_step_done: int

    def _open_surface(self, key: str) -> None: ...

    def _require_project(self) -> bool: ...

    def _sync_project_from_ui(self) -> None: ...

    def _build_options(self): ...

    def _populate_plan_steps(self, steps) -> None: ...

    def _error(self, message: str) -> None: ...

    def _run_build(self, execute: bool) -> None: ...


class BuildController:
    def __init__(self, window: BuildControllerWindow) -> None:
        self.window = window

    def show_plan(self) -> None:
        window = self.window
        if not window._require_project():
            return
        window._sync_project_from_ui()
        assert window.project
        project = window.project
        options = window._build_options()

        def _work():
            return BuildOrchestrator(project, CommandRunner(dry_run=True), options).plan()

        def _done(steps):
            lines = [
                f"{index:02d}. {step.phase.value:18} {step.title} - {step.detail}"
                for index, step in enumerate(steps, start=1)
            ]
            window._populate_plan_steps(steps)
            window.plan_view.setPlainText("\n".join(lines))
            window._open_surface("build")

        window._run_in_worker(_work, _done, "Computing build plan…")

    def run_build(self, execute: bool) -> None:
        window = self.window
        if not window._require_project():
            return
        if window.build_job and window.build_job.running:
            window._error("A build job is already running.")
            return
        if (
            execute
            and QMessageBox.question(window, "Execute build", "Run system build commands now?")
            != QMessageBox.StandardButton.Yes
        ):
            return
        if execute and not window.skip_deps_check.isChecked():
            deps = run_doctor(CommandRunner(dry_run=True))
            missing = missing_required(deps)
            if missing:
                packages = install_packages_for(deps)
                details = "\n".join(f"- {item.binary}: {item.reason}" for item in missing)
                install = apt_install_command(packages)
                window._error(f"Missing required host tools:\n{details}\n\nInstall with:\n{install}")
                return
        os.environ["DISTROFORGE_PRIVILEGE"] = "pkexec" if window.pkexec_check.isChecked() else "sudo"
        window._sync_project_from_ui()
        assert window.project
        project = window.project
        options = window._build_options()
        # An empty field delegates to run_iso_build's per-run evidence log. An explicit
        # path remains an override, but no executing GUI build may omit its command log.
        text = window.log_file_edit.text().strip()
        log_path = Path(text) if text else None
        plan_steps = BuildOrchestrator(project, CommandRunner(dry_run=True), options).plan()
        window._populate_plan_steps(plan_steps)
        window._job_step_total = len(plan_steps)
        window._job_step_done = 0

        def target(emit) -> None:
            report = run_iso_build(
                project,
                options,
                execute=execute,
                log_path=log_path,
            )
            completed = len(report.build_steps)
            if completed:
                emit.progress(
                    completed,
                    completed,
                    "evidence",
                    "Seal ISO build evidence",
                    f"{report.status}: {report.report}",
                    1.0,
                )
            emit(f"ISO-BUILD ({report.status}): {report.report}")
            emit(f"RUN-MANIFEST: {report.run_manifest}")
            if not execute and report.status == "planned":
                emit("Dry-run complete; no ISO was produced.")
            elif not execute and report.blocked:
                emit("Dry-run blocked before command planning; no ISO was produced.")
            if report.failed or (execute and report.blocked):
                detail = (
                    report.failure.output
                    if report.failure and report.failure.output
                    else report.doctor.next_command
                )
                raise RuntimeError(
                    f"ISO build {report.status}; sealed evidence: {report.report}\n{detail}"
                )

        window.build_job = GuiJob(target)
        window.progress.setRange(0, max(window._job_step_total, 1))
        window.progress.setValue(0)
        window.progress.setFormat("0/%m")
        window.progress.setVisible(True)
        window.build_job.start()
        window.job_timer.start()
        window._open_surface("build")
