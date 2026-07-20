from __future__ import annotations

import os
import queue

import pytest

from distroforge.core.build import BuildOptions, BuildOrchestrator
from distroforge.core.command import CommandRunner
from distroforge.core.project import Project
from distroforge.ui.jobs import JobEmitter, JobEvent
from distroforge.ui.qt import QApplication


@pytest.fixture(scope="module")
def qt_app():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    return QApplication.instance() or QApplication([])


def test_job_emitter_carries_fraction() -> None:
    events: queue.Queue[JobEvent] = queue.Queue()
    JobEmitter(events).progress(3, 50, "apply_packages", "Apply package plan", "detail", 0.42)
    event = events.get_nowait()
    assert event.kind == "progress"
    assert (event.current, event.total, event.phase) == (3, 50, "apply_packages")
    assert event.fraction == 0.42


class _ScriptedJob:
    def __init__(self) -> None:
        self._pending: list[JobEvent] = []
        self.running = True

    def feed(self, *events: JobEvent) -> None:
        self._pending.extend(events)

    def poll(self) -> list[JobEvent]:
        pending, self._pending = self._pending, []
        return pending


def test_poll_job_drives_bar_by_weighted_fraction(qt_app, tmp_path) -> None:
    from distroforge.ui.main_window import MainWindow

    window = MainWindow()
    project = Project.create("UiProgress", tmp_path / "p", "26.04")
    project.source_mode = "bootstrap"
    plan = BuildOrchestrator(project, CommandRunner(dry_run=True), BuildOptions()).plan()
    window._populate_plan_steps(plan)
    window._job_step_total = len(plan)
    window._job_step_done = 0

    job = _ScriptedJob()
    window.build_job = job

    # Two step-entry events: the bar tracks the weighted fraction on a fixed 0..1000
    # scale, not the raw step index (step 8 of 49 is far past 8/49 of the bar).
    job.feed(
        JobEvent(
            "progress", "d", current=1, total=len(plan),
            phase="validate", title="Validate project", fraction=0.0,
        ),
        JobEvent(
            "progress", "d", current=8, total=len(plan),
            phase="apply_packages", title="Apply package plan", fraction=0.3,
        ),
    )
    window._poll_job()
    assert window.progress.maximum() == 1000
    assert window.progress.value() == 300
    assert window._job_step_done == 8
    assert window.plan_steps_list.currentRow() == 7

    # Live sub-progress within the same step: same index, higher fraction -> the bar
    # advances but the step pointer and highlighted row do not jump.
    job.feed(
        JobEvent(
            "progress", "d", current=8, total=len(plan),
            phase="apply_packages", title="Apply package plan", fraction=0.5,
        ),
    )
    window._poll_job()
    assert window.progress.value() == 500
    assert window._job_step_done == 8
    assert window.plan_steps_list.currentRow() == 7

    # Completion snaps the bar to full.
    job.running = False
    job.feed(JobEvent("done", "Job finished."))
    window._poll_job()
    assert window.progress.value() == window.progress.maximum() == 1000
    assert window.build_job is None
