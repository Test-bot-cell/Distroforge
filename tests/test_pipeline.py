from __future__ import annotations

from distroforge.core.build import PIPELINE_PHASES, BuildOptions, BuildOrchestrator, BuildPhase
from distroforge.core.command import CommandRunner
from distroforge.core.project import Project


def test_pipeline_phase_registry_contains_unique_phases() -> None:
    phases = [item.phase for item in PIPELINE_PHASES]

    assert len(phases) == len(set(phases))
    assert phases[0] == BuildPhase.VALIDATE
    assert BuildPhase.REBUILD_ISO in phases
    assert phases[-1] == BuildPhase.PREVIEW


def test_build_context_marks_dry_run_as_not_execute(tmp_path) -> None:
    project = Project.create("PipeSmoke", tmp_path / "pipe-smoke", "26.04")
    project.source_mode = "bootstrap"
    orchestrator = BuildOrchestrator(project, CommandRunner(dry_run=True), BuildOptions())

    assert orchestrator.context.execute is False
