from __future__ import annotations

from pathlib import Path

from distroforge.core.build import BuildOptions, BuildOrchestrator
from distroforge.core.command import CommandRunner
from distroforge.core.project import Project


def _files(root: Path) -> set[Path]:
    return {path.relative_to(root) for path in root.rglob("*") if path.is_file()}


def test_dry_run_build_creates_no_host_filesystem_side_effects(tmp_path) -> None:
    project = Project.create("DryRunPurity", tmp_path / "dry-run-purity", "26.04")
    project.source_mode = "bootstrap"
    before = _files(project.root)

    runner = CommandRunner(dry_run=True)
    BuildOrchestrator(project, runner, BuildOptions()).run()

    # The host-artifact writers run and record their writes in command history...
    write_targets = {spec.argv[1] for spec in runner.history if spec.argv[:1] == ("write-file",)}
    assert str(project.output_dir / "distroforge-provenance.json") in write_targets
    assert str(project.output_dir / "report.html") in write_targets

    # ...but planning a build mutates nothing on the host filesystem.
    assert _files(project.root) == before
    assert not (project.output_dir / "distroforge-provenance.json").exists()
    assert not (project.output_dir / "report.html").exists()
