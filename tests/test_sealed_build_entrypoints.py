from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from distroforge.cli import main
from distroforge.core.beginner_iso import (
    explain_beginner_iso_failure,
    prepare_beginner_iso_path,
)
from distroforge.core.build import BuildReport
from distroforge.core.ci import CiOptions, CiService
from distroforge.core.command import CommandRunner, CommandSpec
from distroforge.core.iso_doctor import IsoDoctorReport
from distroforge.core.project import Project


def test_standard_build_cli_delegates_to_the_sealed_builder(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    project = Project.create("CliSeal", tmp_path / "cli-seal", "26.04")
    project.source_mode = "bootstrap"
    project.save()
    command_log = tmp_path / "commands.jsonl"
    command_log.write_text(
        json.dumps(
            {
                "event": "start",
                "command": "mksquashfs root filesystem.squashfs",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    captured: dict[str, object] = {}

    def sealed_builder(project, options, **kwargs):
        captured.update(kwargs)
        return SimpleNamespace(
            status="planned",
            build_steps=("prepare",),
            report=tmp_path / "ISO-BUILD.json",
            run_manifest=tmp_path / "RUN-MANIFEST.json",
            failure=None,
            command_log=command_log,
            blocked=False,
            failed=False,
        )

    monkeypatch.setattr("distroforge.commands.build.run_iso_build", sealed_builder)

    main(["build", str(project.root)])

    output = capsys.readouterr().out
    assert captured["execute"] is False
    assert "sealed build plan written; no ISO was produced" in output
    assert f"ISO-BUILD: {tmp_path / 'ISO-BUILD.json'}" in output
    assert f"RUN-MANIFEST: {tmp_path / 'RUN-MANIFEST.json'}" in output
    assert "mksquashfs root filesystem.squashfs" in output


def test_standard_execute_never_calls_a_blocked_report_complete(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    project = Project.create("CliBlocked", tmp_path / "cli-blocked", "26.04")
    captured: dict[str, object] = {}

    def blocked_builder(project, options, **kwargs):
        captured.update(kwargs)
        return SimpleNamespace(
            status="blocked",
            build_steps=(),
            report=tmp_path / "ISO-BUILD.json",
            run_manifest=tmp_path / "RUN-MANIFEST.json",
            failure=None,
            command_log=None,
            doctor=SimpleNamespace(next_command="fix source selection"),
            blocked=True,
            failed=False,
        )

    monkeypatch.setattr("distroforge.commands.build.run_iso_build", blocked_builder)

    with pytest.raises(SystemExit) as stopped:
        main(["build", str(project.root), "--execute", "--skip-deps-check"])

    streams = capsys.readouterr()
    assert stopped.value.code == 2
    assert captured["execute"] is True
    assert "build blocked; no ISO was produced" in streams.out
    assert "ISO built" not in streams.out
    assert "distroforge: error: fix source selection" in streams.err


def test_beginner_execute_writes_the_same_immutable_build_contract(
    tmp_path: Path, monkeypatch
) -> None:
    project = Project.create("BeginnerSeal", tmp_path / "beginner-seal", "26.04")
    project.source_mode = "bootstrap"
    project.save()

    def ready_doctor(project, options, *, definition=None):
        assert options.output_iso is not None
        return IsoDoctorReport(
            project.root,
            options.output_iso,
            "ready",
            (),
            "none",
        )

    class MinimalBuilder:
        def __init__(self, project, runner, options) -> None:
            self.runner = runner
            self.options = options

        def run(self) -> BuildReport:
            assert self.options.output_iso is not None
            self.options.output_iso.parent.mkdir(parents=True, exist_ok=True)
            self.options.output_iso.write_bytes(b"sealed-iso")
            self.runner.run(
                CommandSpec(
                    ("write-file", str(self.options.output_iso)),
                    description="Record synthetic ISO creation",
                )
            )
            return BuildReport()

    monkeypatch.setattr("distroforge.core.iso_build.diagnose_iso_build", ready_doctor)
    monkeypatch.setattr("distroforge.core.iso_build.BuildOrchestrator", MinimalBuilder)

    report = prepare_beginner_iso_path(project, execute=True)

    assert report.build_status == "completed"
    assert report.command_log is not None
    run_dir = report.command_log.parent
    assert run_dir.parent.name == "runs"
    assert report.build_evidence == run_dir / "ISO-BUILD.json"
    assert report.run_manifest == run_dir / "RUN-MANIFEST.json"
    assert (run_dir / "ISO-BUILD.json").is_file()
    assert (run_dir / "RUN-MANIFEST.json").is_file()
    assert (run_dir / "RUN-MANIFEST.json.sha256").is_file()
    assert (project.output_dir / "ISO-BUILD.json").read_bytes() == (
        run_dir / "ISO-BUILD.json"
    ).read_bytes()


def test_ci_execute_keeps_its_build_preview_structurally_non_executing(
    tmp_path: Path, monkeypatch
) -> None:
    project = Project.create("CiPreview", tmp_path / "ci-preview", "26.04")
    observed: list[bool] = []

    class PreviewOnlyBuilder:
        def __init__(self, project, runner, options) -> None:
            observed.append(runner.dry_run)
            self.runner = runner

        def run(self) -> BuildReport:
            self.runner.run(CommandSpec(("/bin/false",), description="must remain a plan"))
            return BuildReport()

    monkeypatch.setattr("distroforge.core.ci.BuildOrchestrator", PreviewOnlyBuilder)
    executing_ci_runner = CommandRunner(dry_run=False)

    CiService(
        project,
        executing_ci_runner,
        CiOptions(run_pytest=False, run_ruff=False, build_dry_run=True),
    ).run()

    assert observed == [True]
    assert [spec.argv for spec in executing_ci_runner.history] == [("/bin/false",)]


def test_beginner_failure_alias_cannot_read_a_log_outside_the_project(
    tmp_path: Path,
) -> None:
    project = Project.create("AliasContainment", tmp_path / "alias-containment", "26.04")
    outside = tmp_path / "outside-secret.log"
    outside.write_text("must-not-be-read", encoding="utf-8")
    project.output_dir.mkdir(parents=True, exist_ok=True)
    (project.output_dir / "ISO-BUILD.json").write_text(
        json.dumps({"command_log": str(outside)}),
        encoding="utf-8",
    )

    report = explain_beginner_iso_failure(project)

    assert report.command_log == project.root / "beginner-iso-build-commands.jsonl"
    assert "must-not-be-read" not in report.detail


def test_user_build_controllers_do_not_dispatch_an_unsealed_orchestrator() -> None:
    root = Path(__file__).resolve().parents[1]
    cli = (root / "distroforge/commands/build.py").read_text(encoding="utf-8")
    gui = (root / "distroforge/ui/build_controller.py").read_text(encoding="utf-8")
    beginner = (root / "distroforge/core/beginner_iso.py").read_text(encoding="utf-8")

    assert "run_iso_build(" in cli
    assert "orchestrator.run()" not in cli
    assert "run_iso_build(" in gui
    assert "orchestrator.run()" not in gui
    assert "run_iso_build(" in beginner
    assert "BuildOrchestrator(" not in beginner
