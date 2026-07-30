from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from distroforge.cli import build_parser
from distroforge.core import beginner_iso as beginner_iso_module
from distroforge.core import boot_proof as boot_proof_module
from distroforge.core import publish_drill as publish_drill_module
from distroforge.core import release_pipeline as release_pipeline_module
from distroforge.core.artifact_verification import ArtifactVerificationError
from distroforge.core.beginner_iso import run_beginner_iso_boot_proof
from distroforge.core.build import BuildOptions
from distroforge.core.project import Project
from distroforge.core.publish_drill import run_publish_drill
from distroforge.core.release_pipeline import (
    ReleasePipelineReport,
    run_release_pipeline,
)
from tests.conftest import write_valid_boot_proof, write_valid_build_evidence


def _blocked_bundle(
    bundle_dir: Path,
    *,
    build_run_id: str | None,
    boot_run_id: str | None,
) -> SimpleNamespace:
    gate = SimpleNamespace(
        build_run_id=build_run_id,
        boot_run_id=boot_run_id,
        status="blocked",
        items=[],
    )
    return SimpleNamespace(
        bundle_dir=bundle_dir,
        missing=("fixture gate blocker",),
        copied=(),
        publication_identity=None,
        gate=gate,
        status="blocked",
        blocked=True,
    )


def test_release_pipeline_propagates_explicit_build_and_boot_runs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = Project.create("PipelineRuns", tmp_path / "pipeline-runs", "26.04")
    iso = project.output_dir / "selected.iso"
    iso.write_bytes(b"selected product")
    bundle_dir = project.output_dir / "bundle"
    captured: dict[str, object] = {}

    def fake_bundle(*_args: object, **kwargs: object) -> SimpleNamespace:
        captured.update(kwargs)
        return _blocked_bundle(
            bundle_dir,
            build_run_id="build-two",
            boot_run_id="boot-two",
        )

    monkeypatch.setattr(
        release_pipeline_module,
        "create_publish_bundle",
        fake_bundle,
    )
    monkeypatch.setattr(
        release_pipeline_module,
        "select_executed_release_run",
        lambda *_args, **_kwargs: SimpleNamespace(
            run_id="build-two",
            iso_build_payload={"boot_proof": {"run_id": "boot-two"}},
        ),
    )

    report = run_release_pipeline(
        project,
        iso=iso,
        bundle_dir=bundle_dir,
        build_run_id="build-two",
        boot_run_id="boot-two",
    )

    assert captured["build_run_id"] == "build-two"
    assert captured["boot_run_id"] == "boot-two"
    assert report.build_run_id == "build-two"
    assert report.boot_run_id == "boot-two"
    assert report.status == "blocked"


def test_release_pipeline_selects_build_before_creating_boot_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = Project.create("PipelineAuto", tmp_path / "pipeline-auto", "26.04")
    iso = project.output_dir / "PipelineAuto.iso"
    iso.write_bytes(b"product")
    bundle_dir = project.output_dir / "bundle"
    boot_seen: list[str | None] = []
    bundle_seen: list[tuple[str | None, str | None]] = []

    monkeypatch.setattr(
        release_pipeline_module,
        "select_executed_release_run",
        lambda *_args, **_kwargs: SimpleNamespace(
            run_id="build-selected",
            iso_build_payload={"boot_proof": None},
        ),
    )
    monkeypatch.setattr(
        release_pipeline_module,
        "repair_beginner_iso_release_artifacts",
        lambda *_args, **_kwargs: SimpleNamespace(
            status="ready",
            repaired=(),
            skipped=(),
        ),
    )

    def fake_boot(*_args: object, **kwargs: object) -> SimpleNamespace:
        boot_seen.append(kwargs.get("build_run_id"))
        return SimpleNamespace(
            run_id="boot-created",
            status="ready",
            notes=("immutable boot proof",),
        )

    def fake_bundle(*_args: object, **kwargs: object) -> SimpleNamespace:
        bundle_seen.append(
            (
                kwargs.get("build_run_id"),
                kwargs.get("boot_run_id"),
            )
        )
        return _blocked_bundle(
            bundle_dir,
            build_run_id="build-selected",
            boot_run_id="boot-created",
        )

    monkeypatch.setattr(release_pipeline_module, "run_boot_proof_fn", fake_boot)
    monkeypatch.setattr(
        release_pipeline_module,
        "create_publish_bundle",
        fake_bundle,
    )

    report = run_release_pipeline(
        project,
        iso=iso,
        bundle_dir=bundle_dir,
        run_boot_proof=True,
    )

    assert boot_seen == ["build-selected"]
    assert bundle_seen == [("build-selected", "boot-created")]
    assert report.build_run_id == "build-selected"
    assert report.boot_run_id == "boot-created"


def test_release_pipeline_refuses_reuse_and_new_boot_in_one_verdict(
    tmp_path: Path,
) -> None:
    project = Project.create("PipelineConflict", tmp_path / "pipeline-conflict", "26.04")

    report = run_release_pipeline(
        project,
        run_boot_proof=True,
        build_run_id="build-one",
        boot_run_id="boot-existing",
    )

    assert report.status == "blocked"
    assert report.stages[0].name == "boot-proof"
    assert "cannot both reuse" in report.stages[0].detail


def test_release_pipeline_verifies_explicit_build_before_starting_vm(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = Project.create("PipelineVerify", tmp_path / "pipeline-verify", "26.04")
    iso = project.output_dir / "PipelineVerify.iso"
    iso.write_bytes(b"product")

    def reject_build(*_args: object, **_kwargs: object) -> object:
        raise ArtifactVerificationError("requested build run is absent")

    def unexpected_boot(*_args: object, **_kwargs: object) -> object:
        pytest.fail("QEMU must not start for an unverified build run")

    monkeypatch.setattr(
        release_pipeline_module,
        "select_executed_release_run",
        reject_build,
    )
    monkeypatch.setattr(
        release_pipeline_module,
        "run_boot_proof_fn",
        unexpected_boot,
    )

    report = run_release_pipeline(
        project,
        iso=iso,
        run_boot_proof=True,
        build_run_id="missing-build",
    )

    assert report.status == "blocked"
    assert report.stages[0].name == "build-run-selection"
    assert "requested build run is absent" in report.stages[0].detail
    assert report.build_run_id is None
    assert report.boot_run_id is None


def test_direct_boot_refuses_unverified_explicit_build_before_backend(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = Project.create("DirectReject", tmp_path / "direct-reject", "26.04")
    iso = project.output_dir / "DirectReject.iso"
    iso.write_bytes(b"unbound product")

    monkeypatch.setattr(
        boot_proof_module,
        "_run_iso_scan",
        lambda *_args, **_kwargs: pytest.fail(
            "boot backend must not run for an unverified build id"
        ),
    )

    report = boot_proof_module.run_boot_proof(
        project,
        BuildOptions(),
        iso=iso,
        backend="iso-scan",
        execute=True,
        build_run_id="missing-build",
    )

    assert report.status == "blocked"
    assert report.build_run_id == ""
    assert "could not be selected and verified" in " ".join(report.notes)
    assert not (project.workdir / "boot-proof-inputs").exists()


def test_boot_source_path_swap_blocks_before_backend(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = Project.create("BootSwap", tmp_path / "boot-swap", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "BootSwap.iso"
    write_valid_build_evidence(project, iso, run_id="build-selected")
    original_copy = boot_proof_module.copy_immutable_file_descriptor

    def swap_then_copy(source_fd: int, target: Path, **kwargs: Any):
        original_name = iso.with_name("selected-original.iso")
        iso.rename(original_name)
        iso.write_bytes(b"forged replacement")
        return original_copy(source_fd, target, **kwargs)

    monkeypatch.setattr(
        boot_proof_module,
        "copy_immutable_file_descriptor",
        swap_then_copy,
    )
    monkeypatch.setattr(
        boot_proof_module,
        "_run_iso_scan",
        lambda *_args, **_kwargs: pytest.fail(
            "boot backend must not run after the selected ISO path changes"
        ),
    )

    report = boot_proof_module.run_boot_proof(
        project,
        BuildOptions(),
        iso=iso,
        backend="iso-scan",
        execute=True,
        build_run_id="build-selected",
    )

    assert report.status == "blocked"
    assert report.build_run_id == ""
    assert "identity differs from the expected verdict" in " ".join(report.notes)


def test_direct_boot_reuses_embedded_run_without_creating_another(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = Project.create(
        "DirectEmbeddedBoot",
        tmp_path / "direct-embedded-boot",
        "26.04",
    )
    project.source_mode = "bootstrap"
    iso = project.output_dir / "DirectEmbeddedBoot.iso"
    write_valid_build_evidence(project, iso, run_id="build-selected")
    write_valid_boot_proof(
        project,
        iso,
        run_id="boot-embedded",
        build_run_id="build-selected",
    )
    runs_root = project.output_dir / "evidence" / "runs"
    runs_before = {path.name for path in runs_root.iterdir() if path.is_dir()}

    monkeypatch.setattr(
        boot_proof_module,
        "_run_iso_scan",
        lambda *_args, **_kwargs: pytest.fail(
            "an embedded boot run must be reused without starting a backend"
        ),
    )

    report = boot_proof_module.run_boot_proof(
        project,
        BuildOptions(),
        iso=iso,
        backend="iso-scan",
        execute=True,
        build_run_id="build-selected",
    )

    runs_after = {path.name for path in runs_root.iterdir() if path.is_dir()}
    assert report.status == "ready"
    assert report.build_run_id == "build-selected"
    assert report.run_id == "boot-embedded"
    assert report.immutable_proof == runs_root / "boot-embedded" / "boot-proof.json"
    assert "no VM was started" in " ".join(report.notes)
    assert runs_after == runs_before == {"build-selected", "boot-embedded"}
    assert not (project.workdir / "boot-proof-inputs").exists()


def test_pipeline_reuses_embedded_boot_without_starting_backend(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = Project.create("EmbeddedBoot", tmp_path / "embedded-boot", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "EmbeddedBoot.iso"
    write_valid_build_evidence(project, iso, run_id="build-selected")
    write_valid_boot_proof(
        project,
        iso,
        run_id="boot-embedded",
        build_run_id="build-selected",
    )
    bundle_dir = project.output_dir / "bundle"
    seen: list[tuple[str | None, str | None]] = []

    monkeypatch.setattr(
        release_pipeline_module,
        "run_boot_proof_fn",
        lambda *_args, **_kwargs: pytest.fail(
            "an embedded boot run must be reused without starting a backend"
        ),
    )

    def fake_bundle(*_args: object, **kwargs: object) -> SimpleNamespace:
        seen.append(
            (
                kwargs.get("build_run_id"),
                kwargs.get("boot_run_id"),
            )
        )
        return _blocked_bundle(
            bundle_dir,
            build_run_id="build-selected",
            boot_run_id="boot-embedded",
        )

    monkeypatch.setattr(
        release_pipeline_module,
        "create_publish_bundle",
        fake_bundle,
    )

    report = run_release_pipeline(
        project,
        BuildOptions(),
        iso=iso,
        output_dir=project.output_dir,
        bundle_dir=bundle_dir,
        run_boot_proof=True,
    )

    assert seen == [("build-selected", "boot-embedded")]
    assert report.build_run_id == "build-selected"
    assert report.boot_run_id == "boot-embedded"
    boot_stage = next(stage for stage in report.stages if stage.name == "boot-proof")
    assert boot_stage.status == "ready"
    assert "no VM was started" in boot_stage.detail


def test_publish_drill_reuses_explicit_boot_without_starting_another(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = Project.create("DrillRuns", tmp_path / "drill-runs", "26.04")
    iso = project.output_dir / "DrillRuns.iso"
    iso.write_bytes(b"product")
    bundle_dir = project.output_dir / "bundle"
    captured: dict[str, object] = {}

    def fake_pipeline(*_args: object, **kwargs: object) -> ReleasePipelineReport:
        captured.update(kwargs)
        return ReleasePipelineReport(
            project.root,
            bundle_dir,
            "blocked",
            (),
            build_run_id="build-two",
            boot_run_id="boot-two",
        )

    explanation = SimpleNamespace(
        status="blocked",
        markdown=bundle_dir / "RELEASE-EXPLAIN.md",
        next_commands=(),
        to_dict=lambda: {"status": "blocked"},
    )
    monkeypatch.setattr(
        publish_drill_module,
        "run_release_pipeline",
        fake_pipeline,
    )
    monkeypatch.setattr(
        publish_drill_module,
        "explain_release",
        lambda *_args, **_kwargs: explanation,
    )

    report = run_publish_drill(
        project,
        iso=iso,
        bundle_dir=bundle_dir,
        build_run_id="build-two",
        boot_run_id="boot-two",
    )

    assert captured["run_boot_proof"] is False
    assert captured["build_run_id"] == "build-two"
    assert captured["boot_run_id"] == "boot-two"
    assert report.pipeline.build_run_id == "build-two"
    assert report.pipeline.boot_run_id == "boot-two"


def test_beginner_boot_proof_propagates_build_and_new_boot_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = Project.create("BeginnerRuns", tmp_path / "beginner-runs", "26.04")
    iso = project.output_dir / "BeginnerRuns.iso"
    iso.write_bytes(b"product")
    options = BuildOptions(output_iso=iso)
    immutable = (
        project.output_dir
        / "evidence"
        / "runs"
        / "boot-created"
        / "boot-proof.json"
    )
    boot_seen: list[str | None] = []
    gate_seen: list[tuple[str | None, str | None]] = []

    def fake_boot(*_args: object, **kwargs: object) -> SimpleNamespace:
        boot_seen.append(kwargs.get("build_run_id"))
        return SimpleNamespace(
            immutable_proof=immutable,
            proof=project.output_dir / "boot-proof.json",
            run_id="boot-created",
            status="ready",
            notes=("immutable boot proof",),
        )

    def fake_gate(_service: object, *_args: object, **kwargs: object) -> SimpleNamespace:
        gate_seen.append(
            (
                kwargs.get("build_run_id"),
                kwargs.get("boot_run_id"),
            )
        )
        return SimpleNamespace(
            status="ready",
            items=[SimpleNamespace(code="boot-proof", status="ready")],
        )

    monkeypatch.setattr(beginner_iso_module, "run_boot_proof", fake_boot)
    monkeypatch.setattr(
        beginner_iso_module,
        "select_executed_release_run",
        lambda *_args, **_kwargs: SimpleNamespace(
            run_id="build-selected",
            iso_build_payload={"boot_proof": None},
        ),
    )
    monkeypatch.setattr(
        beginner_iso_module.ReleaseGateService,
        "check",
        fake_gate,
    )

    report = run_beginner_iso_boot_proof(
        project,
        options,
        build_run_id="build-selected",
    )

    assert boot_seen == ["build-selected"]
    assert gate_seen == [("build-selected", "boot-created")]
    assert report.proof == immutable
    assert report.build_run_id == "build-selected"
    assert report.boot_run_id == "boot-created"


def test_beginner_iso_parser_exposes_build_run_selection() -> None:
    args = build_parser().parse_args(
        [
            "beginner-iso",
            "/tmp/project",
            "--run-boot-proof",
            "--build-run-id",
            "build-selected",
        ]
    )

    assert args.build_run_id == "build-selected"
