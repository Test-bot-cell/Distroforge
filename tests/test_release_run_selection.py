from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from distroforge.core.artifact_verification import (
    ArtifactVerificationError,
    ArtifactVerificationSession,
)
from distroforge.core.build import BuildOptions
from distroforge.core.project import Project
from distroforge.core.release_gate import ReleaseGateService
from distroforge.core.release_run import select_executed_release_run


def _identity(path: Path) -> dict[str, object]:
    return {
        "path": str(path),
        "size": path.stat().st_size,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _write_release_run(project: Project, iso: Path, run_id: str) -> Path:
    run_dir = project.output_dir / "evidence" / "runs" / run_id
    run_dir.mkdir(parents=True)
    iso_digest = hashlib.sha256(iso.read_bytes()).hexdigest()
    build = run_dir / "ISO-BUILD.json"
    build.write_text(
        json.dumps(
            {
                "schema": "distroforge.iso-build.v2",
                "run_id": run_id,
                "project": str(project.root),
                "status": "built",
                "execute": True,
                "output_iso": str(iso),
                "output_exists": True,
                "output_size": iso.stat().st_size,
                "output_sha256": iso_digest,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    provenance = run_dir / "distroforge-provenance.json"
    provenance.write_text(
        json.dumps(
            {
                "schema": "distroforge.provenance.v2",
                "attestation_kind": "build",
                "run_id": run_id,
                "output_iso": str(iso),
                "output_iso_sha256": iso_digest,
                "run": {"run_id": run_id, "mode": "execute"},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    manifest = run_dir / "RUN-MANIFEST.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": "distroforge.build-run-manifest.v1",
                "run_id": run_id,
                "mode": "execute",
                "status": "built",
                "files": [_identity(build), _identity(provenance), _identity(iso)],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    (run_dir / "RUN-MANIFEST.json.sha256").write_text(
        f"{digest}  RUN-MANIFEST.json\n",
        encoding="utf-8",
    )
    return run_dir


def test_release_run_auto_selection_blocks_two_matching_candidates(
    tmp_path: Path,
) -> None:
    project = Project.create("Ambiguous", tmp_path / "ambiguous", "26.04")
    iso = project.output_dir / "Ambiguous.iso"
    iso.write_bytes(b"same product")
    _write_release_run(project, iso, "run-one")
    _write_release_run(project, iso, "run-two")

    with ArtifactVerificationSession(Path("/")) as session:
        with pytest.raises(
            ArtifactVerificationError,
            match=r"multiple immutable executed build runs.*--build-run-id",
        ):
            select_executed_release_run(
                project,
                iso,
                project.output_dir,
                session,
            )


def test_release_gate_never_reports_ready_for_ambiguous_build_runs(
    tmp_path: Path,
) -> None:
    project = Project.create("AmbiguousGate", tmp_path / "gate", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "AmbiguousGate.iso"
    iso.write_bytes(b"same product")
    _write_release_run(project, iso, "run-one")
    _write_release_run(project, iso, "run-two")

    gate = ReleaseGateService().check(
        project,
        BuildOptions(),
        iso=iso,
        output_dir=project.output_dir,
    )

    assert gate.blocked
    assert gate.build_run_id is None
    provenance = next(item for item in gate.items if item.code == "provenance")
    assert provenance.status == "blocked"
    assert "--build-run-id RUN_ID" in provenance.detail


def test_release_run_explicit_selection_binds_requested_immutable_handles(
    tmp_path: Path,
) -> None:
    project = Project.create("Explicit", tmp_path / "explicit", "26.04")
    iso = project.output_dir / "Explicit.iso"
    iso.write_bytes(b"same product")
    _write_release_run(project, iso, "run-one")
    selected_dir = _write_release_run(project, iso, "run-two")

    session = ArtifactVerificationSession(Path("/"))
    selected = select_executed_release_run(
        project,
        iso,
        project.output_dir,
        session,
        build_run_id="run-two",
    )
    receipt = session.seal_with_receipt()

    assert selected.run_id == "run-two"
    assert selected.run_dir == selected_dir
    bound = receipt.by_absolute_path()
    assert selected.iso_build_path in bound
    assert selected.provenance_path in bound
    assert selected.manifest_path in bound
    assert selected.manifest_sidecar_path in bound


def test_release_run_auto_selection_ignores_stale_global_aliases(
    tmp_path: Path,
) -> None:
    project = Project.create("Aliases", tmp_path / "aliases", "26.04")
    iso = project.output_dir / "Aliases.iso"
    iso.write_bytes(b"first product")
    stale = _write_release_run(project, iso, "run-one")
    iso.write_bytes(b"second product")
    selected_dir = _write_release_run(project, iso, "run-two")
    shutil.copyfile(stale / "ISO-BUILD.json", project.output_dir / "ISO-BUILD.json")
    shutil.copyfile(
        stale / "distroforge-provenance.json",
        project.output_dir / "distroforge-provenance.json",
    )

    with ArtifactVerificationSession(Path("/")) as session:
        selected = select_executed_release_run(
            project,
            iso,
            project.output_dir,
            session,
        )

    assert selected.run_id == "run-two"
    assert selected.run_dir == selected_dir
