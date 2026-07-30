from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from distroforge.cli import build_parser
from distroforge.core.artifact_paths import default_output_iso
from distroforge.core.build import BuildOptions
from distroforge.core.project import Project
from distroforge.core.publish_bundle import create_publish_bundle
from distroforge.core.release_gate import ReleaseGateService
from tests.conftest import (
    package_fixture_options,
    write_valid_boot_proof,
    write_valid_build_evidence,
)


def _identity(path: Path) -> dict[str, object]:
    return {
        "path": str(path),
        "size": path.stat().st_size,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _rewrite_build_manifest(
    run_dir: Path,
    *artifacts: Path,
) -> None:
    manifest = run_dir / "RUN-MANIFEST.json"
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    files = payload.get("files")
    assert isinstance(files, list)
    replacements = {str(path): _identity(path) for path in artifacts}
    seen: set[str] = set()
    for index, item in enumerate(files):
        if not isinstance(item, dict):
            continue
        path = item.get("path")
        if isinstance(path, str) and path in replacements:
            files[index] = replacements[path]
            seen.add(path)
    files.extend(replacements[path] for path in sorted(set(replacements) - seen))
    manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    (run_dir / "RUN-MANIFEST.json.sha256").write_text(
        f"{digest}  RUN-MANIFEST.json\n",
        encoding="utf-8",
    )


def _fixture_project(tmp_path: Path, name: str = "BootAuthority") -> tuple[Project, Path]:
    project = Project.create(name, tmp_path / name.lower(), "26.04")
    project.source_mode = "bootstrap"
    iso = default_output_iso(project)
    iso.write_bytes(b"immutable release product")
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    return project, iso


@pytest.mark.parametrize("mutation", ("absent", "forged", "fifo"))
def test_release_gate_ignores_boot_and_qemu_aliases(
    mutation: str,
    tmp_path: Path,
) -> None:
    project, iso = _fixture_project(tmp_path, f"Alias{mutation.title()}")
    aliases = (
        project.output_dir / "boot-proof.json",
        project.output_dir / "qemu-lab-report.json",
    )
    for alias in aliases:
        alias.unlink()
        if mutation == "forged":
            alias.write_text('{"run_id":"forged-alias"}\n', encoding="utf-8")
        elif mutation == "fifo":
            os.mkfifo(alias)

    report = ReleaseGateService().check(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
        capture_artifact_receipt=True,
    )

    boot = next(item for item in report.items if item.code == "boot-proof")
    assert boot.status == "ready"
    assert report.build_run_id == "build-run"
    assert report.boot_run_id == "proof-run"
    assert report.immutable_boot_proof == (
        project.output_dir / "evidence" / "runs" / "proof-run" / "boot-proof.json"
    )
    assert report.immutable_qemu_report == (
        project.output_dir / "evidence" / "runs" / "proof-run" / "qemu-lab-report.json"
    )
    assert report.artifact_receipt is not None
    consumed = {item.absolute_path for item in report.artifact_receipt.files}
    assert not consumed.intersection(aliases)


def test_embedded_boot_run_wins_and_incompatible_override_blocks(
    tmp_path: Path,
) -> None:
    project, iso = _fixture_project(tmp_path)

    report = ReleaseGateService().check(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
        boot_run_id="different-proof-run",
    )

    boot = next(item for item in report.items if item.code == "boot-proof")
    assert boot.status == "blocked"
    assert "conflicts with the run embedded" in boot.detail
    assert report.build_run_id == "build-run"
    assert report.boot_run_id is None


def test_standalone_boot_run_requires_explicit_selection(
    tmp_path: Path,
) -> None:
    project, iso = _fixture_project(tmp_path, "Standalone")
    run_dir = project.output_dir / "evidence" / "runs" / "build-run"
    build_report = run_dir / "ISO-BUILD.json"
    payload = json.loads(build_report.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    payload["boot_proof"] = None
    build_report.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    _rewrite_build_manifest(run_dir, build_report)

    implicit = ReleaseGateService().check(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
    )
    explicit = ReleaseGateService().check(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
        boot_run_id="proof-run",
    )

    implicit_boot = next(item for item in implicit.items if item.code == "boot-proof")
    explicit_boot = next(item for item in explicit.items if item.code == "boot-proof")
    assert implicit_boot.status == "blocked"
    assert "--boot-run-id RUN_ID" in implicit_boot.detail
    assert explicit_boot.status == "ready"
    assert explicit.boot_run_id == "proof-run"


def test_second_build_selects_only_its_embedded_second_boot_run(
    tmp_path: Path,
) -> None:
    project, iso = _fixture_project(tmp_path, "TwoRuns")
    iso.write_bytes(b"second immutable release product")
    write_valid_build_evidence(project, iso, run_id="run-two")
    write_valid_boot_proof(
        project,
        iso,
        run_id="proof-two",
        build_run_id="run-two",
    )

    report = ReleaseGateService().check(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
        capture_artifact_receipt=True,
        build_run_id="run-two",
    )

    boot = next(item for item in report.items if item.code == "boot-proof")
    assert boot.status == "ready"
    assert report.build_run_id == "run-two"
    assert report.boot_run_id == "proof-two"
    assert report.immutable_iso_build == (
        project.output_dir / "evidence" / "runs" / "run-two" / "ISO-BUILD.json"
    )
    assert report.immutable_boot_proof == (
        project.output_dir / "evidence" / "runs" / "proof-two" / "boot-proof.json"
    )
    serialized = report.to_dict()
    assert serialized["build_run_id"] == "run-two"
    assert serialized["boot_run_id"] == "proof-two"
    assert serialized["immutable_qemu_report"] == str(
        project.output_dir / "evidence" / "runs" / "proof-two" / "qemu-lab-report.json"
    )


def test_publish_bundle_copies_only_gate_selected_immutable_boot_sources(
    tmp_path: Path,
) -> None:
    project, iso = _fixture_project(tmp_path, "BundleAuthority")
    boot_alias = project.output_dir / "boot-proof.json"
    qemu_alias = project.output_dir / "qemu-lab-report.json"
    boot_alias.write_text('{"forged":"boot alias"}\n', encoding="utf-8")
    qemu_alias.write_text('{"forged":"qemu alias"}\n', encoding="utf-8")
    bundle = tmp_path / "bundle"

    report = create_publish_bundle(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
        bundle_dir=bundle,
    )

    immutable_run = project.output_dir / "evidence" / "runs" / "proof-run"
    assert report.published, report.missing
    assert (bundle / "boot-proof.json").read_bytes() == (
        immutable_run / "boot-proof.json"
    ).read_bytes()
    assert (bundle / "qemu-lab-report.json").read_bytes() == (
        immutable_run / "qemu-lab-report.json"
    ).read_bytes()
    assert report.gate.artifact_receipt is not None
    consumed = {item.absolute_path for item in report.gate.artifact_receipt.files}
    assert boot_alias not in consumed
    assert qemu_alias not in consumed


def test_immutable_sbom_is_selected_from_build_provenance_not_alias(
    tmp_path: Path,
) -> None:
    project, iso = _fixture_project(tmp_path, "SbomAuthority")
    run_dir = project.output_dir / "evidence" / "runs" / "build-run"
    provenance = run_dir / "distroforge-provenance.json"
    provenance_payload = json.loads(provenance.read_text(encoding="utf-8"))
    assert isinstance(provenance_payload, dict)
    provenance_payload["sbom_format"] = "spdx"
    provenance.write_text(
        json.dumps(provenance_payload, indent=2) + "\n",
        encoding="utf-8",
    )
    immutable_sbom = run_dir / "distroforge-sbom.spdx.json"
    immutable_sbom.write_text(
        '{"spdxVersion":"SPDX-2.3","name":"immutable"}\n',
        encoding="utf-8",
    )
    _rewrite_build_manifest(run_dir, provenance, immutable_sbom)
    alias = project.output_dir / immutable_sbom.name
    alias.write_text('{"name":"forged alias"}\n', encoding="utf-8")
    options: BuildOptions = package_fixture_options()
    options.provenance.sbom_format = "cyclonedx"
    bundle = tmp_path / "sbom-bundle"

    report = create_publish_bundle(
        project,
        options,
        iso=iso,
        output_dir=project.output_dir,
        bundle_dir=bundle,
    )

    sbom = next(item for item in report.gate.items if item.code == "sbom")
    assert sbom.status == "ready"
    assert report.gate.immutable_sbom == immutable_sbom
    assert report.published, report.missing
    assert (bundle / immutable_sbom.name).read_bytes() == immutable_sbom.read_bytes()
    assert (bundle / immutable_sbom.name).read_bytes() != alias.read_bytes()
    assert report.gate.artifact_receipt is not None
    assert alias not in {item.absolute_path for item in report.gate.artifact_receipt.files}


@pytest.mark.parametrize(
    "command",
    ("release-gate", "publish-bundle", "release-pipeline", "publish-drill"),
)
def test_release_cli_parsers_expose_build_and_boot_run_selection(
    command: str,
    tmp_path: Path,
) -> None:
    parsed = build_parser().parse_args(
        [
            command,
            str(tmp_path),
            "--build-run-id",
            "build-selected",
            "--boot-run-id",
            "boot-selected",
        ]
    )

    assert parsed.build_run_id == "build-selected"
    assert parsed.boot_run_id == "boot-selected"


def test_boot_proof_cli_parser_exposes_build_run_binding(tmp_path: Path) -> None:
    parsed = build_parser().parse_args(
        [
            "boot-proof",
            str(tmp_path),
            "--build-run-id",
            "build-selected",
        ]
    )

    assert parsed.build_run_id == "build-selected"
