from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from distroforge.core.project import Project
from distroforge.core.release_contract import (
    REQUIRED_RELEASE_GATE_CODES,
    release_gate_report_problem,
    release_manifest_problem,
)


def _ready_gate(project: Path, iso: Path) -> dict[str, object]:
    build_run_dir = iso.parent / "evidence" / "runs" / "build-run"
    boot_run_dir = iso.parent / "evidence" / "runs" / "boot-run"
    return {
        "project": str(project),
        "iso": str(iso),
        "output_dir": str(iso.parent),
        "build_run_id": "build-run",
        "boot_run_id": "boot-run",
        "immutable_iso_build": str(build_run_dir / "ISO-BUILD.json"),
        "immutable_provenance": str(
            build_run_dir / "distroforge-provenance.json"
        ),
        "immutable_boot_proof": str(boot_run_dir / "boot-proof.json"),
        "immutable_qemu_report": str(boot_run_dir / "qemu-lab-report.json"),
        "immutable_sbom": str(build_run_dir / "distroforge-sbom.spdx.json"),
        "status": "ready",
        "blocked": False,
        "items": [
            {
                "code": code,
                "status": "ready",
                "detail": f"{code} ready",
            }
            for code in sorted(REQUIRED_RELEASE_GATE_CODES)
        ],
    }


@pytest.mark.parametrize(
    ("field", "forged"),
    (
        ("project", "/project/./source"),
        ("iso", "/project/dist/../../outside.iso"),
        ("iso", "/project//dist/image.iso"),
        ("iso", "/project/dist/image.iso\n"),
        ("output_dir", "/project/dist/\x7f"),
    ),
)
def test_release_gate_rejects_lexically_noncanonical_absolute_paths(
    field: str,
    forged: str,
) -> None:
    project = Path("/project")
    iso = project / "dist" / "image.iso"
    gate = _ready_gate(project, iso)
    gate[field] = forged

    problem = release_gate_report_problem(
        gate,
        expected_project=project,
        expected_iso=iso,
        expected_output_dir=iso.parent,
    )

    assert problem is not None


@pytest.mark.parametrize(
    ("fields", "reason"),
    (
        (
            (
                "build_run_id",
                "immutable_iso_build",
                "immutable_provenance",
                "immutable_sbom",
            ),
            "non-blocked gate has no immutable selected build run",
        ),
        (
            (
                "boot_run_id",
                "immutable_boot_proof",
                "immutable_qemu_report",
            ),
            "non-blocked gate has no immutable selected boot run",
        ),
    ),
)
def test_ready_release_gate_rejects_omitted_run_selection(
    fields: tuple[str, ...],
    reason: str,
) -> None:
    project = Path("/project")
    iso = project / "dist" / "image.iso"
    gate = _ready_gate(project, iso)
    for field in fields:
        gate[field] = None

    problem = release_gate_report_problem(
        gate,
        expected_project=project,
        expected_iso=iso,
        expected_output_dir=iso.parent,
    )

    assert problem == reason


@pytest.mark.parametrize(
    "field",
    (
        "immutable_iso_build",
        "immutable_provenance",
        "immutable_boot_proof",
        "immutable_qemu_report",
        "immutable_sbom",
    ),
)
def test_release_gate_rejects_malformed_non_null_optional_path(
    field: str,
) -> None:
    project = Path("/project")
    iso = project / "dist" / "image.iso"
    gate = _ready_gate(project, iso)
    gate[field] = "relative/not-canonical"

    problem = release_gate_report_problem(
        gate,
        expected_project=project,
        expected_iso=iso,
        expected_output_dir=iso.parent,
    )

    assert problem == f"{field} is not null or one canonical absolute path"


@pytest.mark.parametrize(
    "name",
    (
        "nested/../proof.json",
        "nested//proof.json",
        "nested/./proof.json",
        "proof.json\n",
        "proof\x7f.json",
    ),
)
def test_release_manifest_rejects_noncanonical_relative_names(
    tmp_path: Path,
    name: str,
) -> None:
    bundle = tmp_path / "publish"
    manifest = {
        "generated_at": "2026-07-30T12:00:00+00:00",
        "project": "Canonical",
        "bundle_dir": str(bundle),
        "gate_status": "ready",
        "files": [
            {
                "name": name,
                "size": 1,
                "sha256": "a" * 64,
            }
        ],
    }

    assert (
        release_manifest_problem(
            deepcopy(manifest),
            expected_project_name="Canonical",
            expected_bundle_dir=bundle,
        )
        == "file entries contain an unsafe or duplicate identity"
    )


def test_project_create_and_load_anchor_a_relative_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)

    created = Project.create("Relative", Path("relative-project"), "26.04")
    loaded = Project.load(Path("relative-project"))

    expected = tmp_path / "relative-project"
    assert created.root == expected
    assert created.root.is_absolute()
    assert loaded.root == expected
    assert loaded.root.is_absolute()
