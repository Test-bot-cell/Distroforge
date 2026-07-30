from __future__ import annotations

import os
from pathlib import Path

import pytest

from distroforge.core import build_journey as build_journey_module
from distroforge.core.build import BuildOptions
from distroforge.core.build_journey import _bundle_status, _release_ritual_findings
from distroforge.core.project import Project
from distroforge.core.publish_drill_baseline import (
    promote_publish_drill_baseline,
)
from tests.publish_drill_contract import (
    publish_drill_text,
    stable_directory_identity,
)


def test_bundle_status_reads_one_bounded_regular_json_object(tmp_path: Path) -> None:
    report = tmp_path / "SIGNING-REPORT.json"
    report.write_text('{"status":"signed"}\n', encoding="utf-8")

    assert _bundle_status(report) == "signed"
    assert _bundle_status(tmp_path / "missing.json") == ""


@pytest.mark.parametrize(
    "body",
    [
        b"{",
        b"[]",
        b'{"status":7}',
        b'{"status":""}',
        b'{"status":"signed"}\xff',
    ],
)
def test_bundle_status_marks_invalid_json_or_status_unsafe(
    tmp_path: Path,
    body: bytes,
) -> None:
    report = tmp_path / "VERIFY-REPORT.json"
    report.write_bytes(body)

    assert _bundle_status(report) == "unsafe"


def test_bundle_status_marks_oversize_input_unsafe(tmp_path: Path) -> None:
    report = tmp_path / "VERIFY-REPORT.json"
    report.write_bytes(
        b'{"status":"verified","padding":"'
        + b"x" * (16 * 1024 * 1024)
        + b'"}'
    )

    assert _bundle_status(report) == "unsafe"


def test_bundle_status_accepts_a_valid_report_above_one_mib(tmp_path: Path) -> None:
    report = tmp_path / "VERIFY-REPORT.json"
    report.write_text(
        '{"status":"verified","padding":"'
        + "x" * (2 * 1024 * 1024)
        + '"}\n',
        encoding="utf-8",
    )

    assert _bundle_status(report) == "verified"


def test_bundle_status_marks_disappearance_after_opening_unsafe(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report = tmp_path / "VERIFY-REPORT.json"
    report.write_text('{"status":"verified"}\n', encoding="utf-8")
    real_seal = build_journey_module.ArtifactVerificationSession.seal

    def remove_then_seal(
        session: build_journey_module.ArtifactVerificationSession,
    ) -> object:
        report.unlink()
        return real_seal(session)

    monkeypatch.setattr(
        build_journey_module.ArtifactVerificationSession,
        "seal",
        remove_then_seal,
    )

    assert _bundle_status(report) == "unsafe"


@pytest.mark.parametrize("kind", ["symlink", "fifo", "directory"])
def test_bundle_status_refuses_non_regular_input_without_blocking(
    tmp_path: Path,
    kind: str,
) -> None:
    report = tmp_path / "PUBLISH-DRILL.json"
    if kind == "symlink":
        victim = tmp_path / "victim.json"
        victim.write_text('{"status":"ready_to_publish"}\n', encoding="utf-8")
        report.symlink_to(victim)
    elif kind == "fifo":
        os.mkfifo(report)
    else:
        report.mkdir()

    assert _bundle_status(report) == "unsafe"


def test_release_ritual_reads_publish_drill_baseline_through_bounded_session(
    tmp_path: Path,
) -> None:
    project = Project.create("JourneyIo", tmp_path / "journey-io", "26.04")
    bundle = project.output_dir / "publish"
    bundle.mkdir(parents=True)
    os.mkfifo(bundle / "PUBLISH-DRILL.previous.json")

    findings = _release_ritual_findings(project, BuildOptions())

    assert any("baseline is unsafe" in item for item in findings)


def test_release_ritual_rejects_a_semantically_invalid_baseline(
    tmp_path: Path,
) -> None:
    project = Project.create("JourneyIo", tmp_path / "journey-io", "26.04")
    bundle = project.output_dir / "publish"
    bundle.mkdir(parents=True)
    (bundle / "PUBLISH-DRILL.previous.json").write_text(
        '{"status":"definitely-not-a-drill"}\n',
        encoding="utf-8",
    )

    findings = _release_ritual_findings(project, BuildOptions())

    assert any("baseline is unsafe" in item for item in findings)


def test_release_ritual_labels_receipted_baseline_as_advisory_only(
    tmp_path: Path,
) -> None:
    project = Project.create("JourneyIo", tmp_path / "journey-io", "26.04")
    bundle = project.output_dir / "publish"
    bundle.mkdir(parents=True)
    (bundle / "PUBLISH-DRILL.json").write_text(
        publish_drill_text(
            status="review_required",
            gate="review",
            project=project.root,
            project_name=project.name,
            bundle_dir=bundle,
            bundle_identity=stable_directory_identity(bundle),
        ),
        encoding="utf-8",
    )
    promoted = promote_publish_drill_baseline(project)
    assert promoted.status == "ready"

    findings = _release_ritual_findings(project, BuildOptions())

    assert any("Locally receipted comparison baseline" in item for item in findings)
    assert any("does not authenticate a prior release" in item for item in findings)
