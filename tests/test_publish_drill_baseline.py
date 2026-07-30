from __future__ import annotations

import json
import os
import socket
from pathlib import Path

import pytest

import distroforge.core.publish_drill_baseline as baseline_module
from distroforge.core.artifact_verification import ArtifactVerificationError
from distroforge.core.build import BuildOptions
from distroforge.core.build_journey import _release_ritual_findings
from distroforge.core.project import Project
from distroforge.core.publish_drill_baseline import (
    promote_publish_drill_baseline,
    validate_local_publish_drill_baseline,
)
from distroforge.core.publish_drill_diff import diff_publish_drills
from distroforge.core.release_verification import (
    ReleaseVerifyItem,
    ReleaseVerifyReport,
)
from tests.publish_drill_contract import (
    publish_drill_payload,
    publish_drill_text,
    stable_directory_identity,
)


def _drill_text(
    project: Project,
    bundle: Path,
    status: str = "review_required",
) -> str:
    return publish_drill_text(
        status=status,
        gate="review" if status == "review_required" else "ready",
        project=project.root,
        project_name=project.name,
        bundle_dir=bundle,
        bundle_identity=stable_directory_identity(bundle),
    )


def _project_with_bundle(tmp_path: Path) -> tuple[Project, Path]:
    project = Project.create("BaselineSafe", tmp_path / "project", "26.04")
    bundle = project.output_dir / "publish"
    bundle.mkdir()
    return project, bundle


def test_promotes_exact_verified_bytes_and_publishes_report(tmp_path: Path) -> None:
    project, bundle = _project_with_bundle(tmp_path)
    source = bundle / "PUBLISH-DRILL.json"
    source_bytes = _drill_text(project, bundle).encode("utf-8")
    source.write_bytes(source_bytes)

    report = promote_publish_drill_baseline(project)

    baseline = bundle / "PUBLISH-DRILL.previous.json"
    report_path = bundle / "PUBLISH-DRILL-BASELINE.json"
    assert report.status == "ready"
    assert report.promoted is True
    assert baseline.read_bytes() == source_bytes
    assert baseline.is_file()
    assert not baseline.is_symlink()
    written_report = json.loads(report_path.read_text(encoding="utf-8"))
    assert written_report["status"] == "ready"
    assert written_report["promoted"] is True


def test_ready_to_publish_drill_cannot_self_promote_without_external_pin(
    tmp_path: Path,
) -> None:
    project, bundle = _project_with_bundle(tmp_path)
    (bundle / "PUBLISH-DRILL.json").write_text(
        _drill_text(project, bundle, "ready_to_publish"),
        encoding="utf-8",
    )

    report = promote_publish_drill_baseline(project)

    assert report.status == "blocked"
    assert report.promoted is False
    assert "explicitly trusted complete signer fingerprint" in report.reason
    assert not (bundle / "PUBLISH-DRILL.previous.json").exists()


@pytest.mark.parametrize("terminal_failure", ("blocked", "exception"))
def test_terminal_live_verification_failure_leaves_no_ready_local_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    terminal_failure: str,
) -> None:
    project, bundle = _project_with_bundle(tmp_path)
    payload = publish_drill_payload(
        status="ready_to_publish",
        gate="ready",
        project=project.root,
        project_name=project.name,
        bundle_dir=bundle,
        bundle_identity=stable_directory_identity(bundle),
    )
    verify = payload["evidence"]["verify"]
    assert isinstance(verify, dict)
    raw_items = verify["items"]
    assert isinstance(raw_items, list)
    ready = ReleaseVerifyReport(
        project.root,
        bundle,
        "ready",
        tuple(
            ReleaseVerifyItem(
                str(item["code"]),
                str(item["status"]),
                str(item["detail"]),
            )
            for item in raw_items
            if isinstance(item, dict)
        ),
        tuple(stable_directory_identity(bundle)),
    )
    blocked = ReleaseVerifyReport(
        project.root,
        bundle,
        "blocked",
        (
            ReleaseVerifyItem(
                "artifact-session",
                "blocked",
                "terminal verification drifted",
            ),
        ),
        tuple(stable_directory_identity(bundle)),
    )
    calls = 0

    def verify_twice(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return ready
        if terminal_failure == "exception":
            raise RuntimeError("injected terminal verifier failure")
        return blocked

    monkeypatch.setattr(
        baseline_module,
        "verify_release_bundle",
        verify_twice,
    )
    (bundle / "PUBLISH-DRILL.json").write_text(
        json.dumps(payload) + "\n",
        encoding="utf-8",
    )

    report = promote_publish_drill_baseline(
        project,
        expected_signer_fingerprint="A" * 40,
    )

    assert report.status == "blocked"
    assert calls == 2
    assert report.promoted is True
    assert (bundle / "PUBLISH-DRILL.previous.json").is_file()
    assert not (bundle / "PUBLISH-DRILL-BASELINE.json").exists()
    assert (bundle / "PUBLISH-DRILL-BASELINE-REFUSAL.json").is_file()
    with pytest.raises(ArtifactVerificationError):
        validate_local_publish_drill_baseline(project)
    diff = diff_publish_drills(
        bundle / "PUBLISH-DRILL.previous.json",
        bundle / "PUBLISH-DRILL.json",
    )
    assert diff.verdict == "blocked"
    findings = _release_ritual_findings(project, BuildOptions())
    assert any("baseline is unsafe" in item for item in findings)


def test_joint_project_name_and_manifest_forgery_cannot_bypass_expected_name(
    tmp_path: Path,
) -> None:
    project, bundle = _project_with_bundle(tmp_path)
    forged_name = "ForgedProject"
    payload = publish_drill_payload(
        status="review_required",
        gate="review",
        project=project.root,
        project_name=forged_name,
        bundle_dir=bundle,
        bundle_identity=stable_directory_identity(bundle),
    )
    manifest = payload["evidence"]["manifest"]
    assert manifest["project"] == forged_name
    (bundle / "PUBLISH-DRILL.json").write_text(
        json.dumps(payload) + "\n",
        encoding="utf-8",
    )

    report = promote_publish_drill_baseline(project)

    assert report.status == "blocked"
    assert report.promoted is False
    assert "project_name differs from the expected project" in report.reason
    assert not (bundle / "PUBLISH-DRILL.previous.json").exists()


def test_missing_bundle_blocks_without_creating_it(tmp_path: Path) -> None:
    project = Project.create("NoBundle", tmp_path / "project", "26.04")
    bundle = project.output_dir / "publish"

    report = promote_publish_drill_baseline(project)

    assert report.status == "blocked"
    assert report.promoted is False
    assert not bundle.exists()


@pytest.mark.parametrize(
    ("body", "reason_fragment"),
    (
        (b"\xff", "strict UTF-8"),
        (
            b'{"status":"ready","status":"blocked"}',
            "duplicate JSON key",
        ),
        (b'["ready"]', "one JSON object"),
        (b'{"status":true}', "keys are not exact"),
    ),
)
def test_invalid_drill_content_blocks_and_leaves_no_baseline(
    tmp_path: Path,
    body: bytes,
    reason_fragment: str,
) -> None:
    project, bundle = _project_with_bundle(tmp_path)
    (bundle / "PUBLISH-DRILL.json").write_bytes(body)

    report = promote_publish_drill_baseline(project)

    assert report.status == "blocked"
    assert report.promoted is False
    assert reason_fragment in report.reason
    assert not (bundle / "PUBLISH-DRILL.previous.json").exists()
    persisted = json.loads(
        (bundle / "PUBLISH-DRILL-BASELINE-REFUSAL.json").read_text(
            encoding="utf-8"
        )
    )
    assert persisted["status"] == "blocked"


def test_oversized_drill_blocks_before_buffering(tmp_path: Path) -> None:
    project, bundle = _project_with_bundle(tmp_path)
    source = bundle / "PUBLISH-DRILL.json"
    with source.open("wb") as stream:
        stream.truncate(baseline_module._DRILL_MAX_BYTES + 1)

    report = promote_publish_drill_baseline(project)

    assert report.status == "blocked"
    assert "byte limit" in report.reason
    assert not (bundle / "PUBLISH-DRILL.previous.json").exists()


@pytest.mark.parametrize(
    ("entry_kind", "reason_fragment"),
    (
        ("symlink", "without following links"),
        ("fifo", "regular file"),
        ("directory", "regular file"),
        ("socket", "regular file"),
    ),
)
def test_special_source_entries_block_without_following_or_waiting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    entry_kind: str,
    reason_fragment: str,
) -> None:
    project, bundle = _project_with_bundle(tmp_path)
    source = bundle / "PUBLISH-DRILL.json"
    victim = tmp_path / "external-drill.json"
    victim_bytes = _drill_text(project, bundle).encode("utf-8")
    victim.write_bytes(victim_bytes)
    bound_socket: socket.socket | None = None
    if entry_kind == "symlink":
        source.symlink_to(victim)
    elif entry_kind == "fifo":
        os.mkfifo(source)
    elif entry_kind == "directory":
        source.mkdir()
    else:
        bound_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        with monkeypatch.context() as context:
            context.chdir(bundle)
            try:
                bound_socket.bind(source.name)
            except PermissionError:
                bound_socket.close()
                pytest.skip("sandbox forbids creating Unix-domain socket entries")

    try:
        report = promote_publish_drill_baseline(project)
    finally:
        if bound_socket is not None:
            bound_socket.close()

    assert report.status == "blocked"
    assert report.promoted is False
    assert reason_fragment in report.reason
    assert not (bundle / "PUBLISH-DRILL.previous.json").exists()
    assert victim.read_bytes() == victim_bytes


def test_source_path_swap_during_verdict_blocks_promotion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, bundle = _project_with_bundle(tmp_path)
    source = bundle / "PUBLISH-DRILL.json"
    held = bundle / "held-drill.json"
    source.write_text(_drill_text(project, bundle), encoding="utf-8")
    real_seal = baseline_module.ArtifactVerificationSession.seal
    swapped = False

    def seal_after_swap(
        session: baseline_module.ArtifactVerificationSession,
    ):
        nonlocal swapped
        if session.label == "publish drill baseline promotion" and not swapped:
            swapped = True
            source.rename(held)
            source.write_text(
                _drill_text(project, bundle, "ready"),
                encoding="utf-8",
            )
        return real_seal(session)

    monkeypatch.setattr(
        baseline_module.ArtifactVerificationSession,
        "seal",
        seal_after_swap,
    )

    report = promote_publish_drill_baseline(project)

    assert swapped
    assert report.status == "blocked"
    assert report.promoted is False
    assert "changed during verification" in report.reason
    assert not (bundle / "PUBLISH-DRILL.previous.json").exists()
    assert held.read_text(encoding="utf-8") == _drill_text(project, bundle)
    assert source.read_text(encoding="utf-8") == _drill_text(
        project,
        bundle,
        "ready",
    )


def test_baseline_symlink_blocks_without_touching_victim(tmp_path: Path) -> None:
    project, bundle = _project_with_bundle(tmp_path)
    (bundle / "PUBLISH-DRILL.json").write_text(
        _drill_text(project, bundle),
        encoding="utf-8",
    )
    victim = tmp_path / "baseline-victim.json"
    victim_bytes = b"keep this external baseline\n"
    victim.write_bytes(victim_bytes)
    baseline = bundle / "PUBLISH-DRILL.previous.json"
    baseline.symlink_to(victim)

    report = promote_publish_drill_baseline(project)

    assert report.status == "blocked"
    assert report.promoted is False
    assert baseline.is_symlink()
    assert victim.read_bytes() == victim_bytes
    assert not tuple(bundle.glob(".PUBLISH-DRILL.previous.json.tmp-*"))


def test_parent_swap_before_publication_blocks_without_writing_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, bundle = _project_with_bundle(tmp_path)
    (bundle / "PUBLISH-DRILL.json").write_text(
        _drill_text(project, bundle),
        encoding="utf-8",
    )
    moved_bundle = bundle.with_name("publish-held")
    marker_bytes = b"foreign directory\n"
    real_publish = baseline_module.publish_regular_text
    swapped = False

    def publish_after_parent_swap(path: Path, content: str, **kwargs):
        nonlocal swapped
        if path.name == "PUBLISH-DRILL.previous.json" and not swapped:
            swapped = True
            bundle.rename(moved_bundle)
            bundle.mkdir()
            (bundle / "victim.txt").write_bytes(marker_bytes)
        return real_publish(path, content, **kwargs)

    monkeypatch.setattr(
        baseline_module,
        "publish_regular_text",
        publish_after_parent_swap,
    )

    report = promote_publish_drill_baseline(project)

    assert swapped
    assert report.status == "blocked"
    assert report.promoted is False
    assert {entry.name for entry in bundle.iterdir()} == {"victim.txt"}
    assert (bundle / "victim.txt").read_bytes() == marker_bytes
    assert (moved_bundle / "PUBLISH-DRILL.json").is_file()


def test_unexpected_publication_error_is_converted_to_blocked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, bundle = _project_with_bundle(tmp_path)
    (bundle / "PUBLISH-DRILL.json").write_text(
        _drill_text(project, bundle),
        encoding="utf-8",
    )

    def fail_publication(path: Path, content: str, **kwargs):
        raise RuntimeError("injected publication failure")

    monkeypatch.setattr(
        baseline_module,
        "publish_regular_text",
        fail_publication,
    )

    report = promote_publish_drill_baseline(project)

    assert report.status == "blocked"
    assert report.promoted is False
    assert "injected publication failure" in report.reason
    assert not (bundle / "PUBLISH-DRILL.previous.json").exists()


def test_report_symlink_failure_returns_blocked_without_partial_baseline(
    tmp_path: Path,
) -> None:
    project, bundle = _project_with_bundle(tmp_path)
    source_bytes = _drill_text(project, bundle).encode("utf-8")
    (bundle / "PUBLISH-DRILL.json").write_bytes(source_bytes)
    victim = tmp_path / "report-victim.json"
    victim_bytes = b"keep report victim\n"
    victim.write_bytes(victim_bytes)
    report_path = bundle / "PUBLISH-DRILL-BASELINE.json"
    report_path.symlink_to(victim)

    report = promote_publish_drill_baseline(project)

    assert report.status == "blocked"
    assert report.promoted is True
    assert "report publication failed closed" in report.reason
    assert (bundle / "PUBLISH-DRILL.previous.json").read_bytes() == source_bytes
    assert report_path.is_symlink()
    assert victim.read_bytes() == victim_bytes
    assert not tuple(bundle.glob(".PUBLISH-DRILL-BASELINE.json.tmp-*"))
