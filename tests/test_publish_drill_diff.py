from __future__ import annotations

import json
import os
import socket
from pathlib import Path

import pytest

import distroforge.core.publish_drill_baseline as baseline_module
import distroforge.core.publish_drill_diff as diff_module
from distroforge.core.project import Project
from distroforge.core.publish_drill_baseline import (
    promote_publish_drill_baseline,
    validate_local_publish_drill_baseline,
)
from distroforge.core.publish_drill_diff import diff_publish_drills
from tests.publish_drill_contract import (
    publish_drill_text,
    stable_directory_identity,
)


def _drill_text(
    *,
    status: str = "ready_to_publish",
    gate: str = "ready",
    boot: str = "runtime",
    blockers: tuple[str, ...] = (),
    sha256: str = "abc",
) -> str:
    return publish_drill_text(
        status=status,
        gate=gate,
        boot=boot,
        blockers=blockers,
        sha256=sha256,
    )


def _promoted_local_baseline(
    tmp_path: Path,
) -> tuple[Path, Path, Path]:
    project = Project.create("DiffBaseline", tmp_path / "project", "26.04")
    bundle = project.output_dir / "publish"
    bundle.mkdir()
    current = bundle / "PUBLISH-DRILL.json"
    current.write_text(
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
    return bundle, bundle / "PUBLISH-DRILL.previous.json", current


def test_diff_reports_regression_from_verified_drills(tmp_path: Path) -> None:
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    old.write_text(_drill_text(), encoding="utf-8")
    new.write_text(
        _drill_text(
            status="blocked",
            gate="blocked",
            boot="structural",
            blockers=("boot-proof: downgraded",),
            sha256="def",
        ),
        encoding="utf-8",
    )
    entries_before = {entry.name for entry in tmp_path.iterdir()}

    report = diff_publish_drills(old, new)

    assert report.verdict == "regressed"
    assert report.manifest_changed == ("DistroForge.iso",)
    assert any("boot proof regressed" in reason for reason in report.reasons)
    assert any("new blocker" in reason for reason in report.reasons)
    assert {entry.name for entry in tmp_path.iterdir()} == entries_before


def test_canonical_local_baseline_diff_is_explicitly_structural_only(
    tmp_path: Path,
) -> None:
    _bundle, baseline, current = _promoted_local_baseline(tmp_path)

    report = diff_publish_drills(baseline, current)

    assert report.verdict == "unchanged"
    assert report.assurance == "structural-only"
    assert report.to_dict()["assurance"] == "structural-only"
    assert "Assurance: STRUCTURAL-ONLY" in report.render_text()


def test_canonical_local_baseline_without_ready_receipt_is_blocked(
    tmp_path: Path,
) -> None:
    bundle, baseline, current = _promoted_local_baseline(tmp_path)
    (bundle / "PUBLISH-DRILL-BASELINE.json").unlink()

    report = diff_publish_drills(baseline, current)

    assert report.verdict == "blocked"
    assert any("baseline receipt" in reason for reason in report.reasons)


def test_baseline_hardlink_alias_inside_bundle_cannot_bypass_canonical_paths(
    tmp_path: Path,
) -> None:
    bundle, baseline, current = _promoted_local_baseline(tmp_path)
    (bundle / "PUBLISH-DRILL-BASELINE.json").unlink()
    alias = bundle / "old.json"
    os.link(baseline, alias)

    report = diff_publish_drills(alias, current)

    assert report.verdict == "blocked"
    assert any("canonical" in reason for reason in report.reasons)


def test_canonical_inputs_at_exact_byte_limits_fit_structural_budgets(
    tmp_path: Path,
) -> None:
    project = Project.create("DiffLimits", tmp_path / "project", "26.04")
    bundle = project.output_dir / "publish"
    bundle.mkdir()
    current = bundle / "PUBLISH-DRILL.json"
    payload = publish_drill_text(
        status="review_required",
        gate="review",
        project=project.root,
        project_name=project.name,
        bundle_dir=bundle,
        bundle_identity=stable_directory_identity(bundle),
    ).encode("utf-8")
    current.write_bytes(
        payload + b" " * (diff_module._DRILL_MAX_BYTES - len(payload))
    )
    promoted = promote_publish_drill_baseline(project)
    assert promoted.status == "ready"
    receipt_path = bundle / "PUBLISH-DRILL-BASELINE.json"
    receipt = receipt_path.read_bytes()
    receipt_path.write_bytes(
        receipt
        + b" "
        * (
            baseline_module._REPORT_MAX_BYTES
            - len(receipt)
        )
    )

    assert validate_local_publish_drill_baseline(project) == "review_required"
    report = diff_publish_drills(
        bundle / "PUBLISH-DRILL.previous.json",
        current,
    )

    assert report.verdict == "unchanged"


@pytest.mark.parametrize(
    ("body", "reason_fragment"),
    (
        (b"\xff", "strict UTF-8"),
        (
            b'{"status":"ready","status":"blocked"}',
            "duplicate JSON key",
        ),
        (b'["ready"]', "one JSON object"),
        (b'{"status":NaN}', "canonical JSON"),
    ),
)
def test_invalid_json_input_returns_blocked_report(
    tmp_path: Path,
    body: bytes,
    reason_fragment: str,
) -> None:
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    old.write_bytes(body)
    new.write_text(_drill_text(), encoding="utf-8")

    report = diff_publish_drills(old, new)

    assert report.verdict == "blocked"
    assert report.status_change == "unknown -> unknown"
    assert any(reason_fragment in reason for reason in report.reasons)
    assert {entry.name for entry in tmp_path.iterdir()} == {"old.json", "new.json"}


def test_oversized_input_blocks_before_buffering(tmp_path: Path) -> None:
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    with old.open("wb") as stream:
        stream.truncate(diff_module._DRILL_MAX_BYTES + 1)
    new.write_text(_drill_text(), encoding="utf-8")

    report = diff_publish_drills(old, new)

    assert report.verdict == "blocked"
    assert any("byte limit" in reason for reason in report.reasons)


def test_excessive_json_depth_returns_blocked_report(tmp_path: Path) -> None:
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    nested = "[" * 257 + "0" + "]" * 257
    old.write_text(
        '{"status":"ready","nested":' + nested + "}",
        encoding="utf-8",
    )
    new.write_text(_drill_text(), encoding="utf-8")

    report = diff_publish_drills(old, new)

    assert report.verdict == "blocked"
    assert any("JSON exceeds depth" in reason for reason in report.reasons)


def test_malformed_manifest_shape_returns_blocked_instead_of_raising(
    tmp_path: Path,
) -> None:
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    old.write_text(
        json.dumps({"evidence": {"manifest": {"files": 7}}}),
        encoding="utf-8",
    )
    new.write_text(_drill_text(), encoding="utf-8")

    report = diff_publish_drills(old, new)

    assert report.verdict == "blocked"
    assert any(
        "could not be structurally validated safely" in reason
        for reason in report.reasons
    )


@pytest.mark.parametrize(
    ("entry_kind", "reason_fragment"),
    (
        ("symlink", "without following links"),
        ("fifo", "regular file"),
        ("directory", "regular file"),
        ("socket", "regular file"),
    ),
)
def test_special_input_entries_block_without_following_or_waiting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    entry_kind: str,
    reason_fragment: str,
) -> None:
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    victim = tmp_path / "external.json"
    victim_bytes = _drill_text().encode("utf-8")
    victim.write_bytes(victim_bytes)
    new.write_text(_drill_text(), encoding="utf-8")
    bound_socket: socket.socket | None = None
    if entry_kind == "symlink":
        old.symlink_to(victim)
    elif entry_kind == "fifo":
        os.mkfifo(old)
    elif entry_kind == "directory":
        old.mkdir()
    else:
        bound_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        with monkeypatch.context() as context:
            context.chdir(tmp_path)
            try:
                bound_socket.bind(old.name)
            except PermissionError:
                bound_socket.close()
                pytest.skip("sandbox forbids creating Unix-domain socket entries")

    try:
        report = diff_publish_drills(old, new)
    finally:
        if bound_socket is not None:
            bound_socket.close()

    assert report.verdict == "blocked"
    assert any(reason_fragment in reason for reason in report.reasons)
    assert victim.read_bytes() == victim_bytes


def test_input_path_swap_during_verdict_returns_blocked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old = tmp_path / "old.json"
    held = tmp_path / "old-held.json"
    new = tmp_path / "new.json"
    old.write_text(_drill_text(), encoding="utf-8")
    new.write_text(_drill_text(), encoding="utf-8")
    real_seal = diff_module.ArtifactVerificationSession.seal
    swapped = False

    def seal_after_swap(session: diff_module.ArtifactVerificationSession):
        nonlocal swapped
        if session.label == "publish drill comparison" and not swapped:
            swapped = True
            old.rename(held)
            old.write_text(
                _drill_text(status="blocked", gate="blocked"),
                encoding="utf-8",
            )
        return real_seal(session)

    monkeypatch.setattr(
        diff_module.ArtifactVerificationSession,
        "seal",
        seal_after_swap,
    )

    report = diff_publish_drills(old, new)

    assert swapped
    assert report.verdict == "blocked"
    assert any("changed during verification" in reason for reason in report.reasons)
    assert old.read_text(encoding="utf-8") == _drill_text(
        status="blocked",
        gate="blocked",
    )
    assert held.read_text(encoding="utf-8") == _drill_text()


def test_hardlink_aliases_share_one_parse_in_one_verification_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    old.write_text(_drill_text(), encoding="utf-8")
    os.link(old, new)
    real_seal = diff_module.ArtifactVerificationSession.seal
    closing_metrics = []

    def capture_metrics(session: diff_module.ArtifactVerificationSession):
        metrics = real_seal(session)
        closing_metrics.append(metrics)
        return metrics

    monkeypatch.setattr(
        diff_module.ArtifactVerificationSession,
        "seal",
        capture_metrics,
    )

    report = diff_publish_drills(old, new)

    assert report.verdict == "unchanged"
    assert len(closing_metrics) == 1
    assert closing_metrics[0].json_parses == 1
    assert closing_metrics[0].json_reuse == 1


def test_missing_parent_returns_blocked_without_creating_anything(
    tmp_path: Path,
) -> None:
    old = tmp_path / "missing" / "old.json"
    new = tmp_path / "new.json"
    new.write_text(_drill_text(), encoding="utf-8")

    report = diff_publish_drills(old, new)

    assert report.verdict == "blocked"
    assert not old.parent.exists()
    assert {entry.name for entry in tmp_path.iterdir()} == {"new.json"}
