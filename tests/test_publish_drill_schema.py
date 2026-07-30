from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from distroforge.core.project import Project
from distroforge.core.publish_drill_baseline import (
    promote_publish_drill_baseline,
)
from distroforge.core.publish_drill_diff import diff_publish_drills
from distroforge.core.publish_drill_schema import (
    PublishDrillSchemaError,
    validate_publish_drill_report,
)
from tests.publish_drill_contract import (
    publish_drill_payload,
    publish_drill_text,
)


def test_complete_ready_to_publish_contract_is_accepted() -> None:
    report = publish_drill_payload()

    validated = validate_publish_drill_report(report)

    assert validated.status == "ready_to_publish"
    assert validated.pipeline_status == "ready"
    assert validated.explanation_status == "ready"
    assert validated.signing_status == "signed"
    assert validated.verify_status == "ready"


def test_status_only_ready_to_publish_forgery_is_rejected() -> None:
    with pytest.raises(PublishDrillSchemaError, match="keys are not exact"):
        validate_publish_drill_report({"status": "ready_to_publish"})


@pytest.mark.parametrize(
    ("run_id", "immutable_paths", "reason"),
    (
        (
            "build_run_id",
            (
                "immutable_iso_build",
                "immutable_provenance",
                "immutable_sbom",
            ),
            "non-blocked release gate has no immutable selected build run",
        ),
        (
            "boot_run_id",
            (
                "immutable_boot_proof",
                "immutable_qemu_report",
            ),
            "non-blocked release gate has no immutable selected boot run",
        ),
    ),
)
def test_ready_contract_rejects_omitted_gate_run_selection(
    run_id: str,
    immutable_paths: tuple[str, ...],
    reason: str,
) -> None:
    report = copy.deepcopy(publish_drill_payload())
    pipeline = report["pipeline"]
    evidence = report["evidence"]
    assert isinstance(pipeline, dict)
    assert isinstance(evidence, dict)
    gate = evidence["release_gate"]
    assert isinstance(gate, dict)
    pipeline[run_id] = None
    gate[run_id] = None
    for path in immutable_paths:
        gate[path] = None

    with pytest.raises(PublishDrillSchemaError, match=reason):
        validate_publish_drill_report(report)


def test_ready_contract_rejects_malformed_optional_gate_path() -> None:
    report = copy.deepcopy(publish_drill_payload())
    evidence = report["evidence"]
    assert isinstance(evidence, dict)
    gate = evidence["release_gate"]
    assert isinstance(gate, dict)
    gate["immutable_sbom"] = "relative/not-canonical"

    with pytest.raises(
        PublishDrillSchemaError,
        match="release gate immutable SBOM is not a canonical absolute path",
    ):
        validate_publish_drill_report(report)


@pytest.mark.parametrize(
    ("section", "key", "value", "reason"),
    (
        ("top", "blocked", True, "blocked flag contradicts"),
        (
            "pipeline",
            "bundle_identity",
            [1, 99, 16384, 1000, 1000, 2, 0],
            "bundle identity differs",
        ),
        (
            "explanation",
            "review",
            ["publish-signing: forged residual review"],
            "aggregate status contradicts",
        ),
        (
            "signing",
            "signed",
            ["SHA256SUMS.asc"],
            "exact executed signature set",
        ),
        (
            "verify",
            "blocked",
            True,
            "blocked flag contradicts",
        ),
    ),
)
def test_cross_report_incoherences_are_rejected(
    section: str,
    key: str,
    value: object,
    reason: str,
) -> None:
    report = copy.deepcopy(publish_drill_payload())
    if section == "top":
        target = report
    elif section in {"pipeline", "explanation"}:
        target = report[section]
    else:
        evidence = report["evidence"]
        assert isinstance(evidence, dict)
        target = evidence[section]
    assert isinstance(target, dict)
    target[key] = value

    with pytest.raises(PublishDrillSchemaError, match=reason):
        validate_publish_drill_report(report)


def test_malformed_sha_contract_is_rejected() -> None:
    report = copy.deepcopy(publish_drill_payload())
    evidence = report["evidence"]
    assert isinstance(evidence, dict)
    manifest = evidence["manifest"]
    assert isinstance(manifest, dict)
    files = manifest["files"]
    assert isinstance(files, list)
    iso = files[0]
    assert isinstance(iso, dict)
    iso["sha256"] = "forged"

    with pytest.raises(
        PublishDrillSchemaError,
        match="unsafe or duplicate identity",
    ):
        validate_publish_drill_report(report)


def test_ready_contract_rejects_duplicate_signature_proof() -> None:
    report = copy.deepcopy(publish_drill_payload())
    evidence = report["evidence"]
    assert isinstance(evidence, dict)
    verify = evidence["verify"]
    assert isinstance(verify, dict)
    items = verify["items"]
    assert isinstance(items, list)
    signatures = [
        item for item in items if isinstance(item, dict) and item.get("code") == "signature"
    ]
    signatures[1]["detail"] = signatures[0]["detail"]

    with pytest.raises(PublishDrillSchemaError, match="exact terminal cryptographic"):
        validate_publish_drill_report(report)


def test_ready_contract_binds_terminal_fingerprint_to_signing_report() -> None:
    report = copy.deepcopy(publish_drill_payload())
    evidence = report["evidence"]
    assert isinstance(evidence, dict)
    verify = evidence["verify"]
    assert isinstance(verify, dict)
    items = verify["items"]
    assert isinstance(items, list)
    fingerprint = next(
        item
        for item in items
        if isinstance(item, dict) and item.get("code") == "signature-fingerprint"
    )
    fingerprint["detail"] = "Externally pinned complete signer fingerprint: " + "B" * 40 + "."

    with pytest.raises(PublishDrillSchemaError, match="exact terminal cryptographic"):
        validate_publish_drill_report(report)


@pytest.mark.parametrize(
    ("section", "code", "reason"),
    (
        ("release_gate", "rootfs-identity", "exact release-gate proof set"),
        (
            "verify",
            "runtime-evidence",
            "exact terminal verification proof set",
        ),
    ),
)
def test_ready_contract_rejects_missing_mandatory_proof(
    section: str,
    code: str,
    reason: str,
) -> None:
    report = copy.deepcopy(publish_drill_payload())
    evidence = report["evidence"]
    assert isinstance(evidence, dict)
    verdict = evidence[section]
    assert isinstance(verdict, dict)
    items = verdict["items"]
    assert isinstance(items, list)
    verdict["items"] = [
        item for item in items if not isinstance(item, dict) or item.get("code") != code
    ]

    with pytest.raises(PublishDrillSchemaError, match=reason):
        validate_publish_drill_report(report)


def test_explanation_lists_must_be_unique_and_disjoint() -> None:
    report = copy.deepcopy(publish_drill_payload())
    explanation = report["explanation"]
    assert isinstance(explanation, dict)
    ready = explanation["ready"]
    assert isinstance(ready, list)
    ready.append(ready[0])

    with pytest.raises(PublishDrillSchemaError, match="contains duplicates"):
        validate_publish_drill_report(report)


def test_blocked_contract_may_record_non_ready_iso_sha_verdicts() -> None:
    report = copy.deepcopy(
        publish_drill_payload(
            status="blocked",
            gate="blocked",
        )
    )
    evidence = report["evidence"]
    assert isinstance(evidence, dict)
    gate = evidence["release_gate"]
    assert isinstance(gate, dict)
    items = gate["items"]
    assert isinstance(items, list)
    iso = next(item for item in items if isinstance(item, dict) and item.get("code") == "iso")
    sha = next(item for item in items if isinstance(item, dict) and item.get("code") == "sha256")
    iso.update(status="blocked", detail="Final ISO is unsafe.")
    sha.update(status="blocked", detail="Cannot verify SHA256 without a safe ISO.")

    validated = validate_publish_drill_report(report)

    assert validated.status == "blocked"


def test_baseline_rejects_status_only_ready_to_publish_forgery(
    tmp_path: Path,
) -> None:
    project = Project.create("ForgedBaseline", tmp_path / "project", "26.04")
    bundle = project.output_dir / "publish"
    bundle.mkdir()
    (bundle / "PUBLISH-DRILL.json").write_text(
        '{"status":"ready_to_publish"}\n',
        encoding="utf-8",
    )

    promoted = promote_publish_drill_baseline(project)

    assert promoted.status == "blocked"
    assert promoted.promoted is False
    assert "keys are not exact" in promoted.reason
    assert not (bundle / "PUBLISH-DRILL.previous.json").exists()


def test_diff_rejects_status_only_ready_to_publish_forgery(
    tmp_path: Path,
) -> None:
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    old.write_text(publish_drill_text(), encoding="utf-8")
    new.write_text(
        json.dumps({"status": "ready_to_publish"}) + "\n",
        encoding="utf-8",
    )

    report = diff_publish_drills(old, new)

    assert report.verdict == "blocked"
    assert any("keys are not exact" in reason for reason in report.reasons)
