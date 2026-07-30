from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import NoReturn

from .evidence_run import is_safe_run_id
from .release_contract import (
    ALLOWED_RELEASE_GATE_CODES,
    REQUIRED_RELEASE_GATE_CODES,
    SIGN_TARGETS,
    SIGNATURE_NAMES,
    SIGNING_KEYRING,
    release_gate_code_problem,
    release_manifest_problem,
    release_signing_report_problem,
)

DRILL_STATUSES = frozenset({"blocked", "review_required", "ready_to_publish"})
VERDICT_STATUSES = frozenset({"blocked", "review", "ready"})
ITEM_STATUSES = frozenset({"blocked", "review", "ready"})
STAGE_STATUSES = frozenset({"blocked", "planned", "ready", "review", "signed"})
SIGNING_STATUSES = frozenset({"blocked", "planned", "signed"})
_RESOLVED_GATE_DETAIL = (
    "The sole pre-signing publish review is resolved by the exact "
    "descriptor-bound signature set verified in this verdict."
)
_SHA256 = re.compile(r"[0-9a-f]{64}")
_FINGERPRINT = re.compile(r"(?:[0-9A-F]{40}|[0-9A-F]{64})")
_PIPELINE_STAGES = (
    "boot-proof",
    "repair-artifacts",
    "publish-bundle",
    "manifest-plan",
    "release-notes",
    "sign-release-final",
    "verify-release",
)
_OPTIONAL_PIPELINE_STAGE = "release-pipeline-report"
_READY_VERIFY_CODES = frozenset(
    {
        "manifest",
        "release-gate",
        "signing-report",
        "sha256sums",
        "runtime-evidence",
        "gate-status",
        "signature-fingerprint",
        "signature-keyring",
        "signature",
        "manifest-file",
        "artifact-session",
    }
)


class PublishDrillSchemaError(ValueError):
    """A persisted publish drill contradicts its strict semantic contract."""


@dataclass(frozen=True)
class ValidatedPublishDrill:
    status: str
    pipeline_status: str
    explanation_status: str
    gate_status: str
    signing_status: str
    verify_status: str
    bundle_identity: tuple[int, int, int, int, int, int, int]


def validate_publish_drill_report(
    data: object,
    *,
    expected_project: Path | None = None,
    expected_project_name: str | None = None,
    expected_bundle_dir: Path | None = None,
    expected_bundle_identity: tuple[int, int, int, int, int, int, int] | None = None,
) -> ValidatedPublishDrill:
    """Validate one complete persisted :class:`PublishDrillReport`.

    This is intentionally a semantic validator rather than a permissive JSON
    reader.  Every aggregate is re-derived and every nested report is bound to
    the same declared paths and directory receipt.  Without caller-supplied
    anchors this establishes only internal structural consistency: even a
    ``ready_to_publish`` shape does not authenticate signatures or prove that a
    terminal verifier actually ran.
    """

    report = _object(data, "publish drill")
    _exact_keys(
        report,
        {
            "project",
            "project_name",
            "iso",
            "bundle_dir",
            "status",
            "blocked",
            "drill",
            "execute_signing",
            "pipeline",
            "explanation",
            "evidence",
        },
        "publish drill",
    )
    project = _absolute_path(report.get("project"), "publish drill project")
    project_name = _nonempty_string(
        report.get("project_name"),
        "publish drill project_name",
    )
    if (
        expected_project_name is not None
        and project_name != expected_project_name
    ):
        _fail("publish drill project_name differs from the expected project")
    iso = _absolute_path(report.get("iso"), "publish drill ISO")
    bundle_dir = _absolute_path(
        report.get("bundle_dir"),
        "publish drill bundle",
    )
    if expected_project is not None and project != Path(os.path.abspath(expected_project)):
        _fail("publish drill project differs from the expected project")
    if expected_bundle_dir is not None and bundle_dir != Path(os.path.abspath(expected_bundle_dir)):
        _fail("publish drill bundle differs from the expected bundle")
    drill = _absolute_path(report.get("drill"), "publish drill report path")
    if drill != bundle_dir / "PUBLISH-DRILL.json":
        _fail("publish drill report path is not bound to its bundle")
    status = _enum(report.get("status"), DRILL_STATUSES, "publish drill status")
    blocked = _boolean(report.get("blocked"), "publish drill blocked flag")
    if blocked is not (status == "blocked"):
        _fail("publish drill blocked flag contradicts its status")
    execute_signing = _boolean(
        report.get("execute_signing"),
        "publish drill execute_signing flag",
    )

    pipeline, stage_statuses, bundle_identity = _validate_pipeline(
        report.get("pipeline"),
        project=project,
        bundle_dir=bundle_dir,
    )
    if expected_bundle_identity is not None and bundle_identity != expected_bundle_identity:
        _fail("publish drill bundle identity differs from the expected receipt")
    explanation = _validate_explanation(
        report.get("explanation"),
        project=project,
        iso=iso,
        bundle_dir=bundle_dir,
    )
    gate, manifest, signing, verify = _validate_evidence(
        report.get("evidence"),
        project=project,
        project_name=project_name,
        iso=iso,
        bundle_dir=bundle_dir,
        bundle_identity=bundle_identity,
    )
    if pipeline.get("build_run_id") != gate.get("build_run_id"):
        _fail("pipeline build run differs from the sealed release gate selection")
    if pipeline.get("boot_run_id") != gate.get("boot_run_id"):
        _fail("pipeline boot run differs from the sealed release gate selection")

    pipeline_status = _string(pipeline.get("status"), "pipeline status")
    explanation_status = _string(
        explanation.get("status"),
        "explanation status",
    )
    gate_status = _string(gate.get("status"), "release gate status")
    signing_status = _string(signing.get("status"), "signing status")
    verify_status = _string(verify.get("status"), "verify status")
    if stage_statuses["sign-release-final"] != signing_status:
        _fail("pipeline signing stage contradicts SIGNING-REPORT.json")
    if stage_statuses["verify-release"] != verify_status:
        _fail("pipeline verify stage contradicts VERIFY-REPORT.json")

    derived_status = _derive_drill_status(
        pipeline_status,
        explanation_status,
        verify_status,
    )
    if status != derived_status:
        _fail("publish drill status contradicts pipeline, explanation, and terminal verification")

    _validate_cross_report_contract(
        report=report,
        gate=gate,
        manifest=manifest,
        signing=signing,
        verify=verify,
        explanation=explanation,
        stage_statuses=stage_statuses,
        iso=iso,
    )
    if status == "ready_to_publish":
        _validate_ready_to_publish(
            execute_signing=execute_signing,
            gate=gate,
            manifest=manifest,
            signing=signing,
            verify=verify,
            explanation=explanation,
            stage_statuses=stage_statuses,
        )
    return ValidatedPublishDrill(
        status,
        pipeline_status,
        explanation_status,
        gate_status,
        signing_status,
        verify_status,
        bundle_identity,
    )


def _validate_pipeline(
    value: object,
    *,
    project: Path,
    bundle_dir: Path,
) -> tuple[
    dict[str, object],
    dict[str, str],
    tuple[int, int, int, int, int, int, int],
]:
    pipeline = _object(value, "publish pipeline")
    _exact_keys(
        pipeline,
        {
            "project",
            "bundle_dir",
            "status",
            "stages",
            "bundle_identity",
            "build_run_id",
            "boot_run_id",
        },
        "publish pipeline",
    )
    if _absolute_path(pipeline.get("project"), "pipeline project") != project:
        _fail("pipeline project differs from the publish drill project")
    if _absolute_path(pipeline.get("bundle_dir"), "pipeline bundle") != bundle_dir:
        _fail("pipeline bundle differs from the publish drill bundle")
    status = _enum(
        pipeline.get("status"),
        VERDICT_STATUSES,
        "pipeline status",
    )
    _optional_run_id(pipeline.get("build_run_id"), "pipeline build run")
    _optional_run_id(pipeline.get("boot_run_id"), "pipeline boot run")
    raw_stages = _list(pipeline.get("stages"), "pipeline stages")
    stages: dict[str, str] = {}
    stage_names: list[str] = []
    for index, raw_stage in enumerate(raw_stages):
        stage = _object(raw_stage, f"pipeline stage {index}")
        _exact_keys(stage, {"name", "status", "detail"}, f"pipeline stage {index}")
        name = _nonempty_string(stage.get("name"), f"pipeline stage {index} name")
        if name in stages:
            _fail(f"pipeline contains duplicate stage {name}")
        stage_names.append(name)
        stages[name] = _enum(
            stage.get("status"),
            STAGE_STATUSES,
            f"pipeline stage {name} status",
        )
        _nonempty_string(stage.get("detail"), f"pipeline stage {name} detail")
    allowed_sequences = {
        _PIPELINE_STAGES,
        (*_PIPELINE_STAGES, _OPTIONAL_PIPELINE_STAGE),
    }
    if tuple(stage_names) not in allowed_sequences:
        _fail("pipeline stages are incomplete, duplicated, or out of order")
    derived = _aggregate_stage_status(tuple(stages.values()))
    if status != derived:
        _fail("pipeline aggregate status contradicts its stages")
    identity = _bundle_identity(
        pipeline.get("bundle_identity"),
        "pipeline bundle identity",
    )
    return pipeline, stages, identity


def _validate_explanation(
    value: object,
    *,
    project: Path,
    iso: Path,
    bundle_dir: Path,
) -> dict[str, object]:
    explanation = _object(value, "release explanation")
    _exact_keys(
        explanation,
        {
            "project",
            "iso",
            "bundle_dir",
            "status",
            "blocked",
            "markdown",
            "ready",
            "review",
            "blocked_items",
            "boot_proof",
            "next_commands",
        },
        "release explanation",
    )
    if _absolute_path(explanation.get("project"), "explanation project") != project:
        _fail("explanation project differs from the publish drill project")
    if _absolute_path(explanation.get("iso"), "explanation ISO") != iso:
        _fail("explanation ISO differs from the publish drill ISO")
    if _absolute_path(explanation.get("bundle_dir"), "explanation bundle") != bundle_dir:
        _fail("explanation bundle differs from the publish drill bundle")
    markdown = _absolute_path(
        explanation.get("markdown"),
        "explanation markdown",
    )
    if markdown != bundle_dir / "RELEASE-EXPLAIN.md":
        _fail("explanation markdown path is not bound to its bundle")
    status = _enum(
        explanation.get("status"),
        VERDICT_STATUSES,
        "explanation status",
    )
    blocked_flag = _boolean(
        explanation.get("blocked"),
        "explanation blocked flag",
    )
    if blocked_flag is not (status == "blocked"):
        _fail("explanation blocked flag contradicts its status")
    ready = _string_list(
        explanation.get("ready"),
        "explanation ready items",
    )
    review = _string_list(
        explanation.get("review"),
        "explanation review items",
    )
    blocked = _string_list(
        explanation.get("blocked_items"),
        "explanation blocked items",
    )
    commands = _string_list(
        explanation.get("next_commands"),
        "explanation next commands",
    )
    _require_unique(ready, "explanation ready items")
    _require_unique(review, "explanation review items")
    _require_unique(blocked, "explanation blocked items")
    _require_unique(commands, "explanation next commands")
    if set(ready) & set(review) or set(ready) & set(blocked) or set(review) & set(blocked):
        _fail("explanation verdict lists overlap")
    if not commands:
        _fail("explanation must contain at least one next command")
    derived = "blocked" if blocked else "review" if review else "ready"
    if status != derived:
        _fail("explanation aggregate status contradicts its item lists")
    boot = _object(explanation.get("boot_proof"), "explanation boot proof")
    _exact_keys(
        boot,
        {"status", "selected_backend", "proof_level", "attempted_backends"},
        "explanation boot proof",
    )
    _enum(
        boot.get("status"),
        {"blocked", "missing", "planned", "ready"},
        "boot proof status",
    )
    _nonempty_string(
        boot.get("selected_backend"),
        "boot proof selected backend",
    )
    _enum(
        boot.get("proof_level"),
        {"none", "structural", "runtime"},
        "boot proof level",
    )
    _string(
        boot.get("attempted_backends"),
        "boot proof attempted backends",
    )
    return explanation


def _validate_evidence(
    value: object,
    *,
    project: Path,
    project_name: str,
    iso: Path,
    bundle_dir: Path,
    bundle_identity: tuple[int, int, int, int, int, int, int],
) -> tuple[
    dict[str, object],
    dict[str, object],
    dict[str, object],
    dict[str, object],
]:
    evidence = _object(value, "publish drill evidence")
    _exact_keys(
        evidence,
        {"release_gate", "manifest", "signing", "verify"},
        "publish drill evidence",
    )
    gate = _validate_gate(
        evidence.get("release_gate"),
        project=project,
        iso=iso,
    )
    manifest = _validate_manifest(
        evidence.get("manifest"),
        project_name=project_name,
        bundle_dir=bundle_dir,
        gate=gate,
    )
    signing = _validate_signing(
        evidence.get("signing"),
        project=project,
        bundle_dir=bundle_dir,
        manifest=manifest,
    )
    verify = _validate_verify(
        evidence.get("verify"),
        project=project,
        bundle_dir=bundle_dir,
        bundle_identity=bundle_identity,
    )
    return gate, manifest, signing, verify


def _validate_gate(
    value: object,
    *,
    project: Path,
    iso: Path,
) -> dict[str, object]:
    gate = _object(value, "release gate evidence")
    _exact_keys(
        gate,
        {
            "project",
            "iso",
            "output_dir",
            "build_run_id",
            "boot_run_id",
            "immutable_iso_build",
            "immutable_provenance",
            "immutable_boot_proof",
            "immutable_qemu_report",
            "immutable_sbom",
            "status",
            "blocked",
            "items",
        },
        "release gate evidence",
    )
    if _absolute_path(gate.get("project"), "release gate project") != project:
        _fail("release gate project differs from the publish drill project")
    if _absolute_path(gate.get("iso"), "release gate ISO") != iso:
        _fail("release gate ISO differs from the publish drill ISO")
    output_dir = _absolute_path(
        gate.get("output_dir"),
        "release gate output directory",
    )
    if output_dir != iso.parent:
        _fail("release gate output directory differs from the ISO parent")
    build_run_id = _optional_run_id(
        gate.get("build_run_id"),
        "release gate build run",
    )
    boot_run_id = _optional_run_id(
        gate.get("boot_run_id"),
        "release gate boot run",
    )
    immutable_iso_build = _optional_absolute_path(
        gate.get("immutable_iso_build"),
        "release gate immutable ISO-BUILD",
    )
    immutable_provenance = _optional_absolute_path(
        gate.get("immutable_provenance"),
        "release gate immutable provenance",
    )
    immutable_boot_proof = _optional_absolute_path(
        gate.get("immutable_boot_proof"),
        "release gate immutable boot proof",
    )
    immutable_qemu_report = _optional_absolute_path(
        gate.get("immutable_qemu_report"),
        "release gate immutable QEMU report",
    )
    immutable_sbom = _optional_absolute_path(
        gate.get("immutable_sbom"),
        "release gate immutable SBOM",
    )
    if build_run_id is None:
        if any(
            path is not None
            for path in (
                immutable_iso_build,
                immutable_provenance,
                immutable_sbom,
            )
        ):
            _fail("release gate exposes build artifacts without a selected build run")
    else:
        build_dir = output_dir / "evidence" / "runs" / build_run_id
        if immutable_iso_build != build_dir / "ISO-BUILD.json":
            _fail("release gate immutable ISO-BUILD is outside its selected build run")
        if immutable_provenance != build_dir / "distroforge-provenance.json":
            _fail("release gate immutable provenance is outside its selected build run")
        if immutable_sbom is not None and immutable_sbom.parent != build_dir:
            _fail("release gate immutable SBOM is outside its selected build run")
    if boot_run_id is None:
        if immutable_boot_proof is not None or immutable_qemu_report is not None:
            _fail("release gate exposes boot artifacts without a selected boot run")
    else:
        boot_dir = output_dir / "evidence" / "runs" / boot_run_id
        if immutable_boot_proof != boot_dir / "boot-proof.json":
            _fail("release gate immutable boot proof is outside its selected boot run")
        if immutable_qemu_report is not None and immutable_qemu_report.parent != boot_dir:
            _fail("release gate immutable QEMU report is outside its selected boot run")
    status = _enum(gate.get("status"), VERDICT_STATUSES, "release gate status")
    blocked = _boolean(gate.get("blocked"), "release gate blocked flag")
    if blocked is not (status == "blocked"):
        _fail("release gate blocked flag contradicts its status")
    raw_items = _list(gate.get("items"), "release gate items")
    if not raw_items:
        _fail("release gate has no typed item verdicts")
    item_statuses: list[str] = []
    item_status_by_code: dict[str, str] = {}
    codes: set[str] = set()
    for index, raw_item in enumerate(raw_items):
        item = _object(raw_item, f"release gate item {index}")
        _exact_keys(
            item,
            {"code", "status", "detail"},
            f"release gate item {index}",
        )
        code = _nonempty_string(
            item.get("code"),
            f"release gate item {index} code",
        )
        if code in codes:
            _fail(f"release gate contains duplicate item code {code}")
        codes.add(code)
        item_status = _enum(
            item.get("status"),
            ITEM_STATUSES,
            f"release gate item {code} status",
        )
        item_statuses.append(item_status)
        item_status_by_code[code] = item_status
        _nonempty_string(
            item.get("detail"),
            f"release gate item {code} detail",
        )
    if status != _aggregate_item_status(tuple(item_statuses)):
        _fail("release gate aggregate status contradicts its items")
    build_selected = (
        build_run_id is not None
        and immutable_iso_build is not None
        and immutable_provenance is not None
    )
    boot_selected = (
        boot_run_id is not None
        and immutable_boot_proof is not None
        and immutable_qemu_report is not None
    )
    if status != "blocked" and not build_selected:
        _fail("non-blocked release gate has no immutable selected build run")
    if status != "blocked" and not boot_selected:
        _fail("non-blocked release gate has no immutable selected boot run")
    if item_status_by_code.get("provenance") == "ready" and not build_selected:
        _fail("ready provenance has no immutable selected build run")
    if item_status_by_code.get("boot-proof") == "ready" and (
        not build_selected or not boot_selected
    ):
        _fail("ready boot proof has no immutable build/boot selection")
    if item_status_by_code.get("sbom") == "ready" and immutable_sbom is None:
        _fail("ready SBOM has no immutable selected SBOM")
    code_problem = release_gate_code_problem(codes)
    if code_problem is not None:
        _fail(
            "release gate lacks the exact release-gate proof set: "
            + code_problem
        )
    return gate


def _validate_manifest(
    value: object,
    *,
    project_name: str,
    bundle_dir: Path,
    gate: dict[str, object],
) -> dict[str, object]:
    manifest = _object(value, "release manifest evidence")
    manifest_problem = release_manifest_problem(
        manifest,
        expected_project_name=project_name,
        expected_bundle_dir=bundle_dir,
    )
    if manifest_problem is not None:
        _fail(manifest_problem)
    _exact_keys(
        manifest,
        {"generated_at", "project", "bundle_dir", "gate_status", "files"},
        "release manifest evidence",
    )
    generated_at = _nonempty_string(
        manifest.get("generated_at"),
        "release manifest generated_at",
    )
    try:
        parsed_time = datetime.fromisoformat(generated_at)
    except ValueError as exc:
        raise PublishDrillSchemaError(
            "release manifest generated_at is not strict ISO-8601"
        ) from exc
    if parsed_time.tzinfo is None or parsed_time.utcoffset() is None:
        _fail("release manifest generated_at has no timezone")
    _nonempty_string(manifest.get("project"), "release manifest project")
    if _absolute_path(manifest.get("bundle_dir"), "release manifest bundle") != bundle_dir:
        _fail("release manifest bundle differs from the publish drill bundle")
    gate_status = _enum(
        manifest.get("gate_status"),
        VERDICT_STATUSES,
        "release manifest gate status",
    )
    if gate_status != gate.get("status"):
        _fail("release manifest gate status contradicts RELEASE-GATE.json")
    entries = _manifest_entries(
        manifest.get("files"),
        "release manifest files",
    )
    names = {str(entry["name"]) for entry in entries}
    for required in ("SHA256SUMS", "RELEASE-GATE.json"):
        if required not in names:
            _fail(f"release manifest is missing required file {required}")
    iso_entries = [entry for entry in entries if str(entry["name"]).endswith(".iso")]
    if len(iso_entries) != 1:
        _fail("release manifest must bind exactly one ISO")
    return manifest


def _validate_signing(
    value: object,
    *,
    project: Path,
    bundle_dir: Path,
    manifest: dict[str, object],
) -> dict[str, object]:
    signing = _object(value, "signing evidence")
    contract_problem = release_signing_report_problem(
        signing,
        manifest,
        expected_project=project,
        expected_bundle_dir=bundle_dir,
    )
    if contract_problem is not None:
        _fail(contract_problem)
    _exact_keys(
        signing,
        {
            "project",
            "bundle_dir",
            "manifest",
            "status",
            "execute",
            "signer_fingerprint",
            "verification_keyring",
            "verification_keyring_sha256",
            "signed",
            "planned",
            "skipped",
            "manifest_entries",
        },
        "signing evidence",
    )
    if _absolute_path(signing.get("project"), "signing project") != project:
        _fail("signing project differs from the publish drill project")
    if _absolute_path(signing.get("bundle_dir"), "signing bundle") != bundle_dir:
        _fail("signing bundle differs from the publish drill bundle")
    if (
        _absolute_path(signing.get("manifest"), "signing manifest path")
        != bundle_dir / "RELEASE-MANIFEST.json"
    ):
        _fail("signing manifest path is not bound to the bundle")
    status = _enum(signing.get("status"), SIGNING_STATUSES, "signing status")
    execute = _boolean(signing.get("execute"), "signing execute flag")
    fingerprint = signing.get("signer_fingerprint")
    if fingerprint is not None and (
        not isinstance(fingerprint, str) or _FINGERPRINT.fullmatch(fingerprint) is None
    ):
        _fail("signing fingerprint is not a complete canonical fingerprint")
    keyring = signing.get("verification_keyring")
    keyring_sha = signing.get("verification_keyring_sha256")
    if keyring is None:
        if keyring_sha is not None:
            _fail("signing keyring SHA exists without a keyring")
    else:
        if (
            not isinstance(keyring, str)
            or keyring != SIGNING_KEYRING
            or not _is_sha256(keyring_sha)
        ):
            _fail("signing keyring identity is malformed")
    signed = _string_list(signing.get("signed"), "signed signature names")
    planned = _string_list(signing.get("planned"), "planned signature names")
    skipped = _string_list(signing.get("skipped"), "skipped signing reasons")
    if len(set(signed)) != len(signed) or len(set(planned)) != len(planned):
        _fail("signing target lists contain duplicates")
    entries = _manifest_entries(
        signing.get("manifest_entries"),
        "signing manifest entries",
    )
    if entries != _list(manifest.get("files"), "release manifest files"):
        _fail("signing manifest entries do not reproduce RELEASE-MANIFEST.json")
    manifest_by_name = {str(entry["name"]): entry for entry in entries}
    if keyring is not None:
        keyring_entry = manifest_by_name.get(keyring)
        if keyring_entry is None or keyring_entry.get("sha256") != keyring_sha:
            _fail("signing keyring is not bound by the release manifest")
    if status == "signed":
        if (
            not execute
            or fingerprint is None
            or keyring != SIGNING_KEYRING
            or tuple(signed) != SIGNATURE_NAMES
            or planned
            or skipped
        ):
            _fail("signed report does not contain the exact executed signature set")
    elif status == "planned":
        if execute or signed or tuple(planned) != SIGNATURE_NAMES or skipped:
            _fail("planned signing report contradicts its target lists")
        if keyring is not None or keyring_sha is not None:
            _fail("planned signing report unexpectedly carries a published keyring")
    elif signed or planned or not skipped:
        _fail("blocked signing report has contradictory target or reason lists")
    return signing


def _validate_verify(
    value: object,
    *,
    project: Path,
    bundle_dir: Path,
    bundle_identity: tuple[int, int, int, int, int, int, int],
) -> dict[str, object]:
    verify = _object(value, "verification evidence")
    _exact_keys(
        verify,
        {"project", "bundle_dir", "status", "blocked", "items", "bundle_identity"},
        "verification evidence",
    )
    if _absolute_path(verify.get("project"), "verify project") != project:
        _fail("verify project differs from the publish drill project")
    if _absolute_path(verify.get("bundle_dir"), "verify bundle") != bundle_dir:
        _fail("verify bundle differs from the publish drill bundle")
    status = _enum(verify.get("status"), VERDICT_STATUSES, "verify status")
    blocked = _boolean(verify.get("blocked"), "verify blocked flag")
    if blocked is not (status == "blocked"):
        _fail("verify blocked flag contradicts its status")
    if _bundle_identity(verify.get("bundle_identity"), "verify bundle identity") != bundle_identity:
        _fail("verify bundle identity differs from the pipeline receipt")
    raw_items = _list(verify.get("items"), "verify items")
    if not raw_items:
        _fail("verify report has no typed item verdicts")
    item_statuses: list[str] = []
    for index, raw_item in enumerate(raw_items):
        item = _object(raw_item, f"verify item {index}")
        _exact_keys(item, {"code", "status", "detail"}, f"verify item {index}")
        code = _nonempty_string(item.get("code"), f"verify item {index} code")
        item_statuses.append(
            _enum(
                item.get("status"),
                ITEM_STATUSES,
                f"verify item {code} status",
            )
        )
        _nonempty_string(item.get("detail"), f"verify item {code} detail")
    if status != _aggregate_item_status(tuple(item_statuses)):
        _fail("verify aggregate status contradicts its items")
    if len(_items_by_code(verify, "gate-status")) != 1:
        _fail("verify report must contain exactly one gate-status verdict")
    if len(_items_by_code(verify, "artifact-session")) != 1:
        _fail("verify report must contain exactly one artifact-session verdict")
    return verify


def _validate_cross_report_contract(
    *,
    report: dict[str, object],
    gate: dict[str, object],
    manifest: dict[str, object],
    signing: dict[str, object],
    verify: dict[str, object],
    explanation: dict[str, object],
    stage_statuses: dict[str, str],
    iso: Path,
) -> None:
    gate_items = {
        str(item["code"]): item
        for item in _list(gate.get("items"), "release gate items")
        if isinstance(item, dict)
    }
    manifest_entries = _list(manifest.get("files"), "release manifest files")
    iso_entries = [
        entry
        for entry in manifest_entries
        if isinstance(entry, dict) and str(entry.get("name", "")).endswith(".iso")
    ]
    iso_entry = iso_entries[0]
    if iso_entry.get("name") != iso.name:
        _fail("release manifest ISO name differs from the publish drill ISO")
    iso_item = gate_items["iso"]
    sha_item = gate_items["sha256"]
    if iso_item.get("status") == "ready" and (
        iso_item.get("detail") != f"{iso_entry.get('size')} bytes"
    ):
        _fail("ready release gate ISO verdict does not bind the manifest ISO")
    if sha_item.get("status") == "ready" and (sha_item.get("detail") != iso_entry.get("sha256")):
        _fail("ready release gate SHA verdict does not bind the manifest ISO")
    boot = _object(explanation.get("boot_proof"), "explanation boot proof")
    if stage_statuses["boot-proof"] != boot.get("status"):
        _fail("pipeline boot-proof stage contradicts the explanation")
    signing_status = _string(signing.get("status"), "signing status")
    if signing_status == "signed" and report.get("execute_signing") is not True:
        _fail("signed evidence contradicts the publish drill execution mode")
    gate_status = _string(gate.get("status"), "release gate status")
    gate_verdict = _items_by_code(verify, "gate-status")[0]
    gate_verify_status = gate_verdict.get("status")
    expected_gate_detail = f"Release gate is {gate_status}."
    if gate_status == "ready" and gate_verify_status != "ready":
        _fail("ready release gate is not ready in terminal verification")
    if gate_status == "blocked" and gate_verify_status != "blocked":
        _fail("blocked release gate is not blocked in terminal verification")
    if gate_status == "review" and gate_verify_status not in {"review", "ready"}:
        _fail("review release gate has an incoherent terminal verdict")
    if gate_verify_status == "ready" and gate_status == "review":
        if gate_verdict.get("detail") != _RESOLVED_GATE_DETAIL:
            _fail("terminal verification carries a forged gate-review resolution")
        review_codes = {
            str(item.get("code"))
            for item in _list(gate.get("items"), "release gate items")
            if isinstance(item, dict) and item.get("status") == "review"
        }
        if review_codes != {"publish-signing"}:
            _fail("terminal verification resolved more than the sole publish-signing review")
        _validate_exact_crypto_proofs(signing, verify)
    elif gate_verdict.get("detail") != expected_gate_detail:
        _fail("terminal release-gate verdict does not reproduce the gate status")


def _validate_ready_to_publish(
    *,
    execute_signing: bool,
    gate: dict[str, object],
    manifest: dict[str, object],
    signing: dict[str, object],
    verify: dict[str, object],
    explanation: dict[str, object],
    stage_statuses: dict[str, str],
) -> None:
    if not execute_signing:
        _fail("ready_to_publish requires executed signing")
    expected_stages = {
        "boot-proof": "ready",
        "repair-artifacts": "ready",
        "publish-bundle": "ready",
        "manifest-plan": "ready",
        "release-notes": "ready",
        "sign-release-final": "signed",
        "verify-release": "ready",
    }
    if {name: stage_statuses.get(name) for name in expected_stages} != expected_stages:
        _fail("ready_to_publish requires the exact ready pipeline stages")
    if _OPTIONAL_PIPELINE_STAGE in stage_statuses:
        _fail("ready_to_publish cannot contain a failed pipeline report stage")
    if signing.get("status") != "signed" or verify.get("status") != "ready":
        _fail("ready_to_publish requires signed and terminal-ready evidence")
    if explanation.get("status") != "ready":
        _fail("ready_to_publish requires a ready explanation")
    boot = _object(explanation.get("boot_proof"), "explanation boot proof")
    if boot.get("status") != "ready" or boot.get("proof_level") != "runtime":
        _fail("ready_to_publish requires ready runtime boot proof")
    gate_items = _list(gate.get("items"), "release gate items")
    gate_by_code = {str(item.get("code")): item for item in gate_items if isinstance(item, dict)}
    gate_codes = set(gate_by_code)
    if (
        not REQUIRED_RELEASE_GATE_CODES <= gate_codes
        or not gate_codes <= ALLOWED_RELEASE_GATE_CODES
    ):
        _fail("ready_to_publish lacks the exact release-gate proof set")
    review_codes = {
        str(item.get("code"))
        for item in gate_items
        if isinstance(item, dict) and item.get("status") == "review"
    }
    gate_status = gate.get("status")
    if gate_status == "review":
        if review_codes != {"publish-signing"}:
            _fail("ready_to_publish can resolve only the sole publish-signing review")
        gate_verdict = _items_by_code(verify, "gate-status")[0]
        if (
            gate_verdict.get("status") != "ready"
            or gate_verdict.get("detail") != _RESOLVED_GATE_DETAIL
        ):
            _fail("terminal verification did not resolve the sole publish-signing review")
        ready_items = _string_list(
            explanation.get("ready"),
            "explanation ready items",
        )
        if not any(item.startswith("publish-signing: resolved") for item in ready_items):
            _fail("release explanation did not record resolved publish-signing evidence")
    elif gate_status != "ready" or review_codes:
        _fail("ready_to_publish requires a ready or solely resolvable release gate")
    for code, item in gate_by_code.items():
        expected = "review" if code == "publish-signing" and gate_status == "review" else "ready"
        if item.get("status") != expected:
            _fail("ready_to_publish release-gate proof set is not terminally ready")
    _validate_exact_crypto_proofs(signing, verify)
    _validate_exact_ready_verification(
        verify,
        manifest=manifest,
        bundle_dir=_absolute_path(
            signing.get("bundle_dir"),
            "ready signing bundle",
        ),
    )
    manifest_names = {
        str(entry.get("name"))
        for entry in _list(manifest.get("files"), "release manifest files")
        if isinstance(entry, dict)
    }
    if SIGNING_KEYRING not in manifest_names:
        _fail("ready_to_publish manifest does not bind the verification keyring")


def _validate_exact_crypto_proofs(
    signing: dict[str, object],
    verify: dict[str, object],
) -> None:
    fingerprint = _string(
        signing.get("signer_fingerprint"),
        "ready signing fingerprint",
    )
    keyring_sha = _string(
        signing.get("verification_keyring_sha256"),
        "ready signing keyring SHA",
    )
    signature_items = _items_by_code(verify, "signature")
    expected_signature_details = {
        f"{name} has VALIDSIG from {fingerprint}." for name in SIGNATURE_NAMES
    }
    fingerprint_items = _items_by_code(verify, "signature-fingerprint")
    keyring_items = _items_by_code(verify, "signature-keyring")
    if (
        signing.get("status") != "signed"
        or len(signature_items) != len(SIGN_TARGETS)
        or any(item.get("status") != "ready" for item in signature_items)
        or {item.get("detail") for item in signature_items} != expected_signature_details
        or len(fingerprint_items) != 1
        or len(keyring_items) != 1
        or fingerprint_items[0].get("status") != "ready"
        or keyring_items[0].get("status") != "ready"
        or fingerprint_items[0].get("detail")
        != f"Externally pinned complete signer fingerprint: {fingerprint}."
        or keyring_items[0].get("detail") != f"{SIGNING_KEYRING} matches SHA256 {keyring_sha}."
    ):
        _fail("ready_to_publish lacks the exact terminal cryptographic proof set")


def _validate_exact_ready_verification(
    verify: dict[str, object],
    *,
    manifest: dict[str, object],
    bundle_dir: Path,
) -> None:
    items = [item for item in _list(verify.get("items"), "verify items") if isinstance(item, dict)]
    codes = {str(item.get("code")) for item in items}
    if codes != _READY_VERIFY_CODES:
        _fail("ready_to_publish lacks the exact terminal verification proof set")
    repeated_codes = {"signature", "manifest-file"}
    for code in _READY_VERIFY_CODES - repeated_codes:
        matching = [item for item in items if item.get("code") == code]
        if len(matching) != 1 or matching[0].get("status") != "ready":
            _fail("ready_to_publish terminal verification proofs are not exact")
    expected_read_details = {
        "manifest": str(bundle_dir / "RELEASE-MANIFEST.json"),
        "release-gate": str(bundle_dir / "RELEASE-GATE.json"),
        "signing-report": str(bundle_dir / "SIGNING-REPORT.json"),
    }
    for code, detail in expected_read_details.items():
        if _items_by_code(verify, code)[0].get("detail") != detail:
            _fail("ready_to_publish terminal report paths are not bundle-bound")
    manifest_entries = _list(manifest.get("files"), "release manifest files")
    manifest_details = {
        f"{entry.get('name')} verified." for entry in manifest_entries if isinstance(entry, dict)
    }
    verified_files = _items_by_code(verify, "manifest-file")
    if (
        len(verified_files) != len(manifest_entries)
        or any(item.get("status") != "ready" for item in verified_files)
        or {item.get("detail") for item in verified_files} != manifest_details
    ):
        _fail("ready_to_publish manifest files lack exact terminal verification")
    iso_entries = [
        entry
        for entry in manifest_entries
        if isinstance(entry, dict) and str(entry.get("name", "")).endswith(".iso")
    ]
    iso_name = str(iso_entries[0].get("name"))
    sha_items = _items_by_code(verify, "sha256sums")
    if sha_items[0].get("detail") != f"{iso_name} matches SHA256SUMS.":
        _fail("ready_to_publish terminal SHA256SUMS proof does not bind the ISO")


def _manifest_entries(value: object, label: str) -> list[dict[str, object]]:
    raw_entries = _list(value, label)
    if not raw_entries:
        _fail(f"{label} is empty")
    entries: list[dict[str, object]] = []
    names: set[str] = set()
    for index, raw_entry in enumerate(raw_entries):
        entry = _object(raw_entry, f"{label} entry {index}")
        _exact_keys(
            entry,
            {"name", "size", "sha256"},
            f"{label} entry {index}",
        )
        name = _relative_name(entry.get("name"), f"{label} entry {index} name")
        if name in names:
            _fail(f"{label} contains duplicate path {name}")
        names.add(name)
        size = _integer(entry.get("size"), f"{label} entry {name} size")
        if size < 0:
            _fail(f"{label} entry {name} has a negative size")
        if not _is_sha256(entry.get("sha256")):
            _fail(f"{label} entry {name} has a malformed SHA256")
        entries.append(entry)
    return entries


def _items_by_code(report: dict[str, object], code: str) -> list[dict[str, object]]:
    return [
        item
        for item in _list(report.get("items"), "report items")
        if isinstance(item, dict) and item.get("code") == code
    ]


def _aggregate_stage_status(statuses: tuple[str, ...]) -> str:
    if "blocked" in statuses:
        return "blocked"
    if any(status in {"planned", "review"} for status in statuses):
        return "review"
    return "ready"


def _aggregate_item_status(statuses: tuple[str, ...]) -> str:
    if "blocked" in statuses:
        return "blocked"
    if "review" in statuses:
        return "review"
    return "ready"


def _derive_drill_status(
    pipeline_status: str,
    explanation_status: str,
    verify_status: str,
) -> str:
    if "blocked" in {pipeline_status, explanation_status, verify_status}:
        return "blocked"
    if pipeline_status == "ready" and explanation_status == "ready" and verify_status == "ready":
        return "ready_to_publish"
    return "review_required"


def _bundle_identity(
    value: object,
    label: str,
) -> tuple[int, int, int, int, int, int, int]:
    raw = _list(value, label)
    if len(raw) != 7:
        _fail(f"{label} must contain exactly seven integers")
    fields = [_integer(item, f"{label} field {index}") for index, item in enumerate(raw)]
    identity = (
        fields[0],
        fields[1],
        fields[2],
        fields[3],
        fields[4],
        fields[5],
        fields[6],
    )
    if (
        identity[0] < 0
        or identity[1] <= 0
        or identity[2] != stat.S_IFDIR
        or identity[3] < 0
        or identity[4] < 0
        or identity[5] <= 0
        or identity[6] < 0
    ):
        _fail(f"{label} is not a valid stable directory identity")
    return identity


def _absolute_path(value: object, label: str) -> Path:
    text = _nonempty_string(value, label)
    if _has_control(text):
        _fail(f"{label} contains control characters")
    path = Path(text)
    if not path.is_absolute() or Path(os.path.abspath(text)) != path or str(path) != text:
        _fail(f"{label} is not a canonical absolute path")
    return path


def _optional_absolute_path(value: object, label: str) -> Path | None:
    if value is None:
        return None
    return _absolute_path(value, label)


def _optional_run_id(value: object, label: str) -> str | None:
    if value is None:
        return None
    if not is_safe_run_id(value):
        _fail(f"{label} is not a canonical safe run id")
    assert isinstance(value, str)
    return value


def _relative_name(value: object, label: str) -> str:
    name = _nonempty_string(value, label)
    path = Path(name)
    if (
        _has_control(name)
        or "\\" in name
        or path.is_absolute()
        or path.as_posix() != name
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        _fail(f"{label} is not a canonical relative path")
    return name


def _exact_keys(value: dict[str, object], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        _fail(f"{label} keys are not exact (missing={missing}, extra={extra})")


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        _fail(f"{label} must be one JSON object")
    return value


def _list(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        _fail(f"{label} must be one JSON list")
    return value


def _string_list(value: object, label: str) -> list[str]:
    raw = _list(value, label)
    values: list[str] = []
    for index, item in enumerate(raw):
        values.append(_nonempty_string(item, f"{label} item {index}"))
    return values


def _require_unique(values: list[str], label: str) -> None:
    if len(set(values)) != len(values):
        _fail(f"{label} contains duplicates")


def _enum(value: object, allowed: set[str] | frozenset[str], label: str) -> str:
    text = _string(value, label)
    if text not in allowed:
        _fail(f"{label} has no strict supported value")
    return text


def _string(value: object, label: str) -> str:
    if not isinstance(value, str):
        _fail(f"{label} must be a string")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise PublishDrillSchemaError(f"{label} is not strict UTF-8") from exc
    return value


def _nonempty_string(value: object, label: str) -> str:
    text = _string(value, label)
    if not text or "\x00" in text:
        _fail(f"{label} must be a non-empty safe string")
    return text


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        _fail(f"{label} must be a boolean")
    return value


def _integer(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        _fail(f"{label} must be an integer")
    return value


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _has_control(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def _fail(message: str) -> NoReturn:
    raise PublishDrillSchemaError(message)
