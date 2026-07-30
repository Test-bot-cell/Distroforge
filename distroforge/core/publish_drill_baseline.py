from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass, replace
from pathlib import Path

from .artifact_verification import (
    ArtifactIdentity,
    ArtifactLimits,
    ArtifactVerificationError,
    ArtifactVerificationSession,
)
from .evidence_run import (
    ImmutableCopyReceipt,
    StableParentIdentity,
    publish_regular_text,
)
from .project import Project
from .publish_drill_schema import validate_publish_drill_report
from .release_signing import full_fingerprint
from .release_verification import ReleaseVerifyReport, verify_release_bundle

_DRILL_MAX_BYTES = 16 * 1024 * 1024
_REPORT_MAX_BYTES = 4 * 1024 * 1024
_BASELINE_LIMITS = ArtifactLimits(
    max_open_files=4,
    max_file_bytes=_DRILL_MAX_BYTES,
    max_buffered_bytes=_DRILL_MAX_BYTES,
    max_hashed_bytes=2 * _DRILL_MAX_BYTES,
    max_json_depth=256,
    max_json_nodes=1_000_000,
    max_closing_fds=32,
)
_LOCAL_BASELINE_READ_LIMITS = ArtifactLimits(
    max_open_files=2,
    max_file_bytes=_DRILL_MAX_BYTES,
    max_buffered_bytes=_DRILL_MAX_BYTES + _REPORT_MAX_BYTES,
    max_hashed_bytes=2 * (_DRILL_MAX_BYTES + _REPORT_MAX_BYTES),
    max_json_depth=256,
    max_json_nodes=1_000_000,
    max_closing_fds=32,
)


@dataclass(frozen=True)
class PublishDrillBaselineReport:
    project: Path
    bundle_dir: Path
    source: Path
    baseline: Path
    report: Path
    status: str
    promoted: bool
    allow_blocked: bool
    reason: str
    baseline_size: int | None = None
    baseline_sha256: str | None = None

    @property
    def blocked(self) -> bool:
        return self.status == "blocked"

    def to_dict(self) -> dict[str, object]:
        return {
            "project": str(self.project),
            "bundle_dir": str(self.bundle_dir),
            "source": str(self.source),
            "baseline": str(self.baseline),
            "report": str(self.report),
            "status": self.status,
            "blocked": self.blocked,
            "promoted": self.promoted,
            "allow_blocked": self.allow_blocked,
            "reason": self.reason,
            "baseline_size": self.baseline_size,
            "baseline_sha256": self.baseline_sha256,
        }

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def render_text(self) -> str:
        return "\n".join(
            [
                "Publish drill baseline",
                f"Project: {self.project}",
                f"Bundle: {self.bundle_dir}",
                f"Status: {self.status.upper()}",
                f"Promoted: {self.promoted}",
                f"Source: {self.source}",
                f"Baseline: {self.baseline}",
                f"Report: {self.report}",
                f"Reason: {self.reason}",
                f"Baseline size: {self.baseline_size}",
                f"Baseline SHA256: {self.baseline_sha256}",
            ]
        )


def promote_publish_drill_baseline(
    project: Project,
    *,
    bundle_dir: Path | None = None,
    allow_blocked: bool = False,
    expected_signer_fingerprint: str | None = None,
    expected_product_iso: Path | None = None,
    expected_product_output_dir: Path | None = None,
) -> PublishDrillBaselineReport:
    bundle_dir = Path(os.path.abspath(bundle_dir or project.output_dir / "publish"))
    source = bundle_dir / "PUBLISH-DRILL.json"
    baseline = bundle_dir / "PUBLISH-DRILL.previous.json"
    report_path = bundle_dir / "PUBLISH-DRILL-BASELINE.json"
    refusal_report_path = bundle_dir / "PUBLISH-DRILL-BASELINE-REFUSAL.json"
    session: ArtifactVerificationSession | None = None
    bundle_identity: StableParentIdentity | None = None
    source_text = ""
    source_receipt: ImmutableCopyReceipt | None = None
    drill_status = "missing"
    opening_verification: ReleaseVerifyReport | None = None
    try:
        session = ArtifactVerificationSession(
            bundle_dir,
            label="publish drill baseline promotion",
            limits=_BASELINE_LIMITS,
        )
        bundle_identity = _stable_directory_identity(session.anchor_identity)
        handle = session.file(
            Path(source.name),
            label="publish drill baseline source",
            max_bytes=_DRILL_MAX_BYTES,
        )
        data = handle.json_object()
        drill_status = validate_publish_drill_report(
            data,
            expected_project=project.root,
            expected_project_name=project.name,
            expected_bundle_dir=bundle_dir,
            expected_bundle_identity=bundle_identity,
        ).status
        drill_iso_value = data.get("iso")
        if not isinstance(drill_iso_value, str):
            raise ArtifactVerificationError(
                "validated publish drill has no canonical ISO path"
            )
        if expected_product_iso is None:
            expected_product_iso = Path(drill_iso_value)
        if expected_product_output_dir is None:
            expected_product_output_dir = expected_product_iso.parent
        if drill_status == "ready_to_publish":
            expected_fingerprint = full_fingerprint(
                expected_signer_fingerprint
            )
            if expected_fingerprint is None:
                raise ArtifactVerificationError(
                    "ready_to_publish baseline promotion requires an explicitly "
                    "trusted complete signer fingerprint"
                )
            opening_verification = verify_release_bundle(
                project,
                bundle_dir=bundle_dir,
                expected_signer_fingerprint=expected_fingerprint,
                expected_bundle_identity=bundle_identity,
                expected_product_iso=expected_product_iso,
                expected_product_output_dir=expected_product_output_dir,
                publish_report=False,
            )
            evidence = data.get("evidence")
            persisted_verification = (
                evidence.get("verify")
                if isinstance(evidence, dict)
                else None
            )
            if (
                opening_verification.status != "ready"
                or opening_verification.to_dict() != persisted_verification
            ):
                raise ArtifactVerificationError(
                    "ready_to_publish drill was not reproduced by the live "
                    "descriptor-bound verifier"
                )
        source_text = handle.read_text()
        source_receipt = ImmutableCopyReceipt(
            size=handle.identity.size,
            sha256=handle.digest(),
        )
        session.seal()
    except Exception as exc:
        report = PublishDrillBaselineReport(
            project.root,
            bundle_dir,
            source,
            baseline,
            refusal_report_path,
            "blocked",
            False,
            allow_blocked,
            f"PUBLISH-DRILL.json could not be verified safely: {exc}",
        )
        return _publish_report(report, bundle_identity)
    finally:
        if session is not None:
            session.close()

    if drill_status == "blocked" and not allow_blocked:
        report = PublishDrillBaselineReport(
            project.root,
            bundle_dir,
            source,
            baseline,
            refusal_report_path,
            "blocked",
            False,
            allow_blocked,
            "Refused to promote blocked drill without --allow-blocked.",
        )
        return _publish_report(report, bundle_identity)

    assert bundle_identity is not None
    assert source_receipt is not None
    try:
        published_receipt = publish_regular_text(
            baseline,
            source_text,
            max_bytes=_DRILL_MAX_BYTES,
            expected_parent_identity=bundle_identity,
        )
        if published_receipt != source_receipt:
            raise ArtifactVerificationError(
                "published baseline differs from its held drill snapshot"
            )
    except Exception as exc:
        report = PublishDrillBaselineReport(
            project.root,
            bundle_dir,
            source,
            baseline,
            refusal_report_path,
            "blocked",
            False,
            allow_blocked,
            f"Baseline publication failed closed: {exc}",
        )
        return _publish_report(report, bundle_identity)

    if opening_verification is not None:
        expected_fingerprint = full_fingerprint(
            expected_signer_fingerprint
        )
        assert expected_fingerprint is not None
        try:
            terminal_verification = verify_release_bundle(
                project,
                bundle_dir=bundle_dir,
                expected_signer_fingerprint=expected_fingerprint,
                expected_bundle_identity=bundle_identity,
                expected_product_iso=expected_product_iso,
                expected_product_output_dir=expected_product_output_dir,
                publish_report=False,
            )
        except Exception as exc:
            report = PublishDrillBaselineReport(
                project.root,
                bundle_dir,
                source,
                baseline,
                refusal_report_path,
                "blocked",
                True,
                allow_blocked,
                "Baseline bytes were published, but terminal live verification "
                f"failed closed: {type(exc).__name__}: {exc}",
                published_receipt.size,
                published_receipt.sha256,
            )
            return _publish_report(report, bundle_identity)
        if (
            terminal_verification.status != "ready"
            or terminal_verification.to_dict()
            != opening_verification.to_dict()
        ):
            report = PublishDrillBaselineReport(
                project.root,
                bundle_dir,
                source,
                baseline,
                refusal_report_path,
                "blocked",
                True,
                allow_blocked,
                "Baseline bytes were published, but terminal live verification "
                "changed or blocked; the immutable baseline is not promoted as ready.",
                published_receipt.size,
                published_receipt.sha256,
            )
            return _publish_report(report, bundle_identity)

    report = PublishDrillBaselineReport(
        project.root,
        bundle_dir,
        source,
        baseline,
        report_path,
        "ready",
        True,
        allow_blocked,
        f"Promoted drill with status {drill_status}.",
        published_receipt.size,
        published_receipt.sha256,
    )
    return _publish_report(report, bundle_identity)


def validate_local_publish_drill_baseline(
    project: Project,
    *,
    bundle_dir: Path | None = None,
) -> str:
    """Return the status of one locally receipted comparison baseline.

    The receipt establishes only current local consistency between the
    baseline bytes and its report.  It does not authenticate which process
    created either file, is not a release attestation, and must never
    contribute to ``release_ready``.
    """

    bundle = Path(os.path.abspath(bundle_dir or project.output_dir / "publish"))
    baseline = bundle / "PUBLISH-DRILL.previous.json"
    report_path = bundle / "PUBLISH-DRILL-BASELINE.json"
    session: ArtifactVerificationSession | None = None
    try:
        session = ArtifactVerificationSession(
            bundle,
            label="local publish drill baseline receipt",
            limits=_LOCAL_BASELINE_READ_LIMITS,
        )
        baseline_handle = session.file(
            Path(baseline.name),
            label="local publish drill baseline",
            max_bytes=_DRILL_MAX_BYTES,
        )
        drill = baseline_handle.json_object()
        status = validate_publish_drill_report(
            drill,
            expected_project=project.root,
            expected_project_name=project.name,
            expected_bundle_dir=bundle,
            expected_bundle_identity=_stable_directory_identity(
                session.anchor_identity
            ),
        ).status
        receipt = session.file(
            Path(report_path.name),
            label="local publish drill baseline receipt",
            max_bytes=_REPORT_MAX_BYTES,
        ).json_object()
        problem = local_baseline_receipt_problem(
            receipt,
            expected_project=project.root,
            expected_bundle_dir=bundle,
            expected_baseline=baseline,
            baseline_size=baseline_handle.identity.size,
            baseline_sha256=baseline_handle.digest(),
        )
        if problem is not None:
            raise ArtifactVerificationError(problem)
        session.seal()
        return status
    finally:
        if session is not None:
            session.close()


def local_baseline_receipt_problem(
    value: object,
    *,
    expected_project: Path,
    expected_bundle_dir: Path,
    expected_baseline: Path,
    baseline_size: int,
    baseline_sha256: str,
) -> str | None:
    """Validate the exact non-cryptographic receipt for a local baseline."""

    if not isinstance(value, dict):
        return "publish drill baseline receipt is not an object"
    expected_keys = {
        "project",
        "bundle_dir",
        "source",
        "baseline",
        "report",
        "status",
        "blocked",
        "promoted",
        "allow_blocked",
        "reason",
        "baseline_size",
        "baseline_sha256",
    }
    if set(value) != expected_keys:
        return "publish drill baseline receipt keys are not exact"
    project = Path(os.path.abspath(expected_project))
    bundle = Path(os.path.abspath(expected_bundle_dir))
    baseline = Path(os.path.abspath(expected_baseline))
    report = bundle / "PUBLISH-DRILL-BASELINE.json"
    reason = value.get("reason")
    digest = value.get("baseline_sha256")
    if (
        value.get("project") != str(project)
        or value.get("bundle_dir") != str(bundle)
        or value.get("source") != str(bundle / "PUBLISH-DRILL.json")
        or value.get("baseline") != str(baseline)
        or value.get("report") != str(report)
        or value.get("status") != "ready"
        or value.get("blocked") is not False
        or value.get("promoted") is not True
        or not isinstance(value.get("allow_blocked"), bool)
        or not isinstance(reason, str)
        or not reason
        or any(ord(character) < 32 or ord(character) == 127 for character in reason)
        or not isinstance(value.get("baseline_size"), int)
        or isinstance(value.get("baseline_size"), bool)
        or value.get("baseline_size") != baseline_size
        or not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
        or digest != baseline_sha256
    ):
        return "publish drill baseline has no matching ready local promotion receipt"
    return None


def _publish_report(
    report: PublishDrillBaselineReport,
    bundle_identity: StableParentIdentity | None,
) -> PublishDrillBaselineReport:
    if bundle_identity is None:
        return report
    try:
        publish_regular_text(
            report.report,
            report.render_json() + "\n",
            max_bytes=_REPORT_MAX_BYTES,
            expected_parent_identity=bundle_identity,
        )
    except Exception as exc:
        return replace(
            report,
            status="blocked",
            reason=f"{report.reason} Baseline report publication failed closed: {exc}",
        )
    return report


def _stable_directory_identity(
    identity: ArtifactIdentity,
) -> StableParentIdentity:
    return (
        identity.dev,
        identity.ino,
        stat.S_IFMT(identity.mode),
        identity.uid,
        identity.gid,
        identity.nlink,
        identity.rdev,
    )
