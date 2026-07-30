from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from .artifact_paths import default_output_iso
from .artifact_verification import (
    ArtifactIdentity,
    ArtifactLimits,
    ArtifactVerificationError,
    ArtifactVerificationSession,
)
from .build import BuildOptions
from .evidence_run import (
    StableParentIdentity,
    publish_regular_text,
)
from .project import Project
from .publish_drill_schema import (
    PublishDrillSchemaError,
    validate_publish_drill_report,
)
from .release_explain import ReleaseExplainReport, explain_release
from .release_pipeline import ReleasePipelineReport, run_release_pipeline
from .release_verification import (
    ReleaseVerifyItem,
    ReleaseVerifyReport,
    verify_release_bundle,
)

_DRILL_JSON_MAX_BYTES = 16 * 1024 * 1024
_DRILL_LIMITS = ArtifactLimits(
    max_open_files=16,
    max_file_bytes=_DRILL_JSON_MAX_BYTES,
    max_buffered_bytes=4 * _DRILL_JSON_MAX_BYTES,
    max_hashed_bytes=8 * _DRILL_JSON_MAX_BYTES,
    max_json_depth=256,
    max_json_nodes=1_000_000,
    max_closing_fds=64,
)


@dataclass(frozen=True)
class PublishDrillReport:
    project: Path
    project_name: str
    iso: Path
    bundle_dir: Path
    status: str
    drill: Path
    pipeline: ReleasePipelineReport
    explanation: ReleaseExplainReport
    execute_signing: bool
    evidence: dict[str, object]

    @property
    def blocked(self) -> bool:
        return self.status == "blocked"

    def to_dict(self) -> dict[str, object]:
        return {
            "project": str(self.project),
            "project_name": self.project_name,
            "iso": str(self.iso),
            "bundle_dir": str(self.bundle_dir),
            "status": self.status,
            "blocked": self.blocked,
            "drill": str(self.drill),
            "execute_signing": self.execute_signing,
            "pipeline": self.pipeline.to_dict(),
            "explanation": self.explanation.to_dict(),
            "evidence": self.evidence,
        }

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def render_text(self) -> str:
        lines = [
            "Maintainer publish drill",
            f"Project: {self.project}",
            f"ISO: {self.iso}",
            f"Bundle: {self.bundle_dir}",
            f"Status: {self.status.upper()}",
            f"Signing: {'execute' if self.execute_signing else 'plan'}",
            f"Report: {self.drill}",
            "",
            "Pipeline:",
            *[f"- [{stage.status}] {stage.name}: {stage.detail}" for stage in self.pipeline.stages],
            "",
            "Explanation:",
            f"- status: {self.explanation.status}",
            f"- markdown: {self.explanation.markdown}",
            "",
            "Next commands:",
            *[f"- {command}" for command in self.explanation.next_commands],
        ]
        return "\n".join(lines)


def run_publish_drill(
    project: Project,
    options: BuildOptions | None = None,
    *,
    iso: Path | None = None,
    bundle_dir: Path | None = None,
    execute_signing: bool = False,
    gpg_key: str | None = None,
    gpg_keyring: Path | None = None,
    boot_backend: str = "auto",
    build_run_id: str | None = None,
    boot_run_id: str | None = None,
) -> PublishDrillReport:
    options = options or BuildOptions()
    iso = Path(
        os.path.abspath(
            iso or options.output_iso or default_output_iso(project)
        )
    )
    bundle_dir = Path(
        os.path.abspath(bundle_dir or project.output_dir / "publish")
    )
    pipeline = run_release_pipeline(
        project,
        options,
        iso=iso,
        output_dir=iso.parent,
        bundle_dir=bundle_dir,
        execute_signing=execute_signing,
        gpg_key=gpg_key,
        gpg_keyring=gpg_keyring,
        run_boot_proof=boot_run_id is None,
        boot_proof_execute=True,
        boot_proof_backend=boot_backend,
        build_run_id=build_run_id,
        boot_run_id=boot_run_id,
    )
    pipeline_completed = any(
        stage.name == "verify-release" for stage in pipeline.stages
    )
    try:
        bundle_identity = bundle_dir.lstat()
    except FileNotFoundError:
        bundle_published = False
    else:
        bundle_published = (
            pipeline_completed
            and pipeline.bundle_identity is not None
            and stat.S_ISDIR(bundle_identity.st_mode)
        )
    preliminary: ReleaseVerifyReport
    evidence: dict[str, object] = {}
    evidence_problem: str | None = None
    if bundle_published:
        preliminary = verify_release_bundle(
            project,
            bundle_dir=bundle_dir,
            expected_signer_fingerprint=gpg_key,
            expected_bundle_identity=pipeline.bundle_identity,
            expected_product_iso=iso,
            expected_product_output_dir=iso.parent,
            publish_report=False,
        )
        evidence, evidence_problem = _read_drill_evidence(
            bundle_dir,
            expected_bundle_identity=pipeline.bundle_identity,
        )
    else:
        preliminary = ReleaseVerifyReport(
            project.root,
            bundle_dir,
            "blocked",
            (
                ReleaseVerifyItem(
                    "publication-receipt",
                    "blocked",
                    "Publish drill has no completed immutable bundle receipt.",
                ),
            ),
        )
    explanation = explain_release(
        project,
        iso=iso,
        bundle_dir=bundle_dir,
        write=bundle_published,
        expected_bundle_identity=pipeline.bundle_identity,
        verification=preliminary,
    )
    terminal = preliminary
    if bundle_published:
        terminal = verify_release_bundle(
            project,
            bundle_dir=bundle_dir,
            expected_signer_fingerprint=gpg_key,
            expected_bundle_identity=pipeline.bundle_identity,
            expected_product_iso=iso,
            expected_product_output_dir=iso.parent,
            publish_report=False,
        )
        terminal_problems: list[str] = []
        if terminal.to_dict() != preliminary.to_dict():
            terminal_problems.append(
                "terminal verification changed after drill evidence and explanation"
            )
        if evidence.get("verify") != terminal.to_dict():
            terminal_problems.append(
                "persisted VERIFY-REPORT.json differs from the terminal "
                "read-only verification"
            )
        if terminal_problems:
            suffix = "; ".join(terminal_problems)
            evidence = {
                **evidence,
                "terminal_verification_error": suffix,
            }
            evidence_problem = (
                f"{evidence_problem}; {suffix}"
                if evidence_problem is not None
                else suffix
            )
    status = _drill_status(
        pipeline.status,
        explanation.status,
        terminal.status,
        evidence_problem,
    )
    report = PublishDrillReport(
        project.root,
        project.name,
        iso,
        bundle_dir,
        status,
        bundle_dir / "PUBLISH-DRILL.json",
        pipeline,
        explanation,
        execute_signing,
        evidence,
    )
    if bundle_published and evidence_problem is None:
        try:
            validate_publish_drill_report(
                report.to_dict(),
                expected_project=project.root,
                expected_project_name=project.name,
                expected_bundle_dir=bundle_dir,
                expected_bundle_identity=pipeline.bundle_identity,
            )
        except PublishDrillSchemaError as exc:
            evidence = {
                **evidence,
                "drill_schema_error": str(exc),
            }
            report = PublishDrillReport(
                project.root,
                project.name,
                iso,
                bundle_dir,
                "blocked",
                bundle_dir / "PUBLISH-DRILL.json",
                pipeline,
                explanation,
                execute_signing,
                evidence,
            )
        else:
            try:
                publish_regular_text(
                    report.drill,
                    report.render_json() + "\n",
                    expected_parent_identity=pipeline.bundle_identity,
                )
            except (OSError, ValueError) as exc:
                evidence = {
                    **evidence,
                    "drill_publication_error": str(exc),
                }
                report = PublishDrillReport(
                    project.root,
                    project.name,
                    iso,
                    bundle_dir,
                    "blocked",
                    bundle_dir / "PUBLISH-DRILL.json",
                    pipeline,
                    explanation,
                    execute_signing,
                    evidence,
                )
    return report


def _read_drill_evidence(
    bundle_dir: Path,
    *,
    expected_bundle_identity: StableParentIdentity | None = None,
) -> tuple[dict[str, object], str | None]:
    session: ArtifactVerificationSession | None = None
    evidence: dict[str, object] = {}
    try:
        session = ArtifactVerificationSession(
            Path(os.path.abspath(bundle_dir)),
            label="publish drill terminal evidence",
            limits=_DRILL_LIMITS,
        )
        if (
            expected_bundle_identity is not None
            and _stable_directory_identity(session.anchor_identity)
            != expected_bundle_identity
        ):
            raise ArtifactVerificationError(
                "publish drill bundle differs from the published receipt"
            )
        for key, name in (
            ("release_gate", "RELEASE-GATE.json"),
            ("manifest", "RELEASE-MANIFEST.json"),
            ("signing", "SIGNING-REPORT.json"),
            ("verify", "VERIFY-REPORT.json"),
        ):
            evidence[key] = session.file(
                Path(name),
                label=f"publish drill {name}",
                max_bytes=_DRILL_JSON_MAX_BYTES,
            ).json_object()
        session.seal()
    except (ArtifactVerificationError, OSError, ValueError) as exc:
        return {}, f"terminal evidence did not seal: {exc}"
    finally:
        if session is not None:
            session.close()
    return evidence, None


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


def _drill_status(
    pipeline_status: str,
    explanation_status: str,
    terminal_status: str,
    evidence_problem: str | None,
) -> str:
    if evidence_problem is not None or "blocked" in {
        pipeline_status,
        explanation_status,
        terminal_status,
    }:
        return "blocked"
    if (
        pipeline_status == "ready"
        and explanation_status == "ready"
        and terminal_status == "ready"
    ):
        return "ready_to_publish"
    return "review_required"
