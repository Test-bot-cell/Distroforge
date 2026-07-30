from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass, replace
from pathlib import Path

from .artifact_paths import default_output_iso
from .artifact_verification import (
    ArtifactVerificationError,
    ArtifactVerificationSession,
)
from .beginner_iso import repair_beginner_iso_release_artifacts
from .boot_proof import run_boot_proof
from .build import BuildOptions
from .evidence_run import StableParentIdentity, publish_regular_text
from .project import Project
from .publish_bundle import create_publish_bundle
from .release_gate import ReleaseGateReport
from .release_notes import write_release_notes
from .release_run import (
    ExecutedReleaseRun,
    embedded_boot_run_id,
    select_executed_release_run,
)
from .release_signing import _manifest_content, sign_release_bundle
from .release_verification import verify_release_bundle


@dataclass(frozen=True)
class ReleasePipelineStage:
    name: str
    status: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "status": self.status, "detail": self.detail}


@dataclass(frozen=True)
class ReleasePipelineReport:
    project: Path
    bundle_dir: Path
    status: str
    stages: tuple[ReleasePipelineStage, ...]
    bundle_identity: StableParentIdentity | None = None
    build_run_id: str | None = None
    boot_run_id: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "project": str(self.project),
            "bundle_dir": str(self.bundle_dir),
            "status": self.status,
            "stages": [stage.to_dict() for stage in self.stages],
            "bundle_identity": (
                list(self.bundle_identity)
                if self.bundle_identity is not None
                else None
            ),
            "build_run_id": self.build_run_id,
            "boot_run_id": self.boot_run_id,
        }

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def render_text(self) -> str:
        lines = [
            "Maintainer release pipeline",
            f"Project: {self.project}",
            f"Bundle: {self.bundle_dir}",
            f"Build run: {self.build_run_id or 'not selected'}",
            f"Boot run: {self.boot_run_id or 'not selected'}",
            f"Status: {self.status.upper()}",
            "",
        ]
        lines.extend(f"[{stage.status}] {stage.name}: {stage.detail}" for stage in self.stages)
        return "\n".join(lines)


def run_release_pipeline(
    project: Project,
    options: BuildOptions | None = None,
    *,
    iso: Path | None = None,
    output_dir: Path | None = None,
    bundle_dir: Path | None = None,
    execute_signing: bool = False,
    gpg_key: str | None = None,
    gpg_keyring: Path | None = None,
    run_boot_proof: bool = False,
    boot_proof_execute: bool = True,
    boot_proof_backend: str = "auto",
    build_run_id: str | None = None,
    boot_run_id: str | None = None,
) -> ReleasePipelineReport:
    options = options or BuildOptions()
    iso = Path(
        os.path.abspath(
            iso or options.output_iso or default_output_iso(project)
        )
    )
    output_dir = Path(os.path.abspath(output_dir or iso.parent))
    bundle_dir = Path(
        os.path.abspath(bundle_dir or project.output_dir / "publish")
    )
    stages: list[ReleasePipelineStage] = []
    effective_build_run_id: str | None = None
    effective_boot_run_id: str | None = None
    if run_boot_proof and boot_run_id is not None:
        stages.append(
            ReleasePipelineStage(
                "boot-proof",
                "blocked",
                "A pipeline cannot both reuse --boot-run-id and create a new "
                "boot proof; choose one causal source.",
            )
        )
        return ReleasePipelineReport(
            project.root,
            bundle_dir,
            "blocked",
            tuple(stages),
        )
    try:
        iso_identity = iso.lstat()
    except FileNotFoundError:
        iso_is_regular = False
    else:
        iso_is_regular = stat.S_ISREG(iso_identity.st_mode)

    selected_build: ExecutedReleaseRun | None = None
    selection_session: ArtifactVerificationSession | None = None
    selection_required = (
        run_boot_proof
        or build_run_id is not None
        or boot_run_id is not None
    )
    if iso_is_regular:
        selection_session = ArtifactVerificationSession(
            Path("/"),
            label="release pipeline build-run selection",
        )
        try:
            selected_build = select_executed_release_run(
                project,
                iso,
                output_dir,
                selection_session,
                build_run_id=build_run_id,
            )
            effective_build_run_id = selected_build.run_id
            embedded_boot = embedded_boot_run_id(selected_build)
            effective_boot_run_id = boot_run_id or embedded_boot
        except (
            ArtifactVerificationError,
            OSError,
            UnicodeError,
            TypeError,
            ValueError,
            OverflowError,
            RecursionError,
        ) as exc:
            selection_session.close()
            selection_session = None
            selected_build = None
            effective_build_run_id = None
            effective_boot_run_id = None
            if selection_required:
                stages.append(
                    ReleasePipelineStage(
                        "build-run-selection",
                        "blocked",
                        "Boot/release processing was not started because the "
                        "requested immutable build run could not be selected "
                        f"and verified: {exc}",
                    )
                )
                return ReleasePipelineReport(
                    project.root,
                    bundle_dir,
                    "blocked",
                    tuple(stages),
                )
            # A foreign or not-yet-sealed ISO may legitimately need the beginner
            # repair path. The authoritative gate will report the exact selection
            # error later; this probe only decides whether repair is applicable.
    elif selection_required:
        stages.append(
            ReleasePipelineStage(
                "build-run-selection",
                "blocked",
                "Boot/release processing was not started because the selected "
                "ISO is missing or is not a regular file.",
            )
        )
        return ReleasePipelineReport(
            project.root,
            bundle_dir,
            "blocked",
            tuple(stages),
        )

    if iso_is_regular:
        try:
            if run_boot_proof:
                assert selected_build is not None
                assert selection_session is not None
                embedded_boot = embedded_boot_run_id(selected_build)
                if embedded_boot is not None:
                    effective_boot_run_id = embedded_boot
                    selection_session.seal()
                    stages.append(
                        ReleasePipelineStage(
                            "boot-proof",
                            "ready",
                            "Reused immutable boot run "
                            f"{embedded_boot} embedded by build "
                            f"{selected_build.run_id}; no VM was started.",
                        )
                    )
                else:
                    boot = run_boot_proof_fn(
                        project,
                        options,
                        iso=iso,
                        backend=boot_proof_backend,
                        execute=boot_proof_execute,
                        build_run_id=selected_build.run_id,
                        selected_build=selected_build,
                        selection_session=selection_session,
                    )
                    # The producer seals the descriptor-held build selection
                    # immediately after copying the ISO and before invoking its
                    # backend. This second call is deliberately idempotent and
                    # also protects test doubles or alternate producers.
                    selection_session.seal()
                    effective_boot_run_id = boot.run_id or None
                    stages.append(
                        ReleasePipelineStage(
                            "boot-proof",
                            boot.status,
                            "; ".join(boot.notes),
                        )
                    )
            elif selection_session is not None:
                selection_session.seal()
        except (
            ArtifactVerificationError,
            OSError,
            UnicodeError,
            TypeError,
            ValueError,
            OverflowError,
            RecursionError,
        ) as exc:
            stages.append(
                ReleasePipelineStage(
                    "build-run-closure",
                    "blocked",
                    "The immutable build selection changed before boot/release "
                    f"processing and was refused: {exc}",
                )
            )
            return ReleasePipelineReport(
                project.root,
                bundle_dir,
                "blocked",
                tuple(stages),
            )
        finally:
            if selection_session is not None:
                selection_session.close()
        if not run_boot_proof:
            if effective_boot_run_id is None:
                stages.append(
                    ReleasePipelineStage(
                        "boot-proof",
                        "review",
                        "No immutable boot run is selected; the release gate "
                        "must refuse publication until one is proven.",
                    )
                )
            else:
                stages.append(
                    ReleasePipelineStage(
                        "boot-proof",
                        "ready",
                        "Selected immutable boot run "
                        f"{effective_boot_run_id} for authoritative gate "
                        "validation; no VM was started.",
                    )
                )
        if effective_build_run_id is not None:
            stages.append(
                ReleasePipelineStage(
                    "repair-artifacts",
                    "ready",
                    "Skipped reconstruction because immutable build run "
                    f"{effective_build_run_id} is the authority; compatibility "
                    "aliases were not read or rewritten.",
                )
            )
        else:
            repair = repair_beginner_iso_release_artifacts(
                project,
                replace(options, output_iso=iso),
            )
            repair_detail = (
                "repaired: " + ", ".join(repair.repaired)
                if repair.repaired
                else (
                    "already present and preserved"
                    if repair.status == "ready"
                    else "; ".join(repair.skipped)
                )
            )
            stages.append(
                ReleasePipelineStage(
                    "repair-artifacts",
                    repair.status,
                    repair_detail,
                )
            )
            if repair.status != "ready":
                return ReleasePipelineReport(
                    project.root,
                    bundle_dir,
                    "blocked",
                    tuple(stages),
                    build_run_id=effective_build_run_id,
                    boot_run_id=effective_boot_run_id,
                )
    else:
        stages.append(
            ReleasePipelineStage(
                "repair-artifacts",
                "review",
                "ISO is missing or unsafe; derivable release artifacts were not repaired.",
            )
        )
    bundle = create_publish_bundle(
        project,
        options,
        iso=iso,
        output_dir=output_dir,
        bundle_dir=bundle_dir,
        build_run_id=effective_build_run_id,
        boot_run_id=effective_boot_run_id,
    )
    # Requested or provisional strings are not selected identities.  Only the
    # gate may promote run IDs into the final pipeline report.
    selected_build_run_id = bundle.gate.build_run_id
    selected_boot_run_id = bundle.gate.boot_run_id
    bundle_detail = str(bundle.bundle_dir)
    if bundle.missing:
        bundle_detail += "; " + "; ".join(bundle.missing)
    stages.append(
        ReleasePipelineStage("publish-bundle", bundle.status, bundle_detail)
    )
    if (
        bundle.missing
        or not bundle.copied
        or bundle.publication_identity is None
    ):
        return ReleasePipelineReport(
            project.root,
            bundle.bundle_dir,
            "blocked",
            tuple(stages),
            build_run_id=selected_build_run_id,
            boot_run_id=selected_boot_run_id,
        )
    try:
        published_bundle = bundle.bundle_dir.lstat()
    except FileNotFoundError:
        return ReleasePipelineReport(
            project.root,
            bundle.bundle_dir,
            "blocked",
            tuple(stages),
            build_run_id=selected_build_run_id,
            boot_run_id=selected_boot_run_id,
        )
    if not stat.S_ISDIR(published_bundle.st_mode):
        return ReleasePipelineReport(
            project.root,
            bundle.bundle_dir,
            "blocked",
            tuple(stages),
            build_run_id=selected_build_run_id,
            boot_run_id=selected_boot_run_id,
        )
    safe_execute_signing = execute_signing and not bundle.blocked
    first_sign = sign_release_bundle(
        project,
        bundle_dir=bundle.bundle_dir,
        execute=False,
        gpg_key=gpg_key,
        gpg_keyring=gpg_keyring,
        expected_bundle_identity=bundle.publication_identity,
        expected_product_iso=iso,
        expected_product_output_dir=output_dir,
        publish_artifacts=False,
    )
    stages.append(
        ReleasePipelineStage(
            "manifest-plan",
            "ready" if first_sign.status == "planned" else first_sign.status,
            f"{len(first_sign.planned)} signature targets.",
        )
    )
    provisional_manifest = json.loads(
        _manifest_content(
            project,
            bundle.bundle_dir,
            bundle.gate.status,
            first_sign.manifest_entries,
        )
    )
    notes = write_release_notes(
        project,
        bundle_dir=bundle.bundle_dir,
        expected_bundle_identity=bundle.publication_identity,
        manifest_override=provisional_manifest,
        signing_override=first_sign.to_dict(),
    )
    stages.append(
        ReleasePipelineStage(
            "release-notes",
            "ready" if notes.written else "blocked",
            f"{notes.notes.name}, {notes.changelog.name}",
        )
    )
    final_sign = sign_release_bundle(
        project,
        bundle_dir=bundle.bundle_dir,
        execute=safe_execute_signing,
        gpg_key=gpg_key,
        gpg_keyring=gpg_keyring,
        expected_bundle_identity=bundle.publication_identity,
        expected_product_iso=iso,
        expected_product_output_dir=output_dir,
        # A non-executing pipeline is itself a sealed rehearsal bundle.  The
        # standalone sign-release plan remains non-mutating by default.
        publish_artifacts=True,
    )
    stages.append(ReleasePipelineStage("sign-release-final", final_sign.status, f"{len(final_sign.planned or final_sign.signed)} signature targets."))
    verify = verify_release_bundle(
        project,
        bundle_dir=bundle.bundle_dir,
        expected_signer_fingerprint=gpg_key,
        expected_bundle_identity=bundle.publication_identity,
        expected_product_iso=iso,
        expected_product_output_dir=output_dir,
    )
    stages.append(ReleasePipelineStage("verify-release", verify.status, f"{len(verify.items)} verification checks."))
    if verify.status == "ready" and _sole_publish_signing_review(bundle.gate):
        for index, stage in enumerate(stages):
            if stage.name == "publish-bundle" and stage.status == "review":
                stages[index] = ReleasePipelineStage(
                    "publish-bundle",
                    "ready",
                    stage.detail
                    + "; pre-signing review resolved by terminal verification",
                )
                break
    status = "blocked" if any(stage.status == "blocked" for stage in stages) else "review" if any(stage.status in {"review", "planned"} for stage in stages) else "ready"
    report = ReleasePipelineReport(
        project.root,
        bundle.bundle_dir,
        status,
        tuple(stages),
        bundle.publication_identity,
        selected_build_run_id,
        selected_boot_run_id,
    )
    try:
        publish_regular_text(
            bundle.bundle_dir / "RELEASE-PIPELINE.json",
            report.render_json() + "\n",
            expected_parent_identity=bundle.publication_identity,
        )
    except (OSError, ValueError) as exc:
        stages.append(
            ReleasePipelineStage(
                "release-pipeline-report",
                "blocked",
                f"RELEASE-PIPELINE.json was not published: {exc}",
            )
        )
        report = ReleasePipelineReport(
            project.root,
            bundle.bundle_dir,
            "blocked",
            tuple(stages),
            bundle.publication_identity,
            selected_build_run_id,
            selected_boot_run_id,
        )
    return report


def run_boot_proof_fn(
    project: Project,
    options: BuildOptions,
    *,
    iso: Path,
    backend: str,
    execute: bool,
    build_run_id: str | None = None,
    selected_build: ExecutedReleaseRun | None = None,
    selection_session: ArtifactVerificationSession | None = None,
):
    return run_boot_proof(
        project,
        options,
        iso=iso,
        backend=backend,
        execute=execute,
        build_run_id=build_run_id,
        _selected_build=selected_build,
        _selection_session=selection_session,
    )


def _sole_publish_signing_review(gate: ReleaseGateReport) -> bool:
    review_codes = {
        item.code for item in gate.items if item.status == "review"
    }
    return (
        gate.status == "review"
        and review_codes == {"publish-signing"}
        and not any(item.status == "blocked" for item in gate.items)
    )
