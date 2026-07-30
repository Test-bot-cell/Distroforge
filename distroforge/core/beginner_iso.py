from __future__ import annotations

import json
import shlex
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from html import escape
from pathlib import Path

from .artifact_paths import default_artifact_paths
from .artifact_verification import (
    ArtifactIdentity,
    ArtifactLimits,
    ArtifactVerificationError,
    ArtifactVerificationSession,
)
from .boot_proof import run_boot_proof
from .build import BuildOptions, ProgressCallback
from .build_diagnosis import classify_log
from .build_journey import apply_journey_step, check_journey_step
from .build_memory import BuildAttempt, BuildMemory, options_signature
from .definition import definition_from_project, write_definition
from .dry_run_report import generate_dry_run_report
from .evidence_run import StableParentIdentity, publish_regular_text
from .iso_build import run_iso_build
from .project import Project
from .release_gate import ReleaseGateService
from .release_run import embedded_boot_run_id, select_executed_release_run

_REPAIR_ISO_MAX_BYTES = 64 * 1024 * 1024 * 1024
_REPAIR_TEXT_MAX_BYTES = 16 * 1024 * 1024
_REPAIR_PROVENANCE_MAX_BYTES = 128 * 1024 * 1024
_REPAIR_LIMITS = ArtifactLimits(
    max_open_files=8,
    max_file_bytes=_REPAIR_ISO_MAX_BYTES,
    max_buffered_bytes=4 * _REPAIR_TEXT_MAX_BYTES,
    max_hashed_bytes=2 * _REPAIR_ISO_MAX_BYTES + 16 * _REPAIR_TEXT_MAX_BYTES,
    max_json_depth=128,
    max_json_nodes=100_000,
    max_path_components=64,
    max_closing_fds=64,
    max_inventory_entries=64,
)
_REPAIR_PROVENANCE_LIMITS = ArtifactLimits(
    max_open_files=1,
    max_file_bytes=_REPAIR_PROVENANCE_MAX_BYTES,
    max_buffered_bytes=_REPAIR_PROVENANCE_MAX_BYTES,
    max_hashed_bytes=2 * _REPAIR_PROVENANCE_MAX_BYTES,
    max_json_depth=256,
    max_json_nodes=2_000_000,
    max_path_components=64,
    max_closing_fds=16,
    max_inventory_entries=16,
)


class _RepairAnchorChanged(ArtifactVerificationError):
    """The repair output directory no longer names its opening inode."""


@dataclass(frozen=True)
class BeginnerIsoPathReport:
    project: Path
    definition: Path
    dry_run: Path | None
    command_log: Path | None
    build_evidence: Path | None
    run_manifest: Path | None
    executed: bool
    build_status: str
    gate_status: str
    notes: tuple[str, ...]
    next_command: str
    build_run_id: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "project": str(self.project),
            "definition": str(self.definition),
            "dry_run": str(self.dry_run) if self.dry_run else None,
            "command_log": str(self.command_log) if self.command_log else None,
            "build_evidence": str(self.build_evidence) if self.build_evidence else None,
            "run_manifest": str(self.run_manifest) if self.run_manifest else None,
            "executed": self.executed,
            "build_status": self.build_status,
            "gate_status": self.gate_status,
            "notes": list(self.notes),
            "next_command": self.next_command,
            "build_run_id": self.build_run_id,
        }

    def render_text(self) -> str:
        lines = [
            "Beginner ISO path",
            f"Project: {self.project}",
            f"Definition: {self.definition}",
            f"Dry-run: {self.dry_run or 'not written'}",
            f"Command log: {self.command_log or 'not written'}",
            f"ISO-BUILD evidence: {self.build_evidence or 'not written'}",
            f"Run manifest: {self.run_manifest or 'not written'}",
            f"Build run: {self.build_run_id or 'not selected'}",
            f"Build: {self.build_status}",
            f"Release gate: {self.gate_status.upper()}",
            "",
            "Steps:",
        ]
        lines.extend(f"- {note}" for note in self.notes)
        lines.extend(["", "Next:", self.next_command])
        return "\n".join(lines)

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


@dataclass(frozen=True)
class BeginnerIsoFailureReport:
    project: Path
    command_log: Path
    category: str
    title: str
    detail: str
    next_action: str
    gate_status: str

    def to_dict(self) -> dict[str, object]:
        return {
            "project": str(self.project),
            "command_log": str(self.command_log),
            "category": self.category,
            "title": self.title,
            "detail": self.detail,
            "next_action": self.next_action,
            "gate_status": self.gate_status,
        }

    def render_text(self) -> str:
        return "\n".join(
            [
                "Beginner ISO failure explanation",
                f"Project: {self.project}",
                f"Command log: {self.command_log}",
                f"Category: {self.category}",
                f"Problem: {self.title}",
                f"Detail: {self.detail}",
                f"Release gate: {self.gate_status.upper()}",
                "",
                "Next:",
                self.next_action,
            ]
        )

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


@dataclass(frozen=True)
class BeginnerIsoRepairReport:
    project: Path
    iso: Path
    status: str
    repaired: tuple[str, ...]
    skipped: tuple[str, ...]
    gate_status: str
    next_action: str

    def to_dict(self) -> dict[str, object]:
        return {
            "project": str(self.project),
            "iso": str(self.iso),
            "status": self.status,
            "repaired": list(self.repaired),
            "skipped": list(self.skipped),
            "gate_status": self.gate_status,
            "next_action": self.next_action,
        }

    def render_text(self) -> str:
        repaired = [f"- {item}" for item in self.repaired] or ["- none"]
        skipped = [f"- {item}" for item in self.skipped] or ["- none"]
        lines = [
            "Beginner ISO release artifact repair",
            f"Project: {self.project}",
            f"ISO: {self.iso}",
            f"Repair status: {self.status.upper()}",
            f"Release gate: {self.gate_status.upper()}",
            "",
            "Repaired:",
            *repaired,
            "",
            "Skipped:",
            *skipped,
            "",
            "Next:",
            self.next_action,
        ]
        return "\n".join(lines)

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


@dataclass(frozen=True)
class BeginnerIsoBootProofReport:
    project: Path
    iso: Path
    status: str
    proof: Path
    gate_status: str
    notes: tuple[str, ...]
    build_run_id: str | None = None
    boot_run_id: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "project": str(self.project),
            "iso": str(self.iso),
            "status": self.status,
            "proof": str(self.proof),
            "gate_status": self.gate_status,
            "notes": list(self.notes),
            "build_run_id": self.build_run_id,
            "boot_run_id": self.boot_run_id,
        }

    def render_text(self) -> str:
        return "\n".join(
            [
                "Beginner ISO boot proof",
                f"Project: {self.project}",
                f"ISO: {self.iso}",
                f"Status: {self.status}",
                f"Proof: {self.proof}",
                f"Build run: {self.build_run_id or 'not selected'}",
                f"Boot run: {self.boot_run_id or 'not selected'}",
                f"Release gate: {self.gate_status.upper()}",
                "",
                "Notes:",
                *[f"- {note}" for note in self.notes],
            ]
        )

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def prepare_beginner_iso_path(
    project: Project,
    *,
    apply_safe_defaults: bool = False,
    dry_run: bool = False,
    execute: bool = False,
    definition_path: Path | None = None,
    dry_run_path: Path | None = None,
    command_log_path: Path | None = None,
    progress: ProgressCallback | None = None,
    memory: BuildMemory | None = None,
) -> BeginnerIsoPathReport:
    options = BuildOptions()
    notes: list[str] = []
    if apply_safe_defaults:
        for step_id in ("source", "identity", "boot-proof", "release-evidence", "publish-gate"):
            report = apply_journey_step(project, options, step_id)
            notes.extend(report.notes)
    else:
        notes.append("Safe defaults were not applied; existing project settings were used.")
    paths = default_artifact_paths(project)
    options.output_iso = options.output_iso or paths.output_iso
    definition_path = definition_path or project.root / "beginner-iso.yaml"
    write_definition(definition_from_project(project, options, {"path": "beginner-iso"}), definition_path)
    notes.append("Wrote a reviewable beginner ISO build definition.")
    if dry_run or execute:
        dry_run_path = dry_run_path or project.root / "beginner-iso-dry-run.json"
        dry_run_report = generate_dry_run_report(project, options, run_orchestrator=False)
        dry_run_path.write_text(dry_run_report.render_json() + "\n", encoding="utf-8")
        notes.append("Wrote a non-executing dry-run report for the ISO pipeline.")
    for step_id in ("source", "identity", "boot-proof", "release-evidence", "publish-gate"):
        check = check_journey_step(project, options, step_id)
        if check.findings:
            notes.append(f"{step_id}: {check.status} - {check.findings[0]}")
    build_status = "not-run"
    build_evidence: Path | None = None
    run_manifest: Path | None = None
    build_run_id: str | None = None
    if execute:
        # run_iso_build owns the evidence reservation, command log, immutable report
        # and manifest. The beginner path must not be a friendlier-looking bypass
        # around the publication-grade entry point.
        iso_report = run_iso_build(
            project,
            options,
            execute=True,
            definition=definition_path,
            log_path=command_log_path,
        )
        build_evidence = iso_report.report
        run_manifest = iso_report.run_manifest
        build_run_id = iso_report.run_id or None
        if iso_report.status == "built":
            build_status = "completed"
            notes.append(
                "Executed the beginner ISO build workflow and sealed ISO-BUILD/RUN-MANIFEST evidence."
            )
        elif iso_report.status == "failed":
            build_status = "failed"
            detail = iso_report.failure.output if iso_report.failure else "See ISO-BUILD evidence."
            notes.append(f"Build failed; failure evidence was sealed: {detail}")
        else:
            build_status = "blocked"
            notes.append(
                "Build was blocked and produced no ISO; the blocked ISO-BUILD/RUN-MANIFEST evidence was sealed."
            )
        command_log_path = iso_report.command_log
        if memory is not None:
            category = title = ""
            if (
                build_status == "failed"
                and command_log_path is not None
                and command_log_path.exists()
            ):
                rule = classify_log(command_log_path.read_text(encoding="utf-8", errors="replace")[-12000:])
                category, title = rule.code, rule.title
            memory.record(
                BuildAttempt(
                    timestamp=datetime.now(UTC).isoformat(),
                    project=project.name,
                    outcome=build_status,
                    options_signature=options_signature(project.to_dict()),
                    category=category,
                    title=title,
                )
            )
    gate = ReleaseGateService().check(
        project,
        options,
        iso=options.output_iso,
        output_dir=options.output_iso.parent,
        build_run_id=build_run_id,
    )
    if execute and build_status == "completed":
        assert build_run_id is not None
        next_command = shlex.join(
            [
                "distroforge",
                "release-gate",
                str(project.root),
                "--definition",
                str(definition_path),
                "--iso",
                str(options.output_iso),
                "--output-dir",
                str(options.output_iso.parent),
                "--build-run-id",
                build_run_id,
            ]
        )
    elif execute:
        next_command = (
            f"Review the sealed failure evidence at {build_evidence}, fix the cause, "
            "then rerun beginner-iso --execute."
        )
    else:
        next_command = (
            f"distroforge beginner-iso {project.root} "
            "--apply-safe-defaults --dry-run --execute"
        )
    return BeginnerIsoPathReport(
        project.root,
        definition_path,
        dry_run_path if dry_run or execute else None,
        command_log_path if execute else None,
        build_evidence,
        run_manifest,
        execute,
        build_status,
        gate.status,
        tuple(notes),
        next_command,
        build_run_id,
    )


def explain_beginner_iso_failure(project: Project, command_log_path: Path | None = None) -> BeginnerIsoFailureReport:
    command_log = command_log_path or _latest_beginner_command_log(project)
    detail = "No command log was found for the last beginner ISO build."
    category = "missing-log"
    title = "No beginner ISO build log"
    next_action = "Run beginner-iso with --execute, or open Logs if the GUI job is still running."
    if command_log.exists():
        detail = command_log.read_text(encoding="utf-8", errors="replace")[-12000:]
        category, title, next_action = _classify_failure(detail)
    gate = ReleaseGateService().check(project, BuildOptions())
    if category == "unknown" and gate.blocked:
        blocked = next((item for item in gate.items if item.status == "blocked"), None)
        if blocked:
            category = "release-gate"
            title = f"Release gate blocked at {blocked.code}"
            next_action = blocked.detail
    return BeginnerIsoFailureReport(project.root, command_log, category, title, detail.strip()[:500], next_action, gate.status)


def _latest_beginner_command_log(project: Project) -> Path:
    """Resolve the last sealed build log, with the old mutable path as fallback."""

    build_alias = project.output_dir / "ISO-BUILD.json"
    if build_alias.is_file():
        try:
            payload = json.loads(build_alias.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            payload = {}
        selected = payload.get("command_log") if isinstance(payload, dict) else None
        if isinstance(selected, str):
            candidate = Path(selected)
            if not candidate.is_absolute():
                candidate = project.root / candidate
            try:
                candidate.resolve().relative_to(project.root.resolve())
            except (OSError, ValueError):
                pass
            else:
                if candidate.is_file():
                    return candidate
    return project.root / "beginner-iso-build-commands.jsonl"


def repair_beginner_iso_release_artifacts(project: Project, options: BuildOptions | None = None) -> BeginnerIsoRepairReport:
    options = options or BuildOptions()
    paths = default_artifact_paths(project)
    iso = Path(options.output_iso or paths.output_iso).absolute()
    repaired: list[str] = []
    skipped: list[str] = []
    repair_status = "ready"
    output_dir = iso.parent
    iso_session: ArtifactVerificationSession | None = None
    try:
        iso_session = ArtifactVerificationSession(
            output_dir.absolute(),
            label="beginner ISO release repair",
            limits=_REPAIR_LIMITS,
        )
        iso_handle = iso_session.file(
            Path(iso.name),
            label="beginner ISO",
            max_bytes=_REPAIR_ISO_MAX_BYTES,
        )
        digest = iso_handle.digest()
        iso_identity = iso_handle.identity
        generated_at = _identity_timestamp(iso_handle.identity.mtime_ns)
        parent_identity = _stable_repair_identity(iso_session.anchor_identity)
        iso_session.seal()
        iso_session.close()
        iso_session = None
        provenance_path = output_dir / "distroforge-provenance.json"
        provenance = _read_optional_repair_provenance(
            provenance_path,
            expected_parent_identity=parent_identity,
        )
        provenance_kind = _matching_provenance_kind(provenance, digest)
        preserve_build = provenance_kind == "build"

        _publish_or_preserve_repair_text(
            output_dir / "SHA256SUMS",
            f"{digest}  {iso.name}\n",
            repaired=repaired,
            skipped=skipped,
            preserve_existing=preserve_build,
            expected_parent_identity=parent_identity,
        )
        buildinfo_content = (
            f"Build-Date: {generated_at}\n"
            f"Artifact: {iso.name}\n"
            "Builder: DistroForge\n"
            "Repair: beginner-iso\n"
        )
        _publish_or_preserve_repair_text(
            output_dir / "BUILDINFO",
            buildinfo_content,
            repaired=repaired,
            skipped=skipped,
            preserve_existing=preserve_build,
            expected_parent_identity=parent_identity,
        )
        if provenance_kind:
            skipped.append(
                "Existing build provenance already matches the ISO; it was preserved."
                if preserve_build
                else "Existing reconstructed provenance already matches the ISO; it was preserved."
            )
        else:
            provenance_content = (
                json.dumps(
                    {
                        "schema": "distroforge.provenance.v2",
                        "attestation_kind": "reconstructed",
                        "generated_at": generated_at,
                        "project": project.to_dict(),
                        "output_iso": str(iso),
                        "output_iso_sha256": digest,
                        "repair": "beginner-iso-release-artifacts",
                    },
                    indent=2,
                )
                + "\n"
            )
            _publish_or_preserve_repair_text(
                provenance_path,
                provenance_content,
                repaired=repaired,
                skipped=skipped,
                preserve_existing=False,
                expected_parent_identity=parent_identity,
            )
        html_name = options.html_report.filename if options.html_report.enabled else "report.html"
        _publish_or_preserve_repair_text(
            output_dir / html_name,
            _minimal_html_report(project, iso, digest),
            repaired=repaired,
            skipped=skipped,
            preserve_existing=preserve_build,
            expected_parent_identity=parent_identity,
        )
        _revalidate_repair_iso(
            iso,
            identity=iso_identity,
            expected_sha256=digest,
            expected_parent_identity=parent_identity,
        )
        skipped.append("Boot proof was not repaired; run QEMU/bootcheck/QA to prove bootability.")
    except ArtifactVerificationError as exc:
        repair_status = "blocked"
        repaired.clear()
        skipped.append(
            "ISO is missing or unsafe; release artifact repair was refused: "
            f"{exc}. Any complete immutable file left by a concurrent change is "
            "non-authoritative; retry in a fresh output directory."
        )
    finally:
        if iso_session is not None:
            iso_session.close()
    gate = ReleaseGateService().check(project, options, iso=iso, output_dir=iso.parent)
    next_action = (
        "Use a fresh output directory before retrying the repair."
        if repair_status == "blocked"
        else (
            "Run boot proof and release-gate again."
            if gate.status != "ready"
            else "Release gate is ready."
        )
    )
    return BeginnerIsoRepairReport(
        project.root,
        iso,
        repair_status,
        tuple(repaired),
        tuple(skipped),
        gate.status,
        next_action,
    )


def _read_optional_repair_provenance(
    path: Path,
    *,
    expected_parent_identity: StableParentIdentity,
) -> dict[str, object] | None:
    session: ArtifactVerificationSession | None = None
    try:
        session = ArtifactVerificationSession(
            path.parent.absolute(),
            label="beginner ISO provenance",
            limits=_REPAIR_PROVENANCE_LIMITS,
        )
        _require_repair_anchor(session, expected_parent_identity)
        payload = session.file(
            Path(path.name),
            label="beginner ISO provenance",
            max_bytes=_REPAIR_PROVENANCE_MAX_BYTES,
        ).json_object()
        session.seal()
        return payload
    except _RepairAnchorChanged:
        raise
    except ArtifactVerificationError:
        return None
    finally:
        if session is not None:
            session.close()


def _matching_provenance_kind(
    data: dict[str, object] | None,
    iso_sha256: str,
) -> str:
    if (
        data is None
        or data.get("schema") != "distroforge.provenance.v2"
        or data.get("output_iso_sha256") != iso_sha256
    ):
        return ""
    kind = data.get("attestation_kind")
    return (
        kind
        if isinstance(kind, str) and kind in {"build", "reconstructed"}
        else ""
    )


def _publish_or_preserve_repair_text(
    path: Path,
    content: str,
    *,
    repaired: list[str],
    skipped: list[str],
    preserve_existing: bool,
    expected_parent_identity: StableParentIdentity,
) -> None:
    encoded = content.encode("utf-8", errors="strict")
    max_bytes = max(len(encoded), 1)
    if preserve_existing and _existing_bounded_regular(
        path,
        expected_parent_identity=expected_parent_identity,
    ):
        skipped.append(
            f"Existing {path.name} belongs to sealed build evidence; it was preserved."
        )
        return
    try:
        publish_regular_text(
            path,
            content,
            max_bytes=_REPAIR_TEXT_MAX_BYTES,
            expected_parent_identity=expected_parent_identity,
        )
    except (OSError, ValueError) as exc:
        raise ArtifactVerificationError(
            f"{path.name} repair was refused: {exc}"
        ) from exc
    _verify_repair_text(
        path,
        encoded,
        max_bytes=max_bytes,
        expected_parent_identity=expected_parent_identity,
    )
    repaired.append(path.name)


def _verify_repair_text(
    path: Path,
    expected: bytes,
    *,
    max_bytes: int,
    expected_parent_identity: StableParentIdentity,
) -> None:
    session = ArtifactVerificationSession(
        path.parent.absolute(),
        label=f"published {path.name}",
        limits=ArtifactLimits(
            max_open_files=1,
            max_file_bytes=max_bytes,
            max_buffered_bytes=max_bytes,
            max_hashed_bytes=2 * max_bytes,
            max_path_components=64,
            max_closing_fds=16,
            max_inventory_entries=16,
        ),
    )
    try:
        _require_repair_anchor(session, expected_parent_identity)
        body = session.file(
            Path(path.name),
            label=f"published {path.name}",
            max_bytes=max_bytes,
            allow_empty=True,
        ).read_bytes()
        if body != expected:
            raise ArtifactVerificationError(
                f"published {path.name} does not contain the expected bytes"
            )
        session.seal()
    finally:
        session.close()


def _existing_bounded_regular(
    path: Path,
    *,
    expected_parent_identity: StableParentIdentity,
) -> bool:
    session: ArtifactVerificationSession | None = None
    opened = False
    try:
        session = ArtifactVerificationSession(
            path.parent.absolute(),
            label=f"existing {path.name}",
            limits=ArtifactLimits(
                max_open_files=1,
                max_file_bytes=_REPAIR_TEXT_MAX_BYTES,
                max_buffered_bytes=_REPAIR_TEXT_MAX_BYTES,
                max_hashed_bytes=2 * _REPAIR_TEXT_MAX_BYTES,
                max_path_components=64,
                max_closing_fds=16,
                max_inventory_entries=16,
            ),
        )
        _require_repair_anchor(session, expected_parent_identity)
        session.file(
            Path(path.name),
            label=f"existing {path.name}",
            max_bytes=_REPAIR_TEXT_MAX_BYTES,
            allow_empty=True,
        ).read_bytes()
        opened = True
        session.seal()
        return True
    except _RepairAnchorChanged:
        raise
    except ArtifactVerificationError as exc:
        if not opened and _caused_by_missing_file(exc):
            return False
        raise
    finally:
        if session is not None:
            session.close()


def _identity_timestamp(mtime_ns: int) -> str:
    seconds, nanoseconds = divmod(mtime_ns, 1_000_000_000)
    return datetime.fromtimestamp(seconds, UTC).replace(
        microsecond=nanoseconds // 1_000
    ).isoformat()


def _revalidate_repair_iso(
    iso: Path,
    *,
    identity: ArtifactIdentity,
    expected_sha256: str,
    expected_parent_identity: StableParentIdentity,
) -> None:
    session = ArtifactVerificationSession(
        iso.parent.absolute(),
        label="beginner ISO repair closure",
        limits=_REPAIR_LIMITS,
    )
    try:
        _require_repair_anchor(session, expected_parent_identity)
        handle = session.file(
            Path(iso.name),
            label="beginner ISO",
            max_bytes=_REPAIR_ISO_MAX_BYTES,
        )
        if handle.identity != identity:
            raise ArtifactVerificationError(
                "beginner ISO changed while release artifacts were repaired"
            )
        if handle.digest() != expected_sha256:
            raise ArtifactVerificationError(
                "beginner ISO bytes changed while release artifacts were repaired"
            )
        session.seal()
    finally:
        session.close()


def _stable_repair_identity(identity: ArtifactIdentity) -> StableParentIdentity:
    return (
        identity.dev,
        identity.ino,
        stat.S_IFMT(identity.mode),
        identity.uid,
        identity.gid,
        identity.nlink,
        identity.rdev,
    )


def _require_repair_anchor(
    session: ArtifactVerificationSession,
    expected: StableParentIdentity,
) -> None:
    if _stable_repair_identity(session.anchor_identity) != expected:
        raise _RepairAnchorChanged(
            "beginner ISO output directory changed during release artifact repair"
        )


def _caused_by_missing_file(exc: BaseException) -> bool:
    current: BaseException | None = exc
    while current is not None:
        if isinstance(current, FileNotFoundError):
            return True
        current = current.__cause__
    return False


def run_beginner_iso_boot_proof(
    project: Project,
    options: BuildOptions | None = None,
    *,
    execute: bool = True,
    build_run_id: str | None = None,
) -> BeginnerIsoBootProofReport:
    options = options or BuildOptions()
    paths = default_artifact_paths(project)
    iso = Path(options.output_iso or paths.output_iso).absolute()
    proof = project.output_dir / "evidence" / "plans" / "unselected" / "boot-proof.json"
    notes: list[str] = []
    status = "blocked"
    selected_build_run_id: str | None = None
    boot_run_id: str | None = None
    options.prebuild_vm.enabled = True
    if execute:
        selection_session = ArtifactVerificationSession(
            Path("/"),
            label="beginner boot-proof build-run selection",
        )
        try:
            selected = select_executed_release_run(
                project,
                iso,
                iso.parent,
                selection_session,
                build_run_id=build_run_id,
            )
            selected_build_run_id = selected.run_id
            embedded_boot = embedded_boot_run_id(selected)
            if embedded_boot is not None:
                boot_run_id = embedded_boot
                proof = (
                    iso.parent
                    / "evidence"
                    / "runs"
                    / embedded_boot
                    / "boot-proof.json"
                )
                selection_session.seal()
                status = "ready"
                notes.append(
                    "Reused immutable boot run "
                    f"{embedded_boot} embedded by build {selected.run_id}; "
                    "no VM was started."
                )
            else:
                boot = run_boot_proof(
                    project,
                    options,
                    iso=iso,
                    backend="qemu",
                    execute=True,
                    build_run_id=selected.run_id,
                    _selected_build=selected,
                    _selection_session=selection_session,
                )
                selection_session.seal()
                proof = boot.immutable_proof or boot.proof
                boot_run_id = boot.run_id or None
                status = boot.status
                notes.extend(boot.notes)
        except (
            ArtifactVerificationError,
            OSError,
            UnicodeError,
            TypeError,
            ValueError,
            OverflowError,
            RecursionError,
        ) as exc:
            selected_build_run_id = None
            boot_run_id = None
            notes.append(
                "Boot proof was not started because the requested immutable "
                f"build run could not be selected and kept stable: {exc}"
            )
        finally:
            selection_session.close()
    elif not iso.exists():
        notes.append("ISO is missing; build or select an ISO before boot proof.")
    else:
        boot = run_boot_proof(
            project,
            options,
            iso=iso,
            backend="qemu",
            execute=False,
            build_run_id=build_run_id,
        )
        proof = boot.immutable_proof or boot.proof
        boot_run_id = boot.run_id or None
        status = boot.status
        notes.extend(boot.notes)
    gate = ReleaseGateService().check(
        project,
        options,
        iso=iso,
        output_dir=iso.parent,
        build_run_id=selected_build_run_id,
        boot_run_id=boot_run_id,
    )
    if execute and boot_run_id is not None:
        boot_gate = next(
            (item for item in gate.items if item.code == "boot-proof"),
            None,
        )
        if boot_gate is None or boot_gate.status != "ready":
            status = "blocked"
    return BeginnerIsoBootProofReport(
        project.root,
        iso,
        status,
        proof,
        gate.status,
        tuple(notes),
        selected_build_run_id,
        boot_run_id,
    )


def _classify_failure(text: str) -> tuple[str, str, str]:
    rule = classify_log(text)
    return rule.code, rule.title, rule.remediation



def _minimal_html_report(project: Project, iso: Path, digest: str) -> str:
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>DistroForge Beginner ISO Report</title></head><body>"
        f"<h1>{escape(project.name)}</h1>"
        f"<p>ISO: {escape(str(iso))}</p>"
        f"<p>SHA256: {escape(digest)}</p>"
        "<p>Generated by beginner ISO release artifact repair.</p>"
        "</body></html>"
    )
