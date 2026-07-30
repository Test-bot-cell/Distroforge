from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

from .artifact_paths import default_output_iso
from .artifact_verification import (
    ArtifactHandle,
    ArtifactIdentity,
    ArtifactLimits,
    ArtifactVerificationError,
    ArtifactVerificationSession,
)
from .build import BuildOptions
from .command import CommandError, CommandRunner
from .evidence_run import (
    copy_immutable_file,
    copy_immutable_file_descriptor,
    evidence_run_path,
    is_safe_run_id,
    new_run_id,
    publish_optional_text_alias_receipt,
    write_immutable_text,
)
from .prebuild_vm import QemuLabService, validate_qemu_report
from .project import Project
from .release_run import (
    ExecutedReleaseRun,
    embedded_boot_run_id,
    select_executed_release_run,
)
from .validate import validate_prebuild_vm_options

# The backends that start a machine. Only these can honour a firmware choice, and
# only these have a firmware worth validating before anything runs.
_QEMU_BACKENDS = frozenset({"auto", "qemu"})
BOOT_PROOF_SCHEMA = "distroforge.boot-proof.v2"
BOOT_RUN_MANIFEST_SCHEMA = "distroforge.boot-proof-run-manifest.v1"
BOOT_PROOF_ALIAS_PUBLICATION_SCHEMA = (
    "distroforge.boot-proof-alias-publication.v1"
)
BOOT_PROOF_ALIAS_PUBLICATION_NAME = "BOOT-PROOF-ALIAS-PUBLICATION.json"
_BOOT_JSON_MAX_BYTES = 16 * 1024 * 1024
_BOOT_SIDECAR_MAX_BYTES = 1024 * 1024
_BOOT_INVENTORY_MAX_ENTRIES = 4096
_BOOT_SESSION_LIMITS = ArtifactLimits(
    max_open_files=_BOOT_INVENTORY_MAX_ENTRIES,
    max_buffered_bytes=256 * 1024 * 1024,
    max_closing_fds=8192,
)


@dataclass(frozen=True)
class _RunInventory:
    anchor_identity: ArtifactIdentity
    entries: tuple[tuple[Path, ArtifactIdentity], ...]

    def by_path(self) -> dict[Path, ArtifactIdentity]:
        return dict(self.entries)


@dataclass(frozen=True)
class _MeasuredArtifact:
    identity: ArtifactIdentity
    sha256: str
    body: bytes | None = None


@dataclass(frozen=True)
class BootProofReport:
    project: Path
    iso: Path
    backend: str
    status: str
    proof: Path
    qemu_report: Path
    notes: tuple[str, ...]
    evidence: dict[str, object] | None = None
    attempted_backends: tuple[str, ...] = ()
    selected_backend: str = ""
    proof_level: str = "none"
    firmware: str = ""
    secure_boot: bool = False
    run_id: str = ""
    created_at: str = ""
    iso_sha256: str = ""
    immutable_proof: Path | None = None
    immutable_qemu_report: Path | None = None
    qemu_report_sha256: str = ""
    reached_milestone: str = ""
    build_run_id: str = ""
    command_log: Path | None = None
    run_manifest: Path | None = None
    alias_publication_receipt: Path | None = None

    @property
    def blocked(self) -> bool:
        return self.status == "blocked"

    @property
    def firmware_summary(self) -> str:
        """Which firmware the evidence is about, in the words a reader needs.

        A BIOS boot and a UEFI boot are not the same proof, and on a BIOS host the
        difference is the whole value of the report: without this line a reader has no
        way to tell a real UEFI proof from a green report about the half that already
        worked. Empty for backends that boot nothing, so the line stays absent rather
        than claiming a firmware that never ran.
        """
        if not self.firmware:
            return ""
        return f"{self.firmware} with Secure Boot" if self.secure_boot else self.firmware

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": BOOT_PROOF_SCHEMA,
            "run_id": self.run_id,
            "created_at": self.created_at,
            "project": str(self.project),
            "iso": str(self.iso),
            "iso_sha256": self.iso_sha256,
            "backend": self.backend,
            "status": self.status,
            "blocked": self.blocked,
            "proof": self.proof.name,
            "qemu_report": self.qemu_report.name,
            "notes": list(self.notes),
            "evidence": self.evidence or {},
            "attempted_backends": list(self.attempted_backends or (self.backend,)),
            "selected_backend": self.selected_backend or self.backend,
            "proof_level": self.proof_level,
            "firmware": self.firmware,
            "secure_boot": self.secure_boot,
            "immutable_proof": self.immutable_proof.name if self.immutable_proof else None,
            "immutable_qemu_report": (
                str(self.immutable_qemu_report)
                if self.immutable_qemu_report
                else None
            ),
            "qemu_report_sha256": self.qemu_report_sha256,
            "reached_milestone": self.reached_milestone,
            "build_run_id": self.build_run_id,
            "command_log": self.command_log.name if self.command_log else None,
            "run_manifest": self.run_manifest.name if self.run_manifest else None,
            "alias_publication_receipt": (
                str(self.alias_publication_receipt)
                if self.alias_publication_receipt
                else None
            ),
        }

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def render_text(self) -> str:
        lines = [
            "Boot proof",
            f"Project: {self.project}",
            f"ISO: {self.iso}",
            f"Backend: {self.backend}",
            f"Selected backend: {self.selected_backend or self.backend}",
            *([f"Firmware: {self.firmware_summary}"] if self.firmware else []),
            f"Proof level: {self.proof_level}",
            f"Status: {self.status.upper()}",
            f"Proof: {self.proof}",
            f"QEMU report alias (optional): {self.qemu_report}",
            (
                "Immutable QEMU report: "
                f"{self.immutable_qemu_report or 'not produced'}"
            ),
            (
                "Alias publication receipt: "
                f"{self.alias_publication_receipt or 'not recorded'}"
            ),
            "",
            "Notes:",
            *[f"- {note}" for note in self.notes],
        ]
        if self.evidence:
            lines.extend(["", "Evidence:"])
            for key, value in self.evidence.items():
                lines.append(f"- {key}: {value}")
        return "\n".join(lines)


def resolve_firmware(override: str, inherited: str) -> str:
    """The firmware a proof will really run -- asked once, answered here.

    An empty override means "whatever this project's own options say", so a definition
    that already describes a UEFI lab keeps describing one and the flag is only needed
    to change that answer. Deliberately the same precedence as the squashfs compressor:
    one shape for "flag beats definition beats default" is easier to trust than three.
    """
    return override or inherited


def run_boot_proof(
    project: Project,
    options: BuildOptions | None = None,
    *,
    iso: Path | None = None,
    backend: str = "auto",
    timeout: int | None = None,
    firmware: str = "",
    secure_boot: bool = False,
    execute: bool = False,
    build_run_id: str | None = None,
    _selected_build: ExecutedReleaseRun | None = None,
    _selection_session: ArtifactVerificationSession | None = None,
    _trusted_build_context: bool = False,
    _require_build_selection: bool = False,
    _build_output_dir: Path | None = None,
    _source_iso_handle: ArtifactHandle | None = None,
    _source_verification_session: ArtifactVerificationSession | None = None,
) -> BootProofReport:
    """Run one proof, optionally bound to a descriptor-held build selection.

    Public callers that supply ``build_run_id`` are verified here before any
    run directory, ISO copy, or VM command is created.  Release orchestrators
    can pass the already-selected run and its still-open session so the source
    ISO is copied from the exact descriptor that established the build
    verdict.  ``_trusted_build_context`` is reserved for the ISO producer while
    its immutable build report is not publishable yet.
    """

    options = options or BuildOptions()
    selected_iso = Path(os.path.abspath(iso or options.output_iso or default_output_iso(project)))
    source_iso_handle = _source_iso_handle
    source_verification_session = _source_verification_session
    if _selected_build is not None:
        if _selection_session is None:
            raise ValueError("descriptor-bound boot proof requires its selection session")
        if source_iso_handle is not None or source_verification_session is not None:
            raise ValueError("boot proof received two descriptor-bound ISO sources")
        if build_run_id not in {None, _selected_build.run_id}:
            raise ValueError("descriptor-bound boot proof build run id is inconsistent")
        build_run_id = _selected_build.run_id
        source_iso_handle = _selected_build.iso_handle
        source_verification_session = _selection_session
    elif _selection_session is not None:
        raise ValueError("boot proof selection session has no selected build")
    elif (source_iso_handle is None) is not (source_verification_session is None):
        raise ValueError("boot proof ISO source requires both a handle and its session")

    if (
        execute
        and (build_run_id is not None or _require_build_selection)
        and not _trusted_build_context
    ):
        if _selected_build is None:
            selection_session = ArtifactVerificationSession(
                Path("/"),
                label="boot proof build-run selection",
            )
            try:
                selected_build = select_executed_release_run(
                    project,
                    selected_iso,
                    Path(os.path.abspath(_build_output_dir or selected_iso.parent)),
                    selection_session,
                    build_run_id=build_run_id,
                )
            except (
                ArtifactVerificationError,
                OSError,
                UnicodeError,
                TypeError,
                ValueError,
                OverflowError,
                RecursionError,
            ) as exc:
                report = _blocked_build_selection_report(
                    project,
                    options,
                    selected_iso,
                    backend=backend,
                    detail=str(exc),
                )
                selection_session.close()
                return report
            try:
                if embedded_boot_run_id(selected_build) is not None:
                    return _reuse_embedded_boot_proof(
                        project,
                        options,
                        selected_iso,
                        selected_build,
                        selection_session,
                    )
                return _run_boot_proof(
                    project,
                    options,
                    iso=selected_iso,
                    backend=backend,
                    timeout=timeout,
                    firmware=firmware,
                    secure_boot=secure_boot,
                    execute=execute,
                    build_run_id=selected_build.run_id,
                    source_iso_handle=selected_build.iso_handle,
                    source_verification_session=selection_session,
                )
            finally:
                selection_session.close()
        assert _selection_session is not None
        if embedded_boot_run_id(_selected_build) is not None:
            return _reuse_embedded_boot_proof(
                project,
                options,
                selected_iso,
                _selected_build,
                _selection_session,
            )
        return _run_boot_proof(
            project,
            options,
            iso=selected_iso,
            backend=backend,
            timeout=timeout,
            firmware=firmware,
            secure_boot=secure_boot,
            execute=execute,
            build_run_id=build_run_id,
            source_iso_handle=source_iso_handle,
            source_verification_session=source_verification_session,
        )

    return _run_boot_proof(
        project,
        options,
        iso=selected_iso,
        backend=backend,
        timeout=timeout,
        firmware=firmware,
        secure_boot=secure_boot,
        execute=execute,
        build_run_id=build_run_id,
        source_iso_handle=source_iso_handle,
        source_verification_session=source_verification_session,
    )


def _blocked_build_selection_report(
    project: Project,
    options: BuildOptions,
    iso: Path,
    *,
    backend: str,
    detail: str,
) -> BootProofReport:
    """Return a typed pre-execution refusal without publishing evidence."""

    run_id = new_run_id()
    return BootProofReport(
        project=project.root,
        iso=iso,
        backend=backend,
        status="blocked",
        proof=project.output_dir / "boot-proof.json",
        qemu_report=project.output_dir / options.prebuild_vm.report_name,
        notes=(
            "Boot proof was not started because the requested immutable "
            f"build run could not be selected and verified: {detail}",
        ),
        attempted_backends=(backend,),
        selected_backend="none",
        proof_level="none",
        run_id=run_id,
        created_at=datetime.now(UTC).isoformat(),
        # A requested value is not a selected identity.  Keep it only in the
        # refusal detail and never serialize it as an accepted build binding.
        build_run_id="",
    )


def _reuse_embedded_boot_proof(
    project: Project,
    options: BuildOptions,
    iso: Path,
    selected_build: ExecutedReleaseRun,
    selection_session: ArtifactVerificationSession,
) -> BootProofReport:
    """Validate and return the boot run already sealed into ``ISO-BUILD``.

    A new standalone run would be unusable because the release gate correctly
    treats the producer-embedded run as authoritative.  Revalidation happens
    before returning ``ready`` and never consults the compatibility aliases.
    """

    embedded_run_id = embedded_boot_run_id(selected_build)
    if embedded_run_id is None:
        raise ArtifactVerificationError("selected build has no embedded boot run")
    output_dir = selected_build.run_dir.parents[2]
    proof_path = (
        output_dir
        / "evidence"
        / "runs"
        / embedded_run_id
        / "boot-proof.json"
    )
    qemu_path: Path | None = None
    try:
        selection_session.seal()
        # Late import keeps the producer module independent during release-gate
        # import while still reusing the one authoritative boot validator.
        from .release_gate import ReleaseGateService

        gate = ReleaseGateService().check(
            project,
            options,
            iso=iso,
            output_dir=output_dir,
            build_run_id=selected_build.run_id,
            boot_run_id=embedded_run_id,
        )
        boot_item = next(
            (item for item in gate.items if item.code == "boot-proof"),
            None,
        )
        if (
            boot_item is None
            or boot_item.status != "ready"
            or gate.immutable_boot_proof != proof_path
            or gate.immutable_qemu_report is None
        ):
            detail = (
                boot_item.detail
                if boot_item is not None
                else "release gate emitted no boot-proof verdict"
            )
            raise ArtifactVerificationError(
                "embedded boot run did not revalidate: " + detail
            )
        qemu_path = gate.immutable_qemu_report
        with ArtifactVerificationSession(
            Path("/"),
            label=f"embedded boot run {embedded_run_id}",
            limits=_BOOT_SESSION_LIMITS,
        ) as proof_session:
            payload = proof_session.file_path(
                proof_path,
                label="embedded immutable boot proof",
                max_bytes=_BOOT_JSON_MAX_BYTES,
            ).json_object()
    except (
        ArtifactVerificationError,
        OSError,
        UnicodeError,
        TypeError,
        ValueError,
        OverflowError,
        RecursionError,
    ) as exc:
        return BootProofReport(
            project=project.root,
            iso=iso,
            backend="embedded",
            status="blocked",
            proof=proof_path,
            qemu_report=qemu_path or proof_path.with_name(options.prebuild_vm.report_name),
            notes=(
                "No VM was started. The selected build already embeds boot "
                f"run {embedded_run_id}, but it could not be reused safely: {exc}",
            ),
            attempted_backends=("embedded",),
            selected_backend="none",
            proof_level="none",
            run_id=embedded_run_id,
            created_at=datetime.now(UTC).isoformat(),
            immutable_proof=proof_path,
            immutable_qemu_report=qemu_path,
            build_run_id=selected_build.run_id,
            run_manifest=proof_path.with_name("RUN-MANIFEST.json"),
            alias_publication_receipt=proof_path.with_name(
                BOOT_PROOF_ALIAS_PUBLICATION_NAME
            ),
        )

    attempted = payload.get("attempted_backends")
    attempted_backends = (
        tuple(item for item in attempted if isinstance(item, str) and item)
        if isinstance(attempted, list)
        else ()
    )
    evidence = payload.get("evidence")
    assert qemu_path is not None
    return BootProofReport(
        project=project.root,
        iso=iso,
        backend=str(payload.get("backend", "qemu")),
        status="ready",
        proof=proof_path,
        qemu_report=qemu_path,
        notes=(
            "Reused immutable boot run "
            f"{embedded_run_id} embedded by build {selected_build.run_id}; "
            "no VM was started.",
        ),
        evidence=evidence if isinstance(evidence, dict) else None,
        attempted_backends=attempted_backends,
        selected_backend=str(payload.get("selected_backend", "qemu")),
        proof_level=str(payload.get("proof_level", "runtime")),
        firmware=str(payload.get("firmware", "")),
        secure_boot=payload.get("secure_boot") is True,
        run_id=embedded_run_id,
        created_at=str(payload.get("created_at", "")),
        iso_sha256=str(payload.get("iso_sha256", "")),
        immutable_proof=proof_path,
        immutable_qemu_report=qemu_path,
        qemu_report_sha256=str(payload.get("qemu_report_sha256", "")),
        reached_milestone=str(payload.get("reached_milestone", "")),
        build_run_id=selected_build.run_id,
        command_log=proof_path.with_name("commands.jsonl"),
        run_manifest=proof_path.with_name("RUN-MANIFEST.json"),
        alias_publication_receipt=proof_path.with_name(
            BOOT_PROOF_ALIAS_PUBLICATION_NAME
        ),
    )


def _run_boot_proof(
    project: Project,
    options: BuildOptions,
    *,
    iso: Path,
    backend: str,
    timeout: int | None,
    firmware: str,
    secure_boot: bool,
    execute: bool,
    build_run_id: str | None,
    source_iso_handle: ArtifactHandle | None,
    source_verification_session: ArtifactVerificationSession | None,
) -> BootProofReport:
    raw_build_context = options._evidence_context
    if raw_build_context is None:
        build_context: dict[str, object] = {}
    elif isinstance(raw_build_context, dict):
        build_context = raw_build_context
    else:
        raise ValueError("boot proof evidence context must be a mapping")
    context_build_run_id = build_context.get("run_id")
    if build_run_id is not None:
        if not is_safe_run_id(build_run_id):
            raise ValueError(f"boot proof requires a safe build_run_id: {build_run_id!r}")
        bound_build_run_id = build_run_id
    elif context_build_run_id is None:
        bound_build_run_id = ""
    elif is_safe_run_id(context_build_run_id):
        assert isinstance(context_build_run_id, str)
        bound_build_run_id = context_build_run_id
    else:
        raise ValueError(
            "boot proof evidence context contains an unsafe build run_id: "
            f"{context_build_run_id!r}"
        )
    iso = Path(os.path.abspath(iso))
    run_id = new_run_id()
    created_at = datetime.now(UTC).isoformat()
    proof = project.output_dir / ("boot-proof.json" if execute else "boot-proof.plan.json")
    immutable_proof = evidence_run_path(
        project.output_dir,
        run_id,
        "boot-proof.json",
        executed=execute,
    )
    qemu_report = project.output_dir / options.prebuild_vm.report_name
    immutable_qemu_report = (
        evidence_run_path(
            project.output_dir,
            run_id,
            options.prebuild_vm.report_name,
            executed=execute,
        )
        if backend in _QEMU_BACKENDS
        else None
    )
    command_log = evidence_run_path(
        project.output_dir,
        run_id,
        "commands.jsonl",
        executed=execute,
    )
    run_manifest = evidence_run_path(
        project.output_dir,
        run_id,
        "RUN-MANIFEST.json",
        executed=execute,
    )
    alias_publication_receipt = evidence_run_path(
        project.output_dir,
        run_id,
        BOOT_PROOF_ALIAS_PUBLICATION_NAME,
        executed=execute,
    )
    attempted = (backend,)
    selected = backend
    proof_level = "none"
    prelude: list[str] = []
    run_firmware = ""
    run_secure_boot = False
    blockers: list[str] = []
    consumed_iso = project.workdir / "boot-proof-inputs" / run_id / iso.name
    try:
        _reserve_run_directory_nofollow(immutable_proof.parent)
        _reserve_run_directory_nofollow(consumed_iso.parent)
        _ensure_directory_nofollow(project.workdir / "prebuild-vm")
        if source_iso_handle is None:
            copied_iso = copy_immutable_file(iso, consumed_iso)
        else:
            if source_verification_session is None:
                raise ArtifactVerificationError(
                    "boot proof lost its descriptor-bound ISO verification session"
                )
            if source_iso_handle.logical_path != iso:
                raise ArtifactVerificationError(
                    "boot proof ISO descriptor names a different product path"
                )
            copied_iso = copy_immutable_file_descriptor(
                source_iso_handle.fileno,
                consumed_iso,
                expected_source_identity=source_iso_handle.identity,
            )
            # Close the build selection before any backend is invoked.  This
            # revalidates the complete build/provenance/manifest path set and
            # turns a concurrent path swap into a blocker before QEMU starts.
            source_verification_session.seal()
        session = ArtifactVerificationSession(
            project.root,
            label=f"boot proof run {run_id}",
            limits=_BOOT_SESSION_LIMITS,
        )
    except (ArtifactVerificationError, OSError, ValueError) as exc:
        return BootProofReport(
            project=project.root,
            iso=iso,
            backend=backend,
            status="blocked",
            proof=proof,
            qemu_report=qemu_report,
            notes=(f"Boot proof artifact session could not start safely: {exc}",),
            attempted_backends=attempted,
            selected_backend="none",
            run_id=run_id,
            created_at=created_at,
            immutable_proof=immutable_proof,
            immutable_qemu_report=immutable_qemu_report,
            build_run_id=(
                "" if source_iso_handle is not None else bound_build_run_id
            ),
            run_manifest=run_manifest,
            alias_publication_receipt=alias_publication_receipt,
        )
    iso_handle: ArtifactHandle | None = None
    try:
        iso_handle = session.file_path(
            consumed_iso,
            label="boot proof ISO",
            allow_empty=True,
        )
        if iso_handle.identity.size != copied_iso.size or iso_handle.digest() != copied_iso.sha256:
            raise ArtifactVerificationError("boot proof ISO copy differs from its held source")
    except (ArtifactVerificationError, OSError, ValueError) as exc:
        blockers.append(f"boot-proof-iso: {exc}")
    if backend in _QEMU_BACKENDS:
        # Decided here rather than inside the QEMU backend so the report carries the
        # firmware even when the run never starts, and so a refusal happens before a
        # machine is launched instead of after it has booted the wrong one.
        run_firmware = resolve_firmware(firmware, options.prebuild_vm.firmware)
        run_secure_boot = secure_boot or options.prebuild_vm.secure_boot
        options.prebuild_vm.firmware = run_firmware
        options.prebuild_vm.secure_boot = run_secure_boot
        # Validated on a copy with the lab enabled, because those checks are gated on
        # `enabled` and the QEMU backend only sets it once it has decided to run. This
        # is what refuses Secure Boot on BIOS, an absent OVMF image, and a firmware
        # pair that cannot enforce Secure Boot while the report would claim it does.
        blockers.extend(
            f"{issue.code}: {issue.message}"
            for issue in validate_prebuild_vm_options(replace(options.prebuild_vm, enabled=True))
            if issue.level == "error"
        )
    elif firmware or secure_boot:
        # Ignoring it silently would hand a green structural scan to someone who asked
        # to watch a machine boot under a named firmware.
        prelude.append(
            f"Firmware selection does not apply to the {backend} backend; nothing was booted."
        )
    if blockers:
        status = "blocked"
        notes = blockers
        evidence = {
            "status": "blocked",
            "firmware": run_firmware,
            "secure_boot": run_secure_boot,
        }
        selected = "none"
    elif backend == "auto":
        assert iso_handle is not None
        status, notes, evidence, attempted, selected, proof_level = _run_auto_proof(
            project,
            options,
            iso=consumed_iso,
            reported_iso=iso,
            iso_handle=iso_handle,
            qemu_report=immutable_qemu_report,
            qemu_report_alias=qemu_report,
            timeout=timeout,
            execute=execute,
            run_id=run_id,
            session=session,
        )
    elif backend == "iso-scan":
        assert iso_handle is not None
        status, notes, evidence = _run_iso_scan(
            iso,
            iso_handle=iso_handle,
            execute=execute,
        )
        proof_level = "structural" if status == "ready" else "none"
    elif backend == "qemu":
        assert iso_handle is not None
        status, notes, evidence = _run_qemu_proof(
            project,
            options,
            iso=consumed_iso,
            reported_iso=iso,
            iso_handle=iso_handle,
            qemu_report=immutable_qemu_report,
            qemu_report_alias=qemu_report,
            timeout=timeout,
            execute=execute,
            run_id=run_id,
            session=session,
        )
        proof_level = "runtime" if status == "ready" else "none"
    else:
        status = "blocked"
        notes = [f"Unsupported boot proof backend: {backend}."]
        evidence = None
        selected = "none"
    qemu_report_sha256 = ""
    if execute and selected == "qemu" and immutable_qemu_report is not None:
        try:
            qemu_handle = session.file_path(
                immutable_qemu_report,
                label="immutable QEMU report",
                max_bytes=_BOOT_JSON_MAX_BYTES,
            )
            qemu_report_sha256 = qemu_handle.digest()
            qemu_validation = validate_qemu_report(
                immutable_qemu_report,
                consumed_iso,
                session=session,
            )
            if not qemu_validation.ok:
                raise ArtifactVerificationError(qemu_validation.detail)
        except (ArtifactVerificationError, OSError, ValueError) as exc:
            status = "blocked"
            proof_level = "none"
            notes.append(f"QEMU report evidence is blocked: {exc}")
    reached_milestone = ""
    if isinstance(evidence, dict):
        reached_milestone = str(evidence.get("reached_milestone", ""))
        if not reached_milestone and isinstance(evidence.get("qemu"), dict):
            reached_milestone = str(evidence["qemu"].get("reached_milestone", ""))
    run_handles: dict[Path, _MeasuredArtifact] = {}
    opening_inventory: _RunInventory | None = None
    try:
        opening_inventory = _inventory_run_directory(immutable_proof.parent)
        run_handles = _measure_inventory_files(
            opening_inventory,
            immutable_proof.parent,
        )
    except (ArtifactVerificationError, OSError, ValueError) as exc:
        status = "blocked"
        proof_level = "none"
        notes.append(f"Boot run inventory is blocked: {exc}")
    report = BootProofReport(
        project=project.root,
        iso=iso,
        backend=backend,
        status=status,
        proof=proof,
        qemu_report=qemu_report,
        notes=tuple([*prelude, *notes]),
        evidence=evidence,
        attempted_backends=attempted,
        selected_backend=selected,
        proof_level=proof_level,
        firmware=run_firmware,
        secure_boot=run_secure_boot,
        run_id=run_id,
        created_at=created_at,
        iso_sha256=iso_handle.digest() if iso_handle is not None else "",
        immutable_proof=immutable_proof,
        immutable_qemu_report=immutable_qemu_report,
        qemu_report_sha256=qemu_report_sha256,
        reached_milestone=reached_milestone,
        build_run_id=bound_build_run_id,
        command_log=(
            command_log if command_log.relative_to(immutable_proof.parent) in run_handles else None
        ),
        run_manifest=run_manifest,
        alias_publication_receipt=alias_publication_receipt,
    )
    try:
        content = report.render_json() + "\n"
        proof_receipt = write_immutable_text(immutable_proof, content)
        proof_measurement = _measure_artifact_path(
            immutable_proof,
            max_bytes=_BOOT_JSON_MAX_BYTES,
            capture=True,
        )
        if (
            proof_measurement.identity.size != proof_receipt.size
            or proof_measurement.sha256 != proof_receipt.sha256
        ):
            raise ArtifactVerificationError(
                "immutable boot proof measurement differs from its publication receipt"
            )
        if _strict_json_object(proof_measurement.body) != report.to_dict():
            raise ArtifactVerificationError(
                "immutable boot proof differs from its in-memory verdict"
            )
        after_proof = _inventory_run_directory(immutable_proof.parent)
        _assert_inventory_extension(
            opening_inventory,
            after_proof,
            added={Path(immutable_proof.name): proof_measurement.identity},
        )
        run_handles[Path(immutable_proof.name)] = proof_measurement
        alias_parent_fd, alias_parent_identity = _open_directory_nofollow(
            proof.parent
        )
        os.close(alias_parent_fd)
        alias_receipt_payload = publish_optional_text_alias_receipt(
            proof,
            content,
            schema=BOOT_PROOF_ALIAS_PUBLICATION_SCHEMA,
            run_id=run_id,
            authoritative_source_path=immutable_proof,
            authoritative_source_receipt=proof_receipt,
            authoritative_source_key="authoritative_report",
            expected_parent_identity=alias_parent_identity,
        )
        alias_receipt_content = json.dumps(alias_receipt_payload, indent=2) + "\n"
        write_immutable_text(alias_publication_receipt, alias_receipt_content)
        alias_receipt_measurement = _measure_artifact_path(
            alias_publication_receipt,
            max_bytes=_BOOT_JSON_MAX_BYTES,
            capture=True,
        )
        if (
            _strict_json_object(alias_receipt_measurement.body)
            != alias_receipt_payload
        ):
            raise ArtifactVerificationError(
                "boot proof alias publication receipt differs from its payload"
            )
        after_alias_receipt = _inventory_run_directory(immutable_proof.parent)
        _assert_inventory_extension(
            after_proof,
            after_alias_receipt,
            added={
                Path(alias_publication_receipt.name):
                    alias_receipt_measurement.identity,
            },
        )
        run_handles[Path(alias_publication_receipt.name)] = (
            alias_receipt_measurement
        )
        manifest_files = [
            _measured_manifest_identity(
                immutable_proof.parent / relative,
                measurement,
                role="boot-run-evidence",
            )
            for relative, measurement in sorted(
                run_handles.items(),
                key=lambda item: item[0].as_posix(),
            )
        ]
        if iso_handle is not None:
            iso_identity = _manifest_identity(
                iso,
                iso_handle,
                role="proven-iso",
            )
            iso_identity["consumed_via"] = "held-descriptor"
            manifest_files.append(iso_identity)
        manifest_payload = {
            "schema": BOOT_RUN_MANIFEST_SCHEMA,
            "run_id": run_id,
            "mode": "execute" if execute else "plan",
            "status": status,
            "created_at": created_at,
            "build_run_id": bound_build_run_id,
            "files": manifest_files,
        }
        write_immutable_text(
            run_manifest,
            json.dumps(manifest_payload, indent=2) + "\n",
        )
        manifest_measurement = _measure_artifact_path(
            run_manifest,
            max_bytes=_BOOT_JSON_MAX_BYTES,
            capture=True,
        )
        if _strict_json_object(manifest_measurement.body) != manifest_payload:
            raise ArtifactVerificationError(
                "boot proof run manifest differs from its recorded payload"
            )
        sidecar = run_manifest.with_name(f"{run_manifest.name}.sha256")
        sidecar_content = f"{manifest_measurement.sha256}  {run_manifest.name}\n"
        write_immutable_text(sidecar, sidecar_content)
        sidecar_measurement = _measure_artifact_path(
            sidecar,
            max_bytes=_BOOT_SIDECAR_MAX_BYTES,
            capture=True,
        )
        if _strict_utf8(sidecar_measurement.body) != sidecar_content:
            raise ArtifactVerificationError("boot proof run manifest sidecar is not canonical")
        final_inventory = _inventory_run_directory(immutable_proof.parent)
        _assert_inventory_extension(
            after_alias_receipt,
            final_inventory,
            added={
                Path(run_manifest.name): manifest_measurement.identity,
                Path(sidecar.name): sidecar_measurement.identity,
            },
        )
        final_handles = _bind_inventory_files(
            final_inventory,
            immutable_proof.parent,
            session,
        )
        expected_measurements = {
            **run_handles,
            Path(run_manifest.name): manifest_measurement,
            Path(sidecar.name): sidecar_measurement,
        }
        proof_handle = final_handles[Path(immutable_proof.name)]
        manifest_handle = final_handles[Path(run_manifest.name)]
        sidecar_handle = final_handles[Path(sidecar.name)]
        if proof_handle.json_object() != report.to_dict():
            raise ArtifactVerificationError("immutable boot proof changed before final parsing")
        if manifest_handle.json_object() != manifest_payload:
            raise ArtifactVerificationError("boot proof run manifest changed before final parsing")
        if sidecar_handle.read_text() != sidecar_content:
            raise ArtifactVerificationError(
                "boot proof run manifest sidecar changed before final parsing"
            )
        if (
            execute
            and selected == "qemu"
            and immutable_qemu_report is not None
        ):
            validation = validate_qemu_report(
                immutable_qemu_report,
                consumed_iso,
                session=session,
            )
            if not validation.ok:
                raise ArtifactVerificationError(
                    f"QEMU report final validation failed: {validation.detail}"
                )
        for relative, measurement in expected_measurements.items():
            handle = final_handles.get(relative)
            if (
                handle is None
                or handle.identity != measurement.identity
                or handle.digest() != measurement.sha256
            ):
                raise ArtifactVerificationError(
                    f"boot proof artifact changed before final binding: {relative}"
                )
        session.seal()
        return report
    except (
        ArtifactVerificationError,
        CommandError,
        OSError,
        TimeoutError,
        ValueError,
    ) as exc:
        blocked_notes = (*report.notes, f"Boot proof evidence closure failed: {exc}")
        return replace(
            report,
            status="blocked",
            notes=blocked_notes,
            proof_level="none",
        )
    finally:
        session.close()


def _reserve_run_directory_nofollow(directory: Path) -> None:
    absolute = Path(os.path.abspath(directory))
    if not absolute.is_absolute() or ".." in absolute.parts or "\x00" in str(absolute):
        raise ArtifactVerificationError(f"boot proof run directory is not canonical: {directory}")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open("/", flags)
    try:
        components = absolute.parts[1:]
        for index, component in enumerate(components):
            child = -1
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except FileNotFoundError:
                os.mkdir(component, 0o755, dir_fd=descriptor)
                os.fsync(descriptor)
                child = os.open(component, flags, dir_fd=descriptor)
            except OSError as exc:
                raise ArtifactVerificationError(
                    "boot proof run directory contains a symlink or "
                    f"non-directory component: {absolute}"
                ) from exc
            else:
                if index == len(components) - 1:
                    os.close(child)
                    raise ArtifactVerificationError(
                        f"boot proof run directory already exists: {absolute}"
                    )
            os.close(descriptor)
            descriptor = child
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _ensure_directory_nofollow(directory: Path) -> None:
    """Create missing directory components without traversing a link."""
    absolute = Path(os.path.abspath(directory))
    if not absolute.is_absolute() or ".." in absolute.parts or "\x00" in str(absolute):
        raise ArtifactVerificationError(f"boot proof directory is not canonical: {directory}")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open("/", flags)
    try:
        for component in absolute.parts[1:]:
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except FileNotFoundError:
                os.mkdir(component, 0o755, dir_fd=descriptor)
                os.fsync(descriptor)
                child = os.open(component, flags, dir_fd=descriptor)
            except OSError as exc:
                raise ArtifactVerificationError(
                    "boot proof directory contains a symlink or "
                    f"non-directory component: {absolute}"
                ) from exc
            os.close(descriptor)
            descriptor = child
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _measure_artifact_path(
    path: Path,
    *,
    max_bytes: int,
    capture: bool,
    allow_empty: bool = False,
) -> _MeasuredArtifact:
    """Measure one regular inode and close both its FD and pathname identity."""
    if not path.is_absolute() or ".." in path.parts or "\x00" in str(path) or max_bytes <= 0:
        raise ArtifactVerificationError(
            f"boot proof artifact path or byte limit is invalid: {path}"
        )
    absolute = Path(os.path.abspath(path))
    _strict_entry_name(absolute.name)
    parent_fd, parent_identity = _open_directory_nofollow(absolute.parent)
    probe_fd = -1
    readable_fd = -1
    closing_parent_fd = -1
    closing_probe_fd = -1
    try:
        try:
            probe_fd = os.open(
                absolute.name,
                os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
        except OSError as exc:
            raise ArtifactVerificationError(
                f"boot proof artifact cannot be pinned safely: {path}: {exc}"
            ) from exc
        opening_identity = ArtifactIdentity.from_stat(os.fstat(probe_fd))
        if not stat.S_ISREG(opening_identity.mode):
            raise ArtifactVerificationError(f"boot proof artifact is not a regular file: {path}")
        if opening_identity.size > max_bytes:
            raise ArtifactVerificationError(
                f"boot proof artifact exceeds its {max_bytes}-byte limit: {path}"
            )
        if opening_identity.size == 0 and not allow_empty:
            raise ArtifactVerificationError(f"boot proof artifact is empty: {path}")
        try:
            readable_fd = os.open(
                f"/proc/{os.getpid()}/fd/{probe_fd}",
                os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK,
            )
        except OSError as exc:
            raise ArtifactVerificationError(
                f"boot proof artifact pinned inode cannot be read: {path}: {exc}"
            ) from exc
        if ArtifactIdentity.from_stat(os.fstat(readable_fd)) != opening_identity:
            raise ArtifactVerificationError(
                f"boot proof artifact changed while acquiring its read FD: {path}"
            )
        digest = hashlib.sha256()
        body_parts: list[bytes] | None = [] if capture else None
        measured_size = 0
        while True:
            chunk = os.read(readable_fd, 1024 * 1024)
            if not chunk:
                break
            measured_size += len(chunk)
            if measured_size > max_bytes:
                raise ArtifactVerificationError(
                    f"boot proof artifact grew beyond its byte limit: {path}"
                )
            digest.update(chunk)
            if body_parts is not None:
                body_parts.append(chunk)
        if measured_size != opening_identity.size:
            raise ArtifactVerificationError(
                f"boot proof artifact changed size while being read: {path}"
            )
        if (
            ArtifactIdentity.from_stat(os.fstat(readable_fd)) != opening_identity
            or ArtifactIdentity.from_stat(os.fstat(probe_fd)) != opening_identity
        ):
            raise ArtifactVerificationError(
                f"boot proof artifact changed while being measured: {path}"
            )
        if ArtifactIdentity.from_stat(os.fstat(parent_fd)) != parent_identity:
            raise ArtifactVerificationError(
                f"boot proof artifact directory changed while being measured: {path}"
            )
        closing_parent_fd, closing_parent_identity = _open_directory_nofollow(absolute.parent)
        if closing_parent_identity != parent_identity:
            raise ArtifactVerificationError(
                f"boot proof artifact directory path changed while being measured: {path}"
            )
        closing_probe_fd = os.open(
            absolute.name,
            os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=closing_parent_fd,
        )
        if ArtifactIdentity.from_stat(os.fstat(closing_probe_fd)) != opening_identity:
            raise ArtifactVerificationError(
                f"boot proof artifact path changed while being measured: {path}"
            )
        return _MeasuredArtifact(
            identity=opening_identity,
            sha256=digest.hexdigest(),
            body=b"".join(body_parts) if body_parts is not None else None,
        )
    except ArtifactVerificationError:
        raise
    except OSError as exc:
        raise ArtifactVerificationError(
            f"boot proof artifact measurement failed: {path}: {exc}"
        ) from exc
    finally:
        for descriptor in (
            closing_probe_fd,
            closing_parent_fd,
            readable_fd,
            probe_fd,
            parent_fd,
        ):
            if descriptor >= 0:
                os.close(descriptor)


def _measure_inventory_files(
    inventory: _RunInventory,
    run_directory: Path,
) -> dict[Path, _MeasuredArtifact]:
    measured: dict[Path, _MeasuredArtifact] = {}
    bytes_hashed = 0
    for relative, opening_identity in inventory.entries:
        if stat.S_ISDIR(opening_identity.mode):
            continue
        if not stat.S_ISREG(opening_identity.mode):
            raise ArtifactVerificationError(
                f"boot proof run contains a symlink or special file: {relative}"
            )
        bytes_hashed += opening_identity.size
        if bytes_hashed > _BOOT_SESSION_LIMITS.max_hashed_bytes:
            raise ArtifactVerificationError("boot proof run exceeds its hashed-byte budget")
        measurement = _measure_artifact_path(
            run_directory / relative,
            max_bytes=_BOOT_SESSION_LIMITS.max_file_bytes,
            capture=False,
            allow_empty=True,
        )
        if measurement.identity != opening_identity:
            raise ArtifactVerificationError(
                f"boot proof run artifact changed during measurement: {relative}"
            )
        measured[relative] = measurement
    return measured


def _strict_utf8(body: bytes | None) -> str:
    if body is None:
        raise ArtifactVerificationError("boot proof artifact bytes were not retained")
    try:
        return body.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ArtifactVerificationError("boot proof artifact is not strict UTF-8") from exc


def _strict_json_object(body: bytes | None) -> dict[str, object]:
    text = _strict_utf8(body)

    def reject_constant(value: str) -> object:
        raise ValueError(f"non-standard JSON constant: {value}")

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (
        json.JSONDecodeError,
        OverflowError,
        RecursionError,
        UnicodeError,
        ValueError,
    ) as exc:
        raise ArtifactVerificationError(f"boot proof artifact is not strict JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ArtifactVerificationError("boot proof artifact must contain one JSON object")
    stack: list[tuple[object, int]] = [(value, 1)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > _BOOT_SESSION_LIMITS.max_json_nodes:
            raise ArtifactVerificationError("boot proof JSON exceeds its structural node limit")
        if depth > _BOOT_SESSION_LIMITS.max_json_depth:
            raise ArtifactVerificationError("boot proof JSON exceeds its structural depth limit")
        if isinstance(current, dict):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
    return value


def _inventory_run_directory(directory: Path) -> _RunInventory:
    descriptor, opening_identity = _open_directory_nofollow(directory)
    entries: dict[Path, ArtifactIdentity] = {}
    counter = [0]
    try:
        _inventory_directory(
            descriptor,
            Path(),
            entries,
            counter,
            depth=0,
        )
        if ArtifactIdentity.from_stat(os.fstat(descriptor)) != opening_identity:
            raise ArtifactVerificationError("boot proof run directory changed during inventory")
        closing_fd, closing_identity = _open_directory_nofollow(directory)
        try:
            if closing_identity != opening_identity:
                raise ArtifactVerificationError(
                    "boot proof run directory path changed during inventory"
                )
        finally:
            os.close(closing_fd)
    except OSError as exc:
        raise ArtifactVerificationError(f"boot proof run inventory failed: {exc}") from exc
    finally:
        os.close(descriptor)
    return _RunInventory(
        opening_identity,
        tuple(sorted(entries.items(), key=lambda item: item[0].as_posix())),
    )


def _inventory_directory(
    directory_fd: int,
    prefix: Path,
    entries: dict[Path, ArtifactIdentity],
    counter: list[int],
    *,
    depth: int,
) -> None:
    if depth > _BOOT_SESSION_LIMITS.max_path_components:
        raise ArtifactVerificationError("boot proof run inventory exceeds its path-depth limit")
    opening_identity = ArtifactIdentity.from_stat(os.fstat(directory_fd))
    names: list[str] = []
    with os.scandir(directory_fd) as iterator:
        for entry in iterator:
            name = _strict_entry_name(entry.name)
            counter[0] += 1
            if counter[0] > _BOOT_INVENTORY_MAX_ENTRIES:
                raise ArtifactVerificationError("boot proof run exceeds its inventory entry limit")
            names.append(name)
    names.sort()
    immediate: dict[str, ArtifactIdentity] = {}
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    for name in names:
        identity = ArtifactIdentity.from_stat(
            os.stat(
                name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        )
        relative = prefix / name
        entries[relative] = identity
        immediate[name] = identity
        if not stat.S_ISDIR(identity.mode):
            continue
        child = os.open(name, flags, dir_fd=directory_fd)
        try:
            if ArtifactIdentity.from_stat(os.fstat(child)) != identity:
                raise ArtifactVerificationError(
                    f"boot proof directory changed while opening: {relative}"
                )
            _inventory_directory(
                child,
                relative,
                entries,
                counter,
                depth=depth + 1,
            )
            if ArtifactIdentity.from_stat(os.fstat(child)) != identity:
                raise ArtifactVerificationError(
                    f"boot proof directory changed during inventory: {relative}"
                )
        finally:
            os.close(child)
    for name, expected in immediate.items():
        current = ArtifactIdentity.from_stat(
            os.stat(
                name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        )
        if current != expected:
            raise ArtifactVerificationError(
                f"boot proof run entry changed during inventory: {prefix / name}"
            )
    if ArtifactIdentity.from_stat(os.fstat(directory_fd)) != opening_identity:
        raise ArtifactVerificationError(
            f"boot proof directory changed during traversal: {prefix or '.'}"
        )


def _bind_inventory_files(
    inventory: _RunInventory,
    run_directory: Path,
    session: ArtifactVerificationSession,
) -> dict[Path, ArtifactHandle]:
    handles: dict[Path, ArtifactHandle] = {}
    for relative, opening_identity in inventory.entries:
        if stat.S_ISDIR(opening_identity.mode):
            continue
        if not stat.S_ISREG(opening_identity.mode):
            raise ArtifactVerificationError(
                f"boot proof run contains a symlink or special file: {relative}"
            )
        handle = session.file_path(
            run_directory / relative,
            label=f"boot proof run artifact {relative.as_posix()}",
            allow_empty=True,
        )
        if handle.identity != opening_identity:
            raise ArtifactVerificationError(
                f"boot proof run artifact changed during binding: {relative}"
            )
        handles[relative] = handle
    return handles


def _assert_inventory_extension(
    before: _RunInventory | None,
    after: _RunInventory,
    *,
    added: dict[Path, ArtifactIdentity],
) -> None:
    if before is None:
        raise ArtifactVerificationError("boot proof opening inventory is unavailable")
    if not _same_directory_object(before.anchor_identity, after.anchor_identity):
        raise ArtifactVerificationError("boot proof run directory identity changed")
    before_entries = before.by_path()
    after_entries = after.by_path()
    expected_paths = set(before_entries) | set(added)
    if set(after_entries) != expected_paths:
        unexpected = sorted(
            (set(after_entries) ^ expected_paths),
            key=Path.as_posix,
        )
        raise ArtifactVerificationError(
            "boot proof run inventory changed unexpectedly: "
            + ", ".join(path.as_posix() for path in unexpected)
        )
    for relative, identity in before_entries.items():
        if after_entries[relative] != identity:
            raise ArtifactVerificationError(f"boot proof run artifact changed: {relative}")
    for relative, identity in added.items():
        if after_entries.get(relative) != identity:
            raise ArtifactVerificationError(f"boot proof publication identity mismatch: {relative}")


def _manifest_identity(
    path: Path,
    handle: ArtifactHandle,
    *,
    role: str,
) -> dict[str, object]:
    return {
        "path": str(path),
        "size": handle.identity.size,
        "sha256": handle.digest(),
        "role": role,
    }


def _measured_manifest_identity(
    path: Path,
    measurement: _MeasuredArtifact,
    *,
    role: str,
) -> dict[str, object]:
    return {
        "path": str(path),
        "size": measurement.identity.size,
        "sha256": measurement.sha256,
        "role": role,
    }


def _open_directory_nofollow(
    directory: Path,
) -> tuple[int, ArtifactIdentity]:
    absolute = Path(os.path.abspath(directory))
    if not absolute.is_absolute() or ".." in absolute.parts or "\x00" in str(absolute):
        raise ArtifactVerificationError(f"boot proof directory is not canonical: {directory}")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open("/", flags)
        for component in absolute.parts[1:]:
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        identity = ArtifactIdentity.from_stat(os.fstat(descriptor))
        if not stat.S_ISDIR(identity.mode):
            raise ArtifactVerificationError(f"boot proof directory is not a directory: {directory}")
        return descriptor, identity
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise ArtifactVerificationError(
            f"boot proof directory contains a symlink or unreadable component: {directory}"
        ) from exc
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def _same_directory_object(
    left: ArtifactIdentity,
    right: ArtifactIdentity,
) -> bool:
    return (
        left.dev,
        left.ino,
        stat.S_IFMT(left.mode),
        left.uid,
        left.gid,
        left.nlink,
        left.rdev,
    ) == (
        right.dev,
        right.ino,
        stat.S_IFMT(right.mode),
        right.uid,
        right.gid,
        right.nlink,
        right.rdev,
    )


def _strict_entry_name(value: str) -> str:
    if value in {"", ".", ".."} or "/" in value or "\x00" in value:
        raise ArtifactVerificationError(f"boot proof run contains an unsafe entry name: {value!r}")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ArtifactVerificationError("boot proof run contains a non-UTF-8 entry name") from exc
    return value


def _run_auto_proof(
    project: Project,
    options: BuildOptions,
    *,
    iso: Path,
    reported_iso: Path,
    iso_handle: ArtifactHandle,
    qemu_report: Path | None,
    qemu_report_alias: Path,
    timeout: int | None,
    execute: bool,
    run_id: str,
    session: ArtifactVerificationSession,
) -> tuple[str, list[str], dict[str, object], tuple[str, ...], str, str]:
    if qemu_report is None:
        raise ArtifactVerificationError(
            "auto boot proof has no immutable QEMU report path"
        )
    attempted = ["qemu"]
    qemu_status, qemu_notes, qemu_evidence = _run_qemu_proof(
        project,
        options,
        iso=iso,
        reported_iso=reported_iso,
        iso_handle=iso_handle,
        qemu_report=qemu_report,
        qemu_report_alias=qemu_report_alias,
        timeout=timeout,
        execute=execute,
        run_id=run_id,
        session=session,
    )
    if qemu_status == "ready":
        evidence = {"qemu": qemu_evidence}
        return (
            "ready",
            ["Auto selected QEMU runtime proof.", *qemu_notes],
            evidence,
            tuple(attempted),
            "qemu",
            "runtime",
        )
    if not execute:
        evidence = {"qemu": qemu_evidence}
        return (
            qemu_status,
            ["Auto planned QEMU runtime proof.", *qemu_notes],
            evidence,
            tuple(attempted),
            "qemu",
            "none",
        )
    attempted.append("iso-scan")
    scan_status, scan_notes, scan_evidence = _run_iso_scan(
        reported_iso,
        iso_handle=iso_handle,
        execute=True,
    )
    evidence = {"qemu": qemu_evidence, "iso_scan": scan_evidence}
    notes = [
        "Auto attempted QEMU runtime proof first.",
        *qemu_notes,
        "Auto fell back to ISO structural scan.",
        *scan_notes,
    ]
    if scan_status == "ready":
        return "ready", notes, evidence, tuple(attempted), "iso-scan", "structural"
    selected = "iso-scan" if scan_status in {"review", "blocked"} else "none"
    return scan_status, notes, evidence, tuple(attempted), selected, "none"


def _run_qemu_proof(
    project: Project,
    options: BuildOptions,
    *,
    iso: Path,
    reported_iso: Path,
    iso_handle: ArtifactHandle,
    qemu_report: Path | None,
    qemu_report_alias: Path,
    timeout: int | None,
    execute: bool,
    run_id: str,
    session: ArtifactVerificationSession,
) -> tuple[str, list[str], dict[str, object]]:
    if qemu_report is None:
        raise ArtifactVerificationError(
            "QEMU boot proof has no immutable report path"
        )
    notes: list[str] = []
    evidence: dict[str, object] = {
        "proof_level": "runtime",
        "qemu_report": str(qemu_report),
        "qemu_report_alias": str(qemu_report_alias),
        # Read back off the options the lab is about to consume, not off the request, so
        # the evidence names the firmware that ran rather than the one that was asked for.
        "firmware": options.prebuild_vm.firmware,
        "secure_boot": options.prebuild_vm.secure_boot,
        "iso": {
            "path": str(reported_iso),
            "size": iso_handle.identity.size,
            "sha256": iso_handle.digest(),
            "consumed_via": "held-descriptor",
        },
    }
    status = "blocked"
    if execute and not CommandRunner.has_binary("qemu-system-x86_64"):
        notes.append("qemu-system-x86_64 is missing; install qemu-system-x86 before boot proof.")
    else:
        options.prebuild_vm.enabled = True
        options.prebuild_vm.timeout_seconds = timeout or options.prebuild_vm.timeout_seconds
        runner = CommandRunner(dry_run=not execute)
        runner.log_path = evidence_run_path(
            project.output_dir,
            run_id,
            "commands.jsonl",
            executed=execute,
        )
        try:
            QemuLabService(
                runner,
                iso,
                project.workdir,
                project.output_dir,
                options.prebuild_vm,
                run_id=run_id,
            ).run()
            if execute:
                provisional = _measure_artifact_path(
                    qemu_report,
                    max_bytes=_BOOT_JSON_MAX_BYTES,
                    capture=True,
                )
                payload = _strict_json_object(provisional.body)
                status = (
                    "ready"
                    if payload.get("status") == "completed" and payload.get("verdict") == "passed"
                    else "blocked"
                )
                notes.append(
                    "Executed QEMU boot proof; final descriptor validation is pending."
                    if status == "ready"
                    else "QEMU report does not claim a completed passing run."
                )
                evidence["qemu_report_validation"] = "pending final descriptor validation"
                boot = payload.get("boot")
                if isinstance(boot, dict):
                    evidence["reached_milestone"] = str(boot.get("reached_milestone", ""))
            else:
                status = "planned"
                notes.append("Planned QEMU boot proof without executing it.")
        except (
            ArtifactVerificationError,
            CommandError,
            OSError,
            TimeoutError,
            ValueError,
        ) as exc:
            status = "blocked"
            notes.append(f"QEMU boot proof failed: {exc}")
    evidence["status"] = status
    return status, notes, evidence


def _run_iso_scan(
    iso: Path,
    *,
    iso_handle: ArtifactHandle,
    execute: bool,
) -> tuple[str, list[str], dict[str, object]]:
    notes: list[str] = []
    evidence: dict[str, object] = {
        "scan_time": datetime.now(UTC).isoformat(),
        "path": str(iso),
        "size": iso_handle.identity.size,
        "sha256": iso_handle.digest(),
        "consumed_via": "held-descriptor",
    }
    if not execute:
        notes.append("Planned ISO structure scan without reading boot metadata.")
        return "planned", notes, evidence
    try:
        descriptor = _scan_iso9660_descriptors(iso_handle)
        external = _scan_with_external_tool(iso_handle)
    except (ArtifactVerificationError, OSError, ValueError) as exc:
        return (
            "blocked",
            [f"ISO structure scan failed closed: {exc}"],
            evidence,
        )
    evidence.update(descriptor)
    if external:
        evidence["external_tool"] = external
    else:
        notes.append(
            "xorriso/isoinfo is unavailable or did not return metadata; used fallback ISO descriptor scan."
        )
    if not descriptor["iso9660"]:
        notes.append("ISO9660 primary volume descriptor was not found.")
        return "blocked", notes, evidence
    volume_id = descriptor.get("volume_id") or "unknown"
    notes.append(f"Read ISO9660 volume ID: {volume_id}.")
    has_boot_record = bool(descriptor.get("el_torito"))
    has_payload = bool(descriptor.get("boot_payload"))
    if has_boot_record and has_payload:
        notes.append("Found El Torito boot record and live boot payload markers.")
        return "ready", notes, evidence
    if has_boot_record:
        notes.append(
            "Found El Torito boot record, but kernel/initrd or live payload markers need review."
        )
        return "review", notes, evidence
    notes.append("El Torito boot record was not confirmed by the structural scan.")
    return "review", notes, evidence


def _scan_iso9660_descriptors(iso: ArtifactHandle) -> dict[str, object]:
    evidence: dict[str, object] = {
        "iso9660": False,
        "volume_id": "",
        "el_torito": False,
        "boot_catalog_lba": None,
        "boot_payload": False,
    }
    descriptor = iso.fileno
    for sector in range(16, 80):
        block = os.pread(descriptor, 2048, sector * 2048)
        if len(block) < 2048 or block[1:6] != b"CD001":
            continue
        if block[0] == 1:
            evidence["iso9660"] = True
            evidence["volume_id"] = block[40:72].decode("ascii", errors="ignore").strip()
        if block[0] == 0 and b"EL TORITO SPECIFICATION" in block[:128]:
            evidence["el_torito"] = True
            evidence["boot_catalog_lba"] = int.from_bytes(block[71:75], "little")
        if block[0] == 255:
            break
    sample = os.pread(
        descriptor,
        min(16 * 1024 * 1024, iso.identity.size),
        0,
    ).upper()
    evidence["boot_payload"] = _has_boot_payload_markers(sample)
    return evidence


def _has_boot_payload_markers(sample: bytes) -> bool:
    kernel = any(marker in sample for marker in (b"VMLINUZ", b"KERNEL"))
    initrd = any(marker in sample for marker in (b"INITRD", b"INITRAMFS"))
    livefs = any(
        marker in sample for marker in (b"CASPER", b"LIVE/FILESYSTEM", b"FILESYSTEM.SQUASHFS")
    )
    bootloader = any(marker in sample for marker in (b"BOOT.CAT", b"ISOLINUX", b"GRUB"))
    return (kernel and initrd) or (livefs and bootloader)


def _scan_with_external_tool(iso: ArtifactHandle) -> dict[str, str] | None:
    held_path = str(iso.proc_fd_path)
    if shutil.which("xorriso"):
        result = _run_metadata_command(
            ("xorriso", "-indev", held_path, "-toc"),
            pass_fds=iso.pass_fds,
        )
        if result is not None:
            return {"tool": "xorriso", "summary": result}
    if shutil.which("isoinfo"):
        result = _run_metadata_command(
            ("isoinfo", "-d", "-i", held_path),
            pass_fds=iso.pass_fds,
        )
        if result is not None:
            return {"tool": "isoinfo", "summary": result}
    return None


def _run_metadata_command(
    argv: tuple[str, ...],
    *,
    pass_fds: tuple[int, ...],
) -> str | None:
    try:
        completed = subprocess.run(
            argv,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
            pass_fds=pass_fds,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (completed.stdout or completed.stderr).strip()
    if completed.returncode != 0 or not text:
        return None
    return " | ".join(text.splitlines()[:6])
