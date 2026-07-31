from __future__ import annotations

import errno
import hashlib
import json
import math
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path

from .artifact_paths import default_artifact_paths
from .artifact_verification import (
    ArtifactHandle,
    ArtifactIdentity,
    ArtifactLimits,
    ArtifactTreeInventory,
    ArtifactVerificationError,
    ArtifactVerificationReceipt,
    ArtifactVerificationSession,
)
from .build import BuildOptions
from .command import VIRTUAL_COMMANDS, CommandError, CommandRunner
from .diff_preview import DiffPreviewService
from .evidence_run import (
    IDENTITY_CLOSURE_SCHEMA,
    canonical_sha256,
    is_safe_run_id,
    observed_executable_counts,
)
from .hashing import parse_sha256_sums, sha256_file, sha256_from_sums_bytes
from .iso_evidence import (
    ISO_ASSEMBLY_FILENAME,
    ISO_ASSEMBLY_SCHEMA,
    validate_iso_assembly_evidence,
)
from .package_apt_actions import (
    MAX_PACKAGE_INPUTS_BYTES,
    MAX_REPORT_JSON_BYTES,
    PACKAGE_APT_ACTIONS_FILENAME,
    PACKAGE_APT_ACTIONS_SCHEMA,
)
from .package_causality import (
    MAX_EVIDENCE_JSON_BYTES as MAX_PACKAGE_CAUSALITY_JSON_BYTES,
)
from .package_causality import (
    PACKAGE_FILESYSTEM_CAUSALITY_FILENAME,
    PACKAGE_FILESYSTEM_CAUSALITY_SCHEMA,
    validate_package_filesystem_causality,
)
from .package_evidence import (
    validate_package_apt_actions_evidence,
    validate_package_evidence,
)
from .packaging import packaging_policy_report
from .prebuild_vm import validate_qemu_report
from .project import Project
from .provenance import CYCLONEDX_FILENAME, SPDX_FILENAME
from .release_contract import (
    release_gate_code_problem,
    release_gate_report_problem,
    release_manifest_problem,
    release_signing_report_problem,
)
from .release_readiness import ReleaseReadinessService
from .release_run import ExecutedReleaseRun, select_executed_release_run
from .release_signing import (
    OPERATIONAL_BUNDLE_FILES,
    SIGN_TARGETS,
    SIGNING_KEYRING,
    full_fingerprint,
    verify_detached_signature,
)
from .rootfs_evidence import (
    MAX_ROOTFS_MANIFEST_JSON_NODES,
    ROOTFS_PACKING_VERIFICATION_SCHEMA,
    validate_rootfs_evidence,
)
from .trust import TrustService
from .vulnscan import VulnScanService

MAX_PROVENANCE_JSON_BYTES = 128 * 1024 * 1024
MAX_RELEASE_EVIDENCE_JSON_BYTES = 128 * 1024 * 1024
MAX_COMMAND_LOG_BYTES = 128 * 1024 * 1024
MAX_SHA256_SIDECAR_BYTES = 4096
_RELEASE_SESSION_LIMITS = ArtifactLimits(
    max_open_files=1024,
    max_file_bytes=64 * 1024 * 1024 * 1024,
    max_buffered_bytes=1024 * 1024 * 1024,
    max_hashed_bytes=512 * 1024 * 1024 * 1024,
    max_json_depth=256,
    max_json_nodes=MAX_ROOTFS_MANIFEST_JSON_NODES,
    max_path_components=256,
    max_closing_fds=4096,
)


@dataclass(frozen=True)
class _ProvenanceSnapshot:
    raw: bytes | None
    data: dict[str, object] | None
    error: str | None


@dataclass(frozen=True)
class _GateContext:
    session: ArtifactVerificationSession
    output_dir: Path
    iso: Path
    project_root: Path
    verify_checksums: bool

    def handle(
        self,
        path: Path,
        *,
        max_bytes: int,
        label: str,
        allow_empty: bool = False,
    ) -> ArtifactHandle:
        return self.session.file_path(
            path.absolute(),
            max_bytes=max_bytes,
            label=label,
            allow_empty=allow_empty,
        )

    def read_bytes(self, path: Path, *, max_bytes: int, label: str) -> bytes:
        return self.handle(path, max_bytes=max_bytes, label=label).read_bytes()

    def read_json(self, path: Path, *, max_bytes: int, label: str) -> object:
        return self.handle(path, max_bytes=max_bytes, label=label).json()

    def digest(
        self,
        path: Path,
        *,
        label: str | None = None,
        max_bytes: int | None = None,
    ) -> str:
        return self.handle(
            path,
            max_bytes=max_bytes or self.session.limits.max_file_bytes,
            label=label or path.name,
        ).digest()

    def size(self, path: Path, *, label: str | None = None) -> int:
        return self.handle(
            path,
            max_bytes=self.session.limits.max_file_bytes,
            label=label or path.name,
        ).identity.size

    def checksum_entry(self, sums: Path, name: str) -> str | None:
        data = self.read_bytes(
            sums,
            max_bytes=MAX_SHA256_SIDECAR_BYTES,
            label="SHA256SUMS",
        )
        return sha256_from_sums_bytes(data, name)

    def inventory(
        self,
        directory: Path,
        *,
        label: str,
    ) -> ArtifactTreeInventory:
        return self.session.tree_inventory_path(
            directory.absolute(),
            label=label,
        )


def _tree_inventory(
    directory: Path,
    *,
    context: _GateContext | None,
    label: str,
) -> ArtifactTreeInventory:
    if context is not None:
        return context.inventory(directory, label=label)
    session = ArtifactVerificationSession(
        Path("/"),
        label=f"{label} artifact session",
        limits=_RELEASE_SESSION_LIMITS,
    )
    try:
        inventory = session.tree_inventory_path(
            directory.absolute(),
            label=label,
        )
        session.seal()
        return inventory
    except BaseException:
        session.close()
        raise


def _unsafe_inventory_entries(
    inventory: ArtifactTreeInventory,
) -> list[str]:
    return sorted(
        name
        for name, identity in inventory.entries
        if not stat.S_ISDIR(identity.mode) and not stat.S_ISREG(identity.mode)
    )


def _tree_safety_problem(
    directory: Path,
    *,
    context: _GateContext | None,
    label: str,
) -> str | None:
    try:
        inventory = _tree_inventory(
            directory,
            context=context,
            label=label,
        )
    except (ArtifactVerificationError, OSError, ValueError) as exc:
        return f"{label} has unsafe symlink, special-file, or unstable inventory evidence: {exc}"
    unsafe = _unsafe_inventory_entries(inventory)
    if unsafe:
        return f"{label} contains unsafe symlink or special entries: {', '.join(unsafe)}"
    return None


def _expected_inventory_entries(files: set[str]) -> set[str]:
    expected = set(files)
    for name in files:
        path = Path(name)
        for index in range(1, len(path.parts)):
            expected.add(Path(*path.parts[:index]).as_posix())
    return expected


@dataclass(frozen=True)
class ReleaseGateItem:
    code: str
    status: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "status": self.status, "detail": self.detail}


@dataclass
class ReleaseGateReport:
    project: Path
    iso: Path
    output_dir: Path
    items: list[ReleaseGateItem] = field(default_factory=list)
    artifact_receipt: ArtifactVerificationReceipt | None = field(
        default=None,
        repr=False,
        compare=False,
    )
    build_run_id: str | None = field(default=None, repr=False, compare=False)
    boot_run_id: str | None = field(default=None, repr=False, compare=False)
    immutable_iso_build: Path | None = field(
        default=None,
        repr=False,
        compare=False,
    )
    immutable_provenance: Path | None = field(
        default=None,
        repr=False,
        compare=False,
    )
    immutable_boot_proof: Path | None = field(
        default=None,
        repr=False,
        compare=False,
    )
    immutable_qemu_report: Path | None = field(
        default=None,
        repr=False,
        compare=False,
    )
    immutable_sbom: Path | None = field(
        default=None,
        repr=False,
        compare=False,
    )

    @property
    def status(self) -> str:
        if any(item.status == "blocked" for item in self.items):
            return "blocked"
        if any(item.status == "review" for item in self.items):
            return "review"
        return "ready"

    @property
    def blocked(self) -> bool:
        return self.status == "blocked"

    def to_dict(self) -> dict[str, object]:
        return {
            "project": str(self.project),
            "iso": str(self.iso),
            "output_dir": str(self.output_dir),
            "build_run_id": self.build_run_id,
            "boot_run_id": self.boot_run_id,
            "immutable_iso_build": (
                str(self.immutable_iso_build) if self.immutable_iso_build is not None else None
            ),
            "immutable_provenance": (
                str(self.immutable_provenance) if self.immutable_provenance is not None else None
            ),
            "immutable_boot_proof": (
                str(self.immutable_boot_proof) if self.immutable_boot_proof is not None else None
            ),
            "immutable_qemu_report": (
                str(self.immutable_qemu_report) if self.immutable_qemu_report is not None else None
            ),
            "immutable_sbom": (
                str(self.immutable_sbom) if self.immutable_sbom is not None else None
            ),
            "status": self.status,
            "blocked": self.blocked,
            "items": [item.to_dict() for item in self.items],
        }

    def render_text(self) -> str:
        lines = [
            "Release gate",
            f"Project: {self.project}",
            f"ISO: {self.iso}",
            f"Output: {self.output_dir}",
            f"Status: {self.status.upper()}",
            "",
        ]
        lines.extend(f"[{item.status}] {item.code}: {item.detail}" for item in self.items)
        return "\n".join(lines)

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class ReleaseGateService:
    def check(
        self,
        project: Project,
        options: BuildOptions,
        *,
        iso: Path | None = None,
        output_dir: Path | None = None,
        bundle_dir: Path | None = None,
        verify_checksums: bool = True,
        capture_artifact_receipt: bool = False,
        build_run_id: str | None = None,
        boot_run_id: str | None = None,
    ) -> ReleaseGateReport:
        """Report the maintainer publish gate for ``project``.

        ``verify_checksums=False`` answers the SHA256 items from the SHA256SUMS
        sidecar instead of re-reading the ISO, which is what the guided journey
        status needs: it is recomputed on every refresh and must not hash a
        multi-gigabyte artifact on the Qt thread. The verifying default stays on
        every authoritative path (``distroforge release-gate``, the Artifacts
        page, ``check_journey_step``), so the gate is never self-confirming
        where its verdict is the answer.

        ``capture_artifact_receipt`` is reserved for an immediate immutable
        bundle copy. It hashes every opened or inventoried product file and must
        stay disabled for the status-only UI path.

        ``build_run_id`` selects one audited ``evidence/runs`` directory.
        Without it the gate requires exactly one immutable executed run matching
        the canonical project and ISO; top-level build/provenance aliases never
        select or authorize a release. ``boot_run_id`` may select a standalone
        immutable boot run only when the selected build report does not embed
        one. An embedded boot run remains authoritative and an incompatible
        explicit value is blocked.
        """
        paths = default_artifact_paths(project)
        iso = iso or options.output_iso or paths.output_iso
        output_dir = output_dir or iso.parent
        bundle_dir = Path(os.path.abspath(bundle_dir or project.output_dir / "publish"))
        report = ReleaseGateReport(project.root, iso, output_dir)
        session = ArtifactVerificationSession(
            Path("/"),
            label="release gate artifact session",
            limits=_RELEASE_SESSION_LIMITS,
        )
        context = _GateContext(
            session=session,
            output_dir=output_dir.absolute(),
            iso=iso.absolute(),
            project_root=project.root.absolute(),
            verify_checksums=verify_checksums,
        )
        try:
            selected_run: ExecutedReleaseRun | None = None
            selection_error: str | None = None
            try:
                selected_run = select_executed_release_run(
                    project,
                    context.iso,
                    context.output_dir,
                    session,
                    build_run_id=build_run_id,
                    verify_iso=verify_checksums,
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
                selection_error = str(exc)
                provenance_snapshot = _ProvenanceSnapshot(
                    None,
                    None,
                    "Immutable executed build run selection failed: " + selection_error,
                )
            else:
                report.build_run_id = selected_run.run_id
                report.immutable_iso_build = selected_run.iso_build_path
                report.immutable_provenance = selected_run.provenance_path
                provenance_snapshot = _ProvenanceSnapshot(
                    selected_run.provenance.read_bytes(),
                    selected_run.provenance_payload,
                    None,
                )
            package_inputs = _package_inputs_item(
                output_dir,
                project,
                options,
                verify=verify_checksums,
                provenance_snapshot=provenance_snapshot,
                context=context,
            )
            _check_source_trust(report, project, options, package_inputs)
            report.items.append(package_inputs)
            report.items.append(
                _rootfs_evidence_item(
                    output_dir,
                    verify=verify_checksums,
                    provenance_snapshot=provenance_snapshot,
                    context=context,
                )
            )
            report.items.append(
                _iso_assembly_item(
                    output_dir,
                    iso,
                    project=project,
                    verify=verify_checksums,
                    provenance_snapshot=provenance_snapshot,
                    context=context,
                )
            )
            _check_vuln_policy(report, project, options)
            _check_iso_and_checksums(
                report,
                iso,
                output_dir,
                verify_checksums,
                context=context,
            )
            _check_boot_proof(
                report,
                iso,
                output_dir,
                options,
                selected_run=selected_run,
                requested_boot_run_id=boot_run_id,
                context=context,
            )
            _check_release_files(
                report,
                iso,
                output_dir,
                options,
                provenance_snapshot=provenance_snapshot,
                context=context,
                verify=verify_checksums,
                selected_run=selected_run,
                selection_error=selection_error,
            )
            _check_release_readiness(
                report,
                iso,
                output_dir,
                verify_checksums,
                context=context,
                qemu_report=report.immutable_qemu_report,
            )
            _check_packaging_policy(report, project.root)
            _check_publish_signing(
                report,
                project.root,
                options,
                project_name=project.name,
                context=context,
                bundle_dir=bundle_dir,
            )
            report.items.append(
                _provenance_snapshot_closure_item(
                    (
                        selected_run.provenance_path
                        if selected_run is not None
                        else output_dir
                        / "evidence"
                        / "runs"
                        / (build_run_id or "<unselected>")
                        / "distroforge-provenance.json"
                    ),
                    provenance_snapshot,
                    context=context,
                )
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
            report.items.append(
                ReleaseGateItem(
                    "artifact-session",
                    "blocked",
                    f"Artifact verification stopped safely: {exc}",
                )
            )
        try:
            if capture_artifact_receipt:
                report.artifact_receipt = session.seal_with_receipt()
                metrics = session.metrics
            else:
                metrics = session.seal()
        except ArtifactVerificationError as exc:
            if not any(item.code == "artifact-session" for item in report.items):
                report.items.append(
                    ReleaseGateItem(
                        "artifact-session",
                        "blocked",
                        f"Artifact verification did not seal: {exc}",
                    )
                )
        else:
            report.items.append(
                ReleaseGateItem(
                    "artifact-session",
                    "ready",
                    "Scoped evidence I/O sealed "
                    f"(files_opened={metrics.files_opened}, "
                    f"bytes_hashed={metrics.bytes_hashed}, "
                    f"digest_reuse={metrics.digest_reuse}, "
                    f"replays={metrics.replays}).",
                )
            )
        return report


def _check_source_trust(
    report: ReleaseGateReport,
    project: Project,
    options: BuildOptions,
    package_inputs: ReleaseGateItem,
) -> None:
    if project.source_mode == "iso":
        trust = TrustService().check_source_iso(
            project.source_iso,
            options.trust,
            # Publication is authoritative even when branding policy is
            # advisory: SHA, detached signature and one full signer pin are not
            # optional properties of a derivative source.
            strict=True,
        )
        if not trust.ok:
            failures = [
                f"{check.code}: {check.message}" for check in trust.checks if check.level == "error"
            ]
            report.items.append(
                ReleaseGateItem(
                    "source-trust",
                    "blocked",
                    "; ".join(failures) or "Source ISO trust checks failed.",
                )
            )
            return
        report.items.append(
            ReleaseGateItem(
                "source-trust",
                "review",
                "Source ISO bytes match the external SHA256 and detached-signature "
                "inputs use one full signer fingerprint; publication remains review "
                "until the signature, verification status and keyring bytes are sealed "
                "in immutable run evidence for offline replay.",
            )
        )
        return
    if project.source_mode == "bootstrap" or project.source_starter:
        report.items.append(
            ReleaseGateItem(
                "source-trust",
                package_inputs.status,
                "Bootstrap trust is closed by the package-input run evidence: "
                + package_inputs.detail,
            )
        )
    else:
        report.items.append(
            ReleaseGateItem("source-trust", "blocked", "No source ISO, starter or bootstrap path.")
        )


def _package_inputs_item(
    output_dir: Path,
    project: Project,
    options: BuildOptions,
    *,
    verify: bool,
    provenance_snapshot: _ProvenanceSnapshot | None = None,
    context: _GateContext | None = None,
) -> ReleaseGateItem:
    provenance = output_dir / "distroforge-provenance.json"
    snapshot = provenance_snapshot or _load_provenance_snapshot(
        provenance,
        context=context,
    )
    if snapshot.error is not None:
        return ReleaseGateItem(
            "package-inputs",
            "blocked",
            "Cannot locate a package-input run without provenance: " + snapshot.error,
        )
    assert snapshot.data is not None
    provenance_data = snapshot.data
    run_id = provenance_data.get("run_id")
    if not is_safe_run_id(run_id):
        return ReleaseGateItem(
            "package-inputs",
            "blocked",
            "Provenance has no safe run identity for package inputs.",
        )
    assert isinstance(run_id, str)
    run = provenance_data.get("run")
    verification_time = run.get("created_at") if isinstance(run, dict) else None
    if not isinstance(verification_time, str) or not verification_time:
        return ReleaseGateItem(
            "package-inputs",
            "blocked",
            "Provenance has no immutable build instant for package freshness checks.",
        )
    run_dir = output_dir / "evidence" / "runs" / run_id
    evidence = run_dir / "PACKAGE-INPUTS.json"
    if not evidence.is_file():
        return ReleaseGateItem(
            "package-inputs",
            "blocked",
            "The current run has no PACKAGE-INPUTS.json closure.",
        )
    action_evidence = run_dir / PACKAGE_APT_ACTIONS_FILENAME
    if not action_evidence.is_file():
        return ReleaseGateItem(
            "package-inputs",
            "blocked",
            f"The current run has no {PACKAGE_APT_ACTIONS_FILENAME} receipt.",
        )
    causality_evidence = run_dir / PACKAGE_FILESYSTEM_CAUSALITY_FILENAME
    if not causality_evidence.is_file():
        return ReleaseGateItem(
            "package-inputs",
            "blocked",
            "The current run has no static package/filesystem identity map.",
        )
    if context is not None:
        try:
            package_run_inventory = context.inventory(
                run_dir,
                label="package validation run inventory",
            )
            unsafe_package_entries = _unsafe_inventory_entries(package_run_inventory)
            if unsafe_package_entries:
                return ReleaseGateItem(
                    "package-inputs",
                    "blocked",
                    "Package validation run contains non-regular entries: "
                    + ", ".join(unsafe_package_entries),
                )
            # Bind and strictly parse the three primary reports before any
            # delegated validator reopens subsidiary evidence.  The tree snapshot
            # then makes every delegated read part of this gate session: a swap or
            # in-place mutation anywhere in the run changes the closing inventory.
            for report_path, byte_limit, report_label in (
                (evidence, MAX_PACKAGE_INPUTS_BYTES, "PACKAGE-INPUTS"),
                (
                    action_evidence,
                    MAX_REPORT_JSON_BYTES,
                    "APT action report",
                ),
                (
                    causality_evidence,
                    MAX_PACKAGE_CAUSALITY_JSON_BYTES,
                    "package/filesystem causality report",
                ),
            ):
                context.handle(
                    report_path,
                    max_bytes=byte_limit,
                    label=report_label,
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
            return ReleaseGateItem(
                "package-inputs",
                "blocked",
                f"Package-input evidence cannot be session-bound: {exc}",
            )
    if not verify:
        try:
            payload = _read_bounded_json_file(
                evidence,
                max_bytes=MAX_PACKAGE_INPUTS_BYTES,
                label="PACKAGE-INPUTS",
                context=context,
            )
            action_payload = _read_bounded_json_file(
                action_evidence,
                max_bytes=MAX_REPORT_JSON_BYTES,
                label="APT action report",
                context=context,
            )
            causality_payload = _read_bounded_json_file(
                causality_evidence,
                max_bytes=MAX_PACKAGE_CAUSALITY_JSON_BYTES,
                label="package/filesystem causality report",
                context=context,
            )
        except (
            OSError,
            UnicodeError,
            TypeError,
            ValueError,
            OverflowError,
            RecursionError,
        ) as exc:
            return ReleaseGateItem(
                "package-inputs",
                "blocked",
                f"Package-input evidence is unreadable: {exc}",
            )
        action_boundary_error = _package_apt_actions_boundary_error(
            action_payload,
            run_dir,
            run_id,
            context=context,
        )
        if action_boundary_error is not None:
            return ReleaseGateItem(
                "package-inputs",
                "blocked",
                action_boundary_error,
            )
        if (
            not isinstance(causality_payload, dict)
            or causality_payload.get("schema") != PACKAGE_FILESYSTEM_CAUSALITY_SCHEMA
            or causality_payload.get("run_id") != run_id
            or causality_payload.get("payload_identity") not in {"partial", "verified"}
            or causality_payload.get("filesystem_causality") != "unverified"
            or causality_payload.get("release_ready") is not False
        ):
            return ReleaseGateItem(
                "package-inputs",
                "blocked",
                "The recorded package/filesystem map does not preserve the M3.1 proof boundary.",
            )
        recorded = payload.get("validation") if isinstance(payload, dict) else None
        if not isinstance(recorded, dict) or recorded.get("ok") is not True:
            return ReleaseGateItem(
                "package-inputs",
                "blocked",
                "Package-input closure did not validate when it was written.",
            )
        if recorded.get("release_ready") is not True:
            detail = recorded.get("detail")
            return ReleaseGateItem(
                "package-inputs",
                "blocked",
                (
                    (
                        f"{detail}; static payload identity is "
                        f"{causality_payload['payload_identity']}, while "
                        "filesystem causality remains unverified"
                    )
                    if isinstance(detail, str) and detail
                    else (
                        "Package inputs close, but installed .deb payload bytes are "
                        "not causally bound to every final rootfs path; the M3.1 "
                        "static identity map cannot supply that producer proof."
                    )
                ),
            )
        return ReleaseGateItem(
            "package-inputs",
            "blocked",
            "Package inputs record readiness, but M3.1 explicitly keeps static "
            "payload identity separate from unverified filesystem causality.",
        )
    try:
        command_argv = _command_argv_ledger(
            run_dir / "commands.jsonl",
            context=context,
        )
    except ValueError as exc:
        return ReleaseGateItem(
            "package-inputs",
            "blocked",
            f"Package-input command ledger is invalid: {exc}",
        )
    validation = validate_package_evidence(
        run_dir,
        expected_run_id=run_id,
        expected_source_mode=project.source_mode,
        expected_signer_fingerprints=[
            *options.bootstrap.archive_signer_fingerprints,
            *[ppa.fingerprint for ppa in options.ppa.ppas if ppa.fingerprint],
        ],
        expected_keyring_sha256=options.bootstrap.archive_keyring_sha256,
        expected_source_policies=options.bootstrap.source_policies,
        expected_verification_time=verification_time,
        apt_command_argv=command_argv,
    )
    if not validation.ok:
        return ReleaseGateItem(
            "package-inputs",
            "blocked",
            validation.detail,
        )
    action_validation = validate_package_apt_actions_evidence(
        run_dir,
        expected_run_id=run_id,
    )
    if not action_validation.ok:
        return ReleaseGateItem(
            "package-inputs",
            "blocked",
            action_validation.detail,
        )
    causality_validation = validate_package_filesystem_causality(
        run_dir,
        expected_run_id=run_id,
    )
    if not causality_validation.ok:
        return ReleaseGateItem(
            "package-inputs",
            "blocked",
            causality_validation.detail,
        )
    return ReleaseGateItem(
        "package-inputs",
        (
            "ready"
            if (
                validation.release_ready
                and action_validation.release_ready
                and causality_validation.release_ready
            )
            else "blocked"
        ),
        (f"{validation.detail}; {action_validation.detail}; {causality_validation.detail}"),
    )


def _read_bounded_json_file(
    path: Path,
    *,
    max_bytes: int,
    label: str,
    context: _GateContext | None = None,
) -> object:
    """Read one regular JSON file through a stable, size-bounded descriptor."""

    if context is not None:
        try:
            return context.read_json(path, max_bytes=max_bytes, label=label)
        except ArtifactVerificationError as exc:
            raise ValueError(str(exc)) from exc
    data = _read_bounded_file(
        path,
        max_bytes=max_bytes,
        label=label,
    )
    return _decode_json(data, label=label)


def _decode_json(data: bytes, *, label: str) -> object:
    try:
        return json.loads(data.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not valid UTF-8 JSON") from exc


def _read_bounded_file(
    path: Path,
    *,
    max_bytes: int,
    label: str,
    context: _GateContext | None = None,
) -> bytes:
    """Read one regular file without following links or blocking on a FIFO."""

    if context is not None:
        try:
            return context.read_bytes(path, max_bytes=max_bytes, label=label)
        except ArtifactVerificationError as exc:
            raise ValueError(str(exc)) from exc
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError(f"{label} is a symlink") from exc
        raise
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > max_bytes:
            raise ValueError(f"{label} exceeds its byte bound")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(max_bytes + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    stable_fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    if (
        len(data) > max_bytes
        or len(data) != before.st_size
        or any(getattr(before, field) != getattr(after, field) for field in stable_fields)
    ):
        raise ValueError(f"{label} changed while it was read")
    return data


def _load_provenance_snapshot(
    path: Path,
    *,
    context: _GateContext | None = None,
) -> _ProvenanceSnapshot:
    try:
        if context is not None:
            handle = context.handle(
                path,
                max_bytes=MAX_PROVENANCE_JSON_BYTES,
                label="provenance",
            )
            raw = handle.read_bytes()
            parsed = handle.json()
        else:
            with ArtifactVerificationSession(
                Path("/"),
                label="provenance snapshot",
                limits=_RELEASE_SESSION_LIMITS,
            ) as session:
                handle = session.file_path(
                    path.absolute(),
                    max_bytes=MAX_PROVENANCE_JSON_BYTES,
                    label="provenance",
                )
                raw = handle.read_bytes()
                parsed = handle.json()
        if not isinstance(parsed, dict):
            raise ValueError("provenance is not a JSON object")
        data = parsed
    except (
        ArtifactVerificationError,
        OSError,
        UnicodeError,
        TypeError,
        ValueError,
        OverflowError,
        RecursionError,
    ) as exc:
        return _ProvenanceSnapshot(None, None, str(exc))
    return _ProvenanceSnapshot(raw, data, None)


def _provenance_snapshot_closure_item(
    path: Path,
    opening: _ProvenanceSnapshot,
    *,
    context: _GateContext | None = None,
) -> ReleaseGateItem:
    if opening.error is not None or opening.raw is None:
        return ReleaseGateItem(
            "provenance-snapshot",
            "blocked",
            "No valid opening provenance snapshot was available.",
        )
    try:
        closing_raw = _read_bounded_file(
            path,
            max_bytes=MAX_PROVENANCE_JSON_BYTES,
            label="provenance",
            context=context,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        return ReleaseGateItem(
            "provenance-snapshot",
            "blocked",
            "Provenance could not be closed against its opening snapshot: " + str(exc),
        )
    if closing_raw != opening.raw:
        return ReleaseGateItem(
            "provenance-snapshot",
            "blocked",
            "Provenance changed while the release gate was evaluated.",
        )
    return ReleaseGateItem(
        "provenance-snapshot",
        "ready",
        "All items used one bounded provenance snapshot; opening and closing bytes match.",
    )


def _package_apt_actions_boundary_error(
    payload: object,
    run_dir: Path,
    run_id: str,
    *,
    context: _GateContext | None = None,
) -> str | None:
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != PACKAGE_APT_ACTIONS_SCHEMA
        or payload.get("run_id") != run_id
        or payload.get("scope") != "apt-dpkg-pre-install-pkgs-v3-planned-actions-m3.2a"
        or payload.get("capture_origin") != "unverified-mutable-target-rootfs"
        or payload.get("filesystem_causality") != "unverified"
        or payload.get("release_ready") is not False
        or payload.get("apt_actions") not in {"self-consistent", "not-observed"}
    ):
        return "The APT action receipt does not preserve the M3.2a proof boundary."
    for identity_field, expected_path in (
        ("package_inputs", "PACKAGE-INPUTS.json"),
        ("capture_journal", "apt/transactions.tsv"),
    ):
        identity = payload.get(identity_field)
        if not isinstance(identity, dict):
            return f"The APT action receipt has no valid {identity_field} identity."
        artifact = run_dir / expected_path
        if (
            identity.get("path") != expected_path
            or artifact.is_symlink()
            or not artifact.is_file()
            or identity.get("size")
            != (
                context.size(artifact, label=expected_path)
                if context is not None
                else artifact.stat().st_size
            )
            or identity.get("sha256")
            != (
                context.digest(artifact, label=expected_path)
                if context is not None
                else sha256_file(artifact)
            )
        ):
            return f"The APT action receipt is not bound to this run's {expected_path}."
    transactions = payload.get("transactions")
    if not isinstance(transactions, list):
        return "The APT action receipt transaction list is malformed."
    if (payload.get("apt_actions") == "self-consistent" and not transactions) or (
        payload.get("apt_actions") == "not-observed" and transactions
    ):
        return "The APT action status contradicts its transaction list."
    transaction_ids: set[str] = set()
    for transaction in transactions:
        if not isinstance(transaction, dict):
            return "The APT action receipt contains a malformed transaction."
        transaction_id = transaction.get("id")
        protocol = transaction.get("protocol")
        capture = transaction.get("capture")
        actions = transaction.get("actions")
        if (
            not isinstance(transaction_id, str)
            or not transaction_id
            or Path(transaction_id).name != transaction_id
            or transaction_id in transaction_ids
            or not isinstance(protocol, dict)
            or protocol.get("version") != 3
            or not isinstance(capture, dict)
            or capture.get("complete") is not True
            or not isinstance(actions, list)
            or protocol.get("action_count") != len(actions)
            or not isinstance(transaction.get("recorder"), dict)
            or not isinstance(transaction.get("configuration"), dict)
        ):
            return "The APT action receipt contains an invalid protocol-v3 transaction."
        transaction_ids.add(transaction_id)
    return None


def _command_argv_ledger(
    path: Path,
    *,
    context: _GateContext | None = None,
) -> tuple[tuple[str, ...], ...]:
    """Load every dispatched argv from the final immutable run log.

    ``PACKAGE-INPUTS.json`` is written before packing and ISO assembly.  Reading
    the complete final log here makes any later APT/debootstrap/mmdebstrap
    invocation part of the independently recomputed ledger rather than silently
    trusting the earlier aggregate.
    """

    try:
        events = _command_jsonl_events(path, context=context)
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValueError(f"commands.jsonl is unreadable: {exc}") from exc
    commands: list[tuple[str, ...]] = []
    for line_number, event in enumerate(events, start=1):
        if not isinstance(event, dict):
            raise ValueError(f"commands.jsonl line {line_number} is not an event")
        if event.get("event") != "start":
            continue
        argv = event.get("argv")
        if (
            not isinstance(argv, list)
            or not argv
            or not all(isinstance(token, str) and token for token in argv)
        ):
            raise ValueError(f"commands.jsonl line {line_number} has malformed argv")
        commands.append(tuple(argv))
    return tuple(commands)


def _command_jsonl_events(
    path: Path,
    *,
    context: _GateContext | None = None,
) -> tuple[object, ...]:
    """Parse one bounded command ledger once per gate verdict."""

    def parse() -> tuple[object, ...]:
        data = _read_bounded_file(
            path,
            max_bytes=MAX_COMMAND_LOG_BYTES,
            label="commands.jsonl",
            context=context,
        )
        if b"\r" in data or (data and not data.endswith(b"\n")):
            raise ValueError("commands.jsonl must use LF records and end with a final LF")
        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise ValueError("commands.jsonl is not strict UTF-8") from exc
        events: list[object] = []
        node_count = 0
        node_limit = (
            context.session.limits.max_json_nodes
            if context is not None
            else _RELEASE_SESSION_LIMITS.max_json_nodes
        )
        depth_limit = (
            context.session.limits.max_json_depth
            if context is not None
            else _RELEASE_SESSION_LIMITS.max_json_depth
        )
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(
                    line,
                    object_pairs_hook=_unique_json_pairs,
                    parse_constant=_reject_json_constant,
                )
                node_count = _validate_json_value(
                    event,
                    initial_nodes=node_count,
                    max_nodes=node_limit,
                    max_depth=depth_limit,
                )
            except (
                json.JSONDecodeError,
                UnicodeError,
                RecursionError,
                OverflowError,
                ValueError,
            ) as exc:
                raise ValueError(
                    f"commands.jsonl line {line_number} is not bounded canonical JSON"
                ) from exc
            events.append(event)
        return tuple(events)

    if context is None:
        return parse()
    return context.session.memo(
        ("commands-jsonl", str(path.absolute())),
        parse,
    )


def _unique_json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON number: {value}")


def _validate_json_value(
    value: object,
    *,
    initial_nodes: int,
    max_nodes: int,
    max_depth: int,
) -> int:
    nodes = initial_nodes
    stack: list[tuple[object, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes:
            raise ValueError(f"JSONL exceeds {max_nodes} nodes")
        if depth > max_depth:
            raise ValueError(f"JSONL exceeds depth {max_depth}")
        if isinstance(current, dict):
            stack.extend((item, depth + 1) for pair in current.items() for item in pair)
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
        elif isinstance(current, float) and not math.isfinite(current):
            raise ValueError("JSONL contains a non-finite number")
        elif isinstance(current, str):
            current.encode("utf-8", errors="strict")
    return nodes


def _rootfs_evidence_item(
    output_dir: Path,
    *,
    verify: bool,
    provenance_snapshot: _ProvenanceSnapshot | None = None,
    context: _GateContext | None = None,
) -> ReleaseGateItem:
    provenance = output_dir / "distroforge-provenance.json"
    snapshot = provenance_snapshot or _load_provenance_snapshot(
        provenance,
        context=context,
    )
    if snapshot.error is not None:
        return ReleaseGateItem(
            "rootfs-identity",
            "blocked",
            "Cannot locate rootfs evidence without provenance: " + snapshot.error,
        )
    assert snapshot.data is not None
    provenance_data = snapshot.data
    run_id = provenance_data.get("run_id")
    if not is_safe_run_id(run_id):
        return ReleaseGateItem(
            "rootfs-identity",
            "blocked",
            "Provenance has no safe run identity for rootfs evidence.",
        )
    assert isinstance(run_id, str)
    run_dir = output_dir / "evidence" / "runs" / run_id
    manifest = run_dir / "ROOTFS-MANIFEST.json"
    verification = run_dir / "ROOTFS-PACKING-VERIFICATION.json"
    if not manifest.is_file() or not verification.is_file():
        return ReleaseGateItem(
            "rootfs-identity",
            "blocked",
            "The current run lacks final rootfs or packed-product evidence.",
        )
    if not verify:
        try:
            payload = _read_bounded_json_file(
                verification,
                max_bytes=MAX_RELEASE_EVIDENCE_JSON_BYTES,
                label="rootfs packing verification",
                context=context,
            )
        except (
            OSError,
            UnicodeError,
            TypeError,
            ValueError,
            OverflowError,
            RecursionError,
        ) as exc:
            return ReleaseGateItem(
                "rootfs-identity",
                "blocked",
                f"Rootfs packing verification is unreadable: {exc}",
            )
        packed_image = payload.get("packed_image") if isinstance(payload, dict) else None
        packed_rootfs = payload.get("packed_rootfs") if isinstance(payload, dict) else None
        if (
            not isinstance(payload, dict)
            or payload.get("schema") != ROOTFS_PACKING_VERIFICATION_SCHEMA
            or payload.get("run_id") != run_id
            or payload.get("status") != "verified"
            or not isinstance(packed_image, dict)
            or packed_image.get("matches_witness") is not True
            or not isinstance(packed_rootfs, dict)
            or packed_rootfs.get("matches_manifest") is not True
        ):
            return ReleaseGateItem(
                "rootfs-identity",
                "blocked",
                "Rootfs packing proof did not close when it was written.",
            )
        return ReleaseGateItem(
            "rootfs-identity",
            "review",
            "Rootfs proof exists; authoritative refresh will rehash the full manifest.",
        )
    validation = validate_rootfs_evidence(
        run_dir,
        expected_run_id=run_id,
        session=context.session if context is not None else None,
    )
    return ReleaseGateItem(
        "rootfs-identity",
        "ready" if validation.ok else "blocked",
        validation.detail,
    )


def _iso_assembly_item(
    output_dir: Path,
    iso: Path,
    *,
    project: Project,
    verify: bool,
    provenance_snapshot: _ProvenanceSnapshot | None = None,
    context: _GateContext | None = None,
) -> ReleaseGateItem:
    provenance = output_dir / "distroforge-provenance.json"
    snapshot = provenance_snapshot or _load_provenance_snapshot(
        provenance,
        context=context,
    )
    if snapshot.error is not None:
        return ReleaseGateItem(
            "iso-assembly",
            "blocked",
            "Cannot locate ISO assembly evidence without provenance: " + snapshot.error,
        )
    assert snapshot.data is not None
    provenance_data = snapshot.data
    run_id = provenance_data.get("run_id")
    if not is_safe_run_id(run_id):
        return ReleaseGateItem(
            "iso-assembly",
            "blocked",
            "Provenance has no safe run identity for ISO assembly evidence.",
        )
    assert isinstance(run_id, str)
    run_dir = output_dir / "evidence" / "runs" / run_id
    evidence = run_dir / ISO_ASSEMBLY_FILENAME
    if not evidence.is_file():
        return ReleaseGateItem(
            "iso-assembly",
            "blocked",
            "The current run lacks final ISO embedded-SquashFS evidence.",
        )
    if not verify:
        try:
            payload = _read_bounded_json_file(
                evidence,
                max_bytes=MAX_RELEASE_EVIDENCE_JSON_BYTES,
                label="ISO assembly evidence",
                context=context,
            )
        except (
            OSError,
            UnicodeError,
            TypeError,
            ValueError,
            OverflowError,
            RecursionError,
        ) as exc:
            return ReleaseGateItem(
                "iso-assembly",
                "blocked",
                f"ISO assembly evidence is unreadable: {exc}",
            )
        if (
            not isinstance(payload, dict)
            or payload.get("schema") != ISO_ASSEMBLY_SCHEMA
            or payload.get("run_id") != run_id
            or payload.get("status") != "verified"
            or payload.get("matches_staged") is not True
            or payload.get("staged_squashfs") != payload.get("embedded_squashfs")
        ):
            return ReleaseGateItem(
                "iso-assembly",
                "blocked",
                "Final ISO embedded-SquashFS proof did not close when written.",
            )
        return ReleaseGateItem(
            "iso-assembly",
            "review",
            "ISO assembly proof exists; authoritative refresh will rehash the final ISO.",
        )
    validation = validate_iso_assembly_evidence(
        run_dir,
        expected_run_id=run_id,
        output_iso_path=iso,
        staged_squashfs_path=(project.iso_root / project.release.livefs / "filesystem.squashfs"),
        session=context.session if context is not None else None,
    )
    return ReleaseGateItem(
        "iso-assembly",
        "ready" if validation.ok else "blocked",
        validation.detail,
    )


def _check_vuln_policy(
    report: ReleaseGateReport,
    project: Project,
    options: BuildOptions,
) -> None:
    if not options.vuln_scan.enabled:
        report.items.append(ReleaseGateItem("vuln-scan", "review", "CVE scanning is not enabled."))
        return
    packages = DiffPreviewService().preview(project, options).install
    scan = VulnScanService(options.vuln_scan).scan(packages)
    counts = scan.counts
    summary = (
        f"policy={scan.policy} db={scan.database} "
        f"database_status={scan.database_status} "
        f"database_error={scan.database_error or 'none'} "
        f"verdict={scan.verdict} "
        f"db_sha256={scan.database_sha256 or 'unavailable'} "
        f"schema={scan.database_schema or 'unavailable'} "
        f"source={scan.database_source or 'unavailable'} "
        f"updated={scan.database_updated or 'unavailable'} "
        f"advisories={scan.advisory_count} scanned={scan.scanned} "
        f"critical={counts['critical']} high={counts['high']} unknown={counts['unknown']}"
    )
    if not scan.ok:
        report.items.append(
            ReleaseGateItem("vuln-scan", "blocked", f"CVE policy violated: {summary}")
        )
    elif scan.verdict == "degraded":
        report.items.append(ReleaseGateItem("vuln-scan", "review", f"CVE scan degraded: {summary}"))
    elif scan.findings:
        report.items.append(
            ReleaseGateItem(
                "vuln-scan", "review", f"Known advisories present (non-blocking): {summary}"
            )
        )
    else:
        report.items.append(
            ReleaseGateItem("vuln-scan", "ready", f"No known advisories matched: {summary}")
        )


def _check_iso_and_checksums(
    report: ReleaseGateReport,
    iso: Path,
    output_dir: Path,
    verify_checksums: bool = True,
    *,
    context: _GateContext | None = None,
) -> None:
    try:
        iso.lstat()
    except FileNotFoundError:
        report.items.append(ReleaseGateItem("iso", "blocked", "Final ISO is missing."))
        report.items.append(
            ReleaseGateItem("sha256", "blocked", "Cannot verify SHA256 without an ISO.")
        )
        return
    except OSError as exc:
        report.items.append(
            ReleaseGateItem("iso", "blocked", f"Final ISO cannot be inspected: {exc}")
        )
        report.items.append(
            ReleaseGateItem("sha256", "blocked", "Cannot verify SHA256 without a safe ISO.")
        )
        return
    try:
        size = context.size(iso, label="final ISO") if context is not None else iso.stat().st_size
    except (ArtifactVerificationError, OSError, ValueError) as exc:
        report.items.append(ReleaseGateItem("iso", "blocked", f"Final ISO is unsafe: {exc}"))
        report.items.append(
            ReleaseGateItem("sha256", "blocked", "Cannot verify SHA256 without a safe ISO.")
        )
        return
    report.items.append(ReleaseGateItem("iso", "ready", f"{size} bytes"))
    sums = output_dir / "SHA256SUMS"
    try:
        sums.lstat()
    except FileNotFoundError:
        report.items.append(ReleaseGateItem("sha256", "blocked", "SHA256SUMS is missing."))
        return
    except OSError as exc:
        report.items.append(
            ReleaseGateItem("sha256", "blocked", f"SHA256SUMS cannot be inspected: {exc}")
        )
        return
    try:
        if context is not None:
            expected = context.checksum_entry(sums, iso.name)
        else:
            expected = sha256_from_sums_bytes(
                _read_bounded_file(
                    sums,
                    max_bytes=MAX_SHA256_SIDECAR_BYTES,
                    label="SHA256SUMS",
                ),
                iso.name,
            )
    except (OSError, UnicodeError, ValueError, ArtifactVerificationError) as exc:
        report.items.append(ReleaseGateItem("sha256", "blocked", f"SHA256SUMS is invalid: {exc}"))
        return
    if not verify_checksums:
        # Status-only pass: SHA256SUMS must cover the ISO, but the bytes are not
        # re-read. Whoever needs the verdict itself asks with the default.
        if expected is None:
            report.items.append(
                ReleaseGateItem("sha256", "blocked", "SHA256SUMS does not list the ISO.")
            )
            return
        report.items.append(ReleaseGateItem("sha256", "ready", expected))
        return
    actual = context.digest(iso, label="final ISO") if context is not None else sha256_file(iso)
    if expected != actual:
        report.items.append(
            ReleaseGateItem("sha256", "blocked", "SHA256SUMS does not match the ISO.")
        )
        return
    report.items.append(ReleaseGateItem("sha256", "ready", actual))


def _check_release_files(
    report: ReleaseGateReport,
    iso: Path,
    output_dir: Path,
    options: BuildOptions,
    *,
    provenance_snapshot: _ProvenanceSnapshot,
    context: _GateContext | None = None,
    verify: bool = True,
    selected_run: ExecutedReleaseRun | None = None,
    selection_error: str | None = None,
) -> None:
    recorded_sbom_format = (
        selected_run.provenance_payload.get("sbom_format") if selected_run is not None else None
    )
    sbom_format = (
        recorded_sbom_format
        if isinstance(recorded_sbom_format, str)
        else options.provenance.sbom_format
    )
    sbom_filename = (
        SPDX_FILENAME
        if sbom_format == "spdx"
        else CYCLONEDX_FILENAME
        if sbom_format == "cyclonedx"
        else None
    )
    embedded_boot_paths: set[Path] = set()
    embedded_boot = (
        selected_run.iso_build_payload.get("boot_proof") if selected_run is not None else None
    )
    if isinstance(embedded_boot, dict) and is_safe_run_id(embedded_boot.get("run_id")):
        embedded_boot_run_id = str(embedded_boot["run_id"])
        embedded_boot_dir = (output_dir / "evidence" / "runs" / embedded_boot_run_id).absolute()
        embedded_boot_paths.add(embedded_boot_dir / "boot-proof.json")
        embedded_qemu_name = embedded_boot.get("qemu_report")
        if (
            isinstance(embedded_qemu_name, str)
            and embedded_qemu_name
            and Path(embedded_qemu_name).name == embedded_qemu_name
            and embedded_qemu_name not in {".", ".."}
            and "\x00" not in embedded_qemu_name
        ):
            embedded_boot_paths.add(embedded_boot_dir / embedded_qemu_name)
    allowed_release_paths = frozenset(
        {
            *embedded_boot_paths,
            *(
                (output_dir / filename).absolute()
                for filename in (
                    "BUILDINFO",
                    "SHA256SUMS",
                    options.html_report.filename,
                )
                if filename is not None
            ),
        }
    )
    for code, filename, enabled in (
        ("buildinfo", "BUILDINFO", options.release_artifacts.enabled),
        ("provenance", "distroforge-provenance.json", options.provenance.enabled),
        ("sbom", sbom_filename, options.provenance.enabled and sbom_filename is not None),
        ("html-report", options.html_report.filename, options.html_report.enabled),
    ):
        if (
            code == "sbom"
            and selected_run is not None
            and recorded_sbom_format not in {"native", "spdx", "cyclonedx"}
        ):
            report.items.append(
                ReleaseGateItem(
                    code,
                    "blocked",
                    "Immutable build provenance has an absent or unsupported sbom_format.",
                )
            )
            continue
        if filename is None:
            report.items.append(
                ReleaseGateItem(code, "review", "Standard-format SBOM export is not enabled.")
            )
            continue
        path = (
            selected_run.provenance_path
            if code == "provenance" and selected_run is not None
            else selected_run.run_dir / filename
            if code == "sbom" and selected_run is not None
            else output_dir / filename
        )
        if code == "provenance" and selected_run is None:
            report.items.append(
                ReleaseGateItem(
                    code,
                    "blocked",
                    "No immutable executed build provenance was selected: "
                    + (selection_error or "selection did not return a run"),
                )
            )
            continue
        if code == "sbom" and selected_run is None:
            report.items.append(
                ReleaseGateItem(
                    code,
                    "blocked",
                    "No immutable executed build run was selected for the SBOM: "
                    + (selection_error or "selection did not return a run"),
                )
            )
            continue
        if code == "sbom":
            report.immutable_sbom = path
        if code == "provenance":
            if not verify:
                status = "review" if provenance_snapshot.error is None else "blocked"
                report.items.append(
                    ReleaseGateItem(
                        code,
                        status,
                        (
                            "Provenance opening snapshot is structurally readable; "
                            "the authoritative gate will bind every artifact."
                            if status == "review"
                            else "Provenance opening snapshot is unreadable."
                        ),
                    )
                )
                continue
            report.items.append(
                _validate_build_provenance(
                    path,
                    iso,
                    output_dir,
                    use_sudo=options.use_sudo,
                    provenance_snapshot=provenance_snapshot,
                    context=context,
                    allowed_release_paths=allowed_release_paths,
                )
            )
            continue
        if path.exists():
            if not verify:
                report.items.append(
                    ReleaseGateItem(
                        code,
                        "review",
                        f"{filename} exists; authoritative binding is deferred.",
                    )
                )
                continue
            if code in {"buildinfo", "sbom", "html-report"} and not _build_manifest_binds(
                output_dir,
                path,
                provenance_snapshot=provenance_snapshot,
                context=context,
            ):
                report.items.append(
                    ReleaseGateItem(
                        code,
                        "blocked" if enabled else "review",
                        f"{filename} exists but is not bound to the current build run.",
                    )
                )
            else:
                report.items.append(ReleaseGateItem(code, "ready", str(path)))
        elif enabled:
            report.items.append(
                ReleaseGateItem(code, "blocked", f"Expected release file is missing: {filename}")
            )
        else:
            report.items.append(ReleaseGateItem(code, "review", f"{filename} is not enabled."))


def _build_manifest_binds(
    output_dir: Path,
    artifact: Path,
    *,
    provenance_snapshot: _ProvenanceSnapshot | None = None,
    context: _GateContext | None = None,
) -> bool:
    snapshot = provenance_snapshot or _load_provenance_snapshot(
        output_dir / "distroforge-provenance.json",
        context=context,
    )
    if snapshot.error is not None or snapshot.data is None:
        return False
    data = snapshot.data
    try:
        run_id = data.get("run_id")
        if not is_safe_run_id(run_id):
            return False
        assert isinstance(run_id, str)
        manifest = _read_bounded_json_file(
            output_dir / "evidence" / "runs" / run_id / "RUN-MANIFEST.json",
            max_bytes=MAX_RELEASE_EVIDENCE_JSON_BYTES,
            label="run manifest",
            context=context,
        )
    except (
        OSError,
        UnicodeError,
        TypeError,
        ValueError,
        OverflowError,
        RecursionError,
    ):
        return False
    files = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(files, list) or not artifact.is_file():
        return False
    try:
        artifact_size = context.size(artifact) if context is not None else artifact.stat().st_size
        artifact_digest = context.digest(artifact) if context is not None else sha256_file(artifact)
    except (ArtifactVerificationError, OSError, ValueError):
        return False
    return any(
        isinstance(item, dict)
        and item.get("path") == str(artifact)
        and item.get("size") == artifact_size
        and item.get("sha256") == artifact_digest
        for item in files
    )


def _identity_closure_problem(run: dict[str, object]) -> str | None:
    component_names = ("builder_source", "definition", "source_iso", "toolchain")
    opening = {name: run.get(name) for name in component_names}
    recorded_opening_sha256 = run.get("opening_identity_sha256")
    if not _is_sha256(recorded_opening_sha256) or recorded_opening_sha256 != canonical_sha256(
        opening
    ):
        return "the opening identity digest is absent or inconsistent"

    closure = run.get("identity_closure")
    if (
        not isinstance(closure, dict)
        or closure.get("schema") != IDENTITY_CLOSURE_SCHEMA
        or closure.get("status") != "closed"
        or closure.get("opening_identity_sha256") != recorded_opening_sha256
        or closure.get("issues") != []
    ):
        return "the structured closing proof is absent, blocked, or inconsistent"
    checks = closure.get("checks")
    if not isinstance(checks, list) or closure.get("checks_sha256") != canonical_sha256(checks):
        return "the closing-check digest is absent or inconsistent"
    by_name = {
        check.get("name"): check
        for check in checks
        if isinstance(check, dict) and isinstance(check.get("name"), str)
    }
    if len(checks) != len(component_names) or set(by_name) != set(component_names):
        return "the closing proof does not cover every trusted input exactly once"
    for name in component_names:
        check = by_name[name]
        final = check.get("final")
        initial_sha256 = canonical_sha256(run.get(name))
        if (
            check.get("status") != "closed"
            or check.get("issues") != []
            or check.get("initial_sha256") != initial_sha256
            or not isinstance(final, dict)
            or check.get("final_sha256") != canonical_sha256(final)
            or check.get("final_sha256") != initial_sha256
        ):
            return f"the {name} opening and closing identities do not match"
    return None


def _git_builder_publication_problem(builder: dict[str, object]) -> str | None:
    if builder.get("kind") != "git":
        return "the builder source is not a reconstructible Git worktree"
    if builder.get("git_measurements_complete") is not True:
        return "one or more Git identity probes failed"
    for object_field in ("head", "tree"):
        value = builder.get(object_field)
        if (
            not isinstance(value, str)
            or re.fullmatch(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", value) is None
        ):
            return f"{object_field} is not a complete Git object ID"
    if builder.get("dirty") is not False:
        return "the builder worktree was dirty when the build opened"
    if builder.get("untracked") != []:
        return "untracked builder files were present"
    if builder.get("ignored_runtime_paths") != []:
        return "ignored runtime files under distroforge/ were present"
    if not _is_sha256(builder.get("worktree_sha256")):
        return "the worktree aggregate SHA256 is absent or malformed"
    if (
        builder.get("tracked_diff_sha256") != "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855"
    ):
        return "the recorded clean worktree has a non-empty tracked diff"
    signature = builder.get("commit_signature")
    if not isinstance(signature, str):
        return "the HEAD commit has no cryptographic signature result"
    signature_parts = signature.split()
    if (
        len(signature_parts) != 2
        or signature_parts[0] not in {"G", "U"}
        or re.fullmatch(
            r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})",
            signature_parts[1],
        )
        is None
    ):
        return (
            "the HEAD commit signature is not cryptographically good "
            "(Git %G? must be G or U with a full signer fingerprint)"
        )
    guard = builder.get("filesystem_guard")
    if (
        builder.get("stable_while_measured") is not True
        or not isinstance(guard, dict)
        or guard.get("stable") is not True
    ):
        return "the builder filesystem did not stay stable while measured"
    return None


def _validate_build_provenance(
    path: Path,
    iso: Path,
    output_dir: Path,
    *,
    use_sudo: bool = True,
    provenance_snapshot: _ProvenanceSnapshot | None = None,
    context: _GateContext | None = None,
    allowed_release_paths: frozenset[Path] = frozenset(),
) -> ReleaseGateItem:
    snapshot = provenance_snapshot or _load_provenance_snapshot(
        path,
        context=context,
    )

    def digest_file(candidate: Path) -> str:
        return context.digest(candidate) if context is not None else sha256_file(candidate)

    def size_file(candidate: Path) -> int:
        return context.size(candidate) if context is not None else candidate.stat().st_size

    if snapshot.error is not None:
        return ReleaseGateItem(
            "provenance",
            "blocked",
            f"Provenance is unreadable: {snapshot.error}",
        )
    assert snapshot.data is not None
    assert snapshot.raw is not None
    data = snapshot.data
    if data.get("schema") != "distroforge.provenance.v2":
        return ReleaseGateItem(
            "provenance", "blocked", "Provenance schema is absent or unsupported."
        )
    if data.get("attestation_kind") != "build":
        return ReleaseGateItem(
            "provenance", "blocked", "Reconstructed provenance is not build evidence."
        )
    if not iso.is_file() or data.get("output_iso_sha256") != digest_file(iso):
        return ReleaseGateItem(
            "provenance", "blocked", "Provenance belongs to different ISO bytes."
        )
    run_id = data.get("run_id")
    run = data.get("run")
    if (
        not is_safe_run_id(run_id)
        or not isinstance(run, dict)
        or run.get("run_id") != run_id
        or run.get("mode") != "execute"
    ):
        return ReleaseGateItem("provenance", "blocked", "Provenance run identity is incomplete.")
    assert isinstance(run_id, str)
    closure_problem = _identity_closure_problem(run)
    if closure_problem:
        return ReleaseGateItem(
            "provenance",
            "blocked",
            f"Provenance run identity did not close: {closure_problem}",
        )
    builder = run.get("builder_source")
    definition = run.get("definition")
    toolchain = run.get("toolchain")
    observed_toolchain = data.get("observed_toolchain")
    command_records = data.get("command_records")
    executed_entrypoints = data.get("executed_host_entrypoints")
    if (
        not isinstance(builder, dict)
        or not (builder.get("worktree_sha256") or builder.get("source_tree_sha256"))
        or not isinstance(definition, dict)
        or not definition.get("effective_sha256")
        or not isinstance(toolchain, dict)
        or not isinstance(observed_toolchain, dict)
        or not isinstance(observed_toolchain.get("command_count"), int)
        or int(observed_toolchain["command_count"]) < 1
        or not isinstance(observed_toolchain.get("tools"), dict)
        or not observed_toolchain["tools"]
        or observed_toolchain.get("resolution_scope") != "post-run-path-snapshot"
        or not isinstance(command_records, list)
        or not command_records
        or not isinstance(executed_entrypoints, list)
        or not executed_entrypoints
    ):
        return ReleaseGateItem(
            "provenance",
            "blocked",
            "Provenance lacks source, definition or observed toolchain identity.",
        )
    builder_publication_problem = _git_builder_publication_problem(builder)
    if builder_publication_problem:
        return ReleaseGateItem(
            "provenance",
            "blocked",
            "Builder Git identity is not publication-grade: " + builder_publication_problem,
        )
    if data.get("commands_sha256") != canonical_sha256(command_records):
        return ReleaseGateItem(
            "provenance",
            "blocked",
            "Provenance command-record digest does not match its command records.",
        )
    command_argv: list[tuple[str, ...]] = []
    for record in command_records:
        if not isinstance(record, dict):
            return ReleaseGateItem(
                "provenance",
                "blocked",
                "Provenance contains an invalid command record.",
            )
        argv = record.get("argv")
        if (
            not isinstance(argv, list)
            or not argv
            or not all(isinstance(token, str) and token for token in argv)
            or not isinstance(record.get("has_stdin"), bool)
            or not isinstance(record.get("env_keys"), list)
            or not all(isinstance(key, str) for key in record.get("env_keys", []))
            or not _is_sha256(record.get("env_sha256"))
        ):
            return ReleaseGateItem(
                "provenance",
                "blocked",
                "Provenance contains a command record without a valid argv.",
            )
        command_argv.append(tuple(argv))
    expected_counts = observed_executable_counts(command_argv)
    observed_tools = observed_toolchain["tools"]
    if (
        observed_toolchain["command_count"] != len(command_records)
        or set(observed_tools) != set(expected_counts)
        or any(
            not isinstance(observed_tools[name], dict)
            or observed_tools[name].get("observed_count") != count
            for name, count in expected_counts.items()
        )
    ):
        return ReleaseGateItem(
            "provenance",
            "blocked",
            "Observed toolchain does not match the recorded command history.",
        )
    observed_leafs = {Path(name).name for name in expected_counts}
    required_tools = {"mksquashfs", "unsquashfs", "xorriso"}
    project_data = data.get("project")
    bootstrap_build = _provenance_is_bootstrap(project_data)
    if bootstrap_build:
        required_tools.update({"dpkg-deb", "grub-mkimage", "mformat", "mcopy"})
        if not observed_leafs & {"mmdebstrap", "debootstrap"}:
            return ReleaseGateItem(
                "provenance",
                "blocked",
                "Bootstrap build provenance has no observed mmdebstrap/debootstrap command.",
            )
    missing_tools = sorted(required_tools - observed_leafs)
    if missing_tools:
        return ReleaseGateItem(
            "provenance",
            "blocked",
            "Build provenance lacks required real tool roles: " + ", ".join(missing_tools),
        )
    if data.get("executed_host_entrypoints_sha256") != canonical_sha256(executed_entrypoints):
        return ReleaseGateItem(
            "provenance",
            "blocked",
            "Executed host-entrypoint digest does not match its records.",
        )
    expected_real_indices = {
        index
        for index, argv in enumerate(command_argv)
        if Path(argv[0]).name not in VIRTUAL_COMMANDS
    }
    captured_indices: set[int] = set()
    captured_executable_leafs: set[str] = set()
    for entry in executed_entrypoints:
        if not isinstance(entry, dict):
            return ReleaseGateItem(
                "provenance",
                "blocked",
                "Executed host-entrypoint record is malformed.",
            )
        index = entry.get("history_index")
        if (
            not isinstance(index, int)
            or index not in expected_real_indices
            or index in captured_indices
            or entry.get("argv") != list(command_argv[index])
            or entry.get("scope") != "host-entrypoint-pre-dispatch"
            or entry.get("available") is not True
            or entry.get("stable_while_hashed") is not True
            or not isinstance(entry.get("size"), int)
            or int(entry["size"]) <= 0
            or not _is_sha256(entry.get("sha256"))
        ):
            return ReleaseGateItem(
                "provenance",
                "blocked",
                "Executed host-entrypoint record does not bind a real recorded command.",
            )
        chain = entry.get("execution_chain")
        if not isinstance(chain, list) or not chain:
            return ReleaseGateItem(
                "provenance",
                "blocked",
                "Executed command has no wrapper/target-root executable chain.",
            )
        post_chain = entry.get("post_execution_chain")
        if (
            entry.get("post_dispatch_verified") is not True
            or entry.get("stable_across_dispatch") is not True
            or not isinstance(entry.get("post_dispatch_captured_at"), str)
            or not entry.get("post_dispatch_captured_at")
            or not isinstance(entry.get("post_dispatch_process_returncode"), int)
            or isinstance(entry.get("post_dispatch_process_returncode"), bool)
            or entry.get("post_dispatch_divergences") != []
            or not isinstance(post_chain, list)
            or len(post_chain) != len(chain)
            or entry.get("post_execution_chain_sha256") != canonical_sha256(post_chain)
        ):
            return ReleaseGateItem(
                "provenance",
                "blocked",
                "Executed command has no valid post-dispatch executable proof.",
            )
        if not _dispatch_binding_closes(entry, chain):
            return ReleaseGateItem(
                "provenance",
                "blocked",
                "Executed command was observed but not dispatched through its pre-hashed descriptors.",
            )
        for executable, post_executable in zip(chain, post_chain, strict=True):
            if (
                not isinstance(executable, dict)
                or executable.get("available") is not True
                or executable.get("stable_while_hashed") is not True
                or not _is_sha256(executable.get("sha256"))
                or not isinstance(executable.get("path"), str)
                or not executable.get("path")
            ):
                return ReleaseGateItem(
                    "provenance",
                    "blocked",
                    "Wrapper or target-root executable identity is incomplete.",
                )
            if not isinstance(post_executable, dict) or not _post_dispatch_identity_closes(
                executable,
                post_executable,
            ):
                return ReleaseGateItem(
                    "provenance",
                    "blocked",
                    "Wrapper or target-root executable changed across dispatch.",
                )
            captured_executable_leafs.add(Path(str(executable.get("command", ""))).name)
        captured_indices.add(index)
    if captured_indices != expected_real_indices:
        return ReleaseGateItem(
            "provenance",
            "blocked",
            "Not every real command has a pre-dispatch executable identity.",
        )
    if bootstrap_build and not captured_executable_leafs & {
        "mmdebstrap",
        "debootstrap",
    }:
        return ReleaseGateItem(
            "provenance",
            "blocked",
            "Bootstrap executable bytes were not captured before dispatch.",
        )
    uncaptured_roles = sorted(required_tools - captured_executable_leafs)
    if uncaptured_roles:
        return ReleaseGateItem(
            "provenance",
            "blocked",
            "Required build executable bytes were not captured before dispatch: "
            + ", ".join(uncaptured_roles),
        )
    immutable_dir = output_dir / "evidence" / "runs" / run_id
    inventory_problem = _tree_safety_problem(
        immutable_dir,
        context=context,
        label="immutable provenance run",
    )
    if inventory_problem is not None:
        return ReleaseGateItem(
            "provenance",
            "blocked",
            inventory_problem,
        )
    immutable = immutable_dir / "distroforge-provenance.json"
    iso_report = immutable_dir / "ISO-BUILD.json"
    package_inputs = immutable_dir / "PACKAGE-INPUTS.json"
    package_apt_actions = immutable_dir / PACKAGE_APT_ACTIONS_FILENAME
    package_filesystem_causality = immutable_dir / PACKAGE_FILESYSTEM_CAUSALITY_FILENAME
    rootfs_manifest = immutable_dir / "ROOTFS-MANIFEST.json"
    rootfs_verification = immutable_dir / "ROOTFS-PACKING-VERIFICATION.json"
    iso_assembly = immutable_dir / ISO_ASSEMBLY_FILENAME
    manifest = immutable_dir / "RUN-MANIFEST.json"
    manifest_sum = immutable_dir / "RUN-MANIFEST.json.sha256"
    required = (
        immutable,
        iso_report,
        package_inputs,
        package_apt_actions,
        package_filesystem_causality,
        rootfs_manifest,
        rootfs_verification,
        iso_assembly,
        manifest,
        manifest_sum,
    )
    missing = [item.name for item in required if not item.is_file()]
    if missing:
        return ReleaseGateItem(
            "provenance",
            "blocked",
            f"Immutable run evidence is incomplete: {', '.join(missing)}",
        )
    if digest_file(immutable) != hashlib.sha256(snapshot.raw).hexdigest():
        return ReleaseGateItem(
            "provenance",
            "blocked",
            "Selected immutable provenance differs from its opening snapshot.",
        )
    package_identity = data.get("package_inputs")
    if (
        not isinstance(package_identity, dict)
        or package_identity.get("path") != str(package_inputs)
        or package_identity.get("role") != "package-input-closure"
        or package_identity.get("size") != size_file(package_inputs)
        or package_identity.get("sha256") != digest_file(package_inputs)
    ):
        return ReleaseGateItem(
            "provenance",
            "blocked",
            "Provenance does not bind this run's package-input closure.",
        )
    package_apt_actions_identity = data.get("package_apt_actions")
    if (
        not isinstance(package_apt_actions_identity, dict)
        or package_apt_actions_identity.get("path") != str(package_apt_actions)
        or package_apt_actions_identity.get("role") != "package-apt-actions"
        or package_apt_actions_identity.get("size") != size_file(package_apt_actions)
        or package_apt_actions_identity.get("sha256") != digest_file(package_apt_actions)
    ):
        return ReleaseGateItem(
            "provenance",
            "blocked",
            "Provenance does not bind this run's APT protocol-v3 action receipt.",
        )
    package_filesystem_causality_identity = data.get("package_filesystem_causality")
    if (
        not isinstance(package_filesystem_causality_identity, dict)
        or package_filesystem_causality_identity.get("path") != str(package_filesystem_causality)
        or package_filesystem_causality_identity.get("role") != "package-filesystem-causality"
        or package_filesystem_causality_identity.get("size")
        != size_file(package_filesystem_causality)
        or package_filesystem_causality_identity.get("sha256")
        != digest_file(package_filesystem_causality)
    ):
        return ReleaseGateItem(
            "provenance",
            "blocked",
            "Provenance does not bind this run's package/filesystem identity map.",
        )
    for evidence_field, artifact, role in (
        ("rootfs_manifest", rootfs_manifest, "rootfs-manifest"),
        (
            "rootfs_packing_verification",
            rootfs_verification,
            "rootfs-packing-verification",
        ),
        ("iso_assembly", iso_assembly, "iso-assembly"),
    ):
        identity = data.get(evidence_field)
        if (
            not isinstance(identity, dict)
            or identity.get("path") != str(artifact)
            or identity.get("role") != role
            or identity.get("size") != size_file(artifact)
            or identity.get("sha256") != digest_file(artifact)
        ):
            return ReleaseGateItem(
                "provenance",
                "blocked",
                f"Provenance does not bind this run's {artifact.name}.",
            )
    rootfs_validation = validate_rootfs_evidence(
        immutable_dir,
        expected_run_id=run_id,
        session=context.session if context is not None else None,
    )
    if not rootfs_validation.ok:
        return ReleaseGateItem(
            "provenance",
            "blocked",
            rootfs_validation.detail,
        )
    # The authoritative package-input item, evaluated before provenance by
    # ReleaseGateService.check(), already recomputes this map from every selected
    # .deb. Provenance independently binds the resulting artifact below; running
    # dpkg-deb over the complete package set a second time would double a
    # potentially multi-gigabyte verification without adding another trust input.
    iso_assembly_validation = validate_iso_assembly_evidence(
        immutable_dir,
        expected_run_id=run_id,
        output_iso_path=iso,
        replay_use_sudo=use_sudo,
        session=context.session if context is not None else None,
    )
    if not iso_assembly_validation.ok:
        return ReleaseGateItem(
            "provenance",
            "blocked",
            iso_assembly_validation.detail,
        )
    try:
        assembly_payload = _read_bounded_json_file(
            iso_assembly,
            max_bytes=MAX_RELEASE_EVIDENCE_JSON_BYTES,
            label="ISO assembly evidence",
            context=context,
        )
    except (
        OSError,
        UnicodeError,
        TypeError,
        ValueError,
        OverflowError,
        RecursionError,
    ) as exc:
        return ReleaseGateItem(
            "provenance",
            "blocked",
            f"ISO assembly evidence is unreadable: {exc}",
        )
    if not isinstance(assembly_payload, dict):
        return ReleaseGateItem(
            "provenance",
            "blocked",
            "ISO assembly evidence is not a JSON object.",
        )
    for provenance_field, assembly_field in (
        ("assembled_output_iso", "output_iso"),
        ("staged_filesystem_squashfs", "staged_squashfs"),
        ("embedded_filesystem_squashfs", "embedded_squashfs"),
    ):
        if data.get(provenance_field) != assembly_payload.get(assembly_field):
            return ReleaseGateItem(
                "provenance",
                "blocked",
                f"Provenance does not bind ISO assembly field {assembly_field}.",
            )
    staged_artifact = data.get("staged_filesystem_squashfs_artifact")
    staged_identity = assembly_payload.get("staged_squashfs")
    if not isinstance(staged_artifact, dict) or not isinstance(staged_identity, dict):
        return ReleaseGateItem(
            "provenance",
            "blocked",
            "Provenance lacks the staged filesystem.squashfs artifact identity.",
        )
    staged_artifact_path = Path(str(staged_artifact.get("path", "")))
    if (
        staged_artifact.get("role") != "staged-filesystem-squashfs"
        or staged_artifact_path.name != staged_identity.get("name")
        or staged_artifact_path.is_symlink()
        or not staged_artifact_path.is_file()
        or staged_artifact.get("size") != staged_identity.get("size")
        or staged_artifact.get("sha256") != staged_identity.get("sha256")
        or staged_artifact.get("size") != size_file(staged_artifact_path)
        or staged_artifact.get("sha256") != digest_file(staged_artifact_path)
    ):
        return ReleaseGateItem(
            "provenance",
            "blocked",
            "Provenance staged SquashFS differs from the packing FD witness.",
        )
    try:
        build = _read_bounded_json_file(
            iso_report,
            max_bytes=MAX_RELEASE_EVIDENCE_JSON_BYTES,
            label="ISO build report",
            context=context,
        )
        run_manifest = _read_bounded_json_file(
            manifest,
            max_bytes=MAX_RELEASE_EVIDENCE_JSON_BYTES,
            label="run manifest",
            context=context,
        )
    except (
        OSError,
        UnicodeError,
        TypeError,
        ValueError,
        OverflowError,
        RecursionError,
    ) as exc:
        return ReleaseGateItem("provenance", "blocked", f"Run evidence is unreadable: {exc}")
    if (
        not isinstance(build, dict)
        or build.get("schema") != "distroforge.iso-build.v2"
        or build.get("run_id") != run_id
        or build.get("status") != "built"
        or build.get("execute") is not True
        or build.get("output_exists") is not True
        or build.get("output_sha256") != digest_file(iso)
    ):
        return ReleaseGateItem(
            "provenance", "blocked", "ISO build report does not bind this run and ISO."
        )
    if (
        not isinstance(run_manifest, dict)
        or run_manifest.get("schema") != "distroforge.build-run-manifest.v1"
        or run_manifest.get("run_id") != run_id
        or run_manifest.get("mode") != "execute"
        or run_manifest.get("status") != "built"
    ):
        return ReleaseGateItem(
            "provenance", "blocked", "Run manifest identity does not match provenance."
        )
    try:
        manifest_sum_bytes = _read_bounded_file(
            manifest_sum,
            max_bytes=MAX_SHA256_SIDECAR_BYTES,
            label="run manifest SHA256 sidecar",
            context=context,
        )
        manifest_sum_entries = parse_sha256_sums(manifest_sum_bytes)
        recorded_manifest_digest = manifest_sum_entries.get(manifest.name)
    except (OSError, UnicodeError, ValueError) as exc:
        return ReleaseGateItem(
            "provenance",
            "blocked",
            f"Run manifest SHA256 sidecar is unreadable: {exc}",
        )
    if len(manifest_sum_entries) != 1 or recorded_manifest_digest != digest_file(manifest):
        return ReleaseGateItem(
            "provenance", "blocked", "Run manifest SHA256 sidecar does not match."
        )
    files = run_manifest.get("files")
    if not isinstance(files, list):
        return ReleaseGateItem("provenance", "blocked", "Run manifest has no file identities.")
    recorded: dict[str, str] = {}
    non_authoritative_aliases = {
        (output_dir / "ISO-BUILD.json").absolute(),
        (output_dir / "distroforge-provenance.json").absolute(),
        (output_dir / SPDX_FILENAME).absolute(),
        (output_dir / CYCLONEDX_FILENAME).absolute(),
    }
    allowed_external = {
        iso.absolute(),
        staged_artifact_path.absolute(),
        path.absolute(),
        *allowed_release_paths,
        *non_authoritative_aliases,
    }
    for item in files:
        if not isinstance(item, dict):
            return ReleaseGateItem(
                "provenance", "blocked", "Run manifest contains an invalid file entry."
            )
        artifact_path = Path(str(item.get("path", "")))
        artifact_key = str(artifact_path)
        if not artifact_key or artifact_key in recorded:
            return ReleaseGateItem(
                "provenance",
                "blocked",
                "Run manifest contains an empty or duplicate artifact path.",
            )
        artifact_absolute = artifact_path.absolute()
        try:
            inside_run = artifact_absolute.is_relative_to(immutable_dir.absolute())
        except (OSError, ValueError):
            inside_run = False
        if not inside_run and artifact_absolute not in allowed_external:
            return ReleaseGateItem(
                "provenance",
                "blocked",
                f"Run manifest path is outside the artifact allowlist: {artifact_path}",
            )
        if artifact_absolute in non_authoritative_aliases:
            # Historical manifests may list the top-level convenience aliases.
            # They are deliberately excluded from the release verdict: only the
            # selected immutable run files above are held and measured.
            if (
                not isinstance(item.get("size"), int)
                or isinstance(item.get("size"), bool)
                or int(item["size"]) < 0
                or not _is_sha256(item.get("sha256"))
            ):
                return ReleaseGateItem(
                    "provenance",
                    "blocked",
                    "Run manifest contains a malformed non-authoritative "
                    f"alias identity: {artifact_path}",
                )
            recorded[artifact_key] = str(item.get("sha256"))
            continue
        if (
            artifact_path.is_symlink()
            or not artifact_path.is_file()
            or item.get("size") != size_file(artifact_path)
            or item.get("sha256") != digest_file(artifact_path)
        ):
            return ReleaseGateItem(
                "provenance",
                "blocked",
                f"Run artifact changed or disappeared: {artifact_path}",
            )
        recorded[artifact_key] = str(item.get("sha256"))
    try:
        run_inventory = _tree_inventory(
            immutable_dir,
            context=context,
            label="immutable run inventory",
        )
    except ArtifactVerificationError as exc:
        return ReleaseGateItem(
            "provenance",
            "blocked",
            f"Immutable run cannot be inventoried safely: {exc}",
        )
    unsafe_run_entries = _unsafe_inventory_entries(run_inventory)
    if unsafe_run_entries:
        return ReleaseGateItem(
            "provenance",
            "blocked",
            "Immutable run contains non-regular entries: " + ", ".join(unsafe_run_entries),
        )
    recorded_run_files = {
        Path(key).absolute().relative_to(immutable_dir.absolute()).as_posix()
        for key in recorded
        if Path(key).absolute().is_relative_to(immutable_dir.absolute())
    }
    recorded_run_files.update(
        {
            manifest.relative_to(immutable_dir).as_posix(),
            manifest_sum.relative_to(immutable_dir).as_posix(),
        }
    )
    unexpected_run_entries = set(run_inventory.by_name()) - _expected_inventory_entries(
        recorded_run_files
    )
    if unexpected_run_entries:
        return ReleaseGateItem(
            "provenance",
            "blocked",
            "Immutable run contains unmanifested entries: "
            + ", ".join(sorted(unexpected_run_entries)),
        )
    for artifact in (
        immutable,
        iso_report,
        iso,
        path,
        output_dir / "SHA256SUMS",
        output_dir / "BUILDINFO",
        package_inputs,
        package_apt_actions,
        package_filesystem_causality,
        rootfs_manifest,
        rootfs_verification,
        iso_assembly,
        staged_artifact_path,
    ):
        if not artifact.is_file():
            return ReleaseGateItem(
                "provenance",
                "blocked",
                f"Required build artifact is missing: {artifact.name}.",
            )
        if recorded.get(str(artifact)) != digest_file(artifact):
            return ReleaseGateItem(
                "provenance",
                "blocked",
                f"Run manifest does not bind {artifact.name}.",
            )
    command_log_error = _command_log_error(
        immutable_dir / "commands.jsonl",
        command_records,
        executed_entrypoints,
        context=context,
    )
    if command_log_error:
        return ReleaseGateItem(
            "provenance",
            "blocked",
            command_log_error,
        )
    return ReleaseGateItem(
        "provenance",
        "ready",
        f"immutable build run {run_id} matches ISO SHA256 {digest_file(iso)}",
    )


def _provenance_is_bootstrap(project_data: object) -> bool:
    """Derive tool roles from the effective source mode, not starter presence.

    Both skeleton and official-ISO starters populate ``source_starter``. Treating
    that field itself as bootstrap made an ISO starter require mmdebstrap,
    GRUB/mtools assembly and the bootstrap-only M3.1 dpkg-deb inspection even
    though none of those commands belonged to the executed path.
    """

    return isinstance(project_data, dict) and project_data.get("source_mode") == "bootstrap"


def _is_sha256(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _post_dispatch_identity_closes(
    pre: dict[str, object],
    post: dict[str, object],
) -> bool:
    """Require the post-dispatch record emitted by ``CommandRunner``.

    A matching digest is not sufficient: atomically replacing an executable with
    identical bytes changes the inode. The held descriptor and the re-resolved path
    must both retain the complete pre-dispatch identity.
    """
    stat_keys = ("device", "inode", "mode", "mtime_ns", "ctime_ns")
    if (
        pre.get("path_matches_open_file") is not True
        or not _valid_stat_identity(pre)
        or post.get("command") != pre.get("command")
        or post.get("argv_index") != pre.get("argv_index")
        or post.get("root") != pre.get("root")
        or post.get("scope") != str(pre.get("scope", "")).replace("-pre-dispatch", "-post-dispatch")
        or post.get("available") is not True
        or post.get("stable_while_hashed") is not True
        or post.get("path_matches_open_file") is not True
        or post.get("path") != pre.get("path")
        or post.get("size") != pre.get("size")
        or post.get("sha256") != pre.get("sha256")
        or any(post.get(key) != pre.get(key) for key in stat_keys)
        or post.get("held_fd_available") is not True
        or post.get("held_fd_sha256") != pre.get("sha256")
        or post.get("held_fd_stable_while_rehashed") is not True
        or post.get("held_fd_metadata_unchanged") is not True
        or post.get("held_fd_sha256_unchanged") is not True
        or post.get("resolved_path_unchanged") is not True
        or post.get("resolved_path_matches_held_fd") is not True
        or post.get("resolved_sha256_unchanged") is not True
        or post.get("stable_across_dispatch") is not True
        or post.get("divergences") != []
    ):
        return False
    held = post.get("held_fd")
    return (
        isinstance(held, dict)
        and _valid_stat_identity(held)
        and held.get("size") == pre.get("size")
        and held.get("sha256") == pre.get("sha256")
        and all(held.get(key) == pre.get(key) for key in stat_keys)
    )


_PROC_FD_PATH = re.compile(r"^/proc/[1-9][0-9]*/fd/[0-9]+$")


def _dispatch_binding_closes(
    entry: dict[str, object],
    chain: list[object],
) -> bool:
    original = entry.get("argv")
    dispatched = entry.get("dispatch_argv")
    executable = entry.get("dispatch_executable")
    bindings = entry.get("dispatch_bindings")
    if (
        entry.get("dispatch_bound") is not True
        or not isinstance(original, list)
        or not all(isinstance(token, str) for token in original)
        or not isinstance(dispatched, list)
        or not isinstance(executable, str)
        or not _PROC_FD_PATH.fullmatch(executable)
        or not isinstance(bindings, list)
        or len(bindings) != len(chain)
    ):
        return False
    grouped: dict[
        int,
        list[tuple[int, dict[str, object], dict[str, object]]],
    ] = {}
    seen_descriptors: set[str] = set()
    for position, (pre, binding) in enumerate(zip(chain, bindings, strict=True)):
        if not isinstance(pre, dict) or not isinstance(binding, dict):
            return False
        index = pre.get("argv_index")
        descriptor = binding.get("descriptor_path")
        if (
            not isinstance(index, int)
            or isinstance(index, bool)
            or index < 0
            or index >= len(original)
            or binding.get("command") != pre.get("command")
            or binding.get("argv_index") != index
            or not isinstance(descriptor, str)
            or not _PROC_FD_PATH.fullmatch(descriptor)
            or descriptor in seen_descriptors
            or binding.get("device") != pre.get("device")
            or binding.get("inode") != pre.get("inode")
            or binding.get("size") != pre.get("size")
            or binding.get("sha256") != pre.get("sha256")
        ):
            return False
        role = pre.get("execution_role", "argv-executable")
        if role not in {
            "argv-executable",
            "script-body",
            "shebang-interpreter",
        }:
            return False
        binding_role = binding.get("execution_role")
        if binding_role is not None and binding_role != role:
            return False
        grouped.setdefault(index, []).append((position, pre, binding))
        seen_descriptors.add(descriptor)

    expected_dispatch = list(original)
    expected_executable: str | None = None
    for index in sorted(grouped, reverse=True):
        group = grouped[index]
        if len(group) == 1:
            _position, pre, binding = group[0]
            if pre.get("execution_role", "argv-executable") != "argv-executable" or original[
                index
            ] != pre.get("command"):
                return False
            expected_mode = "outer-executable" if index == 0 else "nested-argv-rewrite"
            if binding.get("mode") != expected_mode:
                return False
            descriptor = binding["descriptor_path"]
            assert isinstance(descriptor, str)
            if index == 0:
                expected_executable = descriptor
            else:
                expected_dispatch[index] = descriptor
            continue

        if len(group) != 2:
            return False
        scripts = [item for item in group if item[1].get("execution_role") == "script-body"]
        interpreters = [
            item for item in group if item[1].get("execution_role") == "shebang-interpreter"
        ]
        if len(scripts) != 1 or len(interpreters) != 1:
            return False
        script_position, script, script_binding = scripts[0]
        interpreter_position, interpreter, interpreter_binding = interpreters[0]
        arguments = script.get("shebang_arguments")
        if (
            script_position >= interpreter_position
            or script.get("shebang_valid") is not True
            or original[index] != script.get("command")
            or not isinstance(arguments, list)
            or not all(isinstance(value, str) for value in arguments)
            or script.get("shebang_interpreter_command") != interpreter.get("command")
            or interpreter.get("shebang_for") != script.get("command")
            or interpreter.get("shebang_arguments") != arguments
            or script_binding.get("mode") != "script-argument"
        ):
            return False
        expected_interpreter_mode = (
            "outer-shebang-interpreter" if index == 0 else "nested-shebang-interpreter"
        )
        if interpreter_binding.get("mode") != expected_interpreter_mode:
            return False
        interpreter_descriptor = interpreter_binding["descriptor_path"]
        script_descriptor = script_binding["descriptor_path"]
        assert isinstance(interpreter_descriptor, str)
        assert isinstance(script_descriptor, str)
        expected_dispatch[index : index + 1] = [
            interpreter_descriptor,
            *arguments,
            script_descriptor,
        ]
        if index == 0:
            expected_executable = interpreter_descriptor

    return (
        0 in grouped
        and expected_executable is not None
        and executable == expected_executable
        and dispatched == expected_dispatch
    )


def _valid_stat_identity(value: dict[str, object]) -> bool:
    integers = ("device", "inode", "mode", "size", "mtime_ns", "ctime_ns")
    if not all(_is_nonnegative_integer(value.get(key)) for key in integers):
        return False
    inode = value.get("inode")
    size = value.get("size")
    mode = value.get("mode")
    return (
        isinstance(inode, int)
        and not isinstance(inode, bool)
        and inode > 0
        and isinstance(size, int)
        and not isinstance(size, bool)
        and size > 0
        and isinstance(mode, int)
        and not isinstance(mode, bool)
        and stat.S_ISREG(mode)
    )


def _is_nonnegative_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _command_log_error(
    path: Path,
    command_records: list[object],
    executed_entrypoints: list[object],
    *,
    context: _GateContext | None = None,
) -> str | None:
    try:
        events = _command_jsonl_events(path, context=context)
    except (
        OSError,
        UnicodeError,
        TypeError,
        ValueError,
        OverflowError,
        RecursionError,
    ) as exc:
        return f"Command log is unreadable: {exc}"
    starts = [
        event for event in events if isinstance(event, dict) and event.get("event") == "start"
    ]
    if len(starts) < len(command_records):
        return "Command log has fewer start events than provenance command records."
    keys = (
        "argv",
        "cwd",
        "needs_root",
        "description",
        "has_stdin",
        "env_keys",
        "env_sha256",
    )
    for index, record in enumerate(command_records):
        if not isinstance(record, dict) or any(
            starts[index].get(key) != record.get(key) for key in keys
        ):
            return f"Command log diverges from provenance at command index {index}."
    post_dispatch = [
        event
        for event in events
        if isinstance(event, dict) and event.get("event") == "execution-identity-post-dispatch"
    ]
    if len(post_dispatch) != len(executed_entrypoints):
        return (
            "Command log does not contain exactly one post-dispatch identity "
            "for every real command."
        )
    for index, identity in enumerate(executed_entrypoints):
        if not isinstance(identity, dict):
            return f"Provenance execution identity is malformed at index {index}."
        logged = {key: value for key, value in post_dispatch[index].items() if key != "event"}
        if logged != identity:
            return (
                "Command log post-dispatch identity diverges from provenance "
                f"at real-command index {index}."
            )
    return None


def _check_boot_proof(
    report: ReleaseGateReport,
    iso: Path,
    output_dir: Path,
    _options: BuildOptions,
    *,
    selected_run: ExecutedReleaseRun | None,
    requested_boot_run_id: str | None,
    context: _GateContext | None = None,
) -> None:
    """Bind boot authority to one immutable run, never to a top-level alias."""

    if selected_run is None:
        report.items.append(
            ReleaseGateItem(
                "boot-proof",
                "blocked",
                "No immutable executed build run was selected, so no boot run "
                "can be bound to the release.",
            )
        )
        return

    embedded = selected_run.iso_build_payload.get("boot_proof")
    embedded_run_id: str | None = None
    if isinstance(embedded, dict):
        candidate = embedded.get("run_id")
        if not is_safe_run_id(candidate):
            report.items.append(
                ReleaseGateItem(
                    "boot-proof",
                    "blocked",
                    "The selected immutable ISO-BUILD embeds a boot proof without a safe run_id.",
                )
            )
            return
        assert isinstance(candidate, str)
        embedded_run_id = candidate
        if requested_boot_run_id is not None and requested_boot_run_id != embedded_run_id:
            report.items.append(
                ReleaseGateItem(
                    "boot-proof",
                    "blocked",
                    "Explicit boot run "
                    f"{requested_boot_run_id!r} conflicts with the run embedded "
                    f"by build {selected_run.run_id!r}: {embedded_run_id!r}.",
                )
            )
            return

    chosen_run_id = embedded_run_id or requested_boot_run_id
    if chosen_run_id is None:
        report.items.append(
            ReleaseGateItem(
                "boot-proof",
                "blocked",
                "The selected build has no embedded boot run. Select one "
                "standalone immutable proof explicitly with --boot-run-id RUN_ID.",
            )
        )
        return
    if not is_safe_run_id(chosen_run_id):
        report.items.append(
            ReleaseGateItem(
                "boot-proof",
                "blocked",
                "Explicit boot run id is unsafe; pass the exact canonical run id.",
            )
        )
        return

    proof = (
        Path(os.path.abspath(output_dir)) / "evidence" / "runs" / chosen_run_id / "boot-proof.json"
    )
    report.boot_run_id = chosen_run_id
    report.immutable_boot_proof = proof
    validation = _validate_boot_proof(
        proof,
        context.iso if context is not None else Path(os.path.abspath(iso)),
        expected_boot_run_id=chosen_run_id,
        expected_build_run_id=selected_run.run_id,
        context=context,
    )
    try:
        report.immutable_qemu_report = _immutable_boot_qemu_path(
            proof,
            expected_boot_run_id=chosen_run_id,
            context=context,
        )
    except (
        ArtifactVerificationError,
        OSError,
        UnicodeError,
        TypeError,
        ValueError,
        OverflowError,
        RecursionError,
    ):
        # The validator below already turns the malformed path/payload into the
        # single typed boot-proof blocker. Do not manufacture an unverified path
        # merely for report metadata.
        report.immutable_qemu_report = None
    report.items.append(validation)


def _qemu_run_binding_error(
    output_dir: Path,
    iso: Path,
    report_name: str,
    payload: dict[str, object] | None,
    *,
    context: _GateContext | None = None,
) -> str | None:
    def digest_file(candidate: Path) -> str:
        return context.digest(candidate) if context is not None else sha256_file(candidate)

    def size_file(candidate: Path) -> int:
        return context.size(candidate) if context is not None else candidate.stat().st_size

    if not isinstance(payload, dict):
        return "QEMU report payload is missing."
    run_id = payload.get("run_id")
    if not is_safe_run_id(run_id):
        return "QEMU report has no safe run identity."
    assert isinstance(run_id, str)
    run_dir = output_dir / "evidence" / "runs" / run_id
    inventory_problem = _tree_safety_problem(
        run_dir,
        context=context,
        label="QEMU run",
    )
    if inventory_problem is not None:
        return inventory_problem
    manifest_path = run_dir / "RUN-MANIFEST.json"
    sidecar = run_dir / "RUN-MANIFEST.json.sha256"
    try:
        manifest = _read_bounded_json_file(
            manifest_path,
            max_bytes=MAX_RELEASE_EVIDENCE_JSON_BYTES,
            label="QEMU run manifest",
            context=context,
        )
        sidecar_bytes = _read_bounded_file(
            sidecar,
            max_bytes=MAX_SHA256_SIDECAR_BYTES,
            label="QEMU run manifest SHA256 sidecar",
            context=context,
        )
        sidecar_entries = parse_sha256_sums(sidecar_bytes)
        sidecar_digest = sidecar_entries.get(manifest_path.name)
    except (
        OSError,
        UnicodeError,
        TypeError,
        ValueError,
        OverflowError,
        RecursionError,
    ) as exc:
        return f"QEMU run manifest is missing or unreadable: {exc}"
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema")
        not in {
            "distroforge.build-run-manifest.v1",
            "distroforge.boot-proof-run-manifest.v1",
            "distroforge.qemu-run-manifest.v1",
        }
        or manifest.get("run_id") != run_id
        or manifest.get("mode") != "execute"
    ):
        return "QEMU run manifest identity is inconsistent."
    if len(sidecar_entries) != 1 or sidecar_digest != digest_file(manifest_path):
        return "QEMU run manifest sidecar does not match."
    files = manifest.get("files")
    if not isinstance(files, list):
        return "QEMU run manifest has no files."
    recorded: dict[str, str] = {}
    for item in files:
        if not isinstance(item, dict):
            return "QEMU run manifest contains a malformed entry."
        path = Path(str(item.get("path", "")))
        key = str(path)
        absolute = path.absolute()
        if not absolute.is_relative_to(run_dir.absolute()) and absolute != iso.absolute():
            return f"QEMU run manifest path is outside the allowlist: {path}"
        if (
            not key
            or key in recorded
            or path.is_symlink()
            or not path.is_file()
            or item.get("size") != size_file(path)
            or item.get("sha256") != digest_file(path)
        ):
            return f"QEMU run artifact changed or disappeared: {path}"
        recorded[key] = str(item.get("sha256"))
    immutable_report = run_dir / report_name
    command_log = run_dir / "commands.jsonl"
    for required in (immutable_report, command_log, iso):
        if not required.is_file() or recorded.get(str(required)) != digest_file(required):
            return f"QEMU run manifest does not bind {required.name}."
    try:
        run_inventory = _tree_inventory(
            run_dir,
            context=context,
            label="QEMU run inventory",
        )
    except ArtifactVerificationError as exc:
        return f"QEMU run cannot be inventoried safely: {exc}"
    unsafe_run_entries = _unsafe_inventory_entries(run_inventory)
    if unsafe_run_entries:
        return "QEMU run contains non-regular entries: " + ", ".join(unsafe_run_entries)
    recorded_run_files = {
        Path(key).absolute().relative_to(run_dir.absolute()).as_posix()
        for key in recorded
        if Path(key).absolute().is_relative_to(run_dir.absolute())
    }
    recorded_run_files.update({manifest_path.name, sidecar.name})
    unexpected_run_entries = set(run_inventory.by_name()) - _expected_inventory_entries(
        recorded_run_files
    )
    if unexpected_run_entries:
        return "QEMU run contains unmanifested entries: " + ", ".join(
            sorted(unexpected_run_entries)
        )
    return None


def _immutable_boot_qemu_path(
    path: Path,
    *,
    expected_boot_run_id: str,
    context: _GateContext | None,
) -> Path:
    data = _read_bounded_json_file(
        path,
        max_bytes=MAX_RELEASE_EVIDENCE_JSON_BYTES,
        label="immutable boot proof",
        context=context,
    )
    if not isinstance(data, dict) or data.get("run_id") != expected_boot_run_id:
        raise ArtifactVerificationError("immutable boot proof does not bind the selected boot run")
    qemu_name = data.get("qemu_report")
    if (
        not isinstance(qemu_name, str)
        or not qemu_name
        or Path(qemu_name).name != qemu_name
        or qemu_name in {".", ".."}
        or "\x00" in qemu_name
    ):
        raise ArtifactVerificationError(
            "immutable boot proof does not name one strict QEMU report leaf"
        )
    qemu_path = path.parent / qemu_name
    immutable_value = data.get("immutable_qemu_report")
    if immutable_value is not None:
        if (
            not isinstance(immutable_value, str)
            or Path(immutable_value) != qemu_path
            or Path(immutable_value) != Path(os.path.abspath(immutable_value))
        ):
            raise ArtifactVerificationError(
                "immutable boot proof QEMU path differs from its selected run"
            )
    return qemu_path


def _validate_boot_proof(
    path: Path,
    iso: Path,
    *,
    expected_boot_run_id: str,
    expected_build_run_id: str,
    context: _GateContext | None = None,
) -> ReleaseGateItem:
    def digest_file(candidate: Path) -> str:
        if (
            context is not None
            and not context.verify_checksums
            and candidate.absolute() == context.iso
        ):
            recorded = context.checksum_entry(
                context.output_dir / "SHA256SUMS",
                context.iso.name,
            )
            if recorded is None:
                raise ArtifactVerificationError("SHA256SUMS has no status-only ISO digest")
            return recorded
        return context.digest(candidate) if context is not None else sha256_file(candidate)

    def size_file(candidate: Path) -> int:
        return context.size(candidate) if context is not None else candidate.stat().st_size

    try:
        data = _read_bounded_json_file(
            path,
            max_bytes=MAX_RELEASE_EVIDENCE_JSON_BYTES,
            label="boot proof",
            context=context,
        )
    except (
        OSError,
        UnicodeError,
        TypeError,
        ValueError,
        OverflowError,
        RecursionError,
    ) as exc:
        return ReleaseGateItem("boot-proof", "blocked", f"Boot proof is unreadable: {exc}")
    if not isinstance(data, dict) or data.get("schema") != "distroforge.boot-proof.v2":
        return ReleaseGateItem(
            "boot-proof", "blocked", "Boot proof schema is absent or unsupported."
        )
    status = str(data.get("status", "unknown"))
    backend = str(data.get("selected_backend", data.get("backend", "unknown")))
    proof_level = str(data.get("proof_level", "none"))
    if status != "ready":
        return ReleaseGateItem(
            "boot-proof",
            "blocked",
            f"Boot proof report is not ready: {status} via {backend}.",
        )
    if data.get("iso") != str(iso) or data.get("iso_sha256") != digest_file(iso):
        return ReleaseGateItem(
            "boot-proof", "blocked", "Boot proof belongs to different ISO bytes."
        )
    run_id = data.get("run_id")
    if run_id != expected_boot_run_id or not is_safe_run_id(run_id):
        return ReleaseGateItem(
            "boot-proof",
            "blocked",
            "Boot proof run_id differs from the selected immutable boot run.",
        )
    if data.get("build_run_id") != expected_build_run_id:
        return ReleaseGateItem(
            "boot-proof",
            "blocked",
            "Boot proof build_run_id differs from the selected immutable build run.",
        )
    assert isinstance(run_id, str)
    immutable_dir = path.parent
    expected_path = (
        (context.output_dir if context is not None else immutable_dir.parents[2])
        / "evidence"
        / "runs"
        / run_id
        / "boot-proof.json"
    )
    if path.absolute() != expected_path.absolute():
        return ReleaseGateItem(
            "boot-proof",
            "blocked",
            "Boot proof path is not the exact selected immutable run report.",
        )
    inventory_problem = _tree_safety_problem(
        immutable_dir,
        context=context,
        label="boot run",
    )
    if inventory_problem is not None:
        return ReleaseGateItem(
            "boot-proof",
            "blocked",
            inventory_problem,
        )
    immutable_proof = path
    run_manifest_path = immutable_dir / "RUN-MANIFEST.json"
    run_manifest_sum = immutable_dir / "RUN-MANIFEST.json.sha256"
    for required in (immutable_proof, run_manifest_path, run_manifest_sum):
        if not required.is_file():
            return ReleaseGateItem(
                "boot-proof",
                "blocked",
                f"Immutable boot run evidence is missing: {required.name}.",
            )
    if data.get("immutable_proof") not in {
        immutable_proof.name,
        str(immutable_proof),
    }:
        return ReleaseGateItem(
            "boot-proof",
            "blocked",
            "Boot proof does not identify its immutable report.",
        )
    try:
        run_manifest = _read_bounded_json_file(
            run_manifest_path,
            max_bytes=MAX_RELEASE_EVIDENCE_JSON_BYTES,
            label="boot run manifest",
            context=context,
        )
    except (
        OSError,
        UnicodeError,
        TypeError,
        ValueError,
        OverflowError,
        RecursionError,
    ) as exc:
        return ReleaseGateItem(
            "boot-proof",
            "blocked",
            f"Boot run manifest is unreadable: {exc}",
        )
    if (
        not isinstance(run_manifest, dict)
        or run_manifest.get("schema") != "distroforge.boot-proof-run-manifest.v1"
        or run_manifest.get("run_id") != run_id
        or run_manifest.get("build_run_id") != expected_build_run_id
        or run_manifest.get("mode") != "execute"
        or run_manifest.get("status") != status
    ):
        return ReleaseGateItem(
            "boot-proof",
            "blocked",
            "Boot run manifest identity or status is inconsistent.",
        )
    try:
        run_manifest_sum_bytes = _read_bounded_file(
            run_manifest_sum,
            max_bytes=MAX_SHA256_SIDECAR_BYTES,
            label="boot run manifest SHA256 sidecar",
            context=context,
        )
        run_manifest_sum_entries = parse_sha256_sums(run_manifest_sum_bytes)
        run_manifest_digest = run_manifest_sum_entries.get(run_manifest_path.name)
    except (OSError, UnicodeError, ValueError) as exc:
        return ReleaseGateItem(
            "boot-proof",
            "blocked",
            f"Boot run manifest SHA256 sidecar is unreadable: {exc}",
        )
    if len(run_manifest_sum_entries) != 1 or run_manifest_digest != digest_file(run_manifest_path):
        return ReleaseGateItem(
            "boot-proof",
            "blocked",
            "Boot run manifest SHA256 sidecar does not match.",
        )
    files = run_manifest.get("files")
    if not isinstance(files, list):
        return ReleaseGateItem(
            "boot-proof",
            "blocked",
            "Boot run manifest has no file identities.",
        )
    if proof_level != "runtime" or backend != "qemu":
        return ReleaseGateItem(
            "boot-proof",
            "blocked",
            f"{proof_level} proof via {backend} does not satisfy the runtime release gate.",
        )
    try:
        qemu_path = _immutable_boot_qemu_path(
            path,
            expected_boot_run_id=run_id,
            context=context,
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
        return ReleaseGateItem(
            "boot-proof",
            "blocked",
            f"Boot proof does not bind its immutable QEMU report: {exc}",
        )
    quick_status = context is not None and not context.verify_checksums
    if quick_status:
        try:
            qemu_payload = _read_bounded_json_file(
                qemu_path,
                max_bytes=MAX_RELEASE_EVIDENCE_JSON_BYTES,
                label="QEMU status preview",
                context=context,
            )
        except (
            OSError,
            UnicodeError,
            TypeError,
            ValueError,
            OverflowError,
            RecursionError,
        ) as exc:
            return ReleaseGateItem(
                "boot-proof",
                "blocked",
                f"QEMU status preview is unreadable: {exc}",
            )
        if (
            not isinstance(qemu_payload, dict)
            or qemu_payload.get("schema") != "distroforge.qemu-lab.v2"
            or qemu_payload.get("run_id") != run_id
            or qemu_payload.get("status") != "completed"
            or qemu_payload.get("verdict") != "passed"
        ):
            return ReleaseGateItem(
                "boot-proof",
                "blocked",
                "QEMU status preview is not a completed runtime proof.",
            )
        qemu_iso = qemu_payload.get("iso")
        if (
            not isinstance(qemu_iso, dict)
            or qemu_iso.get("sha256") != digest_file(iso)
            or qemu_iso.get("size") != size_file(iso)
            or qemu_iso.get("consumed_via") != "held-descriptor"
        ):
            return ReleaseGateItem(
                "boot-proof",
                "blocked",
                "QEMU status preview belongs to different ISO bytes.",
            )
        validation_detail = (
            "Status-only runtime proof preview matches the recorded ISO checksum; "
            "authoritative byte verification remains deferred."
        )
    else:
        validation = validate_qemu_report(
            qemu_path,
            iso,
            session=context.session if context is not None else None,
        )
        if not validation.ok:
            return ReleaseGateItem("boot-proof", "blocked", validation.detail)
        if validation.payload and validation.payload.get("run_id") != run_id:
            return ReleaseGateItem(
                "boot-proof",
                "blocked",
                "Boot proof and QEMU report use different run IDs.",
            )
        validation_detail = validation.detail
    if data.get("qemu_report_sha256") != digest_file(qemu_path):
        return ReleaseGateItem(
            "boot-proof",
            "blocked",
            "Boot proof does not match its QEMU report SHA256.",
        )
    recorded: dict[str, str] = {}
    for item in files:
        if not isinstance(item, dict):
            return ReleaseGateItem(
                "boot-proof",
                "blocked",
                "Boot run manifest contains an invalid file entry.",
            )
        artifact = Path(str(item.get("path", "")))
        artifact_key = str(artifact)
        absolute = artifact.absolute()
        if not absolute.is_relative_to(immutable_dir.absolute()) and absolute != iso.absolute():
            return ReleaseGateItem(
                "boot-proof",
                "blocked",
                f"Boot run manifest path is outside the allowlist: {artifact}.",
            )
        if (
            not artifact_key
            or artifact_key in recorded
            or artifact.is_symlink()
            or not artifact.is_file()
            or item.get("size") != size_file(artifact)
            or item.get("sha256") != digest_file(artifact)
        ):
            return ReleaseGateItem(
                "boot-proof",
                "blocked",
                f"Boot run artifact changed, disappeared or is duplicated: {artifact}.",
            )
        recorded[artifact_key] = str(item.get("sha256"))
    try:
        run_inventory = _tree_inventory(
            immutable_dir,
            context=context,
            label="boot run inventory",
        )
    except ArtifactVerificationError as exc:
        return ReleaseGateItem(
            "boot-proof",
            "blocked",
            f"Boot run cannot be inventoried safely: {exc}",
        )
    unsafe_run_entries = _unsafe_inventory_entries(run_inventory)
    if unsafe_run_entries:
        return ReleaseGateItem(
            "boot-proof",
            "blocked",
            "Boot run contains non-regular entries: " + ", ".join(unsafe_run_entries),
        )
    recorded_run_files = {
        Path(key).absolute().relative_to(immutable_dir.absolute()).as_posix()
        for key in recorded
        if Path(key).absolute().is_relative_to(immutable_dir.absolute())
    }
    recorded_run_files.update({run_manifest_path.name, run_manifest_sum.name})
    unexpected_run_entries = set(run_inventory.by_name()) - _expected_inventory_entries(
        recorded_run_files
    )
    if unexpected_run_entries:
        return ReleaseGateItem(
            "boot-proof",
            "blocked",
            "Boot run contains unmanifested entries: " + ", ".join(sorted(unexpected_run_entries)),
        )
    for required in (immutable_proof, qemu_path, iso):
        if recorded.get(str(required)) != digest_file(required):
            return ReleaseGateItem(
                "boot-proof",
                "blocked",
                f"Boot run manifest does not bind {required.name}.",
            )
    command_log = immutable_dir / "commands.jsonl"
    if (
        data.get("command_log") != command_log.name
        or not command_log.is_file()
        or recorded.get(str(command_log)) != digest_file(command_log)
    ):
        return ReleaseGateItem(
            "boot-proof",
            "blocked",
            "Boot proof has no sealed command log for the QEMU invocation.",
        )
    return ReleaseGateItem("boot-proof", "ready", validation_detail)


def _check_release_readiness(
    report: ReleaseGateReport,
    iso: Path,
    output_dir: Path,
    verify_checksums: bool = True,
    *,
    context: _GateContext | None = None,
    qemu_report: Path | None = None,
) -> None:
    readiness = ReleaseReadinessService().check(
        iso,
        output_dir,
        verify_checksum=verify_checksums,
        session=context.session if context is not None else None,
        qemu_report=qemu_report,
        use_default_qemu_alias=False,
    )
    report.items.append(
        ReleaseGateItem(
            "release-readiness",
            "blocked" if readiness.blocked else "review",
            "Release readiness report is available; review non-blocking evidence items.",
        )
    )


def _check_packaging_policy(report: ReleaseGateReport, root: Path) -> None:
    if not (root / "debian/control").exists():
        report.items.append(
            ReleaseGateItem(
                "packaging-policy", "review", "No Debian source package metadata in project root."
            )
        )
        return
    policy = packaging_policy_report(root)
    if policy.blocked:
        report.items.append(
            ReleaseGateItem("packaging-policy", "blocked", "Packaging policy is blocked.")
        )
        return
    autopkgtest_status = (
        policy.autopkgtest_policy.status if policy.autopkgtest_policy else "undeclared"
    )
    status = "ready" if autopkgtest_status == "declared and meaningful" else "review"
    report.items.append(
        ReleaseGateItem("packaging-policy", status, f"Autopkgtest: {autopkgtest_status}.")
    )


def _check_publish_signing(
    report: ReleaseGateReport,
    root: Path,
    options: BuildOptions,
    *,
    project_name: str,
    context: _GateContext | None = None,
    bundle_dir: Path | None = None,
) -> None:
    if not options.release_artifacts.sign:
        return
    bundle = Path(os.path.abspath(bundle_dir or root / "dist" / "publish"))
    required = (
        "RELEASE-MANIFEST.json",
        "SIGNING-REPORT.json",
        "SHA256SUMS",
        "RELEASE-GATE.json",
        SIGNING_KEYRING,
        "SHA256SUMS.asc",
        "RELEASE-GATE.json.asc",
        "RELEASE-MANIFEST.json.asc",
    )
    try:
        bundle_exists = _publish_bundle_directory_exists(bundle)
    except (ArtifactVerificationError, OSError) as exc:
        report.items.append(
            ReleaseGateItem(
                "publish-signing",
                "blocked",
                f"Cannot anchor publish signing bundle safely: {exc}",
            )
        )
        return
    if not bundle_exists:
        report.items.append(
            ReleaseGateItem(
                "publish-signing",
                "review",
                f"Missing publish signing evidence: {', '.join(required)}",
            )
        )
        return

    session = context.session if context is not None else None
    owned_session = session is None
    if session is None:
        session = ArtifactVerificationSession(
            Path("/"),
            label="publish signing artifact session",
            limits=_RELEASE_SESSION_LIMITS,
        )

    def handle(name: str, *, max_bytes: int, label: str) -> ArtifactHandle:
        assert session is not None
        return session.file_path(
            (bundle / name).absolute(),
            max_bytes=max_bytes,
            label=label,
        )

    try:
        bundle_inventory = session.tree_inventory_path(
            bundle,
            label="publish bundle inventory",
        )
        unsafe_bundle_entries = _unsafe_inventory_entries(bundle_inventory)
        if unsafe_bundle_entries:
            report.items.append(
                ReleaseGateItem(
                    "publish-signing",
                    "blocked",
                    "Publish bundle contains non-regular entries: "
                    + ", ".join(unsafe_bundle_entries),
                )
            )
            return
        inventory_names = bundle_inventory.by_name()
        missing = [name for name in required if name not in inventory_names]
        if missing:
            report.items.append(
                ReleaseGateItem(
                    "publish-signing",
                    "review",
                    f"Missing publish signing evidence: {', '.join(missing)}",
                )
            )
            return
        current_iso_path = context.iso if context is not None else Path(os.path.abspath(report.iso))
        current_iso_handle = session.file_path(
            current_iso_path,
            max_bytes=session.limits.max_file_bytes,
            label="current release-gate ISO",
        )
        manifest_handle = handle(
            "RELEASE-MANIFEST.json",
            max_bytes=MAX_RELEASE_EVIDENCE_JSON_BYTES,
            label="release manifest",
        )
        signing_handle = handle(
            "SIGNING-REPORT.json",
            max_bytes=MAX_RELEASE_EVIDENCE_JSON_BYTES,
            label="signing report",
        )
        sums_handle = handle(
            "SHA256SUMS",
            max_bytes=MAX_SHA256_SIDECAR_BYTES,
            label="publish SHA256SUMS",
        )
        keyring_handle = handle(
            SIGNING_KEYRING,
            max_bytes=MAX_RELEASE_EVIDENCE_JSON_BYTES,
            label="release verification keyring",
        )
        target_handles = {
            name: handle(
                name,
                max_bytes=MAX_RELEASE_EVIDENCE_JSON_BYTES,
                label=f"signed payload {name}",
            )
            for name in SIGN_TARGETS
        }
        signature_handles = {
            f"{name}.asc": handle(
                f"{name}.asc",
                max_bytes=MAX_RELEASE_EVIDENCE_JSON_BYTES,
                label=f"detached signature {name}.asc",
            )
            for name in SIGN_TARGETS
        }
        manifest = manifest_handle.json_object()
        signing = signing_handle.json_object()
        gate = target_handles["RELEASE-GATE.json"].json_object()
        sums_entries = parse_sha256_sums(sums_handle.read_bytes())
        problem = _publish_signing_contract_problem(
            bundle,
            root,
            project_name,
            manifest,
            signing,
            gate,
            sums_entries,
            keyring_handle,
            target_handles,
            options,
            session,
            bundle_inventory,
            current_iso_handle,
        )
        if problem is not None:
            report.items.append(ReleaseGateItem("publish-signing", "blocked", problem))
            return
        expected = full_fingerprint(options.release_artifacts.gpg_key)
        assert expected is not None
        if not CommandRunner.has_binary("gpg"):
            report.items.append(
                ReleaseGateItem(
                    "publish-signing",
                    "blocked",
                    "Executed publish signing cannot be verified because gpg is missing.",
                )
            )
            return
        runner = CommandRunner(dry_run=False)
        for name in SIGN_TARGETS:
            signature_name = f"{name}.asc"
            signature = signature_handles[signature_name]
            payload = target_handles[name]
            verify_detached_signature(
                runner,
                bundle / signature_name,
                bundle / name,
                bundle / SIGNING_KEYRING,
                expected,
                signature_fd=signature.fileno,
                payload_fd=payload.fileno,
                keyring_fd=keyring_handle.fileno,
            )
        report.items.append(
            ReleaseGateItem(
                "publish-signing",
                "ready",
                "The release snapshot, strict SHA256SUMS, pinned keyring and exactly "
                "three detached signatures are descriptor-bound and cryptographically "
                f"verified for {expected}.",
            )
        )
    except (
        ArtifactVerificationError,
        CommandError,
        OSError,
        UnicodeError,
        TypeError,
        ValueError,
        OverflowError,
        RecursionError,
    ) as exc:
        report.items.append(
            ReleaseGateItem(
                "publish-signing",
                "blocked",
                f"Publish signing evidence is invalid: {exc}",
            )
        )
    finally:
        if owned_session:
            try:
                session.seal()
            except ArtifactVerificationError as exc:
                if not any(
                    item.code == "publish-signing" and item.status == "blocked"
                    for item in report.items
                ):
                    report.items.append(
                        ReleaseGateItem(
                            "publish-signing",
                            "blocked",
                            f"Publish signing evidence did not seal: {exc}",
                        )
                    )


def _publish_bundle_directory_exists(bundle: Path) -> bool:
    """Observe one absolute bundle path without following any component."""

    if not bundle.is_absolute() or "\x00" in str(bundle) or ".." in bundle.parts:
        raise ArtifactVerificationError(f"publish signing bundle path is not canonical: {bundle}")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open("/", flags)
        for component in bundle.parts[1:]:
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except FileNotFoundError:
                return False
            except OSError as exc:
                raise ArtifactVerificationError(
                    "publish signing bundle contains a symlink, non-directory, "
                    f"or unreadable component: {bundle}"
                ) from exc
            previous = descriptor
            descriptor = child
            os.close(previous)
        try:
            identity = ArtifactIdentity.from_stat(os.fstat(descriptor))
        except OSError as exc:
            raise ArtifactVerificationError(
                f"publish signing bundle cannot be identified: {bundle}"
            ) from exc
        if not stat.S_ISDIR(identity.mode):
            raise ArtifactVerificationError(f"publish signing bundle is not a directory: {bundle}")
        return True
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _publish_signing_contract_problem(
    bundle: Path,
    project_root: Path,
    project_name: str,
    manifest: dict[str, object],
    signing: dict[str, object],
    gate: dict[str, object],
    sums_entries: dict[str, str],
    keyring: ArtifactHandle,
    targets: dict[str, ArtifactHandle],
    options: BuildOptions,
    session: ArtifactVerificationSession,
    inventory: ArtifactTreeInventory,
    current_iso: ArtifactHandle,
) -> str | None:
    manifest_problem = release_manifest_problem(
        manifest,
        expected_project_name=project_name,
        expected_bundle_dir=bundle,
    )
    if manifest_problem is not None:
        return f"RELEASE-MANIFEST.json is not authoritative: {manifest_problem}."
    report_problem = release_signing_report_problem(
        signing,
        manifest,
        expected_project=project_root,
        expected_bundle_dir=bundle,
    )
    if report_problem is not None:
        return f"SIGNING-REPORT.json is not authoritative: {report_problem}."
    gate_problem = release_gate_report_problem(
        gate,
        expected_project=project_root,
        expected_iso=current_iso.logical_path,
        expected_output_dir=current_iso.logical_path.parent,
    )
    if gate_problem is not None:
        return f"RELEASE-GATE.json is not authoritative: {gate_problem}."
    required_signatures = {f"{name}.asc" for name in SIGN_TARGETS}
    signed_value = signing.get("signed")
    if (
        signing.get("status") != "signed"
        or signing.get("execute") is not True
        or not isinstance(signed_value, list)
        or len(signed_value) != len(required_signatures)
        or not all(isinstance(name, str) for name in signed_value)
        or set(signed_value) != required_signatures
        or signing.get("planned") != []
        or signing.get("skipped") != []
    ):
        return (
            "Executed signing must record exactly the three required detached "
            "signatures, with no planned or skipped target."
        )
    expected = full_fingerprint(options.release_artifacts.gpg_key)
    recorded_value = signing.get("signer_fingerprint")
    recorded = full_fingerprint(recorded_value if isinstance(recorded_value, str) else None)
    if expected is None or recorded != expected:
        return (
            "SIGNING-REPORT.json does not match the configured complete OpenPGP signer fingerprint."
        )
    keyring_digest = signing.get("verification_keyring_sha256")
    if (
        signing.get("verification_keyring") != SIGNING_KEYRING
        or not _is_sha256(keyring_digest)
        or keyring.digest() != keyring_digest
    ):
        return "The pinned release verification keyring identity is inconsistent."

    raw_files = manifest.get("files")
    if not isinstance(raw_files, list) or not raw_files:
        return "RELEASE-MANIFEST.json has no file snapshot."
    manifest_entries: dict[str, tuple[int, str]] = {}
    normalized_entries: list[dict[str, object]] = []
    for raw_entry in raw_files:
        if not isinstance(raw_entry, dict):
            return "RELEASE-MANIFEST.json contains a malformed file entry."
        name = raw_entry.get("name")
        size = raw_entry.get("size")
        digest = raw_entry.get("sha256")
        if (
            not isinstance(name, str)
            or not name
            or "\\" in name
            or "\x00" in name
            or Path(name).is_absolute()
            or Path(name).as_posix() != name
            or any(part in {"", ".", ".."} for part in Path(name).parts)
            or name in manifest_entries
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
            or not isinstance(digest, str)
            or not _is_sha256(digest)
        ):
            return f"RELEASE-MANIFEST.json has an unsafe entry: {name!r}."
        manifest_entries[name] = (size, digest)
        normalized_entries.append({"name": name, "size": size, "sha256": digest})
    if signing.get("manifest_entries") != normalized_entries:
        return "SIGNING-REPORT.json does not reproduce the signed manifest snapshot."

    gate_status = gate.get("status")
    manifest_gate_status = manifest.get("gate_status")
    if (
        gate_status not in {"ready", "review"}
        or manifest_gate_status != gate_status
        or gate.get("blocked") is not False
    ):
        return (
            "The descriptor-held RELEASE-GATE.json status is blocked, invalid, "
            "or differs from the signed manifest snapshot."
        )
    gate_iso_value = gate.get("iso")
    if (
        not isinstance(gate_iso_value, str)
        or not gate_iso_value
        or "\x00" in gate_iso_value
        or ".." in Path(gate_iso_value).parts
        or Path(os.path.abspath(gate_iso_value)) != current_iso.logical_path
    ):
        return "RELEASE-GATE.json does not identify the current descriptor-held ISO."
    raw_gate_items = gate.get("items")
    if not isinstance(raw_gate_items, list) or not raw_gate_items:
        return "RELEASE-GATE.json must contain non-empty typed item verdicts."
    gate_items: dict[str, dict[str, object]] = {}
    for raw_item in raw_gate_items:
        if not isinstance(raw_item, dict):
            return "RELEASE-GATE.json contains malformed item verdicts."
        code = raw_item.get("code")
        status_value = raw_item.get("status")
        detail = raw_item.get("detail")
        if (
            not isinstance(code, str)
            or not code
            or code in gate_items
            or status_value not in {"ready", "review", "blocked"}
            or not isinstance(detail, str)
            or not detail
        ):
            return (
                "RELEASE-GATE.json item verdicts require unique non-empty "
                "codes and strict status/detail strings."
            )
        gate_items[code] = raw_item
    item_statuses = [str(item["status"]) for item in gate_items.values()]
    derived_status = (
        "blocked"
        if "blocked" in item_statuses
        else "review"
        if "review" in item_statuses
        else "ready"
    )
    if derived_status != gate_status:
        return "RELEASE-GATE.json aggregate status contradicts its descriptor-held item verdicts."
    code_problem = release_gate_code_problem(set(gate_items))
    if code_problem is not None:
        return f"RELEASE-GATE.json {code_problem}."

    for name, (expected_size, expected_digest) in manifest_entries.items():
        artifact = session.file_path(
            (bundle / name).absolute(),
            max_bytes=session.limits.max_file_bytes,
            allow_empty=True,
            label=f"manifest artifact {name}",
        )
        if artifact.identity.size != expected_size or artifact.digest() != expected_digest:
            return f"Manifest artifact {name} differs from its signed snapshot."
    for required_name in ("SHA256SUMS", "RELEASE-GATE.json", SIGNING_KEYRING):
        if required_name not in manifest_entries:
            return f"The signed manifest does not bind {required_name}."

    actual_bundle_by_name = inventory.by_name()
    operational_files = set(actual_bundle_by_name) & OPERATIONAL_BUNDLE_FILES
    unsafe_operational = sorted(
        name for name in operational_files if not stat.S_ISREG(actual_bundle_by_name[name].mode)
    )
    if unsafe_operational:
        return (
            "Operational bundle paths must be regular files: " + ", ".join(unsafe_operational) + "."
        )
    expected_bundle_files = (
        set(manifest_entries) | operational_files | {f"{name}.asc" for name in SIGN_TARGETS}
    )
    expected_bundle_entries = _expected_inventory_entries(expected_bundle_files)
    actual_bundle_entries = set(actual_bundle_by_name)
    if actual_bundle_entries != expected_bundle_entries:
        missing = sorted(expected_bundle_entries - actual_bundle_entries)
        unexpected = sorted(actual_bundle_entries - expected_bundle_entries)
        details: list[str] = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unexpected:
            details.append("unexpected " + ", ".join(unexpected))
        return "Publish bundle inventory is not exact: " + "; ".join(details) + "."

    iso_names = sorted(name for name in manifest_entries if name.endswith(".iso"))
    if len(iso_names) != 1:
        return f"The signed manifest must bind exactly one ISO; found {len(iso_names)}."
    iso_name = iso_names[0]
    iso_size, iso_digest = manifest_entries[iso_name]
    if iso_size <= 0:
        return "The signed manifest binds an empty ISO."
    if set(sums_entries) != {iso_name}:
        return "SHA256SUMS must contain exactly the single manifest-bound ISO."
    if sums_entries[iso_name] != manifest_entries[iso_name][1]:
        return "SHA256SUMS does not match the signed ISO snapshot."
    current_iso_digest = current_iso.digest()
    if (
        iso_name != current_iso.logical_path.name
        or iso_size != current_iso.identity.size
        or iso_digest != current_iso_digest
    ):
        return "The signed bundle ISO does not match the current descriptor-held release-gate ISO."
    iso_item = gate_items.get("iso")
    sha_item = gate_items.get("sha256")
    if (
        iso_item is None
        or iso_item.get("status") != "ready"
        or iso_item.get("detail") != f"{current_iso.identity.size} bytes"
        or sha_item is None
        or sha_item.get("status") != "ready"
        or sha_item.get("detail") != current_iso_digest
    ):
        return (
            "RELEASE-GATE.json does not bind its ready ISO and SHA256 items "
            "to the current descriptor-held ISO."
        )
    for name, target in targets.items():
        if name in manifest_entries:
            expected_size, expected_digest = manifest_entries[name]
            if target.identity.size != expected_size or target.digest() != expected_digest:
                return f"Signed payload {name} differs from the manifest snapshot."
    return None


def _boot_proof_summary(path: Path) -> dict[str, str]:
    try:
        data = _read_bounded_json_file(
            path,
            max_bytes=MAX_RELEASE_EVIDENCE_JSON_BYTES,
            label="boot proof summary",
        )
    except (
        OSError,
        UnicodeError,
        TypeError,
        ValueError,
        OverflowError,
        RecursionError,
    ):
        return {"status": "invalid", "selected_backend": "unknown", "proof_level": "none"}
    if not isinstance(data, dict):
        return {"status": "invalid", "selected_backend": "unknown", "proof_level": "none"}
    return {
        "status": str(data.get("status", "unknown")),
        "selected_backend": str(data.get("selected_backend", data.get("backend", "unknown"))),
        "proof_level": str(data.get("proof_level", "none")),
    }
