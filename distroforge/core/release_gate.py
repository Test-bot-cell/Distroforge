from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path

from .artifact_paths import default_artifact_paths
from .build import BuildOptions
from .command import VIRTUAL_COMMANDS
from .diff_preview import DiffPreviewService
from .evidence_run import (
    IDENTITY_CLOSURE_SCHEMA,
    canonical_sha256,
    first_symlink_in_confined_tree,
    observed_executable_counts,
)
from .hashing import sha256_file, sha256_from_sums
from .iso_evidence import (
    ISO_ASSEMBLY_FILENAME,
    ISO_ASSEMBLY_SCHEMA,
    validate_iso_assembly_evidence,
)
from .package_apt_actions import (
    MAX_REPORT_JSON_BYTES,
    PACKAGE_APT_ACTIONS_FILENAME,
    PACKAGE_APT_ACTIONS_SCHEMA,
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
from .release_readiness import ReleaseReadinessService
from .rootfs_evidence import (
    ROOTFS_PACKING_VERIFICATION_SCHEMA,
    validate_rootfs_evidence,
)
from .trust import TrustService
from .vulnscan import VulnScanService


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
        verify_checksums: bool = True,
    ) -> ReleaseGateReport:
        """Report the maintainer publish gate for ``project``.

        ``verify_checksums=False`` answers the SHA256 items from the SHA256SUMS
        sidecar instead of re-reading the ISO, which is what the guided journey
        status needs: it is recomputed on every refresh and must not hash a
        multi-gigabyte artifact on the Qt thread. The verifying default stays on
        every authoritative path (``distroforge release-gate``, the Artifacts
        page, ``check_journey_step``), so the gate is never self-confirming
        where its verdict is the answer.
        """
        paths = default_artifact_paths(project)
        iso = iso or options.output_iso or paths.output_iso
        output_dir = output_dir or iso.parent
        report = ReleaseGateReport(project.root, iso, output_dir)
        package_inputs = _package_inputs_item(
            output_dir,
            project,
            options,
            verify=verify_checksums,
        )
        _check_source_trust(report, project, options, package_inputs)
        report.items.append(package_inputs)
        report.items.append(_rootfs_evidence_item(output_dir, verify=verify_checksums))
        report.items.append(
            _iso_assembly_item(
                output_dir,
                iso,
                project=project,
                verify=verify_checksums,
            )
        )
        _check_vuln_policy(report, project, options)
        _check_iso_and_checksums(report, iso, output_dir, verify_checksums)
        _check_release_files(report, iso, output_dir, options)
        _check_boot_proof(report, iso, output_dir, options)
        _check_release_readiness(report, iso, output_dir, verify_checksums)
        _check_packaging_policy(report, project.root)
        _check_publish_signing(report, project.root, options)
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
                f"{check.code}: {check.message}"
                for check in trust.checks
                if check.level == "error"
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
) -> ReleaseGateItem:
    provenance = output_dir / "distroforge-provenance.json"
    try:
        provenance_data = json.loads(provenance.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return ReleaseGateItem(
            "package-inputs",
            "blocked",
            f"Cannot locate a package-input run without provenance: {exc}",
        )
    run_id = provenance_data.get("run_id")
    if not isinstance(run_id, str) or not run_id or Path(run_id).name != run_id:
        return ReleaseGateItem(
            "package-inputs",
            "blocked",
            "Provenance has no safe run identity for package inputs.",
        )
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
    if not verify:
        try:
            payload = json.loads(evidence.read_text(encoding="utf-8"))
            action_payload = _read_bounded_json_file(
                action_evidence,
                max_bytes=MAX_REPORT_JSON_BYTES,
                label="APT action report",
            )
            causality_payload = json.loads(
                causality_evidence.read_text(encoding="utf-8")
            )
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            return ReleaseGateItem(
                "package-inputs",
                "blocked",
                f"Package-input evidence is unreadable: {exc}",
            )
        action_boundary_error = _package_apt_actions_boundary_error(
            action_payload,
            run_dir,
            run_id,
        )
        if action_boundary_error is not None:
            return ReleaseGateItem(
                "package-inputs",
                "blocked",
                action_boundary_error,
            )
        if (
            not isinstance(causality_payload, dict)
            or causality_payload.get("schema")
            != PACKAGE_FILESYSTEM_CAUSALITY_SCHEMA
            or causality_payload.get("run_id") != run_id
            or causality_payload.get("payload_identity")
            not in {"partial", "verified"}
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
        command_argv = _command_argv_ledger(run_dir / "commands.jsonl")
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
        (
            f"{validation.detail}; {action_validation.detail}; "
            f"{causality_validation.detail}"
        ),
    )


def _read_bounded_json_file(
    path: Path,
    *,
    max_bytes: int,
    label: str,
) -> object:
    """Read one regular JSON file through a stable, size-bounded descriptor."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size <= 0
            or before.st_size > max_bytes
        ):
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
    try:
        return json.loads(data.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not valid UTF-8 JSON") from exc


def _package_apt_actions_boundary_error(
    payload: object,
    run_dir: Path,
    run_id: str,
) -> str | None:
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != PACKAGE_APT_ACTIONS_SCHEMA
        or payload.get("run_id") != run_id
        or payload.get("scope")
        != "apt-dpkg-pre-install-pkgs-v3-planned-actions-m3.2a"
        or payload.get("capture_origin")
        != "unverified-mutable-target-rootfs"
        or payload.get("filesystem_causality") != "unverified"
        or payload.get("release_ready") is not False
        or payload.get("apt_actions")
        not in {"self-consistent", "not-observed"}
    ):
        return (
            "The APT action receipt does not preserve the M3.2a "
            "proof boundary."
        )
    for identity_field, expected_path in (
        ("package_inputs", "PACKAGE-INPUTS.json"),
        ("capture_journal", "apt/transactions.tsv"),
    ):
        identity = payload.get(identity_field)
        if not isinstance(identity, dict):
            return (
                "The APT action receipt has no valid "
                f"{identity_field} identity."
            )
        artifact = run_dir / expected_path
        if (
            identity.get("path") != expected_path
            or artifact.is_symlink()
            or not artifact.is_file()
            or identity.get("size") != artifact.stat().st_size
            or identity.get("sha256") != sha256_file(artifact)
        ):
            return (
                "The APT action receipt is not bound to this run's "
                f"{expected_path}."
            )
    transactions = payload.get("transactions")
    if not isinstance(transactions, list):
        return "The APT action receipt transaction list is malformed."
    if (
        payload.get("apt_actions") == "self-consistent"
        and not transactions
    ) or (
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
            return (
                "The APT action receipt contains an invalid protocol-v3 "
                "transaction."
            )
        transaction_ids.add(transaction_id)
    return None


def _command_argv_ledger(path: Path) -> tuple[tuple[str, ...], ...]:
    """Load every dispatched argv from the final immutable run log.

    ``PACKAGE-INPUTS.json`` is written before packing and ISO assembly.  Reading
    the complete final log here makes any later APT/debootstrap/mmdebstrap
    invocation part of the independently recomputed ledger rather than silently
    trusting the earlier aggregate.
    """

    if path.is_symlink() or not path.is_file():
        raise ValueError("commands.jsonl is missing, non-regular, or a symlink")
    commands: list[tuple[str, ...]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"commands.jsonl line {line_number} is not valid JSON"
                    ) from exc
                if not isinstance(event, dict):
                    raise ValueError(
                        f"commands.jsonl line {line_number} is not an event"
                    )
                if event.get("event") != "start":
                    continue
                argv = event.get("argv")
                if (
                    not isinstance(argv, list)
                    or not argv
                    or not all(isinstance(token, str) and token for token in argv)
                ):
                    raise ValueError(
                        f"commands.jsonl line {line_number} has malformed argv"
                    )
                commands.append(tuple(argv))
    except OSError as exc:
        raise ValueError(f"commands.jsonl is unreadable: {exc}") from exc
    return tuple(commands)


def _rootfs_evidence_item(
    output_dir: Path,
    *,
    verify: bool,
) -> ReleaseGateItem:
    provenance = output_dir / "distroforge-provenance.json"
    try:
        provenance_data = json.loads(provenance.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return ReleaseGateItem(
            "rootfs-identity",
            "blocked",
            f"Cannot locate rootfs evidence without provenance: {exc}",
        )
    run_id = provenance_data.get("run_id")
    if not isinstance(run_id, str) or not run_id or Path(run_id).name != run_id:
        return ReleaseGateItem(
            "rootfs-identity",
            "blocked",
            "Provenance has no safe run identity for rootfs evidence.",
        )
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
            payload = json.loads(verification.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
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
) -> ReleaseGateItem:
    provenance = output_dir / "distroforge-provenance.json"
    try:
        provenance_data = json.loads(provenance.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return ReleaseGateItem(
            "iso-assembly",
            "blocked",
            f"Cannot locate ISO assembly evidence without provenance: {exc}",
        )
    run_id = provenance_data.get("run_id")
    if not isinstance(run_id, str) or not run_id or Path(run_id).name != run_id:
        return ReleaseGateItem(
            "iso-assembly",
            "blocked",
            "Provenance has no safe run identity for ISO assembly evidence.",
        )
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
            payload = json.loads(evidence.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
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
        staged_squashfs_path=(
            project.iso_root
            / project.release.livefs
            / "filesystem.squashfs"
        ),
    )
    return ReleaseGateItem(
        "iso-assembly",
        "ready" if validation.ok else "blocked",
        validation.detail,
    )


def _check_vuln_policy(report: ReleaseGateReport, project: Project, options: BuildOptions) -> None:
    if not options.vuln_scan.enabled:
        report.items.append(ReleaseGateItem("vuln-scan", "review", "CVE scanning is not enabled."))
        return
    packages = DiffPreviewService().preview(project, options).install
    scan = VulnScanService(options.vuln_scan).scan(packages)
    counts = scan.counts
    summary = f"policy={scan.policy} db={scan.database} critical={counts['critical']} high={counts['high']}"
    if not scan.ok:
        report.items.append(
            ReleaseGateItem("vuln-scan", "blocked", f"CVE policy violated: {summary}")
        )
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
    report: ReleaseGateReport, iso: Path, output_dir: Path, verify_checksums: bool = True
) -> None:
    if not iso.exists():
        report.items.append(ReleaseGateItem("iso", "blocked", "Final ISO is missing."))
        report.items.append(
            ReleaseGateItem("sha256", "blocked", "Cannot verify SHA256 without an ISO.")
        )
        return
    report.items.append(ReleaseGateItem("iso", "ready", f"{iso.stat().st_size} bytes"))
    sums = output_dir / "SHA256SUMS"
    if not sums.exists():
        report.items.append(ReleaseGateItem("sha256", "blocked", "SHA256SUMS is missing."))
        return
    expected = sha256_from_sums(sums, iso.name)
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
    actual = sha256_file(iso)
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
) -> None:
    sbom_format = options.provenance.sbom_format
    sbom_filename = (
        SPDX_FILENAME
        if sbom_format == "spdx"
        else CYCLONEDX_FILENAME
        if sbom_format == "cyclonedx"
        else None
    )
    for code, filename, enabled in (
        ("buildinfo", "BUILDINFO", options.release_artifacts.enabled),
        ("provenance", "distroforge-provenance.json", options.provenance.enabled),
        ("sbom", sbom_filename, options.provenance.enabled and sbom_filename is not None),
        ("html-report", options.html_report.filename, options.html_report.enabled),
    ):
        if filename is None:
            report.items.append(
                ReleaseGateItem(code, "review", "Standard-format SBOM export is not enabled.")
            )
            continue
        path = output_dir / filename
        if code == "provenance" and path.exists():
            report.items.append(
                _validate_build_provenance(
                    path,
                    iso,
                    output_dir,
                    use_sudo=options.use_sudo,
                )
            )
            continue
        if path.exists():
            if code in {"buildinfo", "sbom", "html-report"} and not _build_manifest_binds(
                output_dir,
                path,
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


def _build_manifest_binds(output_dir: Path, artifact: Path) -> bool:
    provenance = output_dir / "distroforge-provenance.json"
    try:
        data = json.loads(provenance.read_text(encoding="utf-8"))
        run_id = data.get("run_id")
        if not isinstance(run_id, str) or Path(run_id).name != run_id:
            return False
        manifest = json.loads(
            (output_dir / "evidence" / "runs" / run_id / "RUN-MANIFEST.json").read_text(
                encoding="utf-8"
            )
        )
    except (OSError, json.JSONDecodeError):
        return False
    files = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(files, list) or not artifact.is_file():
        return False
    return any(
        isinstance(item, dict)
        and item.get("path") == str(artifact)
        and item.get("size") == artifact.stat().st_size
        and item.get("sha256") == sha256_file(artifact)
        for item in files
    )


def _identity_closure_problem(run: dict[str, object]) -> str | None:
    component_names = ("builder_source", "definition", "source_iso", "toolchain")
    opening = {name: run.get(name) for name in component_names}
    recorded_opening_sha256 = run.get("opening_identity_sha256")
    if (
        not _is_sha256(recorded_opening_sha256)
        or recorded_opening_sha256 != canonical_sha256(opening)
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
    if (
        not isinstance(checks, list)
        or closure.get("checks_sha256") != canonical_sha256(checks)
    ):
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
            or re.fullmatch(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", value)
            is None
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
        builder.get("tracked_diff_sha256")
        != "e3b0c44298fc1c149afbf4c8996fb924"
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
) -> ReleaseGateItem:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return ReleaseGateItem("provenance", "blocked", f"Provenance is unreadable: {exc}")
    if not isinstance(data, dict) or data.get("schema") != "distroforge.provenance.v2":
        return ReleaseGateItem(
            "provenance", "blocked", "Provenance schema is absent or unsupported."
        )
    if data.get("attestation_kind") != "build":
        return ReleaseGateItem(
            "provenance", "blocked", "Reconstructed provenance is not build evidence."
        )
    if not iso.is_file() or data.get("output_iso_sha256") != sha256_file(iso):
        return ReleaseGateItem(
            "provenance", "blocked", "Provenance belongs to different ISO bytes."
        )
    run_id = data.get("run_id")
    run = data.get("run")
    if (
        not isinstance(run_id, str)
        or not run_id
        or not isinstance(run, dict)
        or run.get("run_id") != run_id
        or run.get("mode") != "execute"
    ):
        return ReleaseGateItem("provenance", "blocked", "Provenance run identity is incomplete.")
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
            "Builder Git identity is not publication-grade: "
            + builder_publication_problem,
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
    unsafe_symlink = first_symlink_in_confined_tree(output_dir, immutable_dir)
    if unsafe_symlink is not None:
        return ReleaseGateItem(
            "provenance",
            "blocked",
            f"Immutable run contains unsafe symlink: {unsafe_symlink}.",
        )
    immutable = immutable_dir / "distroforge-provenance.json"
    iso_report = immutable_dir / "ISO-BUILD.json"
    package_inputs = immutable_dir / "PACKAGE-INPUTS.json"
    package_apt_actions = immutable_dir / PACKAGE_APT_ACTIONS_FILENAME
    package_filesystem_causality = (
        immutable_dir / PACKAGE_FILESYSTEM_CAUSALITY_FILENAME
    )
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
    if sha256_file(immutable) != sha256_file(path):
        return ReleaseGateItem(
            "provenance", "blocked", "Provenance alias differs from immutable evidence."
        )
    package_identity = data.get("package_inputs")
    if (
        not isinstance(package_identity, dict)
        or package_identity.get("path") != str(package_inputs)
        or package_identity.get("role") != "package-input-closure"
        or package_identity.get("size") != package_inputs.stat().st_size
        or package_identity.get("sha256") != sha256_file(package_inputs)
    ):
        return ReleaseGateItem(
            "provenance",
            "blocked",
            "Provenance does not bind this run's package-input closure.",
        )
    package_apt_actions_identity = data.get("package_apt_actions")
    if (
        not isinstance(package_apt_actions_identity, dict)
        or package_apt_actions_identity.get("path")
        != str(package_apt_actions)
        or package_apt_actions_identity.get("role") != "package-apt-actions"
        or package_apt_actions_identity.get("size")
        != package_apt_actions.stat().st_size
        or package_apt_actions_identity.get("sha256")
        != sha256_file(package_apt_actions)
    ):
        return ReleaseGateItem(
            "provenance",
            "blocked",
            "Provenance does not bind this run's APT protocol-v3 action receipt.",
        )
    package_filesystem_causality_identity = data.get(
        "package_filesystem_causality"
    )
    if (
        not isinstance(package_filesystem_causality_identity, dict)
        or package_filesystem_causality_identity.get("path")
        != str(package_filesystem_causality)
        or package_filesystem_causality_identity.get("role")
        != "package-filesystem-causality"
        or package_filesystem_causality_identity.get("size")
        != package_filesystem_causality.stat().st_size
        or package_filesystem_causality_identity.get("sha256")
        != sha256_file(package_filesystem_causality)
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
            or identity.get("size") != artifact.stat().st_size
            or identity.get("sha256") != sha256_file(artifact)
        ):
            return ReleaseGateItem(
                "provenance",
                "blocked",
                f"Provenance does not bind this run's {artifact.name}.",
            )
    rootfs_validation = validate_rootfs_evidence(
        immutable_dir,
        expected_run_id=run_id,
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
    )
    if not iso_assembly_validation.ok:
        return ReleaseGateItem(
            "provenance",
            "blocked",
            iso_assembly_validation.detail,
        )
    try:
        assembly_payload = json.loads(iso_assembly.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return ReleaseGateItem(
            "provenance",
            "blocked",
            f"ISO assembly evidence is unreadable: {exc}",
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
        or staged_artifact.get("size") != staged_artifact_path.stat().st_size
        or staged_artifact.get("sha256") != sha256_file(staged_artifact_path)
    ):
        return ReleaseGateItem(
            "provenance",
            "blocked",
            "Provenance staged SquashFS differs from the packing FD witness.",
        )
    try:
        build = json.loads(iso_report.read_text(encoding="utf-8"))
        run_manifest = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return ReleaseGateItem("provenance", "blocked", f"Run evidence is unreadable: {exc}")
    if (
        not isinstance(build, dict)
        or build.get("schema") != "distroforge.iso-build.v2"
        or build.get("run_id") != run_id
        or build.get("status") != "built"
        or build.get("execute") is not True
        or build.get("output_exists") is not True
        or build.get("output_sha256") != sha256_file(iso)
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
    expected_manifest_line = f"{sha256_file(manifest)}  {manifest.name}"
    if manifest_sum.read_text(encoding="utf-8").strip() != expected_manifest_line:
        return ReleaseGateItem(
            "provenance", "blocked", "Run manifest SHA256 sidecar does not match."
        )
    files = run_manifest.get("files")
    if not isinstance(files, list):
        return ReleaseGateItem("provenance", "blocked", "Run manifest has no file identities.")
    recorded: dict[str, str] = {}
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
        if (
            artifact_path.is_symlink()
            or not artifact_path.is_file()
            or item.get("size") != artifact_path.stat().st_size
            or item.get("sha256") != sha256_file(artifact_path)
        ):
            return ReleaseGateItem(
                "provenance",
                "blocked",
                f"Run artifact changed or disappeared: {artifact_path}",
            )
        recorded[artifact_key] = str(item.get("sha256"))
    unrecorded_run_files = [
        path
        for path in immutable_dir.rglob("*")
        if path.is_file() and path not in {manifest, manifest_sum} and str(path) not in recorded
    ]
    if unrecorded_run_files:
        return ReleaseGateItem(
            "provenance",
            "blocked",
            "Immutable run contains unmanifested files: "
            + ", ".join(path.name for path in unrecorded_run_files),
        )
    alias_report = output_dir / "ISO-BUILD.json"
    if not alias_report.is_file() or sha256_file(alias_report) != sha256_file(iso_report):
        return ReleaseGateItem(
            "provenance",
            "blocked",
            "ISO-BUILD.json alias differs from immutable build evidence.",
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
        if recorded.get(str(artifact)) != sha256_file(artifact):
            return ReleaseGateItem(
                "provenance",
                "blocked",
                f"Run manifest does not bind {artifact.name}.",
            )
    command_log_error = _command_log_error(
        immutable_dir / "commands.jsonl",
        command_records,
        executed_entrypoints,
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
        f"immutable build run {run_id} matches ISO SHA256 {sha256_file(iso)}",
    )


def _provenance_is_bootstrap(project_data: object) -> bool:
    """Derive tool roles from the effective source mode, not starter presence.

    Both skeleton and official-ISO starters populate ``source_starter``. Treating
    that field itself as bootstrap made an ISO starter require mmdebstrap,
    GRUB/mtools assembly and the bootstrap-only M3.1 dpkg-deb inspection even
    though none of those commands belonged to the executed path.
    """

    return (
        isinstance(project_data, dict)
        and project_data.get("source_mode") == "bootstrap"
    )


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
) -> str | None:
    try:
        events = [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except (OSError, json.JSONDecodeError) as exc:
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
    options: BuildOptions,
) -> None:
    qemu_report = output_dir / options.prebuild_vm.report_name
    proof = output_dir / "boot-proof.json"
    if proof.exists():
        report.items.append(_validate_boot_proof(proof, iso))
    elif qemu_report.exists():
        validation = validate_qemu_report(qemu_report, iso)
        binding_error = (
            _qemu_run_binding_error(
                output_dir,
                iso,
                qemu_report.name,
                validation.payload,
            )
            if validation.ok
            else None
        )
        report.items.append(
            ReleaseGateItem(
                "boot-proof",
                "ready" if validation.ok and binding_error is None else "blocked",
                binding_error or validation.detail,
            )
        )
    elif options.prebuild_vm.enabled or options.bootcheck.enabled or options.qa.scenarios:
        report.items.append(
            ReleaseGateItem(
                "boot-proof",
                "blocked",
                "Boot proof is configured but no executed proof report exists.",
            )
        )
    else:
        report.items.append(
            ReleaseGateItem("boot-proof", "blocked", "No QEMU, bootcheck or QA proof configured.")
        )


def _qemu_run_binding_error(
    output_dir: Path,
    iso: Path,
    report_name: str,
    payload: dict[str, object] | None,
) -> str | None:
    if not isinstance(payload, dict):
        return "QEMU report payload is missing."
    run_id = payload.get("run_id")
    if not isinstance(run_id, str) or Path(run_id).name != run_id:
        return "QEMU report has no safe run identity."
    run_dir = output_dir / "evidence" / "runs" / run_id
    unsafe_symlink = first_symlink_in_confined_tree(output_dir, run_dir)
    if unsafe_symlink is not None:
        return f"QEMU run contains unsafe symlink: {unsafe_symlink}."
    manifest_path = run_dir / "RUN-MANIFEST.json"
    sidecar = run_dir / "RUN-MANIFEST.json.sha256"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        sidecar_text = sidecar.read_text(encoding="utf-8").strip()
    except (OSError, json.JSONDecodeError) as exc:
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
    if sidecar_text != f"{sha256_file(manifest_path)}  {manifest_path.name}":
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
        if (
            not key
            or key in recorded
            or path.is_symlink()
            or not path.is_file()
            or item.get("size") != path.stat().st_size
            or item.get("sha256") != sha256_file(path)
        ):
            return f"QEMU run artifact changed or disappeared: {path}"
        recorded[key] = str(item.get("sha256"))
    immutable_report = run_dir / report_name
    command_log = run_dir / "commands.jsonl"
    for required in (immutable_report, command_log, iso):
        if not required.is_file() or recorded.get(str(required)) != sha256_file(required):
            return f"QEMU run manifest does not bind {required.name}."
    unrecorded = [
        path
        for path in run_dir.rglob("*")
        if path.is_file() and path not in {manifest_path, sidecar} and str(path) not in recorded
    ]
    if unrecorded:
        return "QEMU run contains unmanifested files: " + ", ".join(
            path.name for path in unrecorded
        )
    return None


def _validate_boot_proof(path: Path, iso: Path) -> ReleaseGateItem:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
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
    if not iso.is_file() or data.get("iso_sha256") != sha256_file(iso):
        return ReleaseGateItem(
            "boot-proof", "blocked", "Boot proof belongs to different ISO bytes."
        )
    run_id = data.get("run_id")
    if not isinstance(run_id, str) or not run_id or Path(run_id).name != run_id:
        return ReleaseGateItem("boot-proof", "blocked", "Boot proof has no immutable run_id.")
    immutable_dir = path.parent / "evidence" / "runs" / run_id
    unsafe_symlink = first_symlink_in_confined_tree(path.parent, immutable_dir)
    if unsafe_symlink is not None:
        return ReleaseGateItem(
            "boot-proof",
            "blocked",
            f"Boot run contains unsafe symlink: {unsafe_symlink}.",
        )
    immutable_proof = immutable_dir / "boot-proof.json"
    run_manifest_path = immutable_dir / "RUN-MANIFEST.json"
    run_manifest_sum = immutable_dir / "RUN-MANIFEST.json.sha256"
    for required in (immutable_proof, run_manifest_path, run_manifest_sum):
        if not required.is_file():
            return ReleaseGateItem(
                "boot-proof",
                "blocked",
                f"Immutable boot run evidence is missing: {required.name}.",
            )
    if sha256_file(immutable_proof) != sha256_file(path):
        return ReleaseGateItem(
            "boot-proof",
            "blocked",
            "Boot-proof alias differs from immutable evidence.",
        )
    if data.get("immutable_proof") != immutable_proof.name:
        return ReleaseGateItem(
            "boot-proof",
            "blocked",
            "Boot proof does not identify its immutable report.",
        )
    try:
        run_manifest = json.loads(run_manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return ReleaseGateItem(
            "boot-proof",
            "blocked",
            f"Boot run manifest is unreadable: {exc}",
        )
    if (
        not isinstance(run_manifest, dict)
        or run_manifest.get("schema") != "distroforge.boot-proof-run-manifest.v1"
        or run_manifest.get("run_id") != run_id
        or run_manifest.get("mode") != "execute"
        or run_manifest.get("status") != status
    ):
        return ReleaseGateItem(
            "boot-proof",
            "blocked",
            "Boot run manifest identity or status is inconsistent.",
        )
    expected_manifest_line = f"{sha256_file(run_manifest_path)}  {run_manifest_path.name}"
    if run_manifest_sum.read_text(encoding="utf-8").strip() != expected_manifest_line:
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
        if (
            not artifact_key
            or artifact_key in recorded
            or artifact.is_symlink()
            or not artifact.is_file()
            or item.get("size") != artifact.stat().st_size
            or item.get("sha256") != sha256_file(artifact)
        ):
            return ReleaseGateItem(
                "boot-proof",
                "blocked",
                f"Boot run artifact changed, disappeared or is duplicated: {artifact}.",
            )
        recorded[artifact_key] = str(item.get("sha256"))
    unrecorded = [
        item
        for item in immutable_dir.rglob("*")
        if item.is_file()
        and item not in {run_manifest_path, run_manifest_sum}
        and str(item) not in recorded
    ]
    if unrecorded:
        return ReleaseGateItem(
            "boot-proof",
            "blocked",
            "Boot run contains unmanifested files: " + ", ".join(item.name for item in unrecorded),
        )
    for required in (immutable_proof, iso):
        if recorded.get(str(required)) != sha256_file(required):
            return ReleaseGateItem(
                "boot-proof",
                "blocked",
                f"Boot run manifest does not bind {required.name}.",
            )
    if proof_level != "runtime" or backend != "qemu":
        return ReleaseGateItem(
            "boot-proof",
            "blocked",
            f"{proof_level} proof via {backend} does not satisfy the runtime release gate.",
        )
    qemu_path_value = data.get("qemu_report")
    if (
        not isinstance(qemu_path_value, str)
        or not qemu_path_value
        or Path(qemu_path_value).name != qemu_path_value
    ):
        return ReleaseGateItem("boot-proof", "blocked", "Boot proof does not name its QEMU report.")
    qemu_path = immutable_dir / qemu_path_value
    if not qemu_path.is_file():
        return ReleaseGateItem("boot-proof", "blocked", f"QEMU report is missing: {qemu_path}")
    if data.get("qemu_report_sha256") != sha256_file(qemu_path):
        return ReleaseGateItem(
            "boot-proof", "blocked", "Boot proof does not match its QEMU report SHA256."
        )
    validation = validate_qemu_report(qemu_path, iso)
    if not validation.ok:
        return ReleaseGateItem("boot-proof", "blocked", validation.detail)
    if validation.payload and validation.payload.get("run_id") != run_id:
        return ReleaseGateItem(
            "boot-proof", "blocked", "Boot proof and QEMU report use different run IDs."
        )
    command_log = immutable_dir / "commands.jsonl"
    if (
        data.get("command_log") != command_log.name
        or not command_log.is_file()
        or recorded.get(str(command_log)) != sha256_file(command_log)
    ):
        return ReleaseGateItem(
            "boot-proof",
            "blocked",
            "Boot proof has no sealed command log for the QEMU invocation.",
        )
    return ReleaseGateItem("boot-proof", "ready", validation.detail)


def _check_release_readiness(
    report: ReleaseGateReport, iso: Path, output_dir: Path, verify_checksums: bool = True
) -> None:
    readiness = ReleaseReadinessService().check(iso, output_dir, verify_checksum=verify_checksums)
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


def _check_publish_signing(report: ReleaseGateReport, root: Path, options: BuildOptions) -> None:
    if not options.release_artifacts.sign:
        return
    bundle = root / "dist" / "publish"
    required = (
        "RELEASE-MANIFEST.json",
        "SIGNING-REPORT.json",
        "SHA256SUMS.asc",
        "RELEASE-GATE.json.asc",
        "RELEASE-MANIFEST.json.asc",
    )
    missing = [name for name in required if not (bundle / name).exists()]
    if missing:
        report.items.append(
            ReleaseGateItem(
                "publish-signing",
                "review",
                f"Missing publish signing evidence: {', '.join(missing)}",
            )
        )
    else:
        report.items.append(ReleaseGateItem("publish-signing", "ready", str(bundle)))


def _boot_proof_summary(path: Path) -> dict[str, str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"status": "invalid", "selected_backend": "unknown", "proof_level": "none"}
    if not isinstance(data, dict):
        return {"status": "invalid", "selected_backend": "unknown", "proof_level": "none"}
    return {
        "status": str(data.get("status", "unknown")),
        "selected_backend": str(data.get("selected_backend", data.get("backend", "unknown"))),
        "proof_level": str(data.get("proof_level", "none")),
    }
