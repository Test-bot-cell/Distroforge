from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

from .artifact_paths import default_output_iso
from .build import BuildOptions
from .command import CommandError, CommandRunner
from .evidence_run import (
    artifact_identity,
    evidence_run_path,
    new_run_id,
    reserve_evidence_run,
    write_immutable_text,
    write_text_alias,
)
from .hashing import sha256_file
from .prebuild_vm import QemuLabService, validate_qemu_report
from .project import Project
from .validate import validate_prebuild_vm_options

# The backends that start a machine. Only these can honour a firmware choice, and
# only these have a firmware worth validating before anything runs.
_QEMU_BACKENDS = frozenset({"auto", "qemu"})
BOOT_PROOF_SCHEMA = "distroforge.boot-proof.v2"
BOOT_RUN_MANIFEST_SCHEMA = "distroforge.boot-proof-run-manifest.v1"


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
    qemu_report_sha256: str = ""
    reached_milestone: str = ""
    build_run_id: str = ""
    command_log: Path | None = None
    run_manifest: Path | None = None

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
            "qemu_report_sha256": self.qemu_report_sha256,
            "reached_milestone": self.reached_milestone,
            "build_run_id": self.build_run_id,
            "command_log": self.command_log.name if self.command_log else None,
            "run_manifest": self.run_manifest.name if self.run_manifest else None,
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
            f"QEMU report: {self.qemu_report}",
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
) -> BootProofReport:
    options = options or BuildOptions()
    iso = iso or options.output_iso or default_output_iso(project)
    run_id = new_run_id()
    created_at = datetime.now(UTC).isoformat()
    proof = project.output_dir / ("boot-proof.json" if execute else "boot-proof.plan.json")
    immutable_proof = evidence_run_path(
        project.output_dir,
        run_id,
        "boot-proof.json",
        executed=execute,
    )
    reserve_evidence_run(project.output_dir, run_id, executed=execute)
    qemu_report = project.output_dir / options.prebuild_vm.report_name
    attempted = (backend,)
    selected = backend
    proof_level = "none"
    prelude: list[str] = []
    run_firmware = ""
    run_secure_boot = False
    blockers: list[str] = []
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
        blockers = [
            f"{issue.code}: {issue.message}"
            for issue in validate_prebuild_vm_options(replace(options.prebuild_vm, enabled=True))
            if issue.level == "error"
        ]
    elif firmware or secure_boot:
        # Ignoring it silently would hand a green structural scan to someone who asked
        # to watch a machine boot under a named firmware.
        prelude.append(f"Firmware selection does not apply to the {backend} backend; nothing was booted.")
    if blockers:
        status = "blocked"
        notes = blockers
        evidence = {"status": "blocked", "firmware": run_firmware, "secure_boot": run_secure_boot}
        selected = "none"
    elif backend == "auto":
        status, notes, evidence, attempted, selected, proof_level = _run_auto_proof(
            project,
            options,
            iso=iso,
            qemu_report=qemu_report,
            timeout=timeout,
            execute=execute,
            run_id=run_id,
        )
    elif backend == "iso-scan":
        status, notes, evidence = _run_iso_scan(iso, execute=execute)
        proof_level = "structural" if status == "ready" else "none"
    elif backend == "qemu":
        status, notes, evidence = _run_qemu_proof(
            project,
            options,
            iso=iso,
            qemu_report=qemu_report,
            timeout=timeout,
            execute=execute,
            run_id=run_id,
        )
        proof_level = "runtime" if status == "ready" else "none"
    else:
        status = "blocked"
        notes = [f"Unsupported boot proof backend: {backend}."]
        evidence = None
        selected = "none"
    qemu_report_sha256 = (
        sha256_file(qemu_report)
        if qemu_report.is_file() and execute and selected == "qemu"
        else ""
    )
    reached_milestone = ""
    if isinstance(evidence, dict):
        reached_milestone = str(evidence.get("reached_milestone", ""))
        if not reached_milestone and isinstance(evidence.get("qemu"), dict):
            reached_milestone = str(evidence["qemu"].get("reached_milestone", ""))
    build_context = options._evidence_context or {}
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
        iso_sha256=sha256_file(iso) if iso.is_file() else "",
        immutable_proof=immutable_proof,
        qemu_report_sha256=qemu_report_sha256,
        reached_milestone=reached_milestone,
        build_run_id=str(build_context.get("run_id", "")),
        command_log=command_log if command_log.is_file() else None,
        run_manifest=run_manifest,
    )
    content = report.render_json() + "\n"
    write_immutable_text(immutable_proof, content)
    manifest_files = [
        artifact_identity(path, role="boot-run-evidence")
        for path in sorted(immutable_proof.parent.rglob("*"))
        if path.is_file() and path not in {run_manifest, run_manifest.with_suffix(".json.sha256")}
    ]
    if iso.is_file():
        manifest_files.append(artifact_identity(iso, role="proven-iso"))
    manifest_payload = {
        "schema": BOOT_RUN_MANIFEST_SCHEMA,
        "run_id": run_id,
        "mode": "execute" if execute else "plan",
        "status": status,
        "created_at": created_at,
        "files": manifest_files,
    }
    write_immutable_text(
        run_manifest,
        json.dumps(manifest_payload, indent=2) + "\n",
    )
    write_immutable_text(
        run_manifest.with_name(f"{run_manifest.name}.sha256"),
        f"{sha256_file(run_manifest)}  {run_manifest.name}\n",
    )
    write_text_alias(proof, content)
    return report


def _run_auto_proof(
    project: Project,
    options: BuildOptions,
    *,
    iso: Path,
    qemu_report: Path,
    timeout: int | None,
    execute: bool,
    run_id: str,
) -> tuple[str, list[str], dict[str, object], tuple[str, ...], str, str]:
    attempted = ["qemu"]
    qemu_status, qemu_notes, qemu_evidence = _run_qemu_proof(
        project,
        options,
        iso=iso,
        qemu_report=qemu_report,
        timeout=timeout,
        execute=execute,
        run_id=run_id,
    )
    if qemu_status == "ready":
        evidence = {"qemu": qemu_evidence}
        return "ready", ["Auto selected QEMU runtime proof.", *qemu_notes], evidence, tuple(attempted), "qemu", "runtime"
    if not execute:
        evidence = {"qemu": qemu_evidence}
        return qemu_status, ["Auto planned QEMU runtime proof.", *qemu_notes], evidence, tuple(attempted), "qemu", "none"
    attempted.append("iso-scan")
    scan_status, scan_notes, scan_evidence = _run_iso_scan(iso, execute=True)
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
    qemu_report: Path,
    timeout: int | None,
    execute: bool,
    run_id: str,
) -> tuple[str, list[str], dict[str, object]]:
    notes: list[str] = []
    evidence: dict[str, object] = {
        "proof_level": "runtime",
        "qemu_report": str(qemu_report),
        # Read back off the options the lab is about to consume, not off the request, so
        # the evidence names the firmware that ran rather than the one that was asked for.
        "firmware": options.prebuild_vm.firmware,
        "secure_boot": options.prebuild_vm.secure_boot,
    }
    status = "blocked"
    if not iso.exists():
        notes.append("ISO is missing; build or select an ISO before boot proof.")
    elif execute and not CommandRunner.has_binary("qemu-system-x86_64"):
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
                validation = validate_qemu_report(qemu_report, iso)
                status = "ready" if validation.ok else "blocked"
                notes.append(
                    "Executed and verified QEMU boot proof."
                    if validation.ok
                    else f"QEMU report validation failed: {validation.detail}"
                )
                evidence["qemu_report_validation"] = validation.detail
                if validation.payload:
                    boot = validation.payload.get("boot")
                    if isinstance(boot, dict):
                        evidence["reached_milestone"] = str(boot.get("reached_milestone", ""))
            else:
                status = "planned"
                notes.append("Planned QEMU boot proof without executing it.")
        except (CommandError, OSError, TimeoutError, ValueError) as exc:
            status = "blocked"
            notes.append(f"QEMU boot proof failed: {exc}")
    evidence["status"] = status
    return status, notes, evidence


def _run_iso_scan(iso: Path, *, execute: bool) -> tuple[str, list[str], dict[str, object]]:
    notes: list[str] = []
    evidence: dict[str, object] = {"scan_time": datetime.now(UTC).isoformat()}
    if not iso.exists():
        return "blocked", ["ISO is missing; build or select an ISO before boot proof."], evidence
    evidence.update({"size": iso.stat().st_size, "sha256": sha256_file(iso)})
    if not execute:
        notes.append("Planned ISO structure scan without reading boot metadata.")
        return "planned", notes, evidence
    descriptor = _scan_iso9660_descriptors(iso)
    external = _scan_with_external_tool(iso)
    evidence.update(descriptor)
    if external:
        evidence["external_tool"] = external
    else:
        notes.append("xorriso/isoinfo is unavailable or did not return metadata; used fallback ISO descriptor scan.")
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
        notes.append("Found El Torito boot record, but kernel/initrd or live payload markers need review.")
        return "review", notes, evidence
    notes.append("El Torito boot record was not confirmed by the structural scan.")
    return "review", notes, evidence


def _scan_iso9660_descriptors(iso: Path) -> dict[str, object]:
    evidence: dict[str, object] = {
        "iso9660": False,
        "volume_id": "",
        "el_torito": False,
        "boot_catalog_lba": None,
        "boot_payload": False,
    }
    with iso.open("rb") as handle:
        for sector in range(16, 80):
            handle.seek(sector * 2048)
            block = handle.read(2048)
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
        handle.seek(0)
        sample = handle.read(min(16 * 1024 * 1024, iso.stat().st_size)).upper()
    evidence["boot_payload"] = _has_boot_payload_markers(sample)
    return evidence


def _has_boot_payload_markers(sample: bytes) -> bool:
    kernel = any(marker in sample for marker in (b"VMLINUZ", b"KERNEL"))
    initrd = any(marker in sample for marker in (b"INITRD", b"INITRAMFS"))
    livefs = any(marker in sample for marker in (b"CASPER", b"LIVE/FILESYSTEM", b"FILESYSTEM.SQUASHFS"))
    bootloader = any(marker in sample for marker in (b"BOOT.CAT", b"ISOLINUX", b"GRUB"))
    return (kernel and initrd) or (livefs and bootloader)


def _scan_with_external_tool(iso: Path) -> dict[str, str] | None:
    if shutil.which("xorriso"):
        result = _run_metadata_command(("xorriso", "-indev", str(iso), "-toc"))
        if result is not None:
            return {"tool": "xorriso", "summary": result}
    if shutil.which("isoinfo"):
        result = _run_metadata_command(("isoinfo", "-d", "-i", str(iso)))
        if result is not None:
            return {"tool": "isoinfo", "summary": result}
    return None


def _run_metadata_command(argv: tuple[str, ...]) -> str | None:
    try:
        completed = subprocess.run(argv, text=True, capture_output=True, check=False, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (completed.stdout or completed.stderr).strip()
    if completed.returncode != 0 or not text:
        return None
    return " | ".join(text.splitlines()[:6])
