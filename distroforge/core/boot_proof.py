from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .build import BuildOptions
from .command import CommandError, CommandRunner
from .prebuild_vm import QemuLabService
from .project import Project


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

    @property
    def blocked(self) -> bool:
        return self.status == "blocked"

    def to_dict(self) -> dict[str, object]:
        return {
            "project": str(self.project),
            "iso": str(self.iso),
            "backend": self.backend,
            "status": self.status,
            "blocked": self.blocked,
            "proof": str(self.proof),
            "qemu_report": str(self.qemu_report),
            "notes": list(self.notes),
            "evidence": self.evidence or {},
            "attempted_backends": list(self.attempted_backends or (self.backend,)),
            "selected_backend": self.selected_backend or self.backend,
            "proof_level": self.proof_level,
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


def run_boot_proof(
    project: Project,
    options: BuildOptions | None = None,
    *,
    iso: Path | None = None,
    backend: str = "auto",
    timeout: int | None = None,
    execute: bool = False,
) -> BootProofReport:
    options = options or BuildOptions()
    iso = iso or options.output_iso or project.output_dir / f"{project.name}.iso"
    proof = project.output_dir / "boot-proof.json"
    qemu_report = project.output_dir / options.prebuild_vm.report_name
    attempted = (backend,)
    selected = backend
    proof_level = "none"
    if backend == "auto":
        status, notes, evidence, attempted, selected, proof_level = _run_auto_proof(
            project, options, iso=iso, qemu_report=qemu_report, timeout=timeout, execute=execute
        )
    elif backend == "iso-scan":
        status, notes, evidence = _run_iso_scan(iso, execute=execute)
        proof_level = "structural" if status == "ready" else "none"
    elif backend == "qemu":
        status, notes, evidence = _run_qemu_proof(project, options, iso=iso, qemu_report=qemu_report, timeout=timeout, execute=execute)
        proof_level = "runtime" if status == "ready" else "none"
    else:
        status = "blocked"
        notes = [f"Unsupported boot proof backend: {backend}."]
        evidence = None
        selected = "none"
    report = BootProofReport(project.root, iso, backend, status, proof, qemu_report, tuple(notes), evidence, attempted, selected, proof_level)
    proof.write_text(report.render_json() + "\n", encoding="utf-8")
    return report


def _run_auto_proof(
    project: Project,
    options: BuildOptions,
    *,
    iso: Path,
    qemu_report: Path,
    timeout: int | None,
    execute: bool,
) -> tuple[str, list[str], dict[str, object], tuple[str, ...], str, str]:
    attempted = ["qemu"]
    qemu_status, qemu_notes, qemu_evidence = _run_qemu_proof(project, options, iso=iso, qemu_report=qemu_report, timeout=timeout, execute=execute)
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
) -> tuple[str, list[str], dict[str, object]]:
    notes: list[str] = []
    evidence: dict[str, object] = {"proof_level": "runtime", "qemu_report": str(qemu_report)}
    status = "blocked"
    if not iso.exists():
        notes.append("ISO is missing; build or select an ISO before boot proof.")
    elif execute and not CommandRunner.has_binary("qemu-system-x86_64"):
        notes.append("qemu-system-x86_64 is missing; install qemu-system-x86 before boot proof.")
    else:
        options.prebuild_vm.enabled = True
        options.prebuild_vm.timeout_seconds = timeout or options.prebuild_vm.timeout_seconds
        runner = CommandRunner(dry_run=not execute)
        try:
            QemuLabService(runner, iso, project.workdir, project.output_dir, options.prebuild_vm).run()
            if execute:
                status = "ready" if qemu_report.exists() else "blocked"
                notes.append("Executed QEMU boot proof." if qemu_report.exists() else "QEMU did not write the expected qemu-lab-report.json.")
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
    evidence.update({"size": iso.stat().st_size, "sha256": _sha256(iso)})
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


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
