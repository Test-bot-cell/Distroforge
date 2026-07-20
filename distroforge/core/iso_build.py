from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from .boot_proof import BootProofReport, run_boot_proof
from .build import BuildOptions, BuildOrchestrator
from .command import CommandRunner
from .iso_doctor import IsoDoctorReport, diagnose_iso_build
from .project import Project


@dataclass(frozen=True)
class IsoBuildReport:
    project: Path
    output_iso: Path
    status: str
    execute: bool
    report: Path
    doctor: IsoDoctorReport
    build_steps: tuple[str, ...]
    output_exists: bool = False
    output_size: int = 0
    output_sha256: str = ""
    boot_proof: BootProofReport | None = None

    @property
    def blocked(self) -> bool:
        return self.status == "blocked"

    def to_dict(self) -> dict[str, object]:
        return {
            "project": str(self.project),
            "output_iso": str(self.output_iso),
            "status": self.status,
            "blocked": self.blocked,
            "execute": self.execute,
            "report": str(self.report),
            "doctor": self.doctor.to_dict(),
            "build_steps": list(self.build_steps),
            "output_exists": self.output_exists,
            "output_size": self.output_size,
            "output_sha256": self.output_sha256,
            "boot_proof": self.boot_proof.to_dict() if self.boot_proof else None,
        }

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def render_text(self) -> str:
        lines = [
            "ISO build",
            f"Project: {self.project}",
            f"Output ISO: {self.output_iso}",
            f"Status: {self.status.upper()}",
            f"Mode: {'execute' if self.execute else 'dry-run'}",
            f"Output exists: {self.output_exists}",
            f"Output size: {self.output_size}",
            f"Output SHA256: {self.output_sha256 or 'missing'}",
            f"Report: {self.report}",
            "",
            "Doctor:",
            f"- {self.doctor.status}: {self.doctor.next_command}",
            "",
            "Build steps:",
            *([f"- {step}" for step in self.build_steps] or ["- not run"]),
        ]
        if self.boot_proof:
            lines.extend(["", "Boot proof:", f"- {self.boot_proof.status} via {self.boot_proof.selected_backend or self.boot_proof.backend}"])
        return "\n".join(lines)


def run_iso_build(
    project: Project,
    options: BuildOptions | None = None,
    *,
    execute: bool = False,
    boot_proof_backend: str = "none",
    definition: Path | None = None,
    log_path: Path | None = None,
) -> IsoBuildReport:
    options = options or BuildOptions()
    options.output_iso = options.output_iso or project.output_dir / f"{project.name}.iso"
    doctor = diagnose_iso_build(project, options, definition=definition)
    boot_report = None
    steps: tuple[str, ...] = ()
    status = "blocked" if doctor.blocked else "planned"
    if not doctor.blocked:
        runner = CommandRunner(dry_run=not execute, log_path=log_path)
        build = BuildOrchestrator(project, runner, options).run()
        steps = tuple(step.phase.value for step in build.steps)
        exists, size, sha256 = _output_contract(options.output_iso)
        status = "built" if execute and exists and size > 0 else "blocked" if execute else "planned"
        if boot_proof_backend != "none" and (execute or options.output_iso.exists()):
            boot_report = run_boot_proof(
                project,
                options,
                iso=options.output_iso,
                backend=boot_proof_backend,
                execute=execute,
            )
            if boot_report.blocked:
                status = "blocked"
    else:
        exists, size, sha256 = _output_contract(options.output_iso)
    report = IsoBuildReport(
        project.root,
        options.output_iso,
        status,
        execute,
        project.output_dir / "ISO-BUILD.json",
        doctor,
        steps,
        exists,
        size,
        sha256,
        boot_report,
    )
    project.output_dir.mkdir(parents=True, exist_ok=True)
    report.report.write_text(report.render_json() + "\n", encoding="utf-8")
    return report


def _output_contract(path: Path) -> tuple[bool, int, str]:
    if not path.exists() or not path.is_file():
        return False, 0, ""
    size = path.stat().st_size
    return True, size, _sha256(path) if size > 0 else ""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
