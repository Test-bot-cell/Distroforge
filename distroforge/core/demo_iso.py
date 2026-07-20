from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .build import BuildOptions
from .iso_acceptance import IsoAcceptanceReport, accept_iso
from .iso_build import IsoBuildReport, run_iso_build
from .iso_doctor import IsoDoctorReport, diagnose_iso_build
from .project import Project
from .source_starter import apply_source_starter, default_starter_for_release


@dataclass(frozen=True)
class DemoIsoReport:
    project: Path
    created: bool
    output_iso: Path
    status: str
    next_command: str
    doctor: IsoDoctorReport
    build: IsoBuildReport | None = None
    acceptance: IsoAcceptanceReport | None = None

    @property
    def blocked(self) -> bool:
        return self.status == "blocked"

    def to_dict(self) -> dict[str, object]:
        return {
            "project": str(self.project),
            "created": self.created,
            "output_iso": str(self.output_iso),
            "status": self.status,
            "blocked": self.blocked,
            "next_command": self.next_command,
            "doctor": self.doctor.to_dict(),
            "build": self.build.to_dict() if self.build else None,
            "acceptance": self.acceptance.to_dict() if self.acceptance else None,
        }

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def render_text(self) -> str:
        lines = [
            "Demo ISO",
            f"Project: {self.project}",
            f"Created: {self.created}",
            f"Output ISO: {self.output_iso}",
            f"Status: {self.status.upper()}",
            "",
            "Doctor:",
            f"- {self.doctor.status}: {self.doctor.next_command}",
        ]
        if self.build:
            lines.extend(["", "Build:", f"- {self.build.status}: {self.build.report}"])
        if self.acceptance:
            lines.extend(["", "Acceptance:", f"- {self.acceptance.status}: {self.acceptance.next_command}"])
        lines.extend(["", "Next command:", self.next_command or "none"])
        return "\n".join(lines)


def run_demo_iso(root: Path, *, name: str | None = None, release: str = "26.04", execute: bool = False, boot_proof_backend: str = "auto") -> DemoIsoReport:
    project, created = _load_or_create(root, name, release)
    options = BuildOptions(output_iso=project.output_dir / f"{project.name}.iso")
    doctor = diagnose_iso_build(project, options)
    build = None
    acceptance = None
    if not doctor.blocked:
        build = run_iso_build(project, options, execute=execute, boot_proof_backend=boot_proof_backend if execute else "none")
        if execute and build.status == "built":
            acceptance = accept_iso(project, options, iso=options.output_iso)
    status = _status(execute, doctor, build, acceptance)
    report = DemoIsoReport(project.root, created, options.output_iso, status, _next_command(project, execute, doctor, build, acceptance), doctor, build, acceptance)
    project.output_dir.mkdir(parents=True, exist_ok=True)
    (project.output_dir / "DEMO-ISO.json").write_text(report.render_json() + "\n", encoding="utf-8")
    return report


def _load_or_create(root: Path, name: str | None, release: str) -> tuple[Project, bool]:
    if (root / "project.json").exists():
        return Project.load(root), False
    project = Project.create(name or root.name or "DemoISO", root, release)
    apply_source_starter(project, default_starter_for_release(release))
    return project, True


def _status(execute: bool, doctor: IsoDoctorReport, build: IsoBuildReport | None, acceptance: IsoAcceptanceReport | None) -> str:
    if doctor.blocked or (build and build.blocked) or (acceptance and acceptance.blocked):
        return "blocked"
    if acceptance and acceptance.status == "accepted":
        return "accepted"
    if build and build.status == "built":
        return "built"
    return "planned" if not execute else "blocked"


def _next_command(project: Project, execute: bool, doctor: IsoDoctorReport, build: IsoBuildReport | None, acceptance: IsoAcceptanceReport | None) -> str:
    root = str(project.root)
    if doctor.blocked:
        return doctor.next_command
    if not execute:
        return f"distroforge demo-iso {root} --execute"
    if build and build.blocked:
        return f"distroforge iso-build {root} --execute --boot-proof auto"
    if acceptance and acceptance.blocked:
        return acceptance.next_command
    return f"distroforge publish-bundle {root} --iso {project.output_dir / f'{project.name}.iso'}"
