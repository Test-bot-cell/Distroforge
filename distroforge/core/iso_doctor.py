from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .build import BuildOptions
from .command import CommandRunner
from .doctor import apt_install_command
from .project import Project


@dataclass(frozen=True)
class IsoDoctorFinding:
    level: str
    code: str
    message: str
    fix: str

    def to_dict(self) -> dict[str, str]:
        return self.__dict__


@dataclass(frozen=True)
class IsoDoctorReport:
    project: Path
    output_iso: Path
    status: str
    findings: tuple[IsoDoctorFinding, ...]
    next_command: str

    @property
    def blocked(self) -> bool:
        return self.status == "blocked"

    def to_dict(self) -> dict[str, object]:
        return {
            "project": str(self.project),
            "output_iso": str(self.output_iso),
            "status": self.status,
            "blocked": self.blocked,
            "findings": [finding.to_dict() for finding in self.findings],
            "next_command": self.next_command,
        }

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def render_text(self) -> str:
        lines = [
            "ISO doctor",
            f"Project: {self.project}",
            f"Output ISO: {self.output_iso}",
            f"Status: {self.status.upper()}",
            "",
            "Findings:",
            *([f"- [{item.level}] {item.code}: {item.message}" for item in self.findings] or ["- none"]),
            "",
            "Next command:",
            self.next_command or "none",
        ]
        return "\n".join(lines)


def diagnose_iso_build(project: Project, options: BuildOptions | None = None, *, definition: Path | None = None) -> IsoDoctorReport:
    options = options or BuildOptions()
    output_iso = options.output_iso or project.output_dir / f"{project.name}.iso"
    findings: list[IsoDoctorFinding] = []
    if output_iso.exists():
        findings.append(IsoDoctorFinding("info", "iso-exists", f"Output ISO already exists at {output_iso}.", "Run boot proof or publish drill."))
    elif options.output_iso is None:
        findings.append(IsoDoctorFinding("warning", "output-iso-default", f"No explicit output ISO configured; defaulting to {output_iso}.", "Pass --output-iso or set the GUI Output ISO field."))
    if definition and not definition.exists():
        findings.append(IsoDoctorFinding("error", "definition-missing", f"Definition file is missing: {definition}.", "Create the definition file or omit --definition."))
    _check_source(project, findings)
    _check_tools(project, findings)
    if not output_iso.exists() and not any(item.code == "not-built-yet" for item in findings):
        findings.append(IsoDoctorFinding("warning", "not-built-yet", "No output ISO has been produced yet.", "Run an executing build, not only a dry-run."))
    status = "blocked" if any(item.level == "error" for item in findings) else "ready" if output_iso.exists() else "review"
    return IsoDoctorReport(project.root, output_iso, status, tuple(findings), _next_command(project, output_iso, findings, definition))


def _check_source(project: Project, findings: list[IsoDoctorFinding]) -> None:
    if project.source_mode == "iso":
        if not project.source_iso:
            findings.append(IsoDoctorFinding("error", "source-iso-missing", "Project is in ISO source mode but no source ISO is selected.", "Select a source ISO."))
        elif not project.source_iso.exists():
            findings.append(IsoDoctorFinding("error", "source-iso-not-found", f"Source ISO does not exist: {project.source_iso}.", "Choose an existing ISO path."))
    elif project.source_mode == "bootstrap" and not project.source_starter:
        findings.append(IsoDoctorFinding("info", "bootstrap-source", "Project will bootstrap a root filesystem from packages.", "Ensure mmdebstrap or debootstrap is installed."))
    elif not project.source_starter:
        findings.append(IsoDoctorFinding("warning", "source-unknown", f"Source mode is {project.source_mode}.", "Use a source starter, source ISO, or bootstrap mode."))


def _check_tools(project: Project, findings: list[IsoDoctorFinding]) -> None:
    required = ["xorriso", "mksquashfs", "chroot", "apt-get"]
    if project.source_mode == "iso":
        required.append("unsquashfs")
    if project.source_mode == "bootstrap" and not (CommandRunner.has_binary("mmdebstrap") or CommandRunner.has_binary("debootstrap")):
        findings.append(IsoDoctorFinding("error", "host-bootstrap-tool", "Neither mmdebstrap nor debootstrap is available.", "Install mmdebstrap or debootstrap."))
    missing = [binary for binary in required if not CommandRunner.has_binary(binary)]
    if missing:
        packages = {"xorriso": "xorriso", "mksquashfs": "squashfs-tools", "unsquashfs": "squashfs-tools", "chroot": "coreutils", "apt-get": "apt"}
        findings.append(IsoDoctorFinding("error", "host-tools-missing", f"Missing host tools: {', '.join(missing)}.", apt_install_command(sorted({packages[item] for item in missing}))))


def _next_command(project: Project, output_iso: Path, findings: list[IsoDoctorFinding], definition: Path | None) -> str:
    root = str(project.root)
    if any(item.code == "source-iso-missing" for item in findings):
        return f"distroforge build {root} --source-iso /path/to/source.iso --output-iso {output_iso} --execute"
    if any(item.code == "source-iso-not-found" for item in findings):
        return f"distroforge build {root} --source-iso /path/to/existing.iso --output-iso {output_iso} --execute"
    host = next((item for item in findings if item.code in {"host-tools-missing", "host-bootstrap-tool"}), None)
    if host:
        return "distroforge iso-toolchain --install"
    if output_iso.exists():
        return f"distroforge boot-proof {root} --iso {output_iso} --backend auto"
    definition_args = f" --definition {definition}" if definition else ""
    return f"distroforge build {root}{definition_args} --output-iso {output_iso} --execute"
