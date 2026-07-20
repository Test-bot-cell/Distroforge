from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .artifact_paths import default_artifact_paths
from .build import BuildOptions
from .build_journey import apply_journey_step, check_journey_step
from .definition import definition_from_project, write_definition
from .dry_run_report import generate_dry_run_report
from .project import Project
from .release_gate import ReleaseGateService


@dataclass(frozen=True)
class PowerUserIsoPathReport:
    project: Path
    definition: Path
    dry_run: Path | None
    gate_status: str
    modules: tuple[str, ...]
    notes: tuple[str, ...]
    next_command: str

    def to_dict(self) -> dict[str, object]:
        return {
            "project": str(self.project),
            "definition": str(self.definition),
            "dry_run": str(self.dry_run) if self.dry_run else None,
            "gate_status": self.gate_status,
            "modules": list(self.modules),
            "notes": list(self.notes),
            "next_command": self.next_command,
        }

    def render_text(self) -> str:
        lines = [
            "Power user ISO path",
            f"Project: {self.project}",
            f"Definition: {self.definition}",
            f"Dry-run: {self.dry_run or 'not written'}",
            f"Release gate: {self.gate_status.upper()}",
            "",
            "Modules:",
            *[f"- {module}" for module in self.modules],
            "",
            "Notes:",
            *[f"- {note}" for note in self.notes],
            "",
            "Next:",
            self.next_command,
        ]
        return "\n".join(lines)

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def prepare_poweruser_iso_path(
    project: Project,
    *,
    apply_safe_defaults: bool = False,
    dry_run: bool = False,
    definition_path: Path | None = None,
    dry_run_path: Path | None = None,
) -> PowerUserIsoPathReport:
    options = BuildOptions()
    notes: list[str] = []
    if apply_safe_defaults:
        for step_id in ("source", "identity", "deployment", "rollback", "boot-proof", "release-evidence", "publish-gate"):
            report = apply_journey_step(project, options, step_id)
            notes.extend(report.notes)
        options.mirrors.enabled = True
        options.mirrors.deb822 = True
        options.autoinstall.enabled = True
        options.autoinstall.hostname = project.customization.hostname or project.name.lower()
        options.systemd.enable = ["NetworkManager.service"]
        options.drivers.auto = True
        options.snapshots.enabled = True
        options.snapshots.auto_restore_on_failure = True
        notes.append("Enabled deb822 mirrors, autoinstall baseline, explicit service intent and auto drivers.")
        notes.append("Forced rollback snapshots with auto-restore for advanced mutation safety.")
    else:
        notes.append("Safe defaults were not applied; existing project settings were used.")
    paths = default_artifact_paths(project)
    options.output_iso = options.output_iso or paths.output_iso
    definition_path = definition_path or project.root / "poweruser-iso.yaml"
    write_definition(definition_from_project(project, options, {"path": "poweruser-iso"}), definition_path)
    notes.append("Wrote a reviewable power user ISO build definition.")
    if dry_run:
        dry_run_path = dry_run_path or project.root / "poweruser-iso-dry-run.json"
        dry_run_report = generate_dry_run_report(project, options, run_orchestrator=False)
        dry_run_path.write_text(dry_run_report.render_json() + "\n", encoding="utf-8")
        notes.append("Wrote a non-executing dry-run report for the advanced ISO path.")
    for step_id in ("deployment", "rollback", "boot-proof", "release-evidence", "publish-gate"):
        check = check_journey_step(project, options, step_id)
        if check.findings:
            notes.append(f"{step_id}: {check.status} - {check.findings[0]}")
    gate = ReleaseGateService().check(project, options)
    modules = _enabled_modules(options)
    return PowerUserIsoPathReport(
        project.root,
        definition_path,
        dry_run_path if dry_run else None,
        gate.status,
        modules,
        tuple(notes),
        f"distroforge build {project.root} --definition {definition_path}",
    )


def _enabled_modules(options: BuildOptions) -> tuple[str, ...]:
    modules = ["source", "identity", "boot-proof", "release-evidence"]
    if options.mirrors.enabled:
        modules.append("deb822-mirrors")
    if options.autoinstall.enabled:
        modules.append("autoinstall")
    if options.drivers.auto:
        modules.append("auto-drivers")
    if options.systemd.enable or options.systemd.disable or options.systemd.mask:
        modules.append("systemd-services")
    if options.snapshots.enabled:
        modules.append("rollback-snapshots")
    return tuple(modules)
