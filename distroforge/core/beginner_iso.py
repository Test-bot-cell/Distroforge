from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from html import escape
from pathlib import Path

from .artifact_paths import default_artifact_paths
from .build import BuildOptions, BuildOrchestrator, ProgressCallback
from .build_diagnosis import classify_log
from .build_journey import apply_journey_step, check_journey_step
from .build_memory import BuildAttempt, BuildMemory, options_signature
from .command import CommandRunner
from .definition import definition_from_project, write_definition
from .dry_run_report import generate_dry_run_report
from .prebuild_vm import QemuLabService
from .project import Project
from .release_gate import ReleaseGateService


@dataclass(frozen=True)
class BeginnerIsoPathReport:
    project: Path
    definition: Path
    dry_run: Path | None
    command_log: Path | None
    executed: bool
    build_status: str
    gate_status: str
    notes: tuple[str, ...]
    next_command: str

    def to_dict(self) -> dict[str, object]:
        return {
            "project": str(self.project),
            "definition": str(self.definition),
            "dry_run": str(self.dry_run) if self.dry_run else None,
            "command_log": str(self.command_log) if self.command_log else None,
            "executed": self.executed,
            "build_status": self.build_status,
            "gate_status": self.gate_status,
            "notes": list(self.notes),
            "next_command": self.next_command,
        }

    def render_text(self) -> str:
        lines = [
            "Beginner ISO path",
            f"Project: {self.project}",
            f"Definition: {self.definition}",
            f"Dry-run: {self.dry_run or 'not written'}",
            f"Command log: {self.command_log or 'not written'}",
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
    repaired: tuple[str, ...]
    skipped: tuple[str, ...]
    gate_status: str
    next_action: str

    def to_dict(self) -> dict[str, object]:
        return {
            "project": str(self.project),
            "iso": str(self.iso),
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

    def to_dict(self) -> dict[str, object]:
        return {
            "project": str(self.project),
            "iso": str(self.iso),
            "status": self.status,
            "proof": str(self.proof),
            "gate_status": self.gate_status,
            "notes": list(self.notes),
        }

    def render_text(self) -> str:
        return "\n".join(
            [
                "Beginner ISO boot proof",
                f"Project: {self.project}",
                f"ISO: {self.iso}",
                f"Status: {self.status}",
                f"Proof: {self.proof}",
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
    command_log_path = command_log_path or project.root / "beginner-iso-build-commands.jsonl"
    build_status = "not-run"
    if execute:
        try:
            BuildOrchestrator(
                project,
                CommandRunner(dry_run=False, log_path=command_log_path),
                options,
                progress=progress,
            ).run()
            build_status = "completed"
            notes.append("Executed the beginner ISO build workflow.")
        except Exception as exc:  # keep the beginner workflow inspectable after failures
            build_status = "failed"
            notes.append(f"Build failed: {exc}")
        if memory is not None:
            category = title = ""
            if build_status == "failed" and command_log_path.exists():
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
    gate = ReleaseGateService().check(project, options)
    next_command = (
        f"distroforge release-gate {project.root} --definition {definition_path}"
        if execute
        else f"distroforge beginner-iso {project.root} --apply-safe-defaults --dry-run --execute"
    )
    return BeginnerIsoPathReport(
        project.root,
        definition_path,
        dry_run_path if dry_run or execute else None,
        command_log_path if execute else None,
        execute,
        build_status,
        gate.status,
        tuple(notes),
        next_command,
    )


def explain_beginner_iso_failure(project: Project, command_log_path: Path | None = None) -> BeginnerIsoFailureReport:
    command_log = command_log_path or project.root / "beginner-iso-build-commands.jsonl"
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


def repair_beginner_iso_release_artifacts(project: Project, options: BuildOptions | None = None) -> BeginnerIsoRepairReport:
    options = options or BuildOptions()
    paths = default_artifact_paths(project)
    iso = options.output_iso or paths.output_iso
    repaired: list[str] = []
    skipped: list[str] = []
    if not iso.exists():
        skipped.append("ISO is missing; release artifacts cannot be derived.")
    else:
        output_dir = iso.parent
        output_dir.mkdir(parents=True, exist_ok=True)
        digest = _sha256(iso)
        (output_dir / "SHA256SUMS").write_text(f"{digest}  {iso.name}\n", encoding="utf-8")
        repaired.append("SHA256SUMS")
        (output_dir / "BUILDINFO").write_text(
            f"Build-Date: {datetime.now(UTC).isoformat()}\n"
            f"Artifact: {iso.name}\n"
            "Builder: DistroForge\n"
            "Repair: beginner-iso\n",
            encoding="utf-8",
        )
        repaired.append("BUILDINFO")
        (output_dir / "distroforge-provenance.json").write_text(
            json.dumps(
                {
                    "generated_at": datetime.now(UTC).isoformat(),
                    "project": project.to_dict(),
                    "output_iso": str(iso),
                    "repair": "beginner-iso-release-artifacts",
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        repaired.append("distroforge-provenance.json")
        html_name = options.html_report.filename if options.html_report.enabled else "report.html"
        (output_dir / html_name).write_text(_minimal_html_report(project, iso, digest), encoding="utf-8")
        repaired.append(html_name)
        skipped.append("Boot proof was not repaired; run QEMU/bootcheck/QA to prove bootability.")
    gate = ReleaseGateService().check(project, options, iso=iso, output_dir=iso.parent)
    next_action = (
        "Run boot proof and release-gate again." if gate.status != "ready" else "Release gate is ready."
    )
    return BeginnerIsoRepairReport(project.root, iso, tuple(repaired), tuple(skipped), gate.status, next_action)


def run_beginner_iso_boot_proof(
    project: Project,
    options: BuildOptions | None = None,
    *,
    execute: bool = True,
) -> BeginnerIsoBootProofReport:
    options = options or BuildOptions()
    paths = default_artifact_paths(project)
    iso = options.output_iso or paths.output_iso
    proof = project.output_dir / options.prebuild_vm.report_name
    notes: list[str] = []
    status = "blocked"
    options.prebuild_vm.enabled = True
    if not iso.exists():
        notes.append("ISO is missing; build or select an ISO before boot proof.")
    elif execute and not CommandRunner.has_binary("qemu-system-x86_64"):
        notes.append("qemu-system-x86_64 is missing; install qemu-system-x86 before boot proof.")
    else:
        runner = CommandRunner(dry_run=not execute)
        QemuLabService(runner, iso, project.workdir, project.output_dir, options.prebuild_vm).run()
        if execute:
            status = "ready" if proof.exists() else "blocked"
            notes.append("Executed QEMU boot proof." if proof.exists() else "QEMU finished without writing the expected proof report.")
        else:
            status = "planned"
            notes.append("Planned QEMU boot proof without executing it.")
    gate = ReleaseGateService().check(project, options, iso=iso, output_dir=iso.parent)
    return BeginnerIsoBootProofReport(project.root, iso, status, proof, gate.status, tuple(notes))


def _classify_failure(text: str) -> tuple[str, str, str]:
    rule = classify_log(text)
    return rule.code, rule.title, rule.remediation


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
