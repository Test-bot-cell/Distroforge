from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .command import CommandRunner, privilege_backend, sudo_askpass_program
from .diff_preview import DiffPreviewService
from .doctor import REQUIRED_TOOLS, run_doctor
from .policy import PolicyService
from .preflight import validate_build_options
from .transaction import BuildTransaction, plan_transaction
from .trust import TrustReport, TrustService
from .validate import validate_bootstrap_host, validate_for_build
from .vulnscan import VulnScanService

if TYPE_CHECKING:
    from .build import BuildOptions, BuildStep
    from .project import Project


@dataclass(frozen=True)
class DryRunFinding:
    level: str
    code: str
    message: str
    remediation: str = ""

    def to_dict(self) -> dict[str, str]:
        return self.__dict__


@dataclass
class DryRunReport:
    transaction: BuildTransaction
    steps: list[BuildStep]
    commands: list[str] = field(default_factory=list)
    command_summary: dict[str, int] = field(default_factory=dict)
    findings: list[DryRunFinding] = field(default_factory=list)
    install: list[str] = field(default_factory=list)
    remove: list[str] = field(default_factory=list)
    snaps: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    policy: list[dict[str, object]] = field(default_factory=list)
    trust: TrustReport = field(default_factory=TrustReport)
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "transaction": self.transaction.to_dict(),
            "steps": [
                {"phase": step.phase.value, "title": step.title, "detail": step.detail}
                for step in self.steps
            ],
            "commands": self.commands,
            "command_summary": self.command_summary,
            "findings": [finding.to_dict() for finding in self.findings],
            "diff": {
                "install": self.install,
                "remove": self.remove,
                "snaps": self.snaps,
                "services": self.services,
                "flags": self.flags,
            },
            "policy": self.policy,
            "trust": self.trust.to_dict(),
            "error": self.error,
        }

    def render_text(self) -> str:
        lines = [
            f"Dry-run report: {self.transaction.build_id}",
            f"Run dir: {self.transaction.run_dir}",
        ]
        lines.extend(["", "Findings:"])
        if not self.findings:
            lines.append("- no findings")
        for finding in self.findings:
            lines.append(f"- {finding.level.upper():7} {finding.code:28} {finding.message}")
            if finding.remediation:
                lines.append(f"          fix: {finding.remediation}")
        lines.extend(["", "Timeline:"])
        for index, step in enumerate(self.steps, start=1):
            lines.append(f"{index:02d}. {step.phase.value:18} {step.title} - {step.detail}")
        lines.extend(["", "Planned package diff:"])
        lines.append(f"  install: {', '.join(self.install) if self.install else '-'}")
        lines.append(f"  remove:  {', '.join(self.remove) if self.remove else '-'}")
        lines.append(f"  snaps:   {', '.join(self.snaps) if self.snaps else '-'}")
        lines.append(f"  flags:   {', '.join(self.flags) if self.flags else '-'}")
        if self.commands:
            if self.command_summary:
                lines.extend(["", "Command summary:"])
                for key, value in self.command_summary.items():
                    lines.append(f"  {key}: {value}")
            lines.extend(["", "Commands:"])
            lines.extend(f"- {command}" for command in self.commands)
        if self.policy:
            lines.extend(["", "Policy findings:"])
            lines.extend(f"- {item['severity']} {item['code']}: {item['message']}" for item in self.policy)
        if self.trust.checks:
            lines.extend(["", self.trust.render_text()])
        if self.error:
            lines.extend(["", f"Dry-run stopped: {self.error}"])
        return "\n".join(lines)

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def generate_dry_run_report(
    project: Project,
    options: BuildOptions,
    run_orchestrator: bool = True,
) -> DryRunReport:
    from .build import BuildOrchestrator

    preview = DiffPreviewService().preview(project, options)
    orchestrator = BuildOrchestrator(project, CommandRunner(dry_run=True), options)
    steps = orchestrator.plan()
    trust = (
        TrustService().check_source_iso(project.source_iso, options.trust, strict=options.policy.strict)
        if project.source_mode == "iso"
        else TrustReport()
    )
    policy = [finding.to_dict() for finding in PolicyService().check(project, options, options.policy)]
    report = DryRunReport(
        transaction=plan_transaction(project, options),
        steps=steps,
        install=preview.install,
        remove=preview.remove,
        snaps=preview.snaps,
        services=preview.services,
        flags=preview.estimated_flags,
        policy=policy,
        trust=trust,
    )
    report.findings = _collect_findings(project, options, report.trust, report.policy, preview.install)
    if not run_orchestrator:
        return report
    try:
        orchestrator.run()
    except Exception as exc:  # dry-run report should be inspectable even when blocked
        report.error = str(exc)
    report.commands = [spec.display() for spec in orchestrator.runner.history]
    report.command_summary = _summarize_commands(orchestrator.runner.history)
    return report


def _collect_findings(
    project: Project,
    options: BuildOptions,
    trust: TrustReport,
    policy: list[dict[str, object]],
    packages: list[str],
) -> list[DryRunFinding]:
    runner = CommandRunner(dry_run=True)
    findings: list[DryRunFinding] = []
    seen: set[tuple[str, str, str]] = set()

    def add(level: str, code: str, message: str, remediation: str = "") -> None:
        key = (level, code, message)
        if key not in seen:
            seen.add(key)
            findings.append(DryRunFinding(level, code, message, remediation))

    for issue in [
        *validate_for_build(project, runner, execute=False),
        *validate_build_options(project, options, runner, execute=True),
    ]:
        add(issue.level, f"validation-{issue.code}", issue.message)

    for item in run_doctor(runner):
        if item.binary in REQUIRED_TOOLS and not item.available:
            add(
                "error",
                f"host-{item.binary}",
                f"{item.binary} is missing: {item.reason}",
                "Install missing host dependencies before executing the build.",
            )

    if project.source_mode == "bootstrap":
        for issue in validate_bootstrap_host(runner):
            add(issue.level, f"validation-{issue.code}", issue.message)
        _add_bootstrap_findings(project, options, add)
    elif project.source_iso and not project.source_iso.exists():
        add(
            "error",
            "source-iso-missing",
            f"Source ISO does not exist: {project.source_iso}",
            "Select an existing ISO or switch to a skeleton source starter.",
        )

    _add_artifact_findings(project, options, add)
    _add_trust_findings(trust, add)
    _add_vuln_findings(options, packages, add)
    _add_policy_findings(policy, add)
    _add_privilege_finding(options, add)
    return findings


def _add_bootstrap_findings(project: Project, options: BuildOptions, add) -> None:
    root = project.squashfs_root
    if not root.exists():
        add("info", "bootstrap-rootfs-new", f"Bootstrap rootfs will be created at {root}")
        return
    try:
        entries = list(root.iterdir())
    except PermissionError:
        add(
            "error",
            "bootstrap-rootfs-unreadable",
            f"Bootstrap rootfs cannot be inspected: {root}",
            "Fix ownership/permissions or choose a fresh work directory.",
        )
        return
    ready = (root / "var/lib/dpkg/status").exists() and (
        (root / "etc/os-release").exists() or (root / "usr/lib/os-release").exists()
    )
    if not entries:
        add("info", "bootstrap-rootfs-empty", f"Bootstrap rootfs directory is empty: {root}")
    elif ready:
        add("info", "bootstrap-rootfs-reuse", f"Existing valid rootfs will be reused: {root}")
        _add_locked_boot_artifacts(project, options, add)
    else:
        add(
            "error",
            "bootstrap-rootfs-incomplete",
            f"Bootstrap rootfs is non-empty but incomplete: {root}",
            "Clean work/filesystem or choose a new work directory before retrying.",
        )


def _add_locked_boot_artifacts(project: Project, options: BuildOptions, add) -> None:
    boot = project.squashfs_root / "boot"
    if not boot.exists():
        add(
            "warning",
            "bootstrap-boot-missing",
            f"Existing rootfs has no boot directory: {boot}",
            "Install a kernel into the rootfs before ISO assembly.",
        )
        return
    artifacts = [*sorted(boot.glob("vmlinuz-*")), *sorted(boot.glob("initrd.img-*"))]
    if not artifacts:
        add(
            "warning",
            "bootstrap-boot-artifacts-missing",
            f"No vmlinuz-* or initrd.img-* files found under {boot}",
            "Install live kernel packages before ISO assembly.",
        )
        return
    locked = [path for path in artifacts if not os.access(path, os.R_OK)]
    if locked and options.use_sudo:
        add(
            "info",
            "bootstrap-locked-boot-artifacts",
            f"{len(locked)} boot artifact(s) require the privilege helper for copying.",
        )
    elif locked:
        add(
            "error",
            "bootstrap-locked-boot-artifacts",
            f"{len(locked)} boot artifact(s) cannot be read without sudo/pkexec.",
            "Enable the privilege helper or fix rootfs boot file modes.",
        )


def _add_artifact_findings(project: Project, options: BuildOptions, add) -> None:
    if project.workdir.exists():
        add("info", "workdir-existing", f"Work directory already exists: {project.workdir}")
    if project.output_dir.exists() and any(project.output_dir.iterdir()):
        add(
            "warning",
            "output-dir-not-empty",
            f"Output directory is not empty: {project.output_dir}",
            "Review or clean old artifacts before publishing new media.",
        )
    output_iso = options.output_iso or project.output_dir / f"{project.name}-{project.release.version}.iso"
    if output_iso.exists():
        add(
            "warning",
            "output-iso-overwrite",
            f"Output ISO already exists and may be overwritten: {output_iso}",
            "Choose a new Output ISO path or archive the existing file.",
        )


def _add_trust_findings(trust: TrustReport, add) -> None:
    for check in trust.checks:
        if check.level in {"error", "warning"}:
            add(check.level, f"trust-{check.code}", check.message, check.remediation)


def _add_vuln_findings(options: BuildOptions, packages: list[str], add) -> None:
    if not options.vuln_scan.enabled:
        return
    report = VulnScanService(options.vuln_scan).scan(packages)
    for finding in report.findings:
        if finding.level in {"error", "warning"}:
            add(
                finding.level,
                f"vuln-{finding.cve.lower()}",
                f"{finding.severity.upper()} {finding.cve} in {finding.package}: {finding.message}",
                finding.remediation,
            )


def _add_policy_findings(policy: list[dict[str, object]], add) -> None:
    for finding in policy:
        severity = str(finding.get("severity", "warning"))
        code = str(finding.get("code", "policy"))
        message = str(finding.get("message", "Policy finding"))
        remediation = str(finding.get("remediation", ""))
        add(severity, f"policy-{code}", message, remediation)


def _add_privilege_finding(options: BuildOptions, add) -> None:
    if not options.use_sudo:
        add(
            "warning",
            "privilege-disabled",
            "Privilege helper is disabled; rootfs, chroot and ISO operations may fail in execute mode.",
            "Enable sudo/pkexec for full builds.",
        )
        return
    backend = privilege_backend()
    add("info", "privilege-helper", f"Privilege helper for execute mode: {backend or 'sudo'}")
    if backend == "pkexec":
        add(
            "warning",
            "privilege-pkexec-fragile",
            "pkexec may ask for repeated GUI authorizations during long builds.",
            "Use sudo for full builds unless a polkit prompt workflow is required.",
        )
    elif backend == "sudo" and sudo_askpass_program():
        add("info", "privilege-sudo-askpass", f"sudo askpass helper is available: {sudo_askpass_program()}")
    elif backend == "sudo":
        add(
            "warning",
            "privilege-sudo-terminal",
            "sudo needs a terminal or graphical askpass helper when authentication is required.",
            "Install ssh-askpass-gnome for GUI builds or launch DistroForge from a terminal.",
        )


def _summarize_commands(history) -> dict[str, int]:
    virtual = {
        "autoinstall-skip",
        "bootstrap-bios-skip",
        "bootstrap-rootfs-reuse",
        "compatibility-report",
        "qemu-user-static-required",
        "copy-file",
        "copy-tree",
        "policy-report",
        "trust-report",
        "vuln-report",
        "write-file",
    }
    summary = {
        "total": len(history),
        "privileged": 0,
        "virtual": 0,
        "writes": 0,
        "chroot": 0,
    }
    for spec in history:
        argv = spec.argv
        if spec.needs_root or (argv and argv[0] in {"sudo", "pkexec"}):
            summary["privileged"] += 1
        if argv and argv[0] in virtual:
            summary["virtual"] += 1
        if argv and argv[0] in {"write-file", "copy-file", "copy-tree", "mkdir"}:
            summary["writes"] += 1
        if "chroot" in argv:
            summary["chroot"] += 1
    return summary
