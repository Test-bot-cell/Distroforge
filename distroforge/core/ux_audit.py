from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .build import BuildOptions
from .command_registry import CLI_GUI_COMMANDS, commands_requiring_progress
from .project import Project
from .workflows import LEVEL_KEYS


@dataclass(frozen=True)
class UxFinding:
    level: str
    persona: str
    area: str
    message: str
    action: str


@dataclass
class UxAuditReport:
    findings: list[UxFinding] = field(default_factory=list)

    @property
    def score(self) -> int:
        penalty = 0
        for finding in self.findings:
            if finding.level == "error":
                penalty += 18
            elif finding.level == "warning":
                penalty += 9
            else:
                penalty += 3
        return max(0, 100 - penalty)

    def render_text(self) -> str:
        lines = [f"DistroForge UX audit: {self.score}/100"]
        if not self.findings:
            lines.append("No major persona friction found.")
            return "\n".join(lines)
        for finding in self.findings:
            lines.append(
                f"[{finding.level}] {finding.persona} / {finding.area}: "
                f"{finding.message} Action: {finding.action}"
            )
        return "\n".join(lines)


def gui_source_root() -> Path:
    """Canonical GUI source tree scanned by the CLI/GUI parity audit."""
    return Path(__file__).resolve().parent.parent / "ui"


def audit_experience(
    project: Project,
    options: BuildOptions,
    gui_source: Path | None = None,
) -> UxAuditReport:
    report = UxAuditReport()
    for level in LEVEL_KEYS:
        _LEVEL_AUDIT_PATHS[level](report, project, options)
    if gui_source:
        _audit_gui_parity(report, gui_source)
    return report


def _audit_beginner_path(report: UxAuditReport, project: Project, options: BuildOptions) -> None:
    if project.source_mode == "iso" and not project.source_iso:
        report.findings.append(
            UxFinding(
                "warning",
                "beginner",
                "source",
                "No source ISO is selected.",
                "Use the Source page/--source-iso or switch to a skeleton source starter.",
            )
        )
    if project.source_mode == "bootstrap" and not project.customization.desktop:
        report.findings.append(
            UxFinding(
                "warning",
                "beginner",
                "desktop",
                "From-scratch builds are easier to understand with an explicit desktop.",
                "Choose a desktop target before the first dry-run.",
            )
        )
    if not options.sanitize.enabled:
        report.findings.append(
            UxFinding(
                "warning",
                "beginner",
                "safety",
                "Sanitize is disabled.",
                "Keep sanitize enabled unless debugging a build artifact.",
            )
        )


def _audit_power_user_path(report: UxAuditReport, project: Project, options: BuildOptions) -> None:
    if not options.snapshots.enabled:
        report.findings.append(
            UxFinding(
                "info",
                "power-user",
                "rollback",
                "Rollback snapshots are disabled.",
                "Enable snapshots for invasive package, kernel or desktop-source work.",
            )
        )
    if options.system_sync.enabled and not options.system_sync.fallback:
        report.findings.append(
            UxFinding(
                "warning",
                "power-user",
                "system sync",
                "System sync fallback is disabled.",
                "Keep fallback on when emulating a pacman -Syu style flow.",
            )
        )
    if options.kernel_module.enabled and not options.snapshots.enabled:
        report.findings.append(
            UxFinding(
                "warning",
                "power-user",
                "kernel",
                "Kernel work is enabled without rollback snapshots.",
                "Enable snapshots or auto-restore before kernel builds.",
            )
        )


def _audit_maintainer_path(report: UxAuditReport, project: Project, options: BuildOptions) -> None:
    if not options.release_artifacts.enabled:
        report.findings.append(
            UxFinding(
                "warning",
                "maintainer",
                "release",
                "Release artifacts are disabled.",
                "Keep SHA256SUMS/BUILDINFO/INTEGRITY artifacts for reproducible releases.",
            )
        )
    if not options.provenance.enabled:
        report.findings.append(
            UxFinding(
                "warning",
                "maintainer",
                "provenance",
                "Provenance/SBOM output is disabled.",
                "Enable provenance for distro evolution and audit trails.",
            )
        )
    if not options.prebuild_vm.enabled and not options.qa.scenarios:
        report.findings.append(
            UxFinding(
                "info",
                "maintainer",
                "qa",
                "No prebuild VM lab or QA matrix is configured.",
                "Enable at least one live BIOS/UEFI check before publishing.",
            )
        )
    if options.kernel_module.enabled and options.kernel_module.build_mode == "full-deb":
        if not options.kernel_module.require_sha256 or not options.kernel_module.require_gpg:
            report.findings.append(
                UxFinding(
                    "warning",
                    "maintainer",
                    "kernel integrity",
                    "Full kernel .deb builds are not in strict SHA256+GPG mode.",
                    "Require SHA256 and GPG for publishable kernel builds.",
                )
            )


def _audit_developer_path(report: UxAuditReport, project: Project, options: BuildOptions) -> None:
    extending = bool(
        options.plugins.plugins_dir
        or options.import_scripts.scripts
        or options.desktop_source.enabled
    )
    if options.plugins.plugins_dir and not options.snapshots.enabled:
        report.findings.append(
            UxFinding(
                "warning",
                "developer",
                "plugins",
                "Plugin hooks are wired in without rollback snapshots.",
                "Enable snapshots so a failing plugin phase can be rolled back.",
            )
        )
    if options.import_scripts.scripts and not options.snapshots.enabled:
        report.findings.append(
            UxFinding(
                "warning",
                "developer",
                "imported hooks",
                "Imported legacy scripts run as chroot hooks without rollback snapshots.",
                "Enable snapshots before importing scripts that mutate the rootfs.",
            )
        )
    if options.desktop_source.enabled and not options.desktop_source.require_sha256:
        report.findings.append(
            UxFinding(
                "warning",
                "developer",
                "desktop source",
                "Upstream desktop source builds are not pinned to SHA256.",
                "Require SHA256 on desktop source components for reproducible extension.",
            )
        )
    if extending and not options.reproducible.enabled:
        report.findings.append(
            UxFinding(
                "info",
                "developer",
                "reproducibility",
                "Build extensions are active without reproducible build hints.",
                "Enable reproducible builds (SOURCE_DATE_EPOCH/APT snapshot) for distro evolution.",
            )
        )


def _audit_gui_parity(report: UxAuditReport, gui_source: Path) -> None:
    if not gui_source.exists():
        return
    if gui_source.is_dir():
        text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted(gui_source.glob("*.py"))
        )
    else:
        text = gui_source.read_text(encoding="utf-8")
    required = {
        "kernel_full_deb_check": "kernel full .deb",
        "desktop_source_check": "desktop source .deb",
        "system_sync_check": "system sync",
        "prebuild_vm_check": "prebuild VM",
        "_export_build_preset": "maintainer preset export",
        "_import_build_preset": "maintainer preset import",
        "_run_ux_audit": "GUI UX audit",
    }
    for token, label in required.items():
        if token not in text:
            report.findings.append(
                UxFinding(
                    "error",
                    "all",
                    "cli-gui parity",
                    f"{label} is not visible in the GUI source.",
                    "Expose the control in GUI in the same change as the CLI feature.",
                )
            )
    if CLI_GUI_COMMANDS and "gui_parity_report" not in text:
        report.findings.append(
            UxFinding(
                "error",
                "all",
                "cli-gui parity",
                "GUI does not expose the centralized CLI/GUI parity report.",
                "Show core.command_registry mappings in the GUI Command Center.",
            )
        )
    if "QProgressBar" not in text:
        report.findings.append(
            UxFinding(
                "error",
                "all",
                "progress",
                "GUI has no progressbar for long-running CLI-equivalent actions.",
                "Expose a QProgressBar and update it from job progress events.",
            )
        )
    for command in commands_requiring_progress():
        if command not in text and "progress" not in text:
            report.findings.append(
                UxFinding(
                    "error",
                    "all",
                    "progress",
                    f"Long-running command {command!r} is not tied to a progress surface.",
                    "Route GUI execution through the job/progress mechanism.",
                )
            )


_LEVEL_AUDIT_PATHS = {
    "beginner": _audit_beginner_path,
    "power-user": _audit_power_user_path,
    "maintainer": _audit_maintainer_path,
    "developer": _audit_developer_path,
}
