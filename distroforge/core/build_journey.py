from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .source_starter import apply_source_starter, default_starter_for_release
from .workflows import LEVEL_ORDER

if TYPE_CHECKING:
    from pathlib import Path

    from .build import BuildOptions
    from .project import Project


@dataclass(frozen=True)
class BuildJourneyStep:
    step_id: str
    level: str
    title: str
    purpose: str
    done_when: str
    gui_surface: str
    command_hint: str
    action_id: str
    apply_hint: str
    required: bool = True


@dataclass(frozen=True)
class BuildJourneyItem:
    step: BuildJourneyStep
    status: str
    next_action: str

    def to_dict(self) -> dict[str, object]:
        return {
            "step_id": self.step.step_id,
            "level": self.step.level,
            "title": self.step.title,
            "purpose": self.step.purpose,
            "done_when": self.step.done_when,
            "gui_surface": self.step.gui_surface,
            "command_hint": self.step.command_hint,
            "action_id": self.step.action_id,
            "apply_hint": self.step.apply_hint,
            "required": self.step.required,
            "status": self.status,
            "next_action": self.next_action,
        }


@dataclass(frozen=True)
class BuildJourneyReport:
    level: str
    items: tuple[BuildJourneyItem, ...]

    @property
    def current(self) -> BuildJourneyItem | None:
        for item in self.items:
            if item.status == "active":
                return item
        return None

    @property
    def complete(self) -> bool:
        return all(item.status == "done" for item in self.items if item.step.required)

    def to_dict(self) -> dict[str, object]:
        return {
            "level": self.level,
            "complete": self.complete,
            "current_step": self.current.to_dict() if self.current else None,
            "items": [item.to_dict() for item in self.items],
        }

    def render_text(self) -> str:
        lines = [
            f"DistroForge build journey [{self.level}]",
            f"Status: {'complete' if self.complete else 'in progress'}",
        ]
        if self.current:
            lines.extend(
                [
                    "",
                    f"Current step: {self.current.step.title}",
                    f"Why: {self.current.step.purpose}",
                    f"Next: {self.current.next_action}",
                    f"GUI: {self.current.step.gui_surface}",
                    f"CLI: {self.current.step.command_hint}",
                ]
            )
        lines.append("")
        lines.append("Steps:")
        for index, item in enumerate(self.items, start=1):
            lines.append(
                f"{index:02d}. {item.status.upper():7} [{item.step.level}] {item.step.title}"
            )
            lines.append(f"    goal: {item.step.done_when}")
            lines.append(f"    gui: {item.step.gui_surface}")
            lines.append(f"    cli: {item.step.command_hint}")
            lines.append(f"    apply: {item.step.apply_hint}")
        return "\n".join(lines)

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


JOURNEY_STEPS: tuple[BuildJourneyStep, ...] = (
    BuildJourneyStep(
        "source",
        "beginner",
        "Choose a trustworthy source",
        "Every distro build starts from an explicit release skeleton, source ISO or previous project.",
        "A source starter, source ISO, previous project or bootstrap mode is selected.",
        "Source page",
        "distroforge source-starters",
        "open-source",
        "distroforge journey PROJECT --apply source",
    ),
    BuildJourneyStep(
        "identity",
        "beginner",
        "Shape identity and desktop",
        "A usable remix needs a desktop/profile/brand decision before advanced toggles matter.",
        "Desktop, package profile, packages or visible identity are configured.",
        "Desktop & Identity / Packages pages",
        "distroforge profiles",
        "open-packages",
        "distroforge journey PROJECT --apply identity --output beginner.yaml",
    ),
    BuildJourneyStep(
        "dry-run",
        "beginner",
        "Review the dry-run build plan",
        "The first safe build action is understanding commands, artifacts and privileged phases.",
        "Readiness or dry-run has been reviewed before execution.",
        "Build & Release page",
        "distroforge readiness PROJECT",
        "open-build-release",
        "distroforge readiness PROJECT",
    ),
    BuildJourneyStep(
        "deployment",
        "power-user",
        "Decide install and appliance behavior",
        "Autoinstall, users, services, network, kiosk and OEM options change how people receive the image.",
        "Deployment behavior is either intentionally left simple or configured with matching tests.",
        "Advanced Modules page",
        "distroforge autoinstall-templates",
        "open-advanced",
        "distroforge journey PROJECT --apply deployment --output deployment.yaml",
        required=False,
    ),
    BuildJourneyStep(
        "rollback",
        "power-user",
        "Add rollback before risky mutation",
        "System sync, kernels and source-built desktops need recovery points before they mutate a rootfs.",
        "Snapshots are enabled when risky mutation modules are enabled.",
        "Build & Release page",
        "distroforge dry-run-report PROJECT",
        "open-build-release",
        "distroforge journey PROJECT --apply rollback --output rollback.yaml",
    ),
    BuildJourneyStep(
        "boot-proof",
        "maintainer",
        "Prove boot and install behavior",
        "A distro that leaves the lab needs QEMU, bootcheck or QA evidence, not just successful file output.",
        "QEMU, bootcheck or QA scenarios are configured.",
        "Quality Lab / Virtualization Lab",
        "distroforge qemu-smoke-plan --iso PATH",
        "open-virtualization-lab",
        "distroforge journey PROJECT --apply boot-proof --output maintainer.yaml",
    ),
    BuildJourneyStep(
        "release-evidence",
        "maintainer",
        "Prepare release evidence",
        "Maintainers need checksums, provenance, buildinfo, packaging policy and artifact readiness.",
        "Release artifacts, provenance, reproducibility, HTML report or packaging policy review is active.",
        "Artifacts page",
        "distroforge release-readiness --iso PATH --output-dir DIST",
        "open-artifacts",
        "distroforge journey PROJECT --apply release-evidence --output release.yaml",
    ),
    BuildJourneyStep(
        "publish-gate",
        "maintainer",
        "Pass the maintainer publish gate",
        "Publishing requires the final ISO, SHA256SUMS verification, source trust, boot proof and policy evidence.",
        "Release gate is not blocked.",
        "Artifacts page",
        "distroforge release-gate PROJECT",
        "open-artifacts",
        "distroforge release-gate PROJECT --definition maintainer.yaml",
    ),
    BuildJourneyStep(
        "extension-contract",
        "developer",
        "Keep extensions behind contracts",
        "Plugins, hooks, imports and source builds must not bypass validation, docs or CLI/GUI parity.",
        "Developer extensions are paired with tests, docs and public workflow mapping.",
        "Extensions / Maintainer pages",
        "distroforge plugins PROJECT",
        "open-extensions",
        "distroforge journey PROJECT --apply extension-contract",
        required=False,
    ),
)

JOURNEY_ACTION_IDS = tuple(step.step_id for step in JOURNEY_STEPS)


@dataclass(frozen=True)
class BuildJourneyApplyReport:
    step_id: str
    title: str
    changed_project: bool
    changed_options: bool
    notes: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "step_id": self.step_id,
            "title": self.title,
            "changed_project": self.changed_project,
            "changed_options": self.changed_options,
            "notes": list(self.notes),
        }

    def render_text(self) -> str:
        lines = [
            f"Applied journey step: {self.title}",
            f"Project changed: {'yes' if self.changed_project else 'no'}",
            f"Definition changed: {'yes' if self.changed_options else 'no'}",
        ]
        if self.notes:
            lines.extend(["", "Notes:", *[f"- {note}" for note in self.notes]])
        return "\n".join(lines)


@dataclass(frozen=True)
class BuildJourneyCheckReport:
    step_id: str
    title: str
    status: str
    findings: tuple[str, ...]
    command_hint: str
    gui_surface: str

    def to_dict(self) -> dict[str, object]:
        return {
            "step_id": self.step_id,
            "title": self.title,
            "status": self.status,
            "findings": list(self.findings),
            "command_hint": self.command_hint,
            "gui_surface": self.gui_surface,
        }

    def render_text(self) -> str:
        lines = [
            f"Journey check: {self.title}",
            f"Status: {self.status}",
            f"GUI: {self.gui_surface}",
            f"CLI: {self.command_hint}",
        ]
        if self.findings:
            lines.extend(["", "Findings:", *[f"- {finding}" for finding in self.findings]])
        return "\n".join(lines)


def build_journey(project: Project, options: BuildOptions, level: str = "beginner") -> BuildJourneyReport:
    if level not in LEVEL_ORDER:
        raise ValueError(f"Unknown journey level: {level}")
    selected = tuple(
        step for step in JOURNEY_STEPS if LEVEL_ORDER[step.level] <= LEVEL_ORDER[level]
    )
    active_assigned = False
    items: list[BuildJourneyItem] = []
    for step in selected:
        done = _CHECKS[step.step_id](project, options)
        status = "done" if done else "review" if not step.required else "waiting"
        if status == "waiting" and not active_assigned:
            status = "active"
            active_assigned = True
        items.append(BuildJourneyItem(step, status, _NEXT_ACTIONS[step.step_id]))
    return BuildJourneyReport(level, tuple(items))


def apply_journey_step(project: Project, options: BuildOptions, step_id: str) -> BuildJourneyApplyReport:
    steps = {step.step_id: step for step in JOURNEY_STEPS}
    if step_id not in steps:
        raise ValueError(f"Unknown journey step: {step_id}")
    notes: list[str] = []
    changed_project = False
    changed_options = False
    if step_id == "source":
        starter = default_starter_for_release(project.release.version)
        apply_source_starter(project, starter)
        notes.append(f"Selected default source starter: {starter}.")
        changed_project = True
    elif step_id == "identity":
        if not project.customization.desktop:
            project.customization.desktop = "ubuntu"
        project.save()
        notes.append("Selected Ubuntu as the default desktop.")
        changed_project = True
    elif step_id == "deployment":
        options.autoinstall.enabled = True
        options.autoinstall.hostname = project.customization.hostname or project.name.lower()
        notes.append("Enabled a reviewable autoinstall baseline; replace the password hash before publishing.")
        changed_options = True
    elif step_id == "rollback":
        options.snapshots.enabled = True
        options.snapshots.auto_restore_on_failure = True
        notes.append("Enabled rollback snapshots and automatic restore on build failure.")
        changed_options = True
    elif step_id == "boot-proof":
        options.prebuild_vm.enabled = True
        options.bootcheck.enabled = True
        options.qa.scenarios = ["live-bios", "live-uefi"]
        notes.append("Enabled QEMU lab, bootcheck and live BIOS/UEFI QA scenarios.")
        changed_options = True
    elif step_id == "release-evidence":
        options.release_artifacts.enabled = True
        options.provenance.enabled = True
        options.reproducible.enabled = True
        options.html_report.enabled = True
        notes.append("Enabled release artifacts, provenance, reproducibility hints and HTML report.")
        changed_options = True
    elif step_id == "publish-gate":
        options.release_artifacts.enabled = True
        options.provenance.enabled = True
        options.html_report.enabled = True
        options.prebuild_vm.enabled = True
        options.bootcheck.enabled = True
        notes.append("Enabled the proof surfaces the release gate can evaluate; build the ISO and rerun the gate.")
        notes.append("After the gate is ready, sign-release, verify-release and publish-drill-diff against a promoted baseline.")
        changed_options = True
    elif step_id == "extension-contract":
        notes.append("No automatic mutation: add plugin hooks only with tests, docs and CLI/GUI mapping.")
    else:
        notes.append("No mutation needed; run the displayed command and review the output.")
    step = steps[step_id]
    return BuildJourneyApplyReport(step_id, step.title, changed_project, changed_options, tuple(notes))


def check_journey_step(project: Project, options: BuildOptions, step_id: str) -> BuildJourneyCheckReport:
    steps = {step.step_id: step for step in JOURNEY_STEPS}
    if step_id not in steps:
        raise ValueError(f"Unknown journey step: {step_id}")
    step = steps[step_id]
    status, findings = _STEP_CHECKS[step_id](project, options)
    return BuildJourneyCheckReport(
        step_id,
        step.title,
        status,
        tuple(findings),
        step.command_hint,
        step.gui_surface,
    )


def _has_source(project: Project, options: BuildOptions) -> bool:
    return bool(project.source_starter or project.source_iso or project.source_mode == "bootstrap")


def _has_identity(project: Project, options: BuildOptions) -> bool:
    return bool(
        project.customization.desktop
        or project.packages
        or options.package_plan.install
        or options.branding.name
        or options.branding.pretty_name
        or options.branding.product_name
    )


def _reviewed_plan(project: Project, options: BuildOptions) -> bool:
    from .command import CommandRunner
    from .validate import validate_for_build

    issues = validate_for_build(project, CommandRunner(dry_run=True), execute=False)
    return not any(issue.level == "error" for issue in issues)


def _deployment_intent(project: Project, options: BuildOptions) -> bool:
    return bool(
        options.autoinstall.enabled
        or options.kiosk.enabled
        or options.oem.enabled
        or options.users.users
        or options.systemd.enable
        or options.network.dns
    )


def _rollback_ready(project: Project, options: BuildOptions) -> bool:
    return not _risky_mutation_enabled(options) or options.snapshots.enabled


def _boot_proof(project: Project, options: BuildOptions) -> bool:
    return options.prebuild_vm.enabled or options.bootcheck.enabled or bool(options.qa.scenarios)


def _release_evidence(project: Project, options: BuildOptions) -> bool:
    return bool(
        options.release_artifacts.enabled
        or options.provenance.enabled
        or options.reproducible.enabled
        or options.html_report.enabled
    )


def _publish_gate_ready(project: Project, options: BuildOptions) -> bool:
    from .release_gate import ReleaseGateService

    return not ReleaseGateService().check(project, options).blocked


def _extension_contract(project: Project, options: BuildOptions) -> bool:
    return bool(options.plugins.plugins_dir or options.import_scripts.scripts or options.desktop_source.enabled)


def _risky_mutation_enabled(options: BuildOptions) -> bool:
    return options.system_sync.enabled or options.kernel_module.enabled or options.desktop_source.enabled


def _check_source(project: Project, options: BuildOptions) -> tuple[str, list[str]]:
    if not _has_source(project, options):
        return "error", ["Choose a source starter, local ISO or bootstrap mode before configuring modules."]
    findings = [f"Source mode: {project.source_mode}."]
    if project.source_iso and not options.trust.source_sha256 and not options.trust.require_source_checksum:
        findings.append("Local ISO has no checksum requirement; add SHA256 before maintainer review.")
        return "warning", findings
    return "ok", findings


def _check_identity(project: Project, options: BuildOptions) -> tuple[str, list[str]]:
    if not _has_identity(project, options):
        return "warning", ["No desktop, package profile, package set or identity is configured yet."]
    packages = len(project.packages) + len(options.package_plan.install)
    return "ok", [f"Desktop: {project.customization.desktop or 'source default'}; packages selected: {packages}."]


def _check_dry_run(project: Project, options: BuildOptions) -> tuple[str, list[str]]:
    from .command import CommandRunner
    from .validate import validate_for_build

    issues = validate_for_build(project, CommandRunner(dry_run=True), execute=False)
    errors = [f"{issue.code}: {issue.message}" for issue in issues if issue.level == "error"]
    if errors:
        return "error", errors[:3]
    warnings = [f"{issue.code}: {issue.message}" for issue in issues if issue.level == "warning"]
    if warnings:
        return "warning", [*warnings[:3], "Resolve plan warnings, then review the dry-run before execution."]
    return "ok", ["Plan validates cleanly; review the dry-run timeline and privileged phases before execution."]


def _check_deployment(project: Project, options: BuildOptions) -> tuple[str, list[str]]:
    if not _deployment_intent(project, options):
        return "info", ["No install/appliance automation configured; live-media-only remains valid."]
    if options.autoinstall.enabled and not _boot_proof(project, options):
        return "warning", ["Autoinstall is enabled without QEMU, bootcheck or QA proof."]
    return "ok", ["Deployment behavior is configured with matching proof or no blocking risk."]


def _check_rollback(project: Project, options: BuildOptions) -> tuple[str, list[str]]:
    if _risky_mutation_enabled(options) and not options.snapshots.enabled:
        return "error", ["Risky mutation is enabled without rollback snapshots."]
    if options.snapshots.enabled:
        return "ok", ["Rollback snapshots are enabled."]
    return "ok", ["No risky mutation module currently requires snapshots."]


def _check_boot_proof(project: Project, options: BuildOptions) -> tuple[str, list[str]]:
    if not _boot_proof(project, options):
        return "warning", ["No QEMU lab, bootcheck or QA scenarios are configured."]
    return "ok", ["Boot proof is configured through QEMU lab, bootcheck or QA scenarios."]


def _check_release_evidence(project: Project, options: BuildOptions) -> tuple[str, list[str]]:
    if not _release_evidence(project, options):
        return "warning", ["Release artifacts, provenance, reproducibility or HTML report are not enabled."]
    return "ok", ["Release evidence is enabled for maintainer review."]


def _bundle_status(path: Path) -> str:
    if not path.exists():
        return ""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    return str(data.get("status", "")) if isinstance(data, dict) else ""


def _release_ritual_findings(project: Project, options: BuildOptions) -> list[str]:
    bundle_dir = project.output_dir / "publish"
    findings: list[str] = []
    if options.vuln_scan.enabled:
        findings.append(f"CVE scan: enabled (policy={options.vuln_scan.policy}).")
    else:
        findings.append("CVE scan: disabled. Enable with --vuln-scan before maintainer review.")
    signing = _bundle_status(bundle_dir / "SIGNING-REPORT.json")
    findings.append(
        f"Signing: {signing}. Rerun sign-release to refresh the signed manifest."
        if signing
        else "Signing not run. sign-release writes RELEASE-MANIFEST.json and GPG-signs SHA256SUMS."
    )
    verify = _bundle_status(bundle_dir / "VERIFY-REPORT.json")
    findings.append(
        f"Verification: {verify}. verify-release reconfirms the bundle without a rebuild."
        if verify
        else "Verification not run. verify-release checks manifest, SHA256SUMS, gate and signatures without a rebuild."
    )
    findings.append(
        "Baseline present. Run publish-drill-diff to compare against your last release."
        if (bundle_dir / "PUBLISH-DRILL.previous.json").exists()
        else "No baseline. Promote one with publish-drill-baseline to enable release-over-release diffs."
    )
    return findings


def _check_publish_gate(project: Project, options: BuildOptions) -> tuple[str, list[str]]:
    from .release_gate import ReleaseGateService

    gate = ReleaseGateService().check(project, options)
    findings = [f"{item.code}: {item.detail}" for item in gate.items if item.status in {"blocked", "review"}]
    ritual = _release_ritual_findings(project, options)
    if gate.status == "blocked":
        return "error", [*(findings[:3] or ["Release gate is blocked."]), *ritual]
    if gate.status == "review":
        return "warning", [*(findings[:3] or ["Release gate needs maintainer review."]), *ritual]
    return "ok", ["Release gate is ready.", *ritual]


def _check_extension_contract(project: Project, options: BuildOptions) -> tuple[str, list[str]]:
    if not _extension_contract(project, options):
        return "info", ["No extension workflow is active."]
    return "warning", ["Extension workflows need matching tests, docs and CLI/GUI mapping before release."]


_CHECKS: dict[str, Callable[[Project, BuildOptions], bool]] = {
    "source": _has_source,
    "identity": _has_identity,
    "dry-run": _reviewed_plan,
    "deployment": _deployment_intent,
    "rollback": _rollback_ready,
    "boot-proof": _boot_proof,
    "release-evidence": _release_evidence,
    "publish-gate": _publish_gate_ready,
    "extension-contract": _extension_contract,
}

_STEP_CHECKS: dict[str, Callable[[Project, BuildOptions], tuple[str, list[str]]]] = {
    "source": _check_source,
    "identity": _check_identity,
    "dry-run": _check_dry_run,
    "deployment": _check_deployment,
    "rollback": _check_rollback,
    "boot-proof": _check_boot_proof,
    "release-evidence": _check_release_evidence,
    "publish-gate": _check_publish_gate,
    "extension-contract": _check_extension_contract,
}

_NEXT_ACTIONS: dict[str, str] = {
    "source": "Pick a source starter or source ISO before touching advanced modules.",
    "identity": "Choose a desktop/profile, package set or visible identity.",
    "dry-run": "Run readiness and inspect the dry-run timeline before execution.",
    "deployment": "Choose whether this is only live media, an installer, an appliance or OEM media.",
    "rollback": "Enable snapshots before risky system sync, kernel or source-desktop work.",
    "boot-proof": "Add QEMU, bootcheck or QA scenarios before publishing or relying on autoinstall.",
    "release-evidence": "Enable release artifacts and run packaging/release readiness before sharing.",
    "publish-gate": "Build the ISO and pass the release gate, then sign-release, verify-release and run publish-drill-diff against your baseline before publishing.",
    "extension-contract": "Add tests, docs and CLI/GUI mapping for every plugin or hook workflow.",
}
