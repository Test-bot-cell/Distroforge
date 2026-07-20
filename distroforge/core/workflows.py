from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .build import BuildOptions
    from .project import Project


@dataclass(frozen=True)
class WorkflowLevel:
    key: str
    label: str
    summary: str


@dataclass(frozen=True)
class ProductCapability:
    key: str
    label: str
    level: str
    workflow: str
    purpose: str
    when_useful: str
    commands: tuple[str, ...]
    gui_surface: str


@dataclass(frozen=True)
class WorkflowFinding:
    level: str
    code: str
    capability: str
    message: str
    remediation: str = ""

    def to_dict(self) -> dict[str, str]:
        return self.__dict__


@dataclass(frozen=True)
class WorkflowRecommendation:
    action_id: str
    priority: int
    code: str
    capability: str
    action: str
    reason: str
    gui_surface: str
    command_hint: str = ""

    def to_dict(self) -> dict[str, object]:
        return self.__dict__


WORKFLOW_LEVELS: tuple[WorkflowLevel, ...] = (
    WorkflowLevel(
        "beginner",
        "Beginner",
        "Source, desktop, language, packages, branding preset, output path and readiness stay up front.",
    ),
    WorkflowLevel(
        "power-user",
        "Power user",
        "Repositories, mirrors, PPAs, services, snapshots, autoinstall and rollback controls are explicit.",
    ),
    WorkflowLevel(
        "maintainer",
        "Maintainer",
        "Policy, trademark clearance, provenance, QEMU checks and release artifacts drive the review.",
    ),
    WorkflowLevel(
        "developer",
        "Developer",
        "Hooks, plugins, source builds, diagnostics and dry-run command history are available without hiding core safety.",
    ),
)


LEVEL_KEYS: tuple[str, ...] = tuple(level.key for level in WORKFLOW_LEVELS)
LEVEL_ORDER: dict[str, int] = {level.key: index for index, level in enumerate(WORKFLOW_LEVELS)}


def get_workflow_level(key: str) -> WorkflowLevel:
    """Resolve a canonical workflow level by key.

    ``WORKFLOW_LEVELS`` is the single source of truth for the beginner→developer
    progression; the build journey, the journey CLI and personas all derive their
    level vocabulary from it instead of redefining their own.
    """
    for level in WORKFLOW_LEVELS:
        if level.key == key:
            return level
    raise ValueError(f"Unknown workflow level {key!r}. Known: {', '.join(LEVEL_KEYS)}")


PRODUCT_CAPABILITIES: tuple[ProductCapability, ...] = (
    ProductCapability(
        "reference-source-to-iso",
        "Reference source-to-ISO path",
        "beginner",
        "Create a known, reviewable ISO from a source starter or source ISO.",
        "Keep one dependable path from source validation through rebuild, checksums and output artifacts.",
        "Useful for every project; other modules should plug into this path instead of bypassing it.",
        ("new", "plan", "validate", "build", "readiness", "dry-run-report"),
        "build",
    ),
    ProductCapability(
        "package-and-profile-shaping",
        "Package and profile shaping",
        "beginner",
        "Choose desktop, packages, profiles and derivative intent.",
        "Turn a generic source into a recognizable image without hand-editing the rootfs.",
        "Useful when the target image differs mainly by package set, desktop or derivative identity.",
        ("profiles", "profile", "derivative-profiles", "derivative-profile"),
        "packages",
    ),
    ProductCapability(
        "supply-chain-control",
        "Repository and source trust",
        "power-user",
        "Control mirrors, PPAs, snaps, release tracks and source verification.",
        "Make package sources explicit and auditable before execution mutates a rootfs.",
        "Useful when the build depends on non-default repositories, local mirrors or redistributable sources.",
        ("mirrors", "branding", "debrand", "explain-risk"),
        "source",
    ),
    ProductCapability(
        "automation-and-deployment",
        "Autoinstall, users and appliance modes",
        "power-user",
        "Generate installer automation, users, networking, kiosk and OEM flows.",
        "Move from a live remix toward an installable or appliance-like image.",
        "Useful only when paired with boot/install testing; otherwise automation can fail silently for users.",
        ("autoinstall-templates", "image-plan", "upgrade-media"),
        "advanced",
    ),
    ProductCapability(
        "rollback-and-risk-control",
        "Rollback and risky phase control",
        "power-user",
        "Use snapshots and privilege boundaries around invasive package, kernel and source-build work.",
        "Keep experimental changes recoverable and avoid hidden direct writes to protected rootfs/ISO paths.",
        "Useful when system sync, kernel, desktop-source or service changes are enabled.",
        ("restore-snapshot", "dry-run-report"),
        "build",
    ),
    ProductCapability(
        "quality-and-boot-proof",
        "Quality and boot proof",
        "maintainer",
        "Run policy, Secure Boot, QEMU, bootcheck, size and readiness review.",
        "Give maintainers evidence that the image boots and that risky options are intentional.",
        "Useful before publishing, sharing externally, or relying on autoinstall/OEM flows.",
        ("readiness", "qemu-smoke-plan", "secureboot-assist", "ux-audit"),
        "quality",
    ),
    ProductCapability(
        "release-evidence",
        "Release evidence",
        "maintainer",
        "Write release artifacts, provenance, buildinfo, packaging reports and HTML review output.",
        "Turn a local build into something that can be reviewed, reproduced and redistributed responsibly.",
        "Useful when the ISO leaves a personal lab or needs human approval.",
        ("artifact-paths", "release-readiness", "buildinfo-report", "packaging-policy", "hermetic-build-plan"),
        "artifacts",
    ),
    ProductCapability(
        "capture-and-rebuild",
        "Installed-system capture and image planning",
        "maintainer",
        "Capture an existing system profile, diff it, rebuild from it, or plan live-build/livefs workspaces.",
        "Translate a running system or external image workflow into an auditable project path.",
        "Useful when migration or reproducibility matters more than a fresh preset-driven image.",
        ("capture", "capture-diff", "rebuild-from-capture", "live-build-plan", "livefs-iso-plan", "livefs-iso-build"),
        "capture",
    ),
    ProductCapability(
        "maintainer-console-and-shell",
        "Maintainer console & chroot terminal",
        "maintainer",
        "Open a chroot terminal inside the built rootfs, run a local AI-assisted maintainer review, and have ForgeAdvisor explain build logs and findings.",
        "Give maintainers a hands-on console -- a real shell inside the image plus grounded advisor review -- to inspect and explain a build before sign-off.",
        "Useful when a report is not enough: you need to look inside the rootfs yourself or ask the advisor why a build behaved as it did.",
        ("ai-review", "forgeadvisor", "explain", "doctor"),
        "maintainer",
    ),
    ProductCapability(
        "developer-extension",
        "Developer extension surface",
        "developer",
        "Use plugins, imports, recipes, diagnostics and advisors without weakening the reference build path.",
        "Let advanced contributors extend DistroForge while tests and contracts keep public workflows coherent.",
        "Useful for new modules only after their validation, dry-run, docs and parity gates exist.",
        ("plugins", "recipe", "guided-recipe", "ai-review", "forgeadvisor", "export-recipe"),
        "extensions",
    ),
)


def workflow_level_status_text() -> str:
    return " | ".join(f"{level.label}: {level.summary}" for level in WORKFLOW_LEVELS)


def product_capability_text() -> str:
    lines = ["DistroForge workflow map"]
    for capability in PRODUCT_CAPABILITIES:
        lines.append(
            f"- {capability.label} [{capability.level}]: {capability.workflow} "
            f"Useful when: {capability.when_useful}"
        )
    return "\n".join(lines)


def evaluate_workflow_fit(project: Project, options: BuildOptions) -> tuple[WorkflowFinding, ...]:
    findings: list[WorkflowFinding] = []
    requested_packages = [*project.packages, *options.package_plan.install]
    if project.source_mode == "bootstrap" and not project.customization.desktop and not requested_packages:
        findings.append(
            WorkflowFinding(
                "info",
                "workflow-bootstrap-empty",
                "reference-source-to-iso",
                "A minimal skeleton without desktop or packages is useful mainly as a base image.",
                "Choose a desktop/profile/packages if the goal is a usable live ISO rather than a base artifact.",
            )
        )
    if options.autoinstall.enabled and not _has_boot_proof(options):
        findings.append(
            WorkflowFinding(
                "warning",
                "workflow-autoinstall-untested",
                "automation-and-deployment",
                "Autoinstall is enabled without QEMU, bootcheck or QA matrix proof.",
                "Enable prebuild VM, bootcheck or QA scenarios before treating installer automation as ready.",
            )
        )
    if _release_evidence_enabled(options) and not _has_boot_proof(options):
        findings.append(
            WorkflowFinding(
                "warning",
                "workflow-release-evidence-without-boot-proof",
                "quality-and-boot-proof",
                "Release evidence is enabled but no boot proof is configured.",
                "Pair release artifacts/provenance/reproducibility with QEMU or bootcheck evidence.",
            )
        )
    if _risky_mutation_enabled(options) and not options.snapshots.enabled:
        findings.append(
            WorkflowFinding(
                "warning",
                "workflow-risky-module-without-snapshot",
                "rollback-and-risk-control",
                "A risky mutation module is enabled without rollback snapshots.",
                "Enable snapshots before system sync, kernel builds or desktop-source builds.",
            )
        )
    if options.policy.branding_mode in {"redistributable", "approved"} and not options.release_artifacts.enabled:
        findings.append(
            WorkflowFinding(
                "info",
                "workflow-redistributable-without-release-artifacts",
                "release-evidence",
                "Redistributable branding mode is selected without release artifacts.",
                "Enable release artifacts when the ISO is meant to leave a personal lab.",
            )
        )
    return tuple(findings)


def recommend_workflow_actions(
    project: Project,
    options: BuildOptions,
    findings: tuple[WorkflowFinding, ...] = (),
) -> tuple[WorkflowRecommendation, ...]:
    recommendations: list[WorkflowRecommendation] = []
    finding_codes = {finding.code for finding in findings}
    requested_packages = [*project.packages, *options.package_plan.install]

    if project.source_mode == "iso" and not project.source_iso and not project.source_starter:
        recommendations.append(
            WorkflowRecommendation(
                "open-source",
                10,
                "choose-source",
                "reference-source-to-iso",
                "Choose a source starter or source ISO before tuning advanced modules.",
                "A build has no trustworthy starting point until the source is explicit.",
                "Source page",
                "distroforge source-starters",
            )
        )
    if project.source_mode == "bootstrap" and not project.customization.desktop and not requested_packages:
        recommendations.append(
            WorkflowRecommendation(
                "open-packages",
                20,
                "shape-empty-bootstrap",
                "package-and-profile-shaping",
                "Choose a desktop, profile or package set for the skeleton image.",
                "An empty skeleton is mostly a base artifact, not yet a useful live ISO.",
                "Packages / Desktop & Identity pages",
                "distroforge profiles",
            )
        )
    if "workflow-autoinstall-untested" in finding_codes:
        recommendations.append(
            WorkflowRecommendation(
                "open-virtualization-lab",
                30,
                "prove-autoinstall",
                "automation-and-deployment",
                "Enable prebuild VM, bootcheck or QA scenarios before relying on autoinstall.",
                "Installer automation is only useful when the install path is exercised.",
                "Virtualization Lab",
                "distroforge qemu-smoke-plan --iso PATH",
            )
        )
    if "workflow-risky-module-without-snapshot" in finding_codes:
        recommendations.append(
            WorkflowRecommendation(
                "open-build-release",
                35,
                "enable-risk-snapshots",
                "rollback-and-risk-control",
                "Enable rollback snapshots before system sync, kernel or desktop-source work.",
                "These modules mutate deep system state and should have a recovery point.",
                "Build & Release page",
                "distroforge dry-run-report PROJECT",
            )
        )
    if "workflow-release-evidence-without-boot-proof" in finding_codes:
        recommendations.append(
            WorkflowRecommendation(
                "open-virtualization-lab",
                40,
                "pair-release-evidence-with-boot-proof",
                "quality-and-boot-proof",
                "Add QEMU or bootcheck evidence before treating release artifacts as publishable.",
                "Hashes and reports prove what was built; boot proof shows it can actually start.",
                "Quality Lab / Virtualization Lab",
                "distroforge qemu-smoke-plan --iso PATH",
            )
        )
    if "workflow-redistributable-without-release-artifacts" in finding_codes:
        recommendations.append(
            WorkflowRecommendation(
                "open-artifacts",
                45,
                "add-release-artifacts",
                "release-evidence",
                "Enable release artifacts for redistributable or approved branding modes.",
                "An ISO meant to leave a lab needs SHA256SUMS, BUILDINFO and integrity material.",
                "Artifacts page",
                "distroforge release-readiness --iso PATH --output-dir DIST",
            )
        )
    if not recommendations:
        recommendations.append(
            WorkflowRecommendation(
                "open-build-release",
                90,
                "review-dry-run",
                "reference-source-to-iso",
                "Review the dry-run timeline, then execute only when the plan matches your intent.",
                "The safest next step is to inspect commands and artifacts before mutating the host or rootfs.",
                "Build & Release page",
                "distroforge dry-run-report PROJECT",
            )
        )
    return tuple(sorted(recommendations, key=lambda item: item.priority))


def _has_boot_proof(options: BuildOptions) -> bool:
    return options.prebuild_vm.enabled or options.bootcheck.enabled or bool(options.qa.scenarios)


def _release_evidence_enabled(options: BuildOptions) -> bool:
    return (
        options.release_artifacts.enabled
        or options.provenance.enabled
        or options.reproducible.enabled
        or options.html_report.enabled
    )


def _risky_mutation_enabled(options: BuildOptions) -> bool:
    return options.system_sync.enabled or options.kernel_module.enabled or options.desktop_source.enabled
