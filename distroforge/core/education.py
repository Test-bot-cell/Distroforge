from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .diff_preview import DiffPreviewService
from .policy import PolicyService

if TYPE_CHECKING:
    from .build import BuildOptions
    from .project import Project


GLOSSARY: dict[str, str] = {
    "autoinstall": "Subiquity configuration that automates Ubuntu installation choices.",
    "bios": "Legacy PC firmware that boots an image from a master boot record.",
    "casper": "Ubuntu live-boot tooling that describes and starts the live filesystem.",
    "chroot": "A command environment rooted inside the target filesystem.",
    "deb822": "Multi-line apt source format (.sources) that supersedes one-line deb entries.",
    "debootstrap": "Tool that builds a minimal Debian/Ubuntu root filesystem from a mirror.",
    "dkms": "Dynamic Kernel Module Support: rebuilds out-of-tree modules for each kernel.",
    "dry-run": "A planned run that records intended commands without mutating the system.",
    "gpg": "OpenPGP signature verification used to authenticate release artifacts and sources.",
    "iso": "Bootable optical-image format used by Ubuntu and Debian installers/live media.",
    "kernel-module": "A driver or feature loaded into the running Linux kernel.",
    "kiosk": "A locked-down image that boots straight into a single application.",
    "live-build": "Debian toolchain for assembling live filesystem images.",
    "mirror": "An apt server that hosts the distribution's package repositories.",
    "mok": "Machine Owner Key used by Secure Boot workflows for locally trusted modules.",
    "oem": "Manufacturer hand-off mode that defers first-boot user and hardware setup.",
    "persona": "A named preset binding build defaults and QA depth to a workflow level.",
    "policy": "DistroForge guardrails covering safety, Debian packaging, and trademark constraints.",
    "ppa": "Personal Package Archive: a Launchpad-hosted apt repository.",
    "provenance": "A recorded, signable account of how an image was built and from what inputs.",
    "reproducible": "A build that produces identical output from identical inputs.",
    "rootfs": "The root filesystem tree assembled inside the target image.",
    "sanitize": "Removal of host-identifying data such as apt lists and SSH host keys before imaging.",
    "sbom": "Software Bill of Materials: an inventory of every component shipped in the image.",
    "secure-boot": "UEFI feature that only loads signed bootloaders and kernels.",
    "seed": "A package list that defines a flavor's default install set.",
    "sha256": "Cryptographic checksum used to detect corrupt or substituted downloads.",
    "snap": "A confined, self-contained package format with bundled dependencies.",
    "snapshot": "A rollback archive of the root filesystem taken around a risky build phase.",
    "squashfs": "Compressed read-only filesystem used by live Linux images.",
    "subiquity": "Ubuntu's installer that consumes autoinstall answers.",
    "transaction": "A planned build run with its own id, logs, manifests and artifacts.",
    "uefi": "Modern firmware that boots from an EFI system partition.",
}


@dataclass(frozen=True)
class GuidedRecipe:
    key: str
    label: str
    description: str
    prompt: str
    safety_notes: tuple[str, ...]
    profile: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "key": self.key,
            "label": self.label,
            "description": self.description,
            "prompt": self.prompt,
            "safety_notes": list(self.safety_notes),
            "profile": self.profile,
        }


GUIDED_RECIPES: tuple[GuidedRecipe, ...] = (
    GuidedRecipe(
        "general-desktop",
        "General desktop",
        "Balanced Ubuntu desktop with productivity defaults.",
        "balanced ubuntu desktop with productivity apps and live QA",
        ("Keep the default app set intentional.", "Run a live boot check before sharing."),
        profile="desktop",
    ),
    GuidedRecipe(
        "minimal-desktop",
        "Minimal desktop",
        "Smaller graphical image for labs, kiosks and virtual machines.",
        "minimal ubuntu desktop for labs and virtual machines",
        ("Confirm required apps survive the trim.", "Test in a VM before wider use."),
        profile="minimal",
    ),
    GuidedRecipe(
        "developer-workstation",
        "Developer Workstation",
        "Python, Git and compiler tooling with QA enabled.",
        "dev python workstation with git build-essential qemu QA",
        ("Keep build tools intentional.", "Run manifest review before publishing."),
        profile="developer",
    ),
    GuidedRecipe(
        "gaming",
        "Gaming",
        "Desktop gaming baseline with graphics and compatibility tooling.",
        "gaming desktop with steam gamemode mangohud vulkan and controllers",
        ("Keep proprietary drivers explicit.", "Test controller and audio paths."),
        profile="gaming",
    ),
    GuidedRecipe(
        "education",
        "Education",
        "Classroom workstation with learning tools and restrained defaults.",
        "classroom workstation with learning tools and restrained defaults",
        ("Avoid distracting default apps.", "Confirm content is age-appropriate."),
        profile="education",
    ),
    GuidedRecipe(
        "enterprise",
        "Enterprise",
        "Managed workstation baseline with remote access and audit tooling.",
        "managed enterprise workstation with remote access audit and support tooling",
        ("Do not ship default credentials.", "Confirm audit and SSO policy with IT."),
        profile="enterprise",
    ),
    GuidedRecipe(
        "privacy",
        "Privacy and security",
        "Privacy-oriented desktop with firewall and encryption helpers.",
        "privacy focused desktop with firewall encryption and secure messaging",
        ("Keep the firewall enabled by default.", "Avoid telemetry and tracking packages."),
        profile="privacy",
    ),
    GuidedRecipe(
        "lightweight",
        "Lightweight",
        "Lean graphical image for older machines and small virtual machines.",
        "lightweight xfce desktop for older pcs",
        ("Prefer light default services.", "Test on the oldest target hardware."),
        profile="lightweight",
    ),
    GuidedRecipe(
        "kiosk",
        "Kiosk",
        "Browser-focused live image with a small package surface.",
        "minimal kiosk browser autologin",
        ("Avoid network-facing services.", "Pin the kiosk URL and test recovery paths."),
        profile="kiosk",
    ),
    GuidedRecipe(
        "rescue",
        "Rescue ISO",
        "Maintenance-oriented image with diagnostics and no autologin.",
        "rescue maintenance tools no autologin",
        ("Do not ship default credentials.", "Prefer read-only diagnostics where possible."),
    ),
    GuidedRecipe(
        "oem",
        "OEM Hand-off",
        "Image prepared for first-boot setup and hardware checks.",
        "oem first boot drivers qa prebuild vm",
        ("Test on target hardware.", "Keep branding compliant and non-confusing."),
    ),
)


def get_guided_recipe(key: str) -> GuidedRecipe:
    for recipe in GUIDED_RECIPES:
        if recipe.key == key:
            return recipe
    raise KeyError(f"Unknown guided recipe: {key}")


def render_glossary(term: str | None = None) -> str:
    if term:
        key = term.strip().lower()
        if key not in GLOSSARY:
            known = ", ".join(sorted(GLOSSARY))
            raise KeyError(f"Unknown glossary term: {term}. Known terms: {known}")
        return f"{key}: {GLOSSARY[key]}"
    return "\n".join(f"{key:12} {GLOSSARY[key]}" for key in sorted(GLOSSARY))


def explain_risks(project: Project, options: BuildOptions) -> str:
    policy = PolicyService().check(project, options, options.policy)
    diff = DiffPreviewService().preview(project, options)
    lines = ["Risk explanation"]
    if not policy and not diff.estimated_flags:
        lines.append("- No high-risk policy findings detected in the current plan.")
    for finding in policy:
        lines.append(f"- {finding.severity.upper()} {finding.code}: {finding.message}")
        if finding.explanation:
            lines.append(f"  why: {finding.explanation}")
        if finding.remediation:
            lines.append(f"  fix: {finding.remediation}")
    for flag in diff.estimated_flags:
        lines.append(f"- INFO build-flag: {flag}")
    return "\n".join(lines)


def render_guided_recipes() -> str:
    lines = []
    for recipe in GUIDED_RECIPES:
        suffix = f" [profile: {recipe.profile}]" if recipe.profile else ""
        lines.append(f"{recipe.key:22} {recipe.label}{suffix} - {recipe.description}")
    return "\n".join(lines)


def guided_recipes_json() -> str:
    return json.dumps([recipe.to_dict() for recipe in GUIDED_RECIPES], indent=2)
