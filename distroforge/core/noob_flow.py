from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .build import BuildOptions, BuildOrchestrator
from .command import CommandRunner
from .customize import load_desktops
from .definition import definition_from_project, write_definition
from .profiles import get_profile
from .project import Project


@dataclass(frozen=True)
class NoobChoice:
    key: str
    label: str
    description: str
    profile: str
    desktop: str
    packages: tuple[str, ...]
    remove: tuple[str, ...]
    mirror: str
    partitions: str
    persistence: str
    security: str
    duration: str
    volume: str
    risks: tuple[str, ...]


NOOB_CHOICES: dict[str, NoobChoice] = {
    "portable": NoobChoice(
        key="portable",
        label="Portable",
        description="A light live image for USB keys, rescue work and small machines.",
        profile="lightweight",
        desktop="xubuntu",
        packages=("gparted", "testdisk", "rsync"),
        remove=(),
        mirror="Use the default Ubuntu archive unless a local mirror is already trusted.",
        partitions="Keep one live ISO output; partitioning happens only when writing the USB.",
        persistence="Plan an optional casper-rw persistence file for USB workflows.",
        security="Keep SSH server out by default and sanitize machine-specific traces.",
        duration="15-35 min",
        volume="2.5-3.5 GB ISO",
        risks=("USB persistence must be tested on the target hardware.",),
    ),
    "desktop": NoobChoice(
        key="desktop",
        label="Bureau",
        description="A balanced daily desktop image with familiar productivity defaults.",
        profile="desktop",
        desktop="ubuntu",
        packages=("libreoffice", "vlc", "gdebi"),
        remove=(),
        mirror="Use the default Ubuntu archive for the broadest beginner support.",
        partitions="No installer partition changes are made during the ISO build.",
        persistence="Do not enable persistence by default; keep the install/live choice clear.",
        security="Enable standard cleanup and keep Secure Boot decisions visible.",
        duration="25-55 min",
        volume="3.5-5.0 GB ISO",
        risks=("Desktop images are larger; verify free disk space before executing.",),
    ),
    "dev": NoobChoice(
        key="dev",
        label="Dev",
        description="A developer workstation image with build tools and Python basics.",
        profile="developer",
        desktop="ubuntu",
        packages=("vim", "shellcheck", "make"),
        remove=(),
        mirror="Prefer the official archive; add PPAs only through reviewed profile layers.",
        partitions="Keep the ISO build separate from dev workspaces and caches.",
        persistence="Use persistence only for lab USBs; reproducible configs belong in profiles.",
        security="Keep package provenance visible and run dry-run JSON before builds.",
        duration="30-60 min",
        volume="4.0-5.5 GB ISO",
        risks=("Developer packages pull more dependencies; package conflicts need review.",),
    ),
    "kiosk": NoobChoice(
        key="kiosk",
        label="Kiosk",
        description="A browser-oriented image with restrained packages and locked-down intent.",
        profile="kiosk",
        desktop="ubuntu_minimal",
        packages=("ufw",),
        remove=("thunderbird", "libreoffice*"),
        mirror="Use HTTPS-capable official mirrors unless the deployment has an approved mirror.",
        partitions="Keep storage simple; kiosk persistence should be explicit and limited.",
        persistence="Disabled by default so each boot starts from a clean state.",
        security="Enable firewall tooling and review autologin before deployment.",
        duration="20-45 min",
        volume="2.8-4.2 GB ISO",
        risks=("Kiosk lockdown is deployment-specific; review browser policy before shipping.",),
    ),
}

NOOB_PROFILE_ORDER: tuple[str, ...] = tuple(NOOB_CHOICES)


def noob_profile_choices() -> tuple[str, ...]:
    return NOOB_PROFILE_ORDER


def noob_profile_default() -> str:
    return NOOB_PROFILE_ORDER[0]


@dataclass(frozen=True)
class NoobPlan:
    project: Path
    choice: NoobChoice
    definition: Path | None
    install: tuple[str, ...]
    remove: tuple[str, ...]
    build_steps: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": "distroforge.noob-plan.v1",
            "project": str(self.project),
            "profile": self.choice.key,
            "label": self.choice.label,
            "description": self.choice.description,
            "definition": str(self.definition) if self.definition else None,
            "suggestions": {
                "desktop": self.choice.desktop,
                "mirror": self.choice.mirror,
                "partitions": self.choice.partitions,
                "persistence": self.choice.persistence,
                "security": self.choice.security,
            },
            "apps": {
                "add": list(self.install),
                "remove": list(self.remove),
            },
            "estimate": {
                "duration": self.choice.duration,
                "volume": self.choice.volume,
            },
            "risks": list(self.choice.risks),
            "build_steps": list(self.build_steps),
        }

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2) + "\n"

    def render_text(self) -> str:
        desktop_label = load_desktops().get(self.choice.desktop)
        desktop = f"{self.choice.desktop} ({desktop_label.label})" if desktop_label else self.choice.desktop
        lines = [
            f"DistroForge beginner-first plan: {self.choice.label}",
            self.choice.description,
            f"Project: {self.project}",
            f"Definition: {self.definition or 'not written'}",
            "",
            "Smart choices:",
            f"- Desktop: {desktop} - familiar and supported for this profile.",
            f"- Mirror: {self.choice.mirror}",
            f"- Partitions: {self.choice.partitions}",
            f"- Persistence: {self.choice.persistence}",
            f"- Security: {self.choice.security}",
            "",
            "Applications added:",
            *([f"- {package}" for package in self.install] or ["- none"]),
            "",
            "Applications removed:",
            *([f"- {package}" for package in self.remove] or ["- none"]),
            "",
            "Estimate:",
            f"- Duration: {self.choice.duration}",
            f"- Output volume: {self.choice.volume}",
            "",
            "Risks:",
            *[f"- {risk}" for risk in self.choice.risks],
            "",
            "Build plan preview:",
            *_step_chunks(self.build_steps),
            "",
            "Next:",
            "Review the definition, then run a dry-run or build from the same project.",
        ]
        return "\n".join(lines) + "\n"


def noob_choice(key: str) -> NoobChoice:
    try:
        return NOOB_CHOICES[key]
    except KeyError as exc:
        known = ", ".join(sorted(NOOB_CHOICES))
        raise ValueError(f"Unknown noob profile {key!r}. Known: {known}") from exc


def apply_noob_profile(project: Project, key: str, *, persist: bool = False) -> NoobChoice:
    choice = noob_choice(key)
    profile = get_profile(choice.profile)
    project.customization.desktop = choice.desktop
    project.packages = _ordered_unique([*project.packages, *profile.install, *choice.packages])
    project.remove_packages = _ordered_unique([*project.remove_packages, *profile.remove, *choice.remove])
    if persist:
        project.save()
    return choice


def plan_noob_profile(
    project: Project,
    key: str,
    *,
    write: bool = False,
    definition_path: Path | None = None,
) -> NoobPlan:
    choice = noob_choice(key)
    options = BuildOptions()
    steps = tuple(step.title for step in BuildOrchestrator(project, CommandRunner(dry_run=True), options).plan())
    definition = definition_path or project.root / f"{choice.key}-wizard.yaml"
    if write:
        write_definition(definition_from_project(project, options, {"path": "noob-first", "profile": choice.key}), definition)
    return NoobPlan(
        project=project.root,
        choice=choice,
        definition=definition if write else None,
        install=tuple(project.packages),
        remove=tuple(project.remove_packages),
        build_steps=steps,
    )


def _ordered_unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            result.append(value)
            seen.add(value)
    return result


def _step_chunks(steps: tuple[str, ...]) -> list[str]:
    buckets = (
        ("Prepare", ("Validate", "Check", "Apply beginner-safe", "Preview", "Prepare", "Extract", "Unpack", "Import", "Debrand")),
        ("Configure", ("Configure", "Sync system", "Apply package", "Install snaps", "Auto-install")),
        ("Personalize", ("Apply ISO", "Apply branding", "Configure users", "Configure systemd", "Configure network", "Configure kiosk", "Configure OEM")),
        ("Protect", ("Create rollback", "Secure Boot", "Apply reproducible", "Sanitize", "Beginner-safe")),
        ("Assemble", ("Generate", "Write seeds", "Update ISO", "Repack", "Rebuild ISO")),
        ("Review", ("Run prebuild", "Write release", "Boot smoke", "Capture QEMU", "Write SBOM", "Write HTML", "Run QA")),
    )
    lines: list[str] = []
    used: set[str] = set()
    for label, prefixes in buckets:
        matched = [step for step in steps if step not in used and step.startswith(prefixes)]
        if matched:
            used.update(matched)
            visible = list(dict.fromkeys(matched))
            suffix = ""
            repeated = len(matched) - len(visible)
            if repeated:
                suffix = f" ({len(matched)} checkpoints)"
            lines.append(f"- {label}: {', '.join(visible[:4])}" + ("..." if len(visible) > 4 else "") + suffix)
    remaining = [step for step in steps if step not in used]
    if remaining:
        lines.append(f"- Other: {', '.join(remaining[:4])}" + ("..." if len(remaining) > 4 else ""))
    return lines
