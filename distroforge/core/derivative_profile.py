from __future__ import annotations

import json
import shlex
import tomllib
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path

from .definition import write_definition


@dataclass(frozen=True)
class DerivativeProfile:
    key: str
    label: str
    description: str
    base_family: str
    base_release: str
    base_codename: str
    mint_release: str | None
    installer: str
    live_session: str
    hardware_channel: str
    repositories: tuple[str, ...]
    keyring_packages: tuple[str, ...]
    identity_packages: tuple[str, ...]
    desktop_packages: tuple[str, ...]
    installer_packages: tuple[str, ...]
    hardware_packages: tuple[str, ...]
    remove_packages: tuple[str, ...]
    branding_name: str
    branding_vendor: str
    branding_os_id: str
    branding_id_like: str
    grub_theme: str | None

    @property
    def packages(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    *self.keyring_packages,
                    *self.identity_packages,
                    *self.desktop_packages,
                    *self.installer_packages,
                    *self.hardware_packages,
                }
            )
        )


@dataclass(frozen=True)
class DockerfileBuildHints:
    path: Path
    base_image: str | None = None
    apt_packages: tuple[str, ...] = ()
    repositories: tuple[str, ...] = ()
    copied_paths: tuple[str, ...] = ()
    key_fetches: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "base_image": self.base_image,
            "apt_packages": list(self.apt_packages),
            "repositories": list(self.repositories),
            "copied_paths": list(self.copied_paths),
            "key_fetches": list(self.key_fetches),
        }


@dataclass(frozen=True)
class DerivativeValidationIssue:
    name: str
    status: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "status": self.status, "detail": self.detail}


@dataclass
class DerivativeProfilePlan:
    profile: DerivativeProfile
    dockerfile: DockerfileBuildHints | None = None
    validation: tuple[DerivativeValidationIssue, ...] = ()
    warnings: list[str] = field(default_factory=list)

    def definition(self) -> dict[str, object]:
        derivative: dict[str, object] = {
            "key": self.profile.key,
            "label": self.profile.label,
            "base_family": self.profile.base_family,
            "base_release": self.profile.base_release,
            "base_codename": self.profile.base_codename,
            "mint_release": self.profile.mint_release,
            "installer": self.profile.installer,
            "live_session": self.profile.live_session,
            "hardware_channel": self.profile.hardware_channel,
            "identity_packages": list(self.profile.identity_packages),
            "keyring_packages": list(self.profile.keyring_packages),
        }
        if self.dockerfile:
            derivative["dockerfile"] = self.dockerfile.to_dict()
        derivative["validation"] = [issue.to_dict() for issue in self.validation]
        return {
            "schema": "distroforge.preset.v1",
            "metadata": {
                "name": self.profile.branding_name,
                "kind": "distro-derivative-profile",
                "derivative": self.profile.key,
                "base_family": self.profile.base_family,
                "release": self.profile.base_release,
            },
            "source_mode": "bootstrap",
            "packages": list(self.profile.packages),
            "remove_packages": list(self.profile.remove_packages),
            "repositories": list(self.profile.repositories),
            "branding": {
                "name": self.profile.branding_name,
                "product_name": self.profile.branding_name,
                "vendor": self.profile.branding_vendor,
                "os_id": self.profile.branding_os_id,
                "id_like": self.profile.branding_id_like,
                "version_id": self.profile.base_release,
                "version_codename": self.profile.base_codename,
                "grub_theme": self.profile.grub_theme,
                "grub_distributor": self.profile.branding_name,
                "grub_menu_label": self.profile.branding_name,
            },
            "derivative_profile": derivative,
        }

    def render_text(self) -> str:
        lines = [
            f"Derivative profile: {self.profile.key}",
            f"Label: {self.profile.label}",
            self.profile.description,
            "",
            f"Base: {self.profile.base_family} {self.profile.base_release} ({self.profile.base_codename})",
            f"Mint release: {self.profile.mint_release or '-'}",
            f"Installer: {self.profile.installer}",
            f"Live session: {self.profile.live_session}",
            f"Hardware channel: {self.profile.hardware_channel}",
            "",
            "Repositories:",
            *[f"- {repo}" for repo in self.profile.repositories],
            "",
            "Identity packages:",
            *[f"- {package}" for package in self.profile.identity_packages],
            "",
            "Installer packages:",
            *[f"- {package}" for package in self.profile.installer_packages],
            "",
            "Hardware packages:",
            *([f"- {package}" for package in self.profile.hardware_packages] or ["-"]),
        ]
        if self.dockerfile:
            lines.extend(
                [
                    "",
                    "Dockerfile hints:",
                    f"- Base image: {self.dockerfile.base_image or '-'}",
                    f"- APT build packages: {len(self.dockerfile.apt_packages)}",
                    f"- Repositories: {len(self.dockerfile.repositories)}",
                    f"- Key fetches: {len(self.dockerfile.key_fetches)}",
                ]
            )
        if self.validation:
            lines.extend(["", "Validation:"])
            lines.extend(f"- [{issue.status}] {issue.name}: {issue.detail}" for issue in self.validation)
        if self.warnings:
            lines.extend(["", "Warnings:", *[f"- {warning}" for warning in self.warnings]])
        return "\n".join(lines) + "\n"

    def render_json(self) -> str:
        return json.dumps(self.definition(), indent=2) + "\n"


class DerivativeProfileService:
    def list_profiles(self) -> dict[str, DerivativeProfile]:
        return load_derivative_profiles()

    def plan(self, key: str, dockerfile: Path | None = None) -> DerivativeProfilePlan:
        profile = get_derivative_profile(key)
        hints = parse_dockerfile_hints(dockerfile) if dockerfile else None
        validation = validate_derivative_profile(profile, hints)
        warnings = [
            "Mint-like profiles use public repository/package intent; they are not official Linux Mint ISO recipes.",
            "Review trademark, artwork, installer behavior, and repository trust before publishing a derivative ISO.",
        ]
        return DerivativeProfilePlan(profile=profile, dockerfile=hints, validation=validation, warnings=warnings)

    def write_definition(self, key: str, target: Path, dockerfile: Path | None = None) -> DerivativeProfilePlan:
        plan = self.plan(key, dockerfile)
        write_definition(plan.definition(), target)
        return plan


def load_derivative_profiles() -> dict[str, DerivativeProfile]:
    path = files("distroforge.data").joinpath("derivatives.toml")
    raw = tomllib.loads(path.read_text(encoding="utf-8"))
    profiles: dict[str, DerivativeProfile] = {}
    for key, data in raw["derivatives"].items():
        profiles[key] = DerivativeProfile(
            key=key,
            label=str(data["label"]),
            description=str(data["description"]),
            base_family=str(data["base_family"]),
            base_release=str(data["base_release"]),
            base_codename=str(data["base_codename"]),
            mint_release=str(data["mint_release"]) if data.get("mint_release") else None,
            installer=str(data["installer"]),
            live_session=str(data["live_session"]),
            hardware_channel=str(data["hardware_channel"]),
            repositories=_tuple(data, "repositories"),
            keyring_packages=_tuple(data, "keyring_packages"),
            identity_packages=_tuple(data, "identity_packages"),
            desktop_packages=_tuple(data, "desktop_packages"),
            installer_packages=_tuple(data, "installer_packages"),
            hardware_packages=_tuple(data, "hardware_packages"),
            remove_packages=_tuple(data, "remove_packages"),
            branding_name=str(data["branding_name"]),
            branding_vendor=str(data["branding_vendor"]),
            branding_os_id=str(data["branding_os_id"]),
            branding_id_like=str(data["branding_id_like"]),
            grub_theme=str(data["grub_theme"]) if data.get("grub_theme") else None,
        )
    return profiles


def get_derivative_profile(key: str) -> DerivativeProfile:
    profiles = load_derivative_profiles()
    try:
        return profiles[key]
    except KeyError as exc:
        known = ", ".join(sorted(profiles))
        raise ValueError(f"Unknown derivative profile {key!r}. Known: {known}") from exc


def parse_dockerfile_hints(path: Path) -> DockerfileBuildHints:
    text = _join_dockerfile_lines(path.read_text(encoding="utf-8"))
    base_image = None
    packages: set[str] = set()
    repositories: list[str] = []
    copied_paths: list[str] = []
    key_fetches: list[str] = []
    for raw in text.splitlines():
        line = raw.strip().rstrip("\\")
        if line.startswith("FROM "):
            base_image = line.split(None, 1)[1]
        if "apt-get install" in line or " apt install" in line:
            packages.update(_apt_packages_from_line(line))
        if "deb " in line and "://" in line:
            repositories.append(_clean_shell_echo(line))
        if line.startswith(("COPY ", "ADD ")):
            copied_paths.append(line)
        if any(token in line for token in ("wget ", "curl ")) and any(
            suffix in line for suffix in (".gpg", ".asc", "keyring")
        ):
            key_fetches.append(line)
    return DockerfileBuildHints(
        path=path,
        base_image=base_image,
        apt_packages=tuple(sorted(packages)),
        repositories=tuple(repositories),
        copied_paths=tuple(copied_paths),
        key_fetches=tuple(key_fetches),
    )


def validate_derivative_profile(
    profile: DerivativeProfile,
    dockerfile: DockerfileBuildHints | None = None,
) -> tuple[DerivativeValidationIssue, ...]:
    issues: list[DerivativeValidationIssue] = []
    for repo in profile.repositories:
        status = "captured" if "signed-by=" in repo else "blocked"
        issues.append(DerivativeValidationIssue("repository-signed-by", status, repo))
    issues.append(
        DerivativeValidationIssue(
            "keyring-packages",
            "captured" if profile.keyring_packages else "blocked",
            ", ".join(profile.keyring_packages) or "No keyring package declared",
        )
    )
    expected = {"ubuntu": {"ubiquity", "subiquity", "calamares"}, "debian": {"live-installer", "calamares"}}
    allowed = expected.get(profile.base_family, set())
    issues.append(
        DerivativeValidationIssue(
            "installer-family",
            "captured" if profile.installer in allowed else "blocked",
            f"{profile.installer} on {profile.base_family}",
        )
    )
    issues.append(
        DerivativeValidationIssue(
            "identity-packages",
            "captured" if profile.identity_packages else "blocked",
            f"{len(profile.identity_packages)} packages",
        )
    )
    if profile.hardware_channel == "edge":
        has_hwe = any("hwe" in package or package.startswith("linux-") for package in profile.hardware_packages)
        issues.append(
            DerivativeValidationIssue(
                "hardware-channel",
                "captured" if has_hwe else "needs review",
                ", ".join(profile.hardware_packages) or "No hardware packages",
            )
        )
    if dockerfile:
        expected_family = "ubuntu:" if profile.base_family == "ubuntu" else "debian:"
        status = "captured" if dockerfile.base_image and dockerfile.base_image.startswith(expected_family) else "needs review"
        issues.append(
            DerivativeValidationIssue("dockerfile-base", status, dockerfile.base_image or "No FROM line")
        )
    return tuple(issues)


def _tuple(data: dict[str, object], key: str) -> tuple[str, ...]:
    return tuple(str(value) for value in data.get(key, []))


def _apt_packages_from_line(line: str) -> set[str]:
    cleaned = line.replace("&&", " && ").replace(";", " ; ")
    tokens = shlex.split(cleaned)
    packages: set[str] = set()
    capturing = False
    for token in tokens:
        if token in {"apt-get", "apt"}:
            capturing = False
            continue
        if token == "install":
            capturing = True
            continue
        if token in {"&&", ";"}:
            capturing = False
            continue
        if capturing and not token.startswith("-") and token not in {"RUN", "sudo"}:
            packages.add(token)
    return packages


def _clean_shell_echo(line: str) -> str:
    if "deb " not in line:
        return line
    return line[line.find("deb ") :].strip().strip("'\"")


def _join_dockerfile_lines(text: str) -> str:
    lines: list[str] = []
    current = ""
    for raw in text.splitlines():
        stripped = raw.rstrip()
        if not stripped or stripped.lstrip().startswith("#"):
            continue
        if stripped.endswith("\\"):
            current += stripped[:-1] + " "
            continue
        lines.append(current + stripped)
        current = ""
    if current:
        lines.append(current.strip())
    return "\n".join(lines)
