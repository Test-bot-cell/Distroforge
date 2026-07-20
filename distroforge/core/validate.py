from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

from .apt import parse_repository_lines
from .branding_palettes import load_branding_palettes, valid_hex_color
from .command import CommandRunner
from .customize import load_desktops
from .desktop_source import load_desktop_source_profiles
from .doctor import REQUIRED_TOOLS, run_doctor
from .iso import BootLayout
from .project import Project


@dataclass(frozen=True)
class ValidationIssue:
    level: str
    code: str
    message: str


def validate_host(runner: CommandRunner) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    for item in run_doctor(runner):
        if item.binary in REQUIRED_TOOLS and not item.available:
            issues.append(
                ValidationIssue(
                    "error",
                    "missing-tool",
                    f"{item.binary} is required for {item.reason}",
                )
            )
    return issues


def validate_bootstrap_host(runner: CommandRunner) -> list[ValidationIssue]:
    if runner.has_binary("mmdebstrap") or runner.has_binary("debootstrap"):
        return []
    return [
        ValidationIssue(
            "error",
            "missing-bootstrap-tool",
            "mmdebstrap or debootstrap is required for skeleton source starters",
        )
    ]


def validate_project(project: Project, execute: bool = False) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    if not _valid_iso_label(project.name):
        issues.append(
            ValidationIssue(
                "warning",
                "iso-label",
                "Project name may not be a safe ISO volume label; use A-Z0-9_ only for best compatibility",
            )
        )
    if project.source_mode not in {"iso", "bootstrap"}:
        issues.append(
            ValidationIssue(
                "error",
                "source-mode",
                f"Unsupported source mode: {project.source_mode}",
            )
        )
    if project.source_mode == "iso" and not project.source_iso:
        issues.append(
            ValidationIssue(
                "error",
                "source-iso",
                "No source ISO is configured; inject a local ISO or choose a skeleton starter.",
            )
        )
    elif project.source_mode == "iso" and execute and project.source_iso and not project.source_iso.exists():
        issues.append(
            ValidationIssue(
                "error",
                "source-iso-missing",
                f"Source ISO does not exist: {project.source_iso}",
            )
        )

    try:
        parse_repository_lines(project.repositories)
    except ValueError as exc:
        issues.append(ValidationIssue("error", "repository", str(exc)))

    for package in [*project.packages, *project.remove_packages]:
        if not _valid_package_token(package):
            issues.append(
                ValidationIssue(
                    "error",
                    "package-name",
                    f"Invalid package token: {package}",
                )
            )

    desktops = load_desktops()
    if project.customization.desktop and project.customization.desktop not in desktops:
        issues.append(
            ValidationIssue(
                "error",
                "desktop",
                f"Unknown desktop choice: {project.customization.desktop}",
            )
        )
    if project.customization.display_manager and project.customization.display_manager not in {
        "gdm3",
        "lightdm",
        "sddm",
    }:
        issues.append(
            ValidationIssue(
                "error",
                "display-manager",
                f"Unsupported display manager: {project.customization.display_manager}",
            )
        )
    if project.customization.wallpaper:
        wallpaper = Path(project.customization.wallpaper)
        if execute and not wallpaper.exists():
            issues.append(
                ValidationIssue(
                    "error",
                    "wallpaper",
                    f"Wallpaper does not exist: {wallpaper}",
                )
            )
        if wallpaper.suffix.lower() not in {".jpg", ".jpeg", ".png", ".webp"}:
            issues.append(
                ValidationIssue(
                    "warning",
                    "wallpaper-format",
                    "Wallpaper should be a jpg, png or webp image",
                )
            )

    if execute and project.iso_root.exists():
        boot = BootLayout.detect(project.iso_root)
        if not boot.bios_image and not boot.efi_image:
            issues.append(
                ValidationIssue(
                    "warning",
                    "boot-assets",
                    "No BIOS or UEFI boot assets were detected in the extracted ISO tree",
                )
            )

    return issues


_USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]*[$]?$")


def validate_username(name: str) -> bool:
    return bool(_USERNAME_RE.fullmatch(name))


_ISO_LABEL_RE = re.compile(r"^[A-Za-z0-9_]{1,32}$")


def _valid_iso_label(value: str) -> bool:
    return bool(_ISO_LABEL_RE.fullmatch(value.strip()[:32]))


def validate_for_build(
    project: Project, runner: CommandRunner, execute: bool = False
) -> list[ValidationIssue]:
    issues = validate_project(project, execute=execute)
    if execute:
        issues.extend(validate_host(runner))
        if project.source_mode == "bootstrap":
            issues.extend(validate_bootstrap_host(runner))
    return issues


def validate_kernel_module_options(options) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    if not getattr(options, "enabled", False):
        return issues
    build_mode = getattr(options, "build_mode", "module")
    if build_mode not in {"module", "full-deb"}:
        issues.append(
            ValidationIssue(
                "error",
                "kernel-build-mode",
                f"Unsupported kernel build mode: {build_mode}",
            )
        )
    if (
        build_mode == "module"
        and not getattr(options, "module_source", None)
        and not getattr(options, "module_subdir", None)
    ):
        issues.append(
            ValidationIssue(
                "error",
                "kernel-module-source",
                "Kernel module build requires module_source or module_subdir",
            )
        )
    if getattr(options, "channel", "stable") not in {"stable", "longterm", "mainline"}:
        issues.append(
            ValidationIssue(
                "error",
                "kernel-channel",
                f"Unsupported kernel.org channel: {options.channel}",
            )
        )
    if getattr(options, "jobs", 0) < 0:
        issues.append(ValidationIssue("error", "kernel-jobs", "Kernel build jobs cannot be negative"))
    if getattr(options, "config_strategy", "current") not in {"current", "defconfig"}:
        issues.append(
            ValidationIssue(
                "error",
                "kernel-config-strategy",
                f"Unsupported kernel config strategy: {options.config_strategy}",
            )
        )
    if getattr(options, "require_sha256", False) and not getattr(options, "source_sha256", None):
        issues.append(
            ValidationIssue(
                "error",
                "kernel-source-sha256",
                "Kernel strict integrity requires source_sha256",
            )
        )
    if getattr(options, "require_gpg", False) and not getattr(options, "verify_pgp", True):
        issues.append(
            ValidationIssue(
                "error",
                "kernel-source-gpg",
                "Kernel strict integrity cannot disable PGP verification",
            )
        )
    if (
        getattr(options, "require_gpg", False)
        and getattr(options, "source_url", None)
        and not getattr(options, "pgp_url", None)
    ):
        issues.append(
            ValidationIssue(
                "error",
                "kernel-source-gpg",
                "Kernel strict integrity requires pgp_url when source_url is custom",
            )
        )
    return issues


def validate_desktop_source_options(options) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    if not getattr(options, "enabled", False):
        return issues
    profiles = load_desktop_source_profiles()
    desktop = getattr(options, "desktop", None)
    if not desktop:
        issues.append(
            ValidationIssue(
                "error",
                "desktop-source-target",
                "Desktop source build requires a selected desktop profile",
            )
        )
    elif desktop not in profiles:
        issues.append(
            ValidationIssue(
                "error",
                "desktop-source-target",
                f"Unknown desktop source profile: {desktop}",
            )
        )
    if getattr(options, "jobs", 0) < 0:
        issues.append(
            ValidationIssue(
                "error",
                "desktop-source-jobs",
                "Desktop source build jobs cannot be negative",
            )
        )
    if not getattr(options, "local_suffix", "dforge").strip():
        issues.append(
            ValidationIssue(
                "error",
                "desktop-source-suffix",
                "Desktop source package suffix cannot be empty",
            )
        )
    for component in getattr(options, "components", []):
        if not component.name or not component.version or not component.source_url:
            issues.append(
                ValidationIssue(
                    "error",
                    "desktop-source-component",
                    "Desktop source components require name, version and source_url",
                )
            )
        if component.build_system not in {"meson", "cmake", "autotools", "debuild", "debian", "gnome"}:
            issues.append(
                ValidationIssue(
                    "error",
                    "desktop-source-build-system",
                    f"Unsupported desktop source build system: {component.build_system}",
                )
            )
        if getattr(options, "require_sha256", False) and not component.sha256:
            issues.append(
                ValidationIssue(
                    "error",
                    "desktop-source-sha256",
                    f"Desktop source strict integrity requires SHA256 for {component.name}",
                )
            )
    return issues


def validate_system_sync_options(options) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    if not getattr(options, "enabled", False):
        return issues
    if getattr(options, "strategy", "full") not in {"safe", "full"}:
        issues.append(
            ValidationIssue(
                "error",
                "system-sync-strategy",
                f"Unsupported system sync strategy: {options.strategy}",
            )
        )
    for package in getattr(options, "hold_packages", []):
        if not _valid_package_token(package):
            issues.append(
                ValidationIssue(
                    "error",
                    "system-sync-hold",
                    f"Invalid held package token: {package}",
                )
            )
    if (
        not getattr(options, "run_during_build", True)
        and not getattr(options, "post_install_tool", True)
    ):
        issues.append(
            ValidationIssue(
                "error",
                "system-sync-empty",
                "System sync needs either build execution or the post-install helper",
            )
        )
    return issues


def validate_branding_options(options, strict: bool = False) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    asset_level = "error" if strict else "warning"
    color = getattr(options, "plymouth_main_color", None)
    if color and not valid_hex_color(color):
        issues.append(
            ValidationIssue(
                "error",
                "plymouth-main-color",
                f"Plymouth main color must be #RRGGBB: {color}",
            )
        )
    palette = getattr(options, "palette", None)
    if palette and palette != "generate" and palette not in load_branding_palettes():
        issues.append(
            ValidationIssue(
                "error",
                "branding-palette",
                f"Unknown branding palette: {palette}",
            )
        )
    for item in getattr(options, "palette_colors", []):
        if not valid_hex_color(item):
            issues.append(
                ValidationIssue(
                    "error",
                    "branding-palette-color",
                    f"Palette colors must be #RRGGBB: {item}",
                )
            )
    for field in ("home_url", "support_url", "bug_report_url", "privacy_policy_url"):
        url = getattr(options, field, None)
        if url and not _valid_http_url(url):
            issues.append(
                ValidationIssue(
                    asset_level,
                    f"branding-{field.replace('_', '-')}",
                    f"Branding {field} does not look like a valid http/https URL: {url}",
                )
            )
    for field in ("logo", "distributor_logo", "app_icon", "grub_background", "plymouth_logo", "plymouth_background", "login_background", "lightdm_background"):
        path_str = getattr(options, field, None)
        if path_str and not Path(path_str).is_absolute():
            issues.append(
                ValidationIssue(
                    asset_level,
                    f"branding-{field.replace('_', '-')}-relative",
                    f"Branding {field} is a relative path; use an absolute path to avoid build-time resolution issues: {path_str}",
                )
            )
    return issues


def validate_release_artifacts_options(options, strict: bool = False) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    if not getattr(options, "enabled", True):
        return issues
    if strict and not getattr(options, "sign", False):
        issues.append(
            ValidationIssue(
                "error",
                "release-artifacts-unsigned",
                "Strict/redistributable builds must sign release artifacts; "
                "set release_artifacts.sign and provide a gpg_key.",
            )
        )
    return issues


def collect_option_issues(options, strict: bool = False) -> list[ValidationIssue]:
    """Aggregate per-option validation for the build gate (strict-aware)."""
    issues: list[ValidationIssue] = []
    issues.extend(validate_kernel_module_options(options.kernel_module))
    issues.extend(validate_desktop_source_options(options.desktop_source))
    issues.extend(validate_system_sync_options(options.system_sync))
    issues.extend(validate_branding_options(options.branding, strict=strict))
    issues.extend(validate_prebuild_vm_options(options.prebuild_vm))
    issues.extend(validate_release_artifacts_options(options.release_artifacts, strict=strict))
    return issues


def validate_prebuild_vm_options(options) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    if not getattr(options, "enabled", False):
        return issues
    if getattr(options, "profile", "live") not in {"live", "install", "rescue"}:
        issues.append(
            ValidationIssue(
                "error",
                "prebuild-vm-profile",
                f"Unsupported prebuild VM profile: {options.profile}",
            )
        )
    if getattr(options, "firmware", "bios") not in {"bios", "uefi"}:
        issues.append(
            ValidationIssue(
                "error",
                "prebuild-vm-firmware",
                f"Unsupported prebuild VM firmware: {options.firmware}",
            )
        )
    if getattr(options, "memory_mb", 0) < 512:
        issues.append(ValidationIssue("error", "prebuild-vm-memory", "Prebuild VM memory must be at least 512 MB"))
    if getattr(options, "cpus", 0) < 1:
        issues.append(ValidationIssue("error", "prebuild-vm-cpus", "Prebuild VM CPUs must be at least 1"))
    if getattr(options, "timeout_seconds", 0) < 30:
        issues.append(
            ValidationIssue(
                "error",
                "prebuild-vm-timeout",
                "Prebuild VM timeout must be at least 30 seconds",
            )
        )
    if getattr(options, "secure_boot", False) and getattr(options, "firmware", "bios") != "uefi":
        issues.append(
            ValidationIssue(
                "error",
                "prebuild-vm-secure-boot",
                "Prebuild VM Secure Boot requires UEFI firmware",
            )
        )
    return issues


def has_errors(issues: list[ValidationIssue]) -> bool:
    return any(issue.level == "error" for issue in issues)


def format_issues(issues: list[ValidationIssue]) -> str:
    if not issues:
        return "Validation OK"
    return "\n".join(
        f"{issue.level.upper():7} {issue.code:18} {issue.message}" for issue in issues
    )


def _valid_package_token(value: str) -> bool:
    if not value:
        return False
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-.~_:*?")
    return all(char in allowed for char in value)


def _valid_http_url(value: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(value)
        return parsed.scheme in {"http", "https"} and bool(parsed.netloc)
    except Exception:
        return False
