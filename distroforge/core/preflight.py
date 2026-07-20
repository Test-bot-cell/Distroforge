from __future__ import annotations

import shutil
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from .command import CommandRunner, privilege_backend, sudo_askpass_program
from .customize import desktop_conflicting_packages
from .project import Project
from .validate import ValidationIssue, validate_username

if TYPE_CHECKING:
    from .build import BuildOptions


MIN_FREE_BYTES = 12 * 1024 * 1024 * 1024


def validate_build_options(
    project: Project,
    options: BuildOptions,
    runner: CommandRunner,
    execute: bool = False,
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    issues.extend(_validate_paths(project, options, execute=execute))
    issues.extend(_validate_customization(project))
    issues.extend(_validate_package_intent(project, options))
    issues.extend(_validate_kernel_policy(options))
    issues.extend(_validate_host_privilege(options, runner, execute=execute))
    return issues


def _validate_paths(project: Project, options: BuildOptions, execute: bool) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    if project.source_mode == "iso" and project.source_iso:
        if project.source_iso.suffix.lower() != ".iso":
            issues.append(ValidationIssue("warning", "source-extension", "Source image does not end with .iso"))
        if execute and not project.source_iso.exists():
            issues.append(ValidationIssue("error", "source-missing", f"Source ISO does not exist: {project.source_iso}"))
    output_iso = options.output_iso or project.output_dir / f"{project.name}-{project.release.version}.iso"
    if output_iso.exists() and execute:
        issues.append(ValidationIssue("warning", "output-overwrite", f"Output ISO will be overwritten: {output_iso}"))
    root = project.root if project.root.exists() else project.root.parent
    if root.exists():
        free = shutil.disk_usage(root).free
        if free < MIN_FREE_BYTES:
            issues.append(
                ValidationIssue(
                    "warning",
                    "disk-space",
                    f"Less than 12 GiB free on {root}; ISO rebuilds may fail",
                )
            )
    return issues


def _validate_customization(project: Project) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    custom = project.customization
    if custom.autologin_user and not validate_username(custom.autologin_user):
        issues.append(ValidationIssue("error", "autologin-user", f"Invalid autologin user: {custom.autologin_user}"))
    if custom.desktop == "unity" and custom.display_manager == "gdm3":
        issues.append(
            ValidationIssue(
                "warning",
                "unity-display-manager",
                "Unity is usually safer with lightdm than gdm3 for classic autologin remixes",
            )
        )
    if custom.wallpaper:
        wallpaper = Path(custom.wallpaper)
        if wallpaper.suffix.lower() not in {".jpg", ".jpeg", ".png", ".webp"}:
            issues.append(ValidationIssue("warning", "wallpaper-format", "Wallpaper should be jpg, png or webp"))
    return issues


def _validate_package_intent(project: Project, options: BuildOptions) -> list[ValidationIssue]:
    conflicts = desktop_conflicting_packages(project.customization, family=project.release.family)
    project_conflicts = [pkg for pkg in project.packages if pkg in conflicts]
    option_conflicts = [pkg for pkg in options.package_plan.install if pkg in conflicts]
    requested_conflicts = sorted(set(project_conflicts).union(option_conflicts))
    install = (
        set(project.packages).difference(conflicts)
        | set(options.package_plan.install).difference(conflicts)
    )
    remove = set(project.remove_packages) | set(options.package_plan.remove) | set(project_conflicts) | set(option_conflicts)
    overlap = sorted(install & remove)
    if requested_conflicts:
        issues = [
            ValidationIssue(
                "warning",
                "desktop-conflict",
                "The selected desktop will replace these package entries: " + ", ".join(requested_conflicts),
            )
        ]
    else:
        issues = []
    if not overlap:
        return issues
    issues.append(
        ValidationIssue(
            "error",
            "package-conflict",
            "Packages cannot be both installed and removed: " + ", ".join(overlap),
        )
    )
    return issues


def _validate_kernel_policy(options: BuildOptions) -> list[ValidationIssue]:
    if not options.kernel_module.enabled:
        return []
    if options.kernel_module.prune_obsolete_kernels:
        return []
    return [
        ValidationIssue(
            "warning",
            "kernel-prune",
            "Kernel mode should prune obsolete kernels to avoid shipping multiple kernels",
        )
    ]


def _validate_host_privilege(options: BuildOptions, runner: CommandRunner, execute: bool) -> list[ValidationIssue]:
    if not execute or not options.use_sudo:
        return []
    backend = privilege_backend()
    if backend == "pkexec":
        if runner.has_binary("pkexec"):
            return []
        return [ValidationIssue("error", "privilege", "pkexec is required for the selected privilege backend")]
    if backend == "sudo":
        if not runner.has_binary("sudo"):
            return [ValidationIssue("error", "privilege", "sudo is required for privileged build operations")]
        if not sys.stdin.isatty() and not sudo_askpass_program():
            return [
                ValidationIssue(
                    "error",
                    "sudo-askpass",
                    "sudo cannot authenticate without a terminal or graphical askpass helper. "
                    "Install ssh-askpass-gnome, launch DistroForge from a terminal, or select pkexec explicitly.",
                )
            ]
        return []
    if backend == "none":
        return []
    return [ValidationIssue("error", "privilege", f"Unknown privilege backend: {backend}")]
