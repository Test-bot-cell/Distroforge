from __future__ import annotations

import os
import re
import shutil
import stat
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from .artifact_paths import default_output_iso
from .command import CommandRunner, CommandSpec, privilege_backend, sudo_askpass_program
from .customize import desktop_conflicting_packages
from .gpg import normalize_fingerprint
from .hashing import sha256_file
from .package_evidence import (
    default_archive_keyring,
    normalise_package_source_policies,
)
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
    issues.extend(_validate_source_iso_trust(project, options, execute))
    issues.extend(
        _validate_package_evidence_trust(
            project,
            options,
            runner,
            execute,
        )
    )
    issues.extend(_validate_host_privilege(options, runner, execute=execute))
    return issues


def _validate_paths(project: Project, options: BuildOptions, execute: bool) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    if project.source_mode == "iso" and project.source_iso:
        if project.source_iso.suffix.lower() != ".iso":
            issues.append(ValidationIssue("warning", "source-extension", "Source image does not end with .iso"))
        if execute and not project.source_iso.exists():
            issues.append(ValidationIssue("error", "source-missing", f"Source ISO does not exist: {project.source_iso}"))
    output_iso = options.output_iso or default_output_iso(project)
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


_FULL_FINGERPRINT = re.compile(r"^(?:[0-9A-F]{40}|[0-9A-F]{64})$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _validate_source_iso_trust(
    project: Project,
    options: BuildOptions,
    execute: bool,
) -> list[ValidationIssue]:
    """Reject an unauthenticated ISO before any executing remaster starts."""
    if project.source_mode != "iso" or not execute:
        return []
    issues: list[ValidationIssue] = []
    source = project.source_iso
    if source is None:
        issues.append(
            ValidationIssue(
                "error",
                "source-trust-file",
                "Executing ISO remasters require a local source ISO regular file.",
            )
        )
    else:
        issue = _sealed_regular_file_issue(
            source,
            code="source-trust-file",
            description="Source ISO",
        )
        if issue:
            issues.append(issue)

    expected = (options.trust.source_sha256 or "").strip().lower()
    if not _SHA256.fullmatch(expected):
        issues.append(
            ValidationIssue(
                "error",
                "source-trust-sha256",
                "Executing ISO remasters require an externally supplied full SHA256.",
            )
        )

    signature = options.trust.source_signature
    if signature is None:
        issues.append(
            ValidationIssue(
                "error",
                "source-trust-signature",
                "Executing ISO remasters require a detached signature file.",
            )
        )
    else:
        issue = _sealed_regular_file_issue(
            signature,
            code="source-trust-signature",
            description="Detached source signature",
        )
        if issue:
            issues.append(issue)

    fingerprint = normalize_fingerprint(options.trust.source_gpg_fingerprint or "")
    if not _FULL_FINGERPRINT.fullmatch(fingerprint):
        issues.append(
            ValidationIssue(
                "error",
                "source-trust-fingerprint",
                "Executing ISO remasters require one unique full 40- or 64-hex signer fingerprint.",
            )
        )
    return issues


def _sealed_regular_file_issue(
    path: Path,
    *,
    code: str,
    description: str,
) -> ValidationIssue | None:
    symlink = _first_symlink_component(path)
    if symlink is not None:
        return ValidationIssue(
            "error",
            code,
            f"{description} path must not contain symlinks ({symlink}): {path}",
        )
    try:
        metadata = path.lstat()
    except OSError as exc:
        return ValidationIssue(
            "error",
            code,
            f"{description} is unavailable: {path}: {exc}",
        )
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        return ValidationIssue(
            "error",
            code,
            f"{description} must be a non-symlink regular file: {path}",
        )
    if metadata.st_size <= 0:
        return ValidationIssue(
            "error",
            code,
            f"{description} must not be empty: {path}",
        )
    return None


def _first_symlink_component(path: Path) -> Path | None:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            return None
        if stat.S_ISLNK(metadata.st_mode):
            return current
    return None


def _validate_package_evidence_trust(
    project: Project,
    options: BuildOptions,
    runner: CommandRunner,
    execute: bool,
) -> list[ValidationIssue]:
    """Require externally supplied trust pins before an executing sealed build."""
    severity = "error" if execute else "warning"
    issues: list[ValidationIssue] = []
    fingerprints = [
        normalize_fingerprint(value)
        for value in options.bootstrap.archive_signer_fingerprints
    ]
    if not fingerprints:
        issues.append(
            ValidationIssue(
                severity,
                "archive-signer-pin",
                "Executing ISO builds require at least one full archive signer fingerprint.",
            )
        )
    elif (
        any(not _FULL_FINGERPRINT.fullmatch(value) for value in fingerprints)
        or len(set(fingerprints)) != len(fingerprints)
    ):
        issues.append(
            ValidationIssue(
                severity,
                "archive-signer-pin",
                "Archive signer fingerprints must be unique full 40- or 64-hex fingerprints.",
            )
        )

    for ppa in options.ppa.ppas:
        fingerprint = normalize_fingerprint(ppa.fingerprint or "")
        if not _FULL_FINGERPRINT.fullmatch(fingerprint):
            issues.append(
                ValidationIssue(
                    severity,
                    "ppa-signer-pin",
                    f"PPA ppa:{ppa.owner}/{ppa.name} needs an explicit full signer fingerprint for sealed evidence.",
                )
            )

    try:
        source_policies = normalise_package_source_policies(
            options.bootstrap.source_policies
        )
    except ValueError as exc:
        issues.append(
            ValidationIssue(
                severity,
                "package-source-policy",
                f"Sealed package evidence needs valid external per-source policy: {exc}",
            )
        )
        source_policies = ()
    if source_policies:
        policy_signers = {
            fingerprint
            for policy in source_policies
            for fingerprint in policy.signer_fingerprints
        }
        expected_signers = {
            *fingerprints,
            *(
                normalize_fingerprint(ppa.fingerprint or "")
                for ppa in options.ppa.ppas
            ),
        }
        if policy_signers != expected_signers:
            issues.append(
                ValidationIssue(
                    severity,
                    "package-source-policy-signers",
                    "Per-source signer ownership differs from the global archive/PPA pins.",
                )
            )

    if execute and not runner.has_binary("lz4"):
        issues.append(
            ValidationIssue(
                "error",
                "package-index-lz4",
                "Executing sealed builds require lz4 for offline Ubuntu/Debian Packages replay.",
            )
        )

    if project.source_mode != "bootstrap":
        return issues
    expected = (options.bootstrap.archive_keyring_sha256 or "").strip().lower()
    if not _SHA256.fullmatch(expected):
        issues.append(
            ValidationIssue(
                severity,
                "archive-keyring-pin",
                "Fresh bootstrap builds require the archive keyring's full SHA256.",
            )
        )
        return issues
    if source_policies and expected not in {
        digest
        for policy in source_policies
        for digest in policy.keyring_sha256
    }:
        issues.append(
            ValidationIssue(
                severity,
                "package-source-policy-keyring",
                "The bootstrap keyring SHA256 is not owned by any per-source policy.",
            )
        )
    keyring = options.bootstrap.archive_keyring or default_archive_keyring(
        project.release.family
    )
    if execute:
        if keyring.is_symlink() or not keyring.is_file():
            issues.append(
                ValidationIssue(
                    "error",
                    "archive-keyring-file",
                    f"Bootstrap archive keyring is missing, non-regular or symlinked: {keyring}",
                )
            )
        elif sha256_file(keyring) != expected:
            issues.append(
                ValidationIssue(
                    "error",
                    "archive-keyring-pin",
                    f"Bootstrap archive keyring SHA256 differs from its configured pin: {keyring}",
                )
            )
    return issues


def _sudo_authenticates_without_a_prompt(runner: CommandRunner) -> bool:
    """Ask sudo whether it needs to prompt, instead of guessing from the terminal.

    A host with no tty and no askpass helper was refused outright, on the assumption
    that sudo would have nowhere to ask for a password. That assumption is wrong for
    every automated host: a NOPASSWD sudoers rule authenticates with no prompt at all,
    which is exactly the configuration a CI runner, a provisioning script or a cron job
    has. The refusal said "sudo cannot authenticate", which was false there -- it can,
    and without asking -- so the one environment the build most needs to work in was the
    one it rejected, and the message sent the reader off to install a graphical askpass
    on a machine with no display.

    ``sudo -n`` is the question itself rather than a proxy for it: it never prompts and
    exits non-zero when a password would have been required. On this maintainer's
    workstation it exits 1 with "interactive authentication is required", so the error
    above still fires where it should.
    """
    if runner.dry_run:
        # A dry-run runner answers 0 to everything it is handed, so asking it this
        # would fabricate a yes -- the silent success this check exists to prevent.
        return False
    spec = CommandSpec(
        ("sudo", "-n", "true"),
        description="Check whether sudo authenticates without a prompt",
    )
    return runner.run(spec, check=False).returncode == 0


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
        if (
            not sys.stdin.isatty()
            and not sudo_askpass_program()
            and not _sudo_authenticates_without_a_prompt(runner)
        ):
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
