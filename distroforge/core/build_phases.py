from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class BuildPhase(StrEnum):
    VALIDATE = "validate"
    CONSISTENCY = "consistency"
    POLICY = "policy"
    COMPATIBILITY = "compatibility"
    IMPORT_SCRIPTS = "import_scripts"
    DIFF_PREVIEW = "diff_preview"
    PREPARE = "prepare"
    BOOTSTRAP_ROOTFS = "bootstrap_rootfs"
    EXTRACT_ISO = "extract_iso"
    UNPACK_FILESYSTEM = "unpack_filesystem"
    APT_CACHE = "apt_cache"
    PPA = "ppa"
    CONFIGURE_APT = "configure_apt"
    RELEASE_TRACK = "release_track"
    SYSTEM_SYNC = "system_sync"
    AUTODRIVERS = "autodrivers"
    APPLY_PACKAGES = "apply_packages"
    DESKTOP_SOURCE = "desktop_source"
    INSTALL_SNAPS = "install_snaps"
    SIZE_ANALYSIS = "size_analysis"
    VULN_SCAN = "vuln_scan"
    CUSTOMIZE_SYSTEM = "customize_system"
    BRANDING = "branding"
    USERS = "users"
    SYSTEMD = "systemd"
    NETWORK = "network"
    KIOSK = "kiosk"
    OEM = "oem"
    KERNEL_MODULE = "kernel_module"
    SECURE_BOOT = "secure_boot"
    REPRODUCIBLE = "reproducible"
    SNAPSHOT = "snapshot"
    RUN_HOOKS = "run_hooks"
    SANITIZE_TARGET = "sanitize_target"
    HEALTH = "health"
    AUTOINSTALL = "autoinstall"
    SEEDS = "seeds"
    UPDATE_METADATA = "update_metadata"
    REPACK_FILESYSTEM = "repack_filesystem"
    UPDATE_CHECKSUMS = "update_checksums"
    REBUILD_ISO = "rebuild_iso"
    PREBUILD_VM = "prebuild_vm"
    RELEASE_ARTIFACTS = "release_artifacts"
    BOOTCHECK = "bootcheck"
    QEMU_SCREENSHOT = "qemu_screenshot"
    PROVENANCE = "provenance"
    HTML_REPORT = "html_report"
    QA_MATRIX = "qa_matrix"
    PREVIEW = "preview"


@dataclass(frozen=True)
class BuildStep:
    phase: BuildPhase
    title: str
    detail: str


@dataclass(frozen=True)
class BuildPhaseSpec:
    phase: BuildPhase
    title: str


PIPELINE_PHASES: tuple[BuildPhaseSpec, ...] = (
    BuildPhaseSpec(BuildPhase.VALIDATE, "Validate project"),
    BuildPhaseSpec(BuildPhase.CONSISTENCY, "Check remix consistency"),
    BuildPhaseSpec(BuildPhase.POLICY, "Apply beginner-safe policy"),
    BuildPhaseSpec(BuildPhase.COMPATIBILITY, "Check release compatibility"),
    BuildPhaseSpec(BuildPhase.IMPORT_SCRIPTS, "Import legacy scripts"),
    BuildPhaseSpec(BuildPhase.DIFF_PREVIEW, "Preview changes"),
    BuildPhaseSpec(BuildPhase.PREPARE, "Prepare workspace"),
    BuildPhaseSpec(BuildPhase.BOOTSTRAP_ROOTFS, "Bootstrap from scratch"),
    BuildPhaseSpec(BuildPhase.EXTRACT_ISO, "Extract ISO"),
    BuildPhaseSpec(BuildPhase.UNPACK_FILESYSTEM, "Unpack live filesystem"),
    BuildPhaseSpec(BuildPhase.CONFIGURE_APT, "Configure repositories"),
    BuildPhaseSpec(BuildPhase.APT_CACHE, "Configure apt cache"),
    BuildPhaseSpec(BuildPhase.PPA, "Configure verified PPAs"),
    BuildPhaseSpec(BuildPhase.RELEASE_TRACK, "Configure release track"),
    BuildPhaseSpec(BuildPhase.SYSTEM_SYNC, "Sync system packages"),
    BuildPhaseSpec(BuildPhase.AUTODRIVERS, "Auto-install drivers"),
    BuildPhaseSpec(BuildPhase.APPLY_PACKAGES, "Apply package plan"),
    BuildPhaseSpec(BuildPhase.DESKTOP_SOURCE, "Build desktop from source"),
    BuildPhaseSpec(BuildPhase.INSTALL_SNAPS, "Install snaps"),
    BuildPhaseSpec(BuildPhase.SIZE_ANALYSIS, "Analyze image size"),
    BuildPhaseSpec(BuildPhase.VULN_SCAN, "Scan packages for known CVEs"),
    BuildPhaseSpec(BuildPhase.CUSTOMIZE_SYSTEM, "Apply ISO personalization"),
    BuildPhaseSpec(BuildPhase.BRANDING, "Apply branding"),
    BuildPhaseSpec(BuildPhase.USERS, "Configure users and groups"),
    BuildPhaseSpec(BuildPhase.SYSTEMD, "Configure systemd services"),
    BuildPhaseSpec(BuildPhase.NETWORK, "Configure network"),
    BuildPhaseSpec(BuildPhase.KIOSK, "Configure kiosk mode"),
    BuildPhaseSpec(BuildPhase.OEM, "Configure OEM mode"),
    BuildPhaseSpec(BuildPhase.KERNEL_MODULE, "Build kernel module"),
    BuildPhaseSpec(BuildPhase.SECURE_BOOT, "Secure Boot workflow"),
    BuildPhaseSpec(BuildPhase.REPRODUCIBLE, "Apply reproducible build hints"),
    BuildPhaseSpec(BuildPhase.SNAPSHOT, "Create rollback snapshots"),
    BuildPhaseSpec(BuildPhase.RUN_HOOKS, "Run customization hooks"),
    BuildPhaseSpec(BuildPhase.SANITIZE_TARGET, "Sanitize target"),
    BuildPhaseSpec(BuildPhase.HEALTH, "Beginner-safe health report"),
    BuildPhaseSpec(BuildPhase.AUTOINSTALL, "Generate autoinstall"),
    BuildPhaseSpec(BuildPhase.SEEDS, "Write seeds and requested manifests"),
    BuildPhaseSpec(BuildPhase.UPDATE_METADATA, "Update ISO metadata"),
    BuildPhaseSpec(BuildPhase.REPACK_FILESYSTEM, "Repack live filesystem"),
    BuildPhaseSpec(BuildPhase.UPDATE_CHECKSUMS, "Update ISO checksums"),
    BuildPhaseSpec(BuildPhase.REBUILD_ISO, "Rebuild ISO"),
    BuildPhaseSpec(BuildPhase.PREBUILD_VM, "Run prebuild VM lab"),
    BuildPhaseSpec(BuildPhase.RELEASE_ARTIFACTS, "Write release artifacts"),
    BuildPhaseSpec(BuildPhase.BOOTCHECK, "Boot smoke test"),
    BuildPhaseSpec(BuildPhase.QEMU_SCREENSHOT, "Capture QEMU screenshot"),
    BuildPhaseSpec(BuildPhase.PROVENANCE, "Write SBOM/provenance"),
    BuildPhaseSpec(BuildPhase.HTML_REPORT, "Write HTML report"),
    BuildPhaseSpec(BuildPhase.QA_MATRIX, "Run QA boot matrix"),
    BuildPhaseSpec(BuildPhase.PREVIEW, "Preview ISO"),
)
