from __future__ import annotations

from dataclasses import dataclass

from .build_phases import BuildPhase

# Single source of truth for the build progression.
#
# This sequence is the *emission order* of BuildOrchestrator.run(): one entry per
# orch._step() call, including the phases that legitimately repeat (the debrand vs.
# apply BRANDING steps and the three rollback SNAPSHOT points). plan() is derived
# from it and the orchestrator guards every emission against it, so the GUI step
# list, the progress denominator, and the steps run() actually emits cannot drift.
#
# ``title`` MUST equal the title passed to orch._step() at the matching call site in
# core/build_pipeline.py; the runtime guard in BuildOrchestrator._step compares both
# phase and title. ``detail`` is the static, plan-time description shown by
# ``distroforge plan`` and the GUI step list; it is not guarded. ``weight`` is the
# relative cost used to drive a fidelity-weighted progress bar (curated heuristic:
# heavy I/O and package phases dominate so the bar tracks real time, not step count).


@dataclass(frozen=True)
class PlannedStep:
    phase: BuildPhase
    title: str
    detail: str
    weight: float = 1.0


# Curated relative cost per phase. Heavy, always-on phases (unsquashfs, apt,
# mksquashfs, xorriso) carry the most weight; trivial metadata writes carry the
# least. Optional phases use a moderate base cost; the heuristic is honest for a
# typical full build rather than option-exact.
_WEIGHTS: dict[BuildPhase, float] = {
    BuildPhase.VALIDATE: 1.0,
    BuildPhase.CONSISTENCY: 1.0,
    BuildPhase.POLICY: 1.0,
    BuildPhase.COMPATIBILITY: 1.0,
    BuildPhase.IMPORT_SCRIPTS: 1.0,
    BuildPhase.DIFF_PREVIEW: 1.0,
    BuildPhase.PREPARE: 1.0,
    BuildPhase.BOOTSTRAP_ROOTFS: 25.0,
    BuildPhase.EXTRACT_ISO: 8.0,
    BuildPhase.UNPACK_FILESYSTEM: 15.0,
    BuildPhase.CONFIGURE_APT: 2.0,
    BuildPhase.APT_CACHE: 1.0,
    BuildPhase.PPA: 2.0,
    BuildPhase.RELEASE_TRACK: 1.0,
    BuildPhase.SYSTEM_SYNC: 4.0,
    BuildPhase.AUTODRIVERS: 3.0,
    BuildPhase.APPLY_PACKAGES: 20.0,
    BuildPhase.DESKTOP_SOURCE: 6.0,
    BuildPhase.INSTALL_SNAPS: 4.0,
    BuildPhase.SIZE_ANALYSIS: 1.0,
    BuildPhase.VULN_SCAN: 1.0,
    BuildPhase.CUSTOMIZE_SYSTEM: 2.0,
    BuildPhase.BRANDING: 2.0,
    BuildPhase.USERS: 1.0,
    BuildPhase.SYSTEMD: 1.0,
    BuildPhase.NETWORK: 1.0,
    BuildPhase.KIOSK: 1.0,
    BuildPhase.OEM: 1.0,
    BuildPhase.KERNEL_MODULE: 5.0,
    BuildPhase.SECURE_BOOT: 2.0,
    BuildPhase.REPRODUCIBLE: 1.0,
    BuildPhase.SNAPSHOT: 3.0,
    BuildPhase.RUN_HOOKS: 2.0,
    BuildPhase.SANITIZE_TARGET: 3.0,
    BuildPhase.HEALTH: 1.0,
    BuildPhase.AUTOINSTALL: 1.0,
    BuildPhase.SEEDS: 1.0,
    BuildPhase.UPDATE_METADATA: 2.0,
    BuildPhase.REPACK_FILESYSTEM: 18.0,
    BuildPhase.UPDATE_CHECKSUMS: 2.0,
    BuildPhase.REBUILD_ISO: 10.0,
    BuildPhase.PREBUILD_VM: 4.0,
    BuildPhase.RELEASE_ARTIFACTS: 2.0,
    BuildPhase.BOOTCHECK: 4.0,
    BuildPhase.QEMU_SCREENSHOT: 2.0,
    BuildPhase.PROVENANCE: 1.0,
    BuildPhase.HTML_REPORT: 1.0,
    BuildPhase.QA_MATRIX: 5.0,
    BuildPhase.PREVIEW: 3.0,
}


def _step(phase: BuildPhase, title: str, detail: str) -> PlannedStep:
    return PlannedStep(phase=phase, title=title, detail=detail, weight=_WEIGHTS[phase])


def build_phase_sequence(*, source_mode: str, run_preview: bool) -> tuple[PlannedStep, ...]:
    """The canonical, emission-ordered build sequence for the given configuration.

    Only ``source_mode`` (``"iso"`` vs ``"bootstrap"``) and ``run_preview`` change which
    steps are emitted; every other ``orch._step()`` call fires unconditionally, so the
    sequence is fully determined by these two axes.
    """
    if source_mode == "bootstrap":
        source_steps = [
            _step(BuildPhase.BOOTSTRAP_ROOTFS, "Bootstrap from scratch", "Create minimal rootfs and live ISO tree"),
        ]
    else:
        source_steps = [
            _step(BuildPhase.EXTRACT_ISO, "Extract ISO", "Extract the source ISO into the work tree"),
            _step(BuildPhase.UNPACK_FILESYSTEM, "Unpack live filesystem", "Unpack filesystem.squashfs into the squashfs root"),
        ]

    steps: list[PlannedStep] = [
        _step(BuildPhase.VALIDATE, "Validate project", "Check source ISO, packages, repositories and host tools"),
        _step(BuildPhase.CONSISTENCY, "Check remix consistency", "Detect risky desktop, boot, Secure Boot and release-track combinations"),
        _step(BuildPhase.POLICY, "Apply beginner-safe policy", "Optionally enforce strict guardrails before the build starts"),
        _step(BuildPhase.COMPATIBILITY, "Check release compatibility", "Check release support, PPA intent and source mode constraints"),
        _step(BuildPhase.IMPORT_SCRIPTS, "Import legacy scripts", "Optionally import old customization scripts as chroot hooks"),
        _step(BuildPhase.DIFF_PREVIEW, "Preview changes", "Summarize packages, snaps, services and high-risk flags"),
        _step(BuildPhase.PREPARE, "Prepare workspace", "Create the build workspace and output directory"),
        *source_steps,
        _step(BuildPhase.BRANDING, "Debrand source identity", "Scan and rewrite source identity text for redistribution"),
        _step(BuildPhase.CONFIGURE_APT, "Configure repositories", "Write apt sources for the target release"),
        _step(BuildPhase.APT_CACHE, "Configure apt cache", "Optionally configure package cache or proxy"),
        _step(BuildPhase.PPA, "Configure verified PPAs", "Resolve Launchpad signing keys and add signed-by entries"),
        _step(BuildPhase.RELEASE_TRACK, "Configure release track", "Optionally enable a devel/rolling-like apt track with pinning"),
        _step(BuildPhase.SYSTEM_SYNC, "Sync system packages", "Optionally run an apt-native full system sync with fallback"),
        _step(BuildPhase.AUTODRIVERS, "Auto-install drivers", "Optionally run ubuntu-drivers install"),
        _step(BuildPhase.APPLY_PACKAGES, "Apply package plan", "Install/remove requested packages inside the target root"),
        _step(BuildPhase.DESKTOP_SOURCE, "Build desktop from source", "Optionally build selected DE upstream sources into local .deb packages"),
        _step(BuildPhase.INSTALL_SNAPS, "Install snaps", "Optionally install snaps with pinned channels"),
        _step(BuildPhase.SIZE_ANALYSIS, "Analyze image size", "Optionally record largest installed packages"),
        _step(BuildPhase.VULN_SCAN, "Scan packages for known CVEs", "Match the planned package set against the offline advisory database"),
        _step(BuildPhase.SNAPSHOT, "Create rollback snapshot", "Optional rollback snapshot after package application (after-apt)"),
        _step(BuildPhase.CUSTOMIZE_SYSTEM, "Apply ISO personalization", "Configure desktop, display manager, autologin, wallpaper and locale"),
        _step(BuildPhase.BRANDING, "Apply branding", "Apply logo, GRUB, Plymouth and release identity assets"),
        _step(BuildPhase.USERS, "Configure users and groups", "Optionally create default users and group memberships"),
        _step(BuildPhase.SYSTEMD, "Configure systemd services", "Optionally enable, disable or mask services"),
        _step(BuildPhase.NETWORK, "Configure network", "Optionally write Netplan, DNS and apt proxy configuration"),
        _step(BuildPhase.KIOSK, "Configure kiosk mode", "Optionally install browser kiosk session"),
        _step(BuildPhase.OEM, "Configure OEM mode", "Optionally prepare first-boot/OEM reset flow"),
        _step(BuildPhase.SNAPSHOT, "Create rollback snapshot", "Optional rollback snapshot after customization (after-customize)"),
        _step(BuildPhase.KERNEL_MODULE, "Build kernel payload", "Optionally fetch kernel sources, compile module and refresh boot assets"),
        _step(BuildPhase.SECURE_BOOT, "Secure Boot workflow", "Optionally prepare module signing and MOK checks"),
        _step(BuildPhase.REPRODUCIBLE, "Apply reproducible build hints", "Optionally write SOURCE_DATE_EPOCH and apt snapshot metadata"),
        _step(BuildPhase.RUN_HOOKS, "Run customization hooks", "Run pre-build, chroot and post-build hook scripts when present"),
        _step(BuildPhase.SANITIZE_TARGET, "Sanitize target", "Clean caches, logs, histories, temporary files and machine identity"),
        _step(BuildPhase.SNAPSHOT, "Create rollback snapshot", "Optional rollback snapshot after sanitize (after-sanitize)"),
        _step(BuildPhase.HEALTH, "Beginner-safe health report", "Score consistency and guardrail status before final assembly"),
        _step(BuildPhase.AUTOINSTALL, "Generate autoinstall", "Optionally write Subiquity autoinstall.yaml"),
        _step(BuildPhase.SEEDS, "Write seeds", "Write Ubuntu-style seed and requested package manifests"),
        _step(BuildPhase.UPDATE_METADATA, "Update ISO metadata", "Regenerate Casper package manifests and filesystem size"),
        _step(BuildPhase.REPACK_FILESYSTEM, "Repack live filesystem", "Rebuild squashfs with the configured compression"),
        _step(BuildPhase.UPDATE_CHECKSUMS, "Update ISO checksums", "Regenerate md5sum.txt after the new squashfs is written"),
        _step(BuildPhase.REBUILD_ISO, "Rebuild ISO", "Run xorriso to create the output ISO"),
        _step(BuildPhase.PREBUILD_VM, "Run prebuild VM lab", "Optionally boot the ISO in an observable QEMU lab"),
        _step(BuildPhase.RELEASE_ARTIFACTS, "Write release artifacts", "Generate SHA256SUMS, BUILDINFO and optional GPG signature"),
        _step(BuildPhase.BOOTCHECK, "Boot smoke test", "Optionally run a minimal headless QEMU boot check"),
        _step(BuildPhase.QEMU_SCREENSHOT, "Capture QEMU screenshot", "Optionally capture a boot screenshot for visual QA"),
        _step(BuildPhase.PROVENANCE, "Write SBOM/provenance", "Record project definition, commands and output artifact metadata"),
        _step(BuildPhase.HTML_REPORT, "Write HTML report", "Write a human-readable build report for beginners and reviewers"),
        _step(BuildPhase.QA_MATRIX, "Run QA boot matrix", "Optionally run BIOS/UEFI/live/install QEMU scenarios"),
    ]
    if run_preview:
        steps.append(_step(BuildPhase.PREVIEW, "Preview ISO", "Boot the output ISO with QEMU"))
    return tuple(steps)


def total_weight(sequence: tuple[PlannedStep, ...]) -> float:
    return sum(step.weight for step in sequence) or 1.0
