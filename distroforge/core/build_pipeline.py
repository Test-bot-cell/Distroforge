from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from .apt import AptService, parse_repository_lines
from .apt_cache import AptCacheService
from .autoinstall import AutoinstallService
from .bootcheck import BootCheckService
from .bootstrap import BootstrapService
from .branding import BrandingService
from .branding_compliance import BrandingComplianceService
from .build_phases import BuildPhase
from .build_reports import BuildReportArtifactService
from .casper import CasperMetadataService
from .chroot import ChrootService
from .command import CommandSpec
from .consistency import ConsistencyService
from .customize import CustomizationService
from .debrand import DebrandService
from .desktop_source import DesktopSourceService
from .drivers import DriverService
from .evidence_run import close_run_identity, evidence_run_path
from .fsops import FileSystemOps
from .health import HealthService
from .hooks import HookRunner
from .html_report import HtmlReportService
from .importer import ImportService
from .iso import IsoService
from .iso_evidence import (
    ISO_ASSEMBLY_FILENAME,
    iso_extract_member_command,
    iso_extract_member_path_command,
    write_iso_assembly_evidence,
)
from .kernel import KernelModuleService
from .kiosk import KioskService
from .mirrors import MirrorService
from .network import NetworkService
from .oem import OemService
from .package_causality import (
    PACKAGE_FILESYSTEM_CAUSALITY_FILENAME,
    write_package_filesystem_causality,
)
from .package_evidence import PackageEvidenceService
from .plugins import PluginOptions, PluginService
from .policy import CompatibilityService, PolicyService
from .ppa import PpaService
from .prebuild_vm import QemuLabService
from .preflight import validate_build_options
from .provenance import ProvenanceService
from .qa import QaMatrixService
from .qemu_preview import QemuPreviewOptions, QemuPreviewService
from .qemu_screenshot import QemuScreenshotService
from .redistribution import RedistributionAttestationService
from .release_artifacts import ReleaseArtifactService
from .release_track import ReleaseTrackService
from .reproducible import ReproducibleService
from .rootfs_evidence import (
    PackedImageWitness,
    RootfsEvidenceService,
    StableFileWitness,
    rootfs_capture_command,
    rootfs_unpack_command,
    rootfs_verify_command,
)
from .sanitize import SanitizeService
from .secureboot import SecureBootService
from .seeds import SeedService
from .size_analysis import SizeAnalysisService
from .snaps import SnapService
from .snapshots import SnapshotService
from .squashfs import SquashfsService, resolve_compression
from .system_sync import SystemSyncService
from .systemd import SystemdService
from .trust import TrustService
from .users import UserService
from .validate import (
    collect_option_issues,
    format_issues,
    has_errors,
    validate_for_build,
)
from .vulnscan import VulnScanService

if TYPE_CHECKING:
    from .build import BuildOrchestrator


@dataclass(frozen=True)
class BuildServices:
    iso: IsoService
    squashfs: SquashfsService
    apt: AptService
    chroot: ChrootService
    hooks: HookRunner
    casper: CasperMetadataService
    snapshots: SnapshotService
    plugins: PluginService
    release_track: ReleaseTrackService
    package_evidence: PackageEvidenceService
    rootfs_evidence: RootfsEvidenceService


def run_preflight(orch: BuildOrchestrator) -> None:
    orch._step(
        BuildPhase.VALIDATE,
        "Validate project",
        "project and host preflight",
    )
    issues = validate_for_build(orch.project, orch.runner, execute=orch.context.execute)
    issues.extend(
        validate_build_options(
            orch.project,
            orch.options,
            orch.runner,
            execute=orch.context.execute,
        )
    )
    issues.extend(collect_option_issues(orch.options, strict=orch.options.policy.strict))
    if has_errors(issues):
        raise ValueError(format_issues(issues))
    if orch.project.source_mode == "iso":
        TrustService().enforce_source_iso(
            orch.project.source_iso,
            orch.options.trust,
            orch.runner,
            strict=orch.options.policy.strict,
        )

    orch._step(
        BuildPhase.CONSISTENCY,
        "Check remix consistency",
        "desktop, release track and Secure Boot guardrails",
    )
    consistency_issues = ConsistencyService().check(orch.project, orch.options)
    for issue in consistency_issues:
        orch.runner.run(
            CommandSpec(
                argv=("consistency-issue", issue.level, issue.code),
                description=issue.message,
            )
        )
    blocking = [issue for issue in consistency_issues if issue.level == "error"]
    if blocking:
        raise ValueError("\n".join(issue.message for issue in blocking))

    orch._step(
        BuildPhase.POLICY,
        "Apply beginner-safe policy",
        "strict" if orch.options.policy.strict else "advisory",
    )
    policy_violations = PolicyService().check(orch.project, orch.options, orch.options.policy)
    if policy_violations:
        orch.runner.run(
            CommandSpec(
                argv=("policy-report", str(len(policy_violations))),
                description=PolicyService().summary(policy_violations),
            )
        )
        if orch.options.policy.strict:
            raise ValueError(PolicyService().summary(policy_violations))
    clearance_mode = (
        "redistributable" if orch.options.policy.strict else orch.options.policy.branding_mode
    )
    if orch.runner.dry_run:
        orch.runner.run(
            CommandSpec(
                argv=("write-file", str(orch.project.output_dir / "TRADEMARK-CLEARANCE.json")),
                description="Write Canonical trademark clearance report",
            )
        )
    else:
        BrandingComplianceService().write_clearance(
            orch.project,
            orch.options.branding,
            mode=clearance_mode,
        )

    orch._step(
        BuildPhase.COMPATIBILITY,
        "Check release compatibility",
        orch.project.release.label,
    )
    compatibility = CompatibilityService().check(orch.project, orch.options)
    orch.runner.run(
        CommandSpec(
            argv=("compatibility-report", compatibility.release, compatibility.codename),
            description="; ".join(compatibility.messages) or "Release supported by DistroForge",
        )
    )
    BuildReportArtifactService(orch.runner, orch.project, orch.options).write_compatibility_report(
        compatibility
    )

    orch._step(
        BuildPhase.IMPORT_SCRIPTS,
        "Import legacy scripts",
        f"{len(orch.options.import_scripts.scripts)} script(s)",
    )
    ImportService(orch.runner, orch.project.root, orch.options.import_scripts).import_scripts()

    orch._step(BuildPhase.DIFF_PREVIEW, "Preview changes", "package/snap/service diff")
    BuildReportArtifactService(orch.runner, orch.project, orch.options).write_diff_preview()

    orch._step(
        BuildPhase.PREPARE,
        "Prepare workspace",
        f"Create {orch.project.workdir} and {orch.project.output_dir}",
    )
    if orch.context.execute:
        orch.project.workdir.mkdir(parents=True, exist_ok=True)
        orch.project.output_dir.mkdir(parents=True, exist_ok=True)


def build_services(orch: BuildOrchestrator) -> BuildServices:
    # The epoch reaches the two services that write shipped bytes, because that is
    # where a timestamp becomes part of an artifact. Reading it from the options at
    # construction keeps the switch (--reproducible) and the value in one decision.
    epoch = orch.options.reproducible.effective_source_date_epoch
    iso = IsoService(
        orch.runner,
        use_sudo=orch.options.use_sudo,
        source_date_epoch=epoch,
        arch=orch.options.bootstrap.arch,
        require_fresh_extract=(
            orch.options._sealed_run and orch.project.source_mode == "iso"
        ),
    )
    squashfs = SquashfsService(
        orch.runner,
        use_sudo=orch.options.use_sudo,
        source_date_epoch=epoch,
        require_fresh_unpack=(
            orch.options._sealed_run and orch.project.source_mode == "iso"
        ),
    )
    apt = AptService(
        orch.runner,
        orch.project.squashfs_root,
        orch.project.release,
        use_sudo=orch.options.use_sudo,
        arch=orch.options.bootstrap.arch,
        snapshot=orch.options.reproducible.effective_apt_snapshot,
    )
    chroot = ChrootService(orch.runner, orch.project.squashfs_root, use_sudo=orch.options.use_sudo)
    hooks = HookRunner(orch.runner)
    casper = CasperMetadataService(
        orch.runner,
        orch.project.iso_root,
        orch.project.squashfs_root,
        use_sudo=orch.options.use_sudo,
        livefs=orch.project.release.livefs,
    )
    snapshots = SnapshotService(
        orch.runner,
        orch.project.squashfs_root,
        orch.project.workdir / "snapshots",
        orch.options.snapshots,
        use_sudo=orch.options.use_sudo,
    )
    plugins = PluginService(
        orch.runner,
        orch.options.plugins
        if orch.options.plugins.plugins_dir
        else PluginOptions(orch.project.root / "plugins"),
    )
    release_track = ReleaseTrackService(
        orch.runner,
        orch.project.squashfs_root,
        orch.project.release,
        orch.options.release_track,
        use_sudo=orch.options.use_sudo,
        snapshot=orch.options.reproducible.effective_apt_snapshot,
    )
    allowed_archive_signers = [
        *orch.options.bootstrap.archive_signer_fingerprints,
        *[ppa.fingerprint for ppa in orch.options.ppa.ppas if ppa.fingerprint],
    ]
    evidence_context = getattr(orch.options, "_evidence_context", None)
    package_evidence = PackageEvidenceService(
        orch.runner,
        orch.project,
        orch.project.squashfs_root,
        getattr(orch.options, "_evidence_context", None),
        use_sudo=orch.options.use_sudo,
        archive_keyring=orch.options.bootstrap.archive_keyring,
        archive_keyring_sha256=orch.options.bootstrap.archive_keyring_sha256,
        allowed_signer_fingerprints=allowed_archive_signers,
        source_policies=orch.options.bootstrap.source_policies,
        verification_time=(
            evidence_context.get("created_at")
            if isinstance(evidence_context, dict)
            else None
        ),
        fresh_rootfs=(orch.project.source_mode == "bootstrap" and orch.options._sealed_run),
    )
    run_id = str(evidence_context.get("run_id", "")) if isinstance(evidence_context, dict) else ""
    rootfs_evidence = RootfsEvidenceService(
        orch.project.squashfs_root,
        run_id=run_id or None,
    )

    return BuildServices(
        iso=iso,
        squashfs=squashfs,
        apt=apt,
        chroot=chroot,
        hooks=hooks,
        casper=casper,
        snapshots=snapshots,
        plugins=plugins,
        release_track=release_track,
        package_evidence=package_evidence,
        rootfs_evidence=rootfs_evidence,
    )


def acquire_source(orch: BuildOrchestrator, services: BuildServices) -> None:
    iso = services.iso
    squashfs = services.squashfs

    if orch.project.source_mode == "bootstrap":
        orch._step(
            BuildPhase.BOOTSTRAP_ROOTFS,
            "Bootstrap from scratch",
            orch.project.release.codename,
        )
        sealed_keyring = services.package_evidence.seal_bootstrap_keyring()
        bootstrap = BootstrapService(
            orch.runner,
            orch.project.release,
            orch.project.squashfs_root,
            orch.project.iso_root,
            replace(orch.options.bootstrap, archive_keyring=sealed_keyring),
            use_sudo=orch.options.use_sudo,
            require_fresh=orch.options._sealed_run,
        )
        bootstrap.create_rootfs()
        services.package_evidence.capture_bootstrap()
        services.package_evidence.install_capture_hook()
        bootstrap.install_live_base()
        bootstrap.create_iso_tree()
    else:
        orch._step(BuildPhase.EXTRACT_ISO, "Extract ISO", orch._source_iso_text())
        source_iso = orch._require_source_iso()
        if orch.context.execute:
            context = getattr(orch.options, "_evidence_context", None)
            source_identity = context.get("source_iso") if isinstance(context, dict) else None
            opening_sha = (
                source_identity.get("sha256")
                if isinstance(source_identity, dict)
                else None
            )
            expected_sha = orch.options.trust.source_sha256 or opening_sha
            if not isinstance(expected_sha, str) or not expected_sha:
                raise ValueError(
                    "Sealed source extraction requires a trusted opening SHA256"
                )
            iso.extract_witnessed(
                source_iso,
                orch.project.iso_root,
                expected_sha256=expected_sha,
                on_progress=orch._phase_progress,
            )
        else:
            iso.extract(
                source_iso,
                orch.project.iso_root,
                on_progress=orch._phase_progress,
            )

        orch._step(
            BuildPhase.UNPACK_FILESYSTEM,
            "Unpack live filesystem",
            str(orch._filesystem_image()),
        )
        squashfs.unpack(
            orch._filesystem_image(), orch.project.squashfs_root, on_progress=orch._phase_progress
        )
        services.package_evidence.capture_source_baseline()
        services.package_evidence.install_capture_hook()


def configure_repositories(orch: BuildOrchestrator, services: BuildServices) -> None:
    apt = services.apt
    release_track = services.release_track

    orch._step(
        BuildPhase.BRANDING,
        "Debrand source identity",
        "redistributable" if orch.options.policy.strict else "advisory",
    )
    DebrandService(orch.runner).apply(
        orch.project,
        orch.options.branding,
        strict=orch.options.policy.strict,
        use_sudo=orch.options.use_sudo,
    )

    orch._step(
        BuildPhase.CONFIGURE_APT,
        "Configure repositories",
        f"{orch.project.release.codename} apt sources",
    )
    repositories = parse_repository_lines(orch.project.repositories)
    if orch.options.mirrors.enabled and not repositories:
        MirrorService(
            orch.runner,
            orch.project,
            orch.options.mirrors,
            use_sudo=orch.options.use_sudo,
            snapshot=orch.options.reproducible.effective_apt_snapshot,
        ).apply(strict=orch.options.policy.strict)
    else:
        apt.write_sources(repositories or None)
    orch._step(
        BuildPhase.APT_CACHE,
        "Configure apt cache",
        orch.options.apt_cache.proxy_url or str(orch.options.apt_cache.cache_dir or "disabled"),
    )
    AptCacheService(
        orch.runner,
        orch.project.squashfs_root,
        orch.options.apt_cache,
        use_sudo=orch.options.use_sudo,
    ).configure()
    orch._step(
        BuildPhase.PPA,
        "Configure verified PPAs",
        f"{len(orch.options.ppa.ppas)} PPA(s)",
    )
    PpaService(
        orch.runner,
        orch.project.squashfs_root,
        orch.project.release,
        orch.options.ppa,
        use_sudo=orch.options.use_sudo,
    ).configure()
    orch._step(
        BuildPhase.RELEASE_TRACK,
        "Configure release track",
        orch.options.release_track.summary(),
    )
    release_track.configure()


def customize_target(orch: BuildOrchestrator, services: BuildServices) -> None:
    apt = services.apt
    chroot = services.chroot
    snapshots = services.snapshots
    hooks = services.hooks
    plugins = services.plugins
    release_track = services.release_track

    chroot.mount_runtime()
    try:
        apt.update()
        release_track.apply_after_update()
        orch._step(
            BuildPhase.SYSTEM_SYNC,
            "Sync system packages",
            orch.options.system_sync.summary(),
        )
        SystemSyncService(
            orch.runner,
            orch.project.squashfs_root,
            orch.options.system_sync,
            use_sudo=orch.options.use_sudo,
        ).run()
        if orch.options.run_synaptic:
            apt.launch_synaptic()

        orch._step(
            BuildPhase.AUTODRIVERS,
            "Auto-install drivers",
            "enabled" if orch.options.drivers.auto else "disabled",
        )
        DriverService(
            orch.runner,
            orch.project.squashfs_root,
            orch.options.drivers,
            use_sudo=orch.options.use_sudo,
        ).install()

        orch._step(
            BuildPhase.APPLY_PACKAGES,
            "Apply package plan",
            orch._package_plan_text(),
        )
        merged_plan = orch._merged_package_plan()
        apt.apply_plan(merged_plan, on_progress=orch._phase_progress)

        orch._step(
            BuildPhase.DESKTOP_SOURCE,
            "Build desktop from source",
            orch.options.desktop_source.summary(),
        )
        DesktopSourceService(
            orch.runner,
            orch.project.squashfs_root,
            orch.project.workdir,
            orch.options.desktop_source,
            use_sudo=orch.options.use_sudo,
        ).run()

        orch._step(
            BuildPhase.INSTALL_SNAPS,
            "Install snaps",
            f"{len(orch.options.snaps.specs)} snap(s)",
        )
        SnapService(
            orch.runner,
            orch.project.squashfs_root,
            orch.options.snaps,
            use_sudo=orch.options.use_sudo,
        ).install()
        orch._step(
            BuildPhase.SIZE_ANALYSIS,
            "Analyze image size",
            f"top={orch.options.size_analysis.top}"
            if orch.options.size_analysis.enabled
            else "disabled",
        )
        SizeAnalysisService(
            orch.runner,
            orch.project.squashfs_root,
            orch.project.output_dir,
            orch.options.size_analysis,
            use_sudo=orch.options.use_sudo,
        ).run()
        orch._step(
            BuildPhase.VULN_SCAN,
            "Scan packages for known CVEs",
            f"policy={orch.options.vuln_scan.policy}"
            if orch.options.vuln_scan.enabled
            else "disabled",
        )
        VulnScanService(orch.options.vuln_scan).enforce(orch._planned_packages(), orch.runner)
        orch._step(
            BuildPhase.SNAPSHOT,
            "Create rollback snapshot",
            "after-apt" if orch.options.snapshots.enabled else "disabled",
        )
        snapshots.create("after-apt")

        orch._step(
            BuildPhase.CUSTOMIZE_SYSTEM,
            "Apply ISO personalization",
            orch._customization_text(),
        )
        CustomizationService(
            orch.runner,
            orch.project.squashfs_root,
            orch.project.customization,
            use_sudo=orch.options.use_sudo,
        ).apply()

        orch._step(BuildPhase.BRANDING, "Apply branding", orch.options.branding.name or "default")
        BrandingService(
            orch.runner,
            orch.project,
            orch.options.branding,
            use_sudo=orch.options.use_sudo,
        ).apply()

        orch._step(
            BuildPhase.USERS,
            "Configure users and groups",
            f"{len(orch.options.users.users)} user(s)",
        )
        UserService(
            orch.runner,
            orch.project.squashfs_root,
            orch.options.users,
            use_sudo=orch.options.use_sudo,
        ).apply()

        orch._step(
            BuildPhase.SYSTEMD,
            "Configure systemd services",
            (
                f"enable={len(orch.options.systemd.enable)} "
                f"disable={len(orch.options.systemd.disable)} "
                f"mask={len(orch.options.systemd.mask)}"
            ),
        )
        SystemdService(
            orch.runner,
            orch.project.squashfs_root,
            orch.options.systemd,
            use_sudo=orch.options.use_sudo,
        ).apply()

        orch._step(
            BuildPhase.NETWORK,
            "Configure network",
            "netplan/proxy"
            if orch.options.network.netplan_dhcp or orch.options.network.apt_proxy
            else "disabled",
        )
        NetworkService(
            orch.runner,
            orch.project.squashfs_root,
            orch.options.network,
            use_sudo=orch.options.use_sudo,
        ).apply()

        orch._step(
            BuildPhase.KIOSK,
            "Configure kiosk mode",
            orch.options.kiosk.url if orch.options.kiosk.enabled else "disabled",
        )
        KioskService(
            orch.runner,
            orch.project.squashfs_root,
            orch.options.kiosk,
            use_sudo=orch.options.use_sudo,
        ).apply()

        orch._step(
            BuildPhase.OEM,
            "Configure OEM mode",
            "enabled" if orch.options.oem.enabled else "disabled",
        )
        OemService(
            orch.runner,
            orch.project.squashfs_root,
            orch.options.oem,
            use_sudo=orch.options.use_sudo,
        ).apply()
        orch._step(
            BuildPhase.SNAPSHOT,
            "Create rollback snapshot",
            "after-customize" if orch.options.snapshots.enabled else "disabled",
        )
        snapshots.create("after-customize")

        orch._step(
            BuildPhase.KERNEL_MODULE,
            "Build kernel payload",
            orch.options.kernel_module.summary(),
        )
        if orch.options.kernel_module.enabled:
            snapshots.create("before-kernel")
        KernelModuleService(
            orch.runner,
            orch.project.squashfs_root,
            orch.project.workdir,
            orch.options.kernel_module,
            release=orch.project.release,
            use_sudo=orch.options.use_sudo,
        ).run()
        if orch.options.kernel_module.enabled:
            snapshots.create("after-kernel")

        orch._step(
            BuildPhase.SECURE_BOOT,
            "Secure Boot workflow",
            "enabled" if orch.options.secure_boot.enabled else "disabled",
        )
        SecureBootService(
            orch.runner,
            orch.project.squashfs_root,
            orch.options.secure_boot,
            use_sudo=orch.options.use_sudo,
        ).apply()

        orch._step(
            BuildPhase.REPRODUCIBLE,
            "Pin reproducible build inputs",
            orch.options.reproducible.pin_summary(),
        )
        ReproducibleService(orch.options.reproducible).apply()

        plugins.run_phase("pre-host")
        orch._step(BuildPhase.RUN_HOOKS, "Run customization hooks", "hooks")
        hooks.run_phase(orch.project.root / "hooks", "pre-host")
        if orch._stage_chroot_hooks():
            try:
                chroot.run("run-parts", "/distroforge-hooks")
            finally:
                orch._unstage_chroot_hooks()

        sanitize = SanitizeService(
            orch.runner,
            orch.project.squashfs_root,
            orch.options.sanitize,
            use_sudo=orch.options.use_sudo,
        )
        orch._step(
            BuildPhase.FINALIZE_PACKAGES,
            "Finalize package set",
            "guarded autoremove" if orch.options.sanitize.package_autoremove else "no autoremove",
        )
        sanitize.finalize_packages()
        orch._step(
            BuildPhase.PACKAGE_EVIDENCE,
            "Seal package inputs",
            "Release/Packages/keyrings/.deb bytes + self-consistent APT v3 receipt",
        )
        services.package_evidence.seal_before_cleanup()
        orch._step(
            BuildPhase.SANITIZE_TARGET,
            "Sanitize target",
            orch.options.sanitize.summary(),
        )
        sanitize.clean_target()
        orch._step(
            BuildPhase.SNAPSHOT,
            "Create rollback snapshot",
            "after-sanitize" if orch.options.snapshots.enabled else "disabled",
        )
        snapshots.create("after-sanitize")
    finally:
        chroot.unmount_runtime()


def assemble_iso(orch: BuildOrchestrator, services: BuildServices) -> None:
    iso = services.iso
    squashfs = services.squashfs
    casper = services.casper
    hooks = services.hooks
    plugins = services.plugins

    orch._step(BuildPhase.HEALTH, "Beginner-safe health report", "score")
    health = HealthService().score(orch.project, orch.options)
    orch.runner.run(
        CommandSpec(
            argv=("health-score", str(health.score), health.status),
            description="; ".join(health.messages) if health.messages else "No guardrail issues",
        )
    )

    orch._step(
        BuildPhase.AUTOINSTALL,
        "Generate autoinstall",
        "enabled" if orch.options.autoinstall.enabled else "disabled",
    )
    AutoinstallService(
        orch.runner,
        orch.project,
        orch.options.autoinstall,
        use_sudo=orch.options.use_sudo,
    ).write()

    orch._step(BuildPhase.SEEDS, "Write seeds", orch.options.seeds.seed_name)
    SeedService(
        orch.runner,
        orch.project,
        orch.options.seeds,
        use_sudo=orch.options.use_sudo,
    ).write()

    # Host hooks are the final authorized producers of either working tree.  Running
    # them after xorriso allowed a hook to replace the ISO or its staged SquashFS
    # after both had supposedly been sealed.
    hooks.run_phase(orch.project.root / "hooks", "post-host")
    plugins.run_phase("post-host")

    orch._step(
        BuildPhase.UPDATE_METADATA,
        "Update ISO metadata",
        "manifest and filesystem.size",
    )
    casper.update_manifest()
    casper.update_filesystem_size()

    compression = resolve_compression(
        orch.options.squashfs.compression, orch.project.release.compression
    )
    run_id = services.rootfs_evidence.run_id
    if not isinstance(run_id, str) or not run_id:
        raise ValueError("Final rootfs evidence requires a sealed build run_id")
    rootfs_manifest = evidence_run_path(
        orch.project.output_dir,
        run_id,
        "ROOTFS-MANIFEST.json",
        executed=orch.context.execute,
    )
    package_filesystem_causality = evidence_run_path(
        orch.project.output_dir,
        run_id,
        PACKAGE_FILESYSTEM_CAUSALITY_FILENAME,
        executed=orch.context.execute,
    )
    rootfs_verification = evidence_run_path(
        orch.project.output_dir,
        run_id,
        "ROOTFS-PACKING-VERIFICATION.json",
        executed=orch.context.execute,
    )
    iso_assembly_report = evidence_run_path(
        orch.project.output_dir,
        run_id,
        ISO_ASSEMBLY_FILENAME,
        executed=orch.context.execute,
    )
    unpacked_verification_root = orch.project.workdir / f".rootfs-packed-verification-{run_id}"
    iso_verification_root = orch.project.workdir / f".iso-assembly-verification-{run_id}"
    embedded_squashfs = iso_verification_root / "filesystem.squashfs"
    iso_member = f"/{orch.project.release.livefs.strip('/')}/filesystem.squashfs"
    staged_squashfs_identity: dict[str, object] | None = None

    orch._step(
        BuildPhase.ROOTFS_EVIDENCE_CAPTURE,
        "Seal final rootfs identity",
        (
            "pre-packing manifest and static bootstrap payload map"
            if orch.project.source_mode == "bootstrap"
            else "pre-packing manifest; ISO payload map remains unsupported"
        )
        if orch.context.execute
        else "planned only",
    )
    orch.runner.run(
        rootfs_capture_command(
            orch.project.squashfs_root,
            rootfs_manifest,
            run_id=run_id,
            use_sudo=orch.options.use_sudo,
        )
    )
    write_package_filesystem_causality(
        package_filesystem_causality.parent,
        expected_run_id=run_id,
        runner=orch.runner,
    )

    orch._step(BuildPhase.REPACK_FILESYSTEM, "Repack live filesystem", compression)
    squashfs.pack(
        orch.project.squashfs_root,
        orch._filesystem_image(),
        compression=compression,
        on_progress=orch._phase_progress,
    )

    orch._step(
        BuildPhase.ROOTFS_EVIDENCE_VERIFY,
        "Verify packed rootfs identity",
        "FD-witnessed SquashFS round-trip" if orch.context.execute else "planned only",
    )
    cleanup = FileSystemOps(orch.runner, orch.options.use_sudo)
    if not orch.context.execute:
        orch.runner.run(
            CommandSpec(
                argv=(
                    "unsquashfs",
                    "-no-progress",
                    "-d",
                    str(unpacked_verification_root),
                    str(orch._filesystem_image()),
                ),
                needs_root=orch.options.use_sudo,
                description="Plan packed rootfs verification extraction",
            )
        )
        orch.runner.run(
            CommandSpec(
                argv=("write-file", str(rootfs_verification)),
                description="Plan packed rootfs verification evidence",
            )
        )
        cleanup.remove_tree(
            unpacked_verification_root,
            "Plan cleanup of packed rootfs verification tree",
        )
    else:
        if unpacked_verification_root.exists() or unpacked_verification_root.is_symlink():
            raise ValueError(
                f"Packed rootfs verification destination is not fresh: {unpacked_verification_root}"
            )
        try:
            image_witness = PackedImageWitness(orch._filesystem_image())
            with image_witness:
                orch.runner.run(
                    rootfs_unpack_command(
                        image_witness,
                        unpacked_verification_root,
                        use_sudo=orch.options.use_sudo,
                    )
                )
            staged_squashfs_identity = image_witness.sealed_identity
            orch.runner.run(
                rootfs_verify_command(
                    orch.project.squashfs_root,
                    rootfs_manifest,
                    orch._filesystem_image(),
                    unpacked_verification_root,
                    staged_squashfs_identity,
                    rootfs_verification,
                    run_id=run_id,
                    use_sudo=orch.options.use_sudo,
                )
            )
        finally:
            cleanup.remove_tree(
                unpacked_verification_root,
                "Remove packed rootfs verification tree",
            )

    orch._step(BuildPhase.UPDATE_CHECKSUMS, "Update ISO checksums", "md5sum.txt")
    casper.update_md5sums()

    orch._step(BuildPhase.REBUILD_ISO, "Rebuild ISO", str(orch._output_iso()))
    output_iso = orch._output_iso()
    staging_iso = output_iso.with_name(f".{output_iso.name}.building-{run_id}")
    rebuilt_iso_identity = iso.rebuild(
        orch.project,
        output_iso,
        staging_output=staging_iso,
        on_progress=orch._phase_progress,
    )
    if not orch.context.execute:
        orch.runner.run(
            iso_extract_member_path_command(
                output_iso,
                iso_member,
                embedded_squashfs,
                use_sudo=orch.options.use_sudo,
            )
        )
        orch.runner.run(
            CommandSpec(
                argv=("write-file", str(iso_assembly_report)),
                description="Plan final ISO assembly identity evidence",
            )
        )
        cleanup.remove_tree(
            iso_verification_root,
            "Plan cleanup of final ISO assembly verification tree",
        )
    else:
        if staged_squashfs_identity is None:
            raise ValueError("Final ISO assembly lacks the staged SquashFS witness")
        if iso_verification_root.exists() or iso_verification_root.is_symlink():
            raise ValueError(
                f"Final ISO verification destination is not fresh: {iso_verification_root}"
            )
        iso_verification_root.mkdir(parents=False)
        try:
            final_iso_witness = StableFileWitness(output_iso)
            with final_iso_witness:
                orch.runner.run(
                    iso_extract_member_command(
                        final_iso_witness,
                        iso_member,
                        embedded_squashfs,
                        use_sudo=orch.options.use_sudo,
                    )
                )
            final_iso_identity = final_iso_witness.sealed_identity
            if rebuilt_iso_identity != final_iso_identity:
                raise ValueError(
                    "Final ISO changed between atomic publication and member extraction"
                )
            embedded_witness = StableFileWitness(embedded_squashfs)
            with embedded_witness:
                pass
            write_iso_assembly_evidence(
                iso_assembly_report,
                run_id=run_id,
                iso_member=iso_member,
                output_iso=final_iso_identity,
                staged_squashfs=staged_squashfs_identity,
                embedded_squashfs=embedded_witness.sealed_identity,
            )
        finally:
            cleanup.remove_tree(
                iso_verification_root,
                "Remove final ISO assembly verification tree",
            )

    orch._step(
        BuildPhase.PREBUILD_VM,
        "Run prebuild VM lab",
        orch.options.prebuild_vm.summary(),
    )
    QemuLabService(
        orch.runner,
        orch._output_iso(),
        orch.project.workdir,
        orch.project.output_dir,
        orch.options.prebuild_vm,
        run_id=str(getattr(orch.options, "_evidence_context", {}).get("run_id", "")) or None,
    ).run()

    orch._step(BuildPhase.RELEASE_ARTIFACTS, "Write release artifacts", "checksums")
    ReleaseArtifactService(
        orch.runner,
        orch.project.output_dir,
        orch._output_iso(),
        orch.options.release_artifacts,
    ).write()
    RedistributionAttestationService(orch.runner, orch.project).write(
        orch._output_iso(),
        orch.options.branding,
        strict=orch.options.policy.strict,
    )

    orch._step(
        BuildPhase.BOOTCHECK,
        "Boot smoke test",
        "enabled" if orch.options.bootcheck.enabled else "disabled",
    )
    BootCheckService(orch.runner, orch._output_iso(), orch.options.bootcheck).run()

    orch._step(
        BuildPhase.QEMU_SCREENSHOT,
        "Capture QEMU screenshot",
        "enabled" if orch.options.qemu_screenshot.enabled else "disabled",
    )
    QemuScreenshotService(
        orch.runner,
        orch._output_iso(),
        orch.project.output_dir,
        orch.options.qemu_screenshot,
    ).run()

    orch._step(BuildPhase.HTML_REPORT, "Write HTML report", orch.options.html_report.filename)
    HtmlReportService(orch.runner, orch.project, orch.options.html_report).write(
        orch.report,
        orch._output_iso(),
    )

    orch._step(
        BuildPhase.QA_MATRIX,
        "Run QA boot matrix",
        f"{len(orch.options.qa.scenarios)} scenario(s)",
    )
    QaMatrixService(
        orch.runner,
        orch._output_iso(),
        orch.project.workdir,
        orch.options.qa,
    ).run()

    if orch.options.run_preview:
        orch._step(BuildPhase.PREVIEW, "Preview ISO", str(orch._output_iso()))
        QemuPreviewService(
            orch.runner,
            orch._output_iso(),
            orch.project.workdir,
            orch.project.output_dir,
            QemuPreviewOptions(),
        ).run()

    close_run_identity(
        orch.project,
        orch.options,
        getattr(orch.options, "_evidence_context", None),
    )
    orch._step(BuildPhase.PROVENANCE, "Write SBOM/provenance", "json")
    ProvenanceService(
        orch.runner,
        orch.project,
        orch.options.provenance,
        getattr(orch.options, "_evidence_context", None),
    ).write(orch._output_iso(), orch._planned_packages())
