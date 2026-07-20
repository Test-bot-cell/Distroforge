from __future__ import annotations

from dataclasses import dataclass
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
from .health import HealthService
from .hooks import HookRunner
from .html_report import HtmlReportService
from .importer import ImportService
from .iso import IsoService
from .kernel import KernelModuleService
from .kiosk import KioskService
from .mirrors import MirrorService
from .network import NetworkService
from .oem import OemService
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
from .sanitize import SanitizeService
from .secureboot import SecureBootService
from .seeds import SeedService
from .size_analysis import SizeAnalysisService
from .snaps import SnapService
from .snapshots import SnapshotService
from .squashfs import SquashfsService
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


def run_preflight(orch: BuildOrchestrator) -> None:
    orch._step(
        BuildPhase.VALIDATE,
        "Validate project",
        "project and host preflight",
    )
    issues = validate_for_build(
        orch.project, orch.runner, execute=orch.context.execute
    )
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
            orch.project.source_iso, orch.options.trust, orch.runner, strict=orch.options.policy.strict
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
    clearance_mode = "redistributable" if orch.options.policy.strict else orch.options.policy.branding_mode
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
    iso = IsoService(orch.runner, use_sudo=orch.options.use_sudo)
    squashfs = SquashfsService(orch.runner, use_sudo=orch.options.use_sudo)
    apt = AptService(
        orch.runner,
        orch.project.squashfs_root,
        orch.project.release,
        use_sudo=orch.options.use_sudo,
        arch=orch.options.bootstrap.arch,
    )
    chroot = ChrootService(
        orch.runner, orch.project.squashfs_root, use_sudo=orch.options.use_sudo
    )
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
        BootstrapService(
            orch.runner,
            orch.project.release,
            orch.project.squashfs_root,
            orch.project.iso_root,
            orch.options.bootstrap,
            use_sudo=orch.options.use_sudo,
        ).prepare()
    else:
        orch._step(BuildPhase.EXTRACT_ISO, "Extract ISO", orch._source_iso_text())
        iso.extract(orch._require_source_iso(), orch.project.iso_root, on_progress=orch._phase_progress)

        orch._step(
            BuildPhase.UNPACK_FILESYSTEM,
            "Unpack live filesystem",
            str(orch._filesystem_image()),
        )
        squashfs.unpack(
            orch._filesystem_image(), orch.project.squashfs_root, on_progress=orch._phase_progress
        )


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
        VulnScanService(orch.options.vuln_scan).enforce(
            orch._planned_packages(), orch.runner
        )
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
            "Apply reproducible build hints",
            "enabled" if orch.options.reproducible.enabled else "disabled",
        )
        ReproducibleService(
            orch.runner,
            orch.project.squashfs_root,
            orch.options.reproducible,
            use_sudo=orch.options.use_sudo,
        ).apply()

        plugins.run_phase("pre-host")
        orch._step(BuildPhase.RUN_HOOKS, "Run customization hooks", "hooks")
        hooks.run_phase(orch.project.root / "hooks", "pre-host")
        if orch._stage_chroot_hooks():
            chroot.run("run-parts", "/distroforge-hooks")

        orch._step(
            BuildPhase.SANITIZE_TARGET,
            "Sanitize target",
            orch.options.sanitize.summary(),
        )
        SanitizeService(
            orch.runner,
            orch.project.squashfs_root,
            orch.options.sanitize,
            use_sudo=orch.options.use_sudo,
        ).run()
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

    orch._step(
        BuildPhase.UPDATE_METADATA,
        "Update ISO metadata",
        "manifest and filesystem.size",
    )
    casper.update_manifest()
    casper.update_filesystem_size()

    orch._step(
        BuildPhase.REPACK_FILESYSTEM,
        "Repack live filesystem",
        orch.project.release.compression,
    )
    squashfs.pack(
        orch.project.squashfs_root,
        orch._filesystem_image(),
        compression=orch.project.release.compression,
        on_progress=orch._phase_progress,
    )

    orch._step(BuildPhase.UPDATE_CHECKSUMS, "Update ISO checksums", "md5sum.txt")
    casper.update_md5sums()

    orch._step(BuildPhase.REBUILD_ISO, "Rebuild ISO", str(orch._output_iso()))
    iso.rebuild(orch.project, orch._output_iso(), on_progress=orch._phase_progress)
    hooks.run_phase(orch.project.root / "hooks", "post-host")
    plugins.run_phase("post-host")

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

    orch._step(BuildPhase.PROVENANCE, "Write SBOM/provenance", "json")
    ProvenanceService(orch.runner, orch.project, orch.options.provenance).write(
        orch._output_iso(), orch._planned_packages()
    )

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
