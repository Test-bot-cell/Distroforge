from __future__ import annotations

import argparse
from pathlib import Path

from distroforge.core.apt import PackagePlan
from distroforge.core.apt_cache import AptCacheOptions
from distroforge.core.autoinstall import AutoinstallOptions
from distroforge.core.bootcheck import BootCheckOptions
from distroforge.core.bootstrap import BootstrapOptions
from distroforge.core.branding import BrandingOptions
from distroforge.core.branding_palettes import load_branding_palettes, parse_palette_colors
from distroforge.core.build import BuildOptions
from distroforge.core.customize import load_desktops
from distroforge.core.definition import apply_definition, load_definition
from distroforge.core.desktop_source import DesktopSourceComponent, DesktopSourceOptions
from distroforge.core.drivers import DriverOptions
from distroforge.core.html_report import HtmlReportOptions
from distroforge.core.importer import ImportOptions
from distroforge.core.kernel import KernelModuleOptions
from distroforge.core.kiosk import KioskOptions
from distroforge.core.mirrors import MirrorOptions
from distroforge.core.network import NetworkOptions
from distroforge.core.oem import OemOptions
from distroforge.core.persona import get_persona, load_personas
from distroforge.core.plugins import PluginOptions
from distroforge.core.policy import PolicyOptions
from distroforge.core.ppa import PpaOptions, PpaSpec
from distroforge.core.prebuild_vm import PrebuildVmOptions
from distroforge.core.profiles import get_profile
from distroforge.core.project import Project
from distroforge.core.provenance import ProvenanceOptions
from distroforge.core.qa import QaOptions
from distroforge.core.qemu_screenshot import QemuScreenshotOptions
from distroforge.core.release_artifacts import ReleaseArtifactOptions
from distroforge.core.release_track import ReleaseTrackOptions
from distroforge.core.reproducible import ReproducibleOptions
from distroforge.core.sanitize import SanitizeOptions
from distroforge.core.secureboot import SecureBootOptions
from distroforge.core.seeds import SeedOptions
from distroforge.core.size_analysis import SizeAnalysisOptions
from distroforge.core.snaps import SnapOptions, SnapSpec
from distroforge.core.snapshots import SnapshotOptions
from distroforge.core.system_sync import SystemSyncOptions
from distroforge.core.systemd import SystemdOptions
from distroforge.core.trust import TrustOptions
from distroforge.core.users import UserOptions, UserSpec
from distroforge.core.vulnscan import VulnScanOptions


def register_build_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("root", type=Path)
    parser.add_argument("--source-iso", type=Path)
    parser.add_argument("--definition", type=Path)
    register_trust_arguments(parser)
    parser.add_argument("--persona", choices=list(load_personas()))
    parser.add_argument("--from-scratch", action="store_true")
    parser.add_argument("--bootstrap-arch", default="amd64")
    parser.add_argument("--bootstrap-variant", default="minbase")
    parser.add_argument("--bootstrap-mirror")
    parser.add_argument("--output-iso", type=Path)
    parser.add_argument("--install", action="append", default=[])
    parser.add_argument("--remove", action="append", default=[])
    parser.add_argument("--profile", action="append", default=[])
    parser.add_argument("--snap", action="append", default=[])
    parser.add_argument(
        "--ppa",
        action="append",
        default=[],
        help="Verified Launchpad PPA, e.g. ppa:owner/name or ppa:owner/name@FINGERPRINT",
    )
    parser.add_argument("--ppa-no-auto-key", action="store_true")
    parser.add_argument("--apt-cache", action="store_true")
    parser.add_argument("--apt-cache-dir", type=Path)
    parser.add_argument("--apt-proxy")
    parser.add_argument("--mirrors", action="store_true", help="Use deb822 mirror layer for default APT sources")
    parser.add_argument("--mirror-archive")
    parser.add_argument("--mirror-security")
    parser.add_argument("--mirror-country")
    parser.add_argument("--mirror-allow-http", action="store_true")
    parser.add_argument("--mirror-override-ubuntu-security", action="store_true")
    parser.add_argument("--snapshot", action="store_true")
    parser.add_argument("--auto-restore-on-failure", action="store_true")
    parser.add_argument("--oem", action="store_true")
    parser.add_argument("--enable-service", action="append", default=[])
    parser.add_argument("--disable-service", action="append", default=[])
    parser.add_argument("--mask-service", action="append", default=[])
    parser.add_argument(
        "--user",
        action="append",
        default=[],
        help="Create user as name[:group1,group2[:password_hash]]",
    )
    parser.add_argument("--netplan-dhcp", action="store_true")
    parser.add_argument("--dns", action="append", default=[])
    parser.add_argument("--kiosk", action="store_true")
    parser.add_argument("--kiosk-url", default="about:blank")
    parser.add_argument("--kiosk-browser", default="firefox")
    parser.add_argument("--kiosk-user", default="ubuntu")
    parser.add_argument("--drivers-auto", action="store_true")
    parser.add_argument("--release-track", choices=["stable", "devel", "rolling"], default="stable")
    parser.add_argument("--devel-suite", default="devel")
    parser.add_argument("--enable-backports", action="store_true")
    parser.add_argument("--enable-proposed", action="store_true")
    parser.add_argument("--proposed-pin", type=int, default=100)
    parser.add_argument("--rolling-upgrades", action="store_true")
    parser.add_argument("--rolling-full-upgrade", action="store_true")
    parser.add_argument("--system-sync", action="store_true")
    parser.add_argument("--system-sync-strategy", choices=["safe", "full"], default="full")
    parser.add_argument("--system-sync-no-fallback", action="store_true")
    parser.add_argument("--system-sync-hold", action="append", default=[])
    parser.add_argument("--system-sync-post-install-only", action="store_true")
    parser.add_argument("--system-sync-no-post-install-tool", action="store_true")
    parser.add_argument("--autoinstall", action="store_true")
    parser.add_argument("--autoinstall-user", default="ubuntu")
    parser.add_argument("--autoinstall-realname", default="Ubuntu User")
    parser.add_argument("--autoinstall-password-hash")
    parser.add_argument("--autoinstall-package", action="append", default=[])
    parser.add_argument("--autoinstall-late-command", action="append", default=[])
    parser.add_argument("--brand-name")
    parser.add_argument("--brand-pretty-name")
    parser.add_argument("--brand-product-name")
    parser.add_argument("--brand-vendor")
    parser.add_argument("--brand-os-id")
    parser.add_argument("--brand-id-like")
    parser.add_argument("--brand-version-id")
    parser.add_argument("--brand-version-codename")
    parser.add_argument("--brand-home-url")
    parser.add_argument("--brand-support-url")
    parser.add_argument("--brand-bug-report-url")
    parser.add_argument("--brand-privacy-policy-url")
    parser.add_argument("--brand-ansi-color")
    parser.add_argument("--brand-icon-name")
    parser.add_argument("--brand-palette", choices=[*load_branding_palettes(), "generate"])
    parser.add_argument("--brand-palette-colors", help="Custom #hex palette, comma-separated")
    parser.add_argument("--brand-palette-seed")
    parser.add_argument("--brand-logo")
    parser.add_argument("--brand-distributor-logo")
    parser.add_argument("--brand-app-icon")
    parser.add_argument("--brand-grub-background")
    parser.add_argument("--brand-grub-theme")
    parser.add_argument("--brand-grub-distributor")
    parser.add_argument("--brand-grub-menu-label")
    parser.add_argument("--brand-plymouth-theme")
    parser.add_argument("--brand-plymouth-logo")
    parser.add_argument("--brand-plymouth-spinner")
    parser.add_argument("--brand-plymouth-background")
    parser.add_argument("--brand-plymouth-main-color")
    parser.add_argument("--brand-login-background")
    parser.add_argument("--brand-lightdm-background")
    parser.add_argument("--brand-installer-slideshow")
    parser.add_argument("--brand-issue")
    parser.add_argument("--brand-motd")
    parser.add_argument("--secure-boot", action="store_true")
    parser.add_argument("--secure-boot-mok-key")
    parser.add_argument("--secure-boot-mok-cert")
    parser.add_argument("--secure-boot-sign-modules", action="store_true")
    parser.add_argument("--qa", action="append", default=[])
    parser.add_argument("--bootcheck", action="store_true")
    parser.add_argument("--prebuild-vm", action="store_true")
    parser.add_argument("--prebuild-vm-profile", choices=["live", "install", "rescue"], default="live")
    parser.add_argument("--prebuild-vm-firmware", choices=["bios", "uefi"], default="bios")
    parser.add_argument("--prebuild-vm-secure-boot", action="store_true")
    parser.add_argument("--prebuild-vm-tpm", action="store_true")
    parser.add_argument("--prebuild-vm-memory", type=int, default=4096)
    parser.add_argument("--prebuild-vm-cpus", type=int, default=2)
    parser.add_argument("--prebuild-vm-disk-size", default="24G")
    parser.add_argument("--prebuild-vm-network", action="store_true")
    parser.add_argument("--prebuild-vm-timeout", type=int, default=300)
    parser.add_argument("--prebuild-vm-serial-log", default="prebuild-vm-serial.log")
    parser.add_argument("--prebuild-vm-no-screenshot", action="store_true")
    parser.add_argument("--prebuild-vm-screenshot-name", default="prebuild-vm.ppm")
    parser.add_argument("--prebuild-vm-qmp-socket", default="qemu-lab.qmp")
    parser.add_argument("--prebuild-vm-pid-file", default="qemu-lab.pid")
    parser.add_argument("--prebuild-vm-report-name", default="qemu-lab-report.json")
    parser.add_argument("--prebuild-vm-ovmf-code", default="/usr/share/OVMF/OVMF_CODE.fd")
    parser.add_argument("--prebuild-vm-ovmf-vars", default="/usr/share/OVMF/OVMF_VARS.fd")
    parser.add_argument("--prebuild-vm-success-pattern", action="append", default=[])
    parser.add_argument("--qemu-screenshot", action="store_true")
    parser.add_argument("--policy-strict", action="store_true")
    parser.add_argument(
        "--brand-compliance-mode",
        choices=["internal", "redistributable", "approved"],
        default="internal",
    )
    parser.add_argument("--size-report", action="store_true")
    parser.add_argument("--size-top", type=int, default=50)
    parser.add_argument("--vuln-scan", action="store_true")
    parser.add_argument(
        "--vuln-policy",
        choices=["off", "warn", "block-high", "block-critical"],
        default="warn",
    )
    parser.add_argument("--vuln-db", type=Path)
    parser.add_argument("--sbom-format", choices=["native", "spdx", "cyclonedx"], default="native")
    parser.add_argument("--reproducible", action="store_true")
    parser.add_argument("--source-date-epoch", type=int)
    parser.add_argument("--apt-snapshot")
    parser.add_argument("--plugin-dir", type=Path)
    parser.add_argument("--import-script", action="append", type=Path, default=[])
    parser.add_argument("--no-release-artifacts", action="store_true")
    parser.add_argument("--sign-artifacts", action="store_true")
    parser.add_argument("--artifact-gpg-key")
    parser.add_argument("--no-html-report", action="store_true")
    parser.add_argument("--html-report-name", default="report.html")
    register_customization_arguments(parser)
    parser.add_argument("--purge", action="store_true")
    parser.add_argument("--preview", action="store_true")
    parser.add_argument("--synaptic", action="store_true")
    parser.add_argument("--no-sanitize", action="store_true")
    parser.add_argument("--sanitize-apt-lists", action="store_true")
    parser.add_argument("--sanitize-ssh-host-keys", action="store_true")
    parser.add_argument("--no-prune-obsolete-packages", action="store_true")
    parser.add_argument("--keep-logs", action="store_true")
    parser.add_argument("--keep-history", action="store_true")
    parser.add_argument("--keep-machine-id", action="store_true")
    parser.add_argument("--keep-temp", action="store_true")
    parser.add_argument("--kernel-module", type=Path)
    parser.add_argument("--kernel-module-subdir")
    parser.add_argument("--kernel-module-name")
    parser.add_argument("--kernel-channel", default="stable", choices=["stable", "longterm", "mainline"])
    parser.add_argument("--kernel-version")
    parser.add_argument("--kernel-source-url")
    parser.add_argument("--kernel-pgp-url")
    parser.add_argument("--kernel-source-sha256")
    parser.add_argument("--no-kernel-pgp", action="store_true")
    parser.add_argument("--kernel-gpg-keyring")
    parser.add_argument("--kernel-gpg-fingerprint")
    parser.add_argument("--kernel-require-sha256", action="store_true")
    parser.add_argument("--kernel-require-gpg", action="store_true")
    parser.add_argument("--prune-obsolete-kernels", action="store_true")
    parser.add_argument("--kernel-full-deb", action="store_true")
    parser.add_argument("--kernel-localversion", default="-dforge")
    parser.add_argument("--kernel-jobs", type=int, default=0)
    parser.add_argument("--kernel-config-strategy", choices=["current", "defconfig"], default="current")
    parser.add_argument("--kernel-no-install-debs", action="store_true")
    parser.add_argument("--desktop-source", action="store_true")
    parser.add_argument("--desktop-source-version")
    parser.add_argument(
        "--desktop-source-component",
        action="append",
        default=[],
        help="Upstream DE component as name|version|url[|sha256|build_system|package]",
    )
    parser.add_argument("--desktop-source-build-dep", action="append", default=[])
    parser.add_argument("--desktop-source-jobs", type=int, default=0)
    parser.add_argument("--desktop-source-local-suffix", default="dforge")
    parser.add_argument("--desktop-source-no-install-debs", action="store_true")
    parser.add_argument("--desktop-source-require-sha256", action="store_true")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--ci", action="store_true")
    parser.add_argument("--skip-deps-check", action="store_true")
    parser.add_argument("--no-sudo", action="store_true")
    parser.add_argument("--privilege", choices=["sudo", "pkexec", "none"], default="sudo")
    parser.add_argument("--log-file", type=Path)


def register_customization_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--desktop", choices=list(load_desktops()))
    parser.add_argument("--display-manager", choices=["gdm3", "lightdm", "sddm"])
    parser.add_argument("--autologin-user")
    parser.add_argument("--wallpaper", type=Path)
    parser.add_argument("--hostname")
    parser.add_argument("--locale")
    parser.add_argument("--timezone")
    parser.add_argument("--keyboard-layout")


def register_trust_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--source-iso-sha256")
    parser.add_argument("--source-iso-signature", type=Path)
    parser.add_argument("--source-iso-gpg-fingerprint")
    parser.add_argument("--require-source-iso-checksum", action="store_true")
    parser.add_argument("--require-source-iso-signature", action="store_true")


def build_options_from_args(project: Project, args: argparse.Namespace) -> BuildOptions:
    installs = [*_profile_installs(args.profile), *_csv_args(args.install)]
    removes = [*_profile_removes(args.profile), *_csv_args(args.remove)]
    return BuildOptions(
        output_iso=args.output_iso,
        package_plan=PackagePlan(
            install=installs,
            remove=removes,
            purge=args.purge,
        ),
        run_preview=args.preview,
        run_synaptic=args.synaptic,
        use_sudo=not args.no_sudo,
        sanitize=SanitizeOptions(
            enabled=not args.no_sanitize,
            package_autoremove=not args.no_prune_obsolete_packages,
            apt_cache=True,
            apt_lists=args.sanitize_apt_lists,
            logs=not args.keep_logs,
            shell_history=not args.keep_history,
            machine_id=not args.keep_machine_id,
            temp_files=not args.keep_temp,
            ssh_host_keys=args.sanitize_ssh_host_keys,
        ),
        bootstrap=_bootstrap_options(args),
        kernel_module=_kernel_module_options(args),
        desktop_source=_desktop_source_options(project, args),
        snaps=_snap_options(args),
        drivers=_driver_options(args),
        release_track=_release_track_options(args),
        system_sync=_system_sync_options(args),
        autoinstall=_autoinstall_options(project, args),
        branding=_branding_options(args),
        secure_boot=_secure_boot_options(args),
        seeds=SeedOptions(packages=installs, snaps=args.snap),
        qa=_qa_options(args),
        prebuild_vm=_prebuild_vm_options(args),
        ppa=_ppa_options(args),
        apt_cache=_apt_cache_options(args),
        snapshots=SnapshotOptions(
            enabled=args.snapshot,
            auto_restore_on_failure=args.auto_restore_on_failure,
        ),
        oem=OemOptions(enabled=args.oem),
        systemd=SystemdOptions(
            enable=_csv_args(args.enable_service),
            disable=_csv_args(args.disable_service),
            mask=_csv_args(args.mask_service),
        ),
        users=UserOptions(_user_specs(args.user)),
        network=NetworkOptions(
            netplan_dhcp=args.netplan_dhcp,
            dns=_csv_args(args.dns) or None,
            apt_proxy=args.apt_proxy,
        ),
        mirrors=_mirror_options(args),
        kiosk=KioskOptions(
            enabled=args.kiosk,
            browser=args.kiosk_browser,
            url=args.kiosk_url,
            user=args.kiosk_user,
        ),
        bootcheck=BootCheckOptions(enabled=args.bootcheck),
        qemu_screenshot=QemuScreenshotOptions(enabled=args.qemu_screenshot),
        policy=PolicyOptions(strict=args.policy_strict, branding_mode=args.brand_compliance_mode),
        size_analysis=SizeAnalysisOptions(enabled=args.size_report, top=args.size_top),
        reproducible=ReproducibleOptions(
            enabled=args.reproducible,
            source_date_epoch=args.source_date_epoch,
            apt_snapshot=args.apt_snapshot,
        ),
        plugins=PluginOptions(args.plugin_dir),
        release_artifacts=ReleaseArtifactOptions(
            enabled=not args.no_release_artifacts,
            sign=args.sign_artifacts,
            gpg_key=args.artifact_gpg_key,
        ),
        html_report=HtmlReportOptions(
            enabled=not args.no_html_report,
            filename=args.html_report_name,
        ),
        import_scripts=ImportOptions(args.import_script),
        trust=_trust_options(args),
        vuln_scan=VulnScanOptions(
            enabled=args.vuln_scan,
            policy=args.vuln_policy,
            db_path=args.vuln_db,
        ),
        provenance=ProvenanceOptions(sbom_format=args.sbom_format),
    )


def apply_cli_overrides(project: Project, args: argparse.Namespace, options: BuildOptions) -> None:
    _apply_persona(args, options)
    _apply_cli_options(project, args, options)


def project_options_from_args(args: argparse.Namespace) -> tuple[Project, BuildOptions]:
    project = Project.load(args.root)
    sanitize_message = project.desktop_sanitization_message()
    if sanitize_message:
        print(sanitize_message)
    options = BuildOptions()
    if getattr(args, "definition", None):
        options = apply_definition(project, load_definition(args.definition))
    if getattr(args, "no_sudo", False):
        options.use_sudo = False
    apply_trust_args(options, args)
    return project, options


def apply_trust_args(options: BuildOptions | TrustOptions, args: argparse.Namespace) -> None:
    trust = options.trust if isinstance(options, BuildOptions) else options
    if getattr(args, "source_iso_sha256", None):
        trust.source_sha256 = args.source_iso_sha256
    if getattr(args, "source_iso_signature", None):
        trust.source_signature = args.source_iso_signature
    if getattr(args, "source_iso_gpg_fingerprint", None):
        trust.source_gpg_fingerprint = args.source_iso_gpg_fingerprint
    if getattr(args, "require_source_iso_checksum", False):
        trust.require_source_checksum = True
    if getattr(args, "require_source_iso_signature", False):
        trust.require_source_signature = True


def apply_customization_args(project: Project, args: argparse.Namespace) -> None:
    custom = project.customization
    if getattr(args, "desktop", None):
        custom.desktop = args.desktop
    if getattr(args, "display_manager", None):
        custom.display_manager = args.display_manager
    if getattr(args, "autologin_user", None):
        custom.autologin_user = args.autologin_user
    if getattr(args, "wallpaper", None):
        custom.wallpaper = str(args.wallpaper)
    if getattr(args, "hostname", None):
        custom.hostname = args.hostname
    if getattr(args, "locale", None):
        custom.locale = args.locale
    if getattr(args, "timezone", None):
        custom.timezone = args.timezone
    if getattr(args, "keyboard_layout", None):
        custom.keyboard_layout = args.keyboard_layout


def _csv_args(values: list[str]) -> list[str]:
    items: list[str] = []
    for value in values:
        items.extend(part.strip() for part in value.split(",") if part.strip())
    return items


def _profile_installs(keys: list[str]) -> list[str]:
    packages: list[str] = []
    for key in keys:
        packages.extend(get_profile(key).install)
    return packages


def _profile_removes(keys: list[str]) -> list[str]:
    packages: list[str] = []
    for key in keys:
        packages.extend(get_profile(key).remove)
    return packages


def _bootstrap_options(args: argparse.Namespace) -> BootstrapOptions:
    return BootstrapOptions(
        arch=args.bootstrap_arch,
        variant=args.bootstrap_variant,
        mirror=args.bootstrap_mirror,
    )


def _kernel_module_options(args: argparse.Namespace) -> KernelModuleOptions:
    build_mode = "full-deb" if args.kernel_full_deb else "module"
    return KernelModuleOptions(
        enabled=bool(args.kernel_full_deb or args.kernel_module or args.kernel_module_subdir),
        build_mode=build_mode,
        channel=args.kernel_channel,
        version=args.kernel_version,
        source_url=args.kernel_source_url,
        pgp_url=args.kernel_pgp_url,
        source_sha256=args.kernel_source_sha256,
        module_source=str(args.kernel_module) if args.kernel_module else None,
        module_subdir=args.kernel_module_subdir,
        module_name=args.kernel_module_name,
        verify_pgp=not args.no_kernel_pgp,
        prune_obsolete_kernels=args.prune_obsolete_kernels,
        localversion=args.kernel_localversion,
        jobs=args.kernel_jobs,
        config_strategy=args.kernel_config_strategy,
        install_debs=not args.kernel_no_install_debs,
        gpg_keyring=args.kernel_gpg_keyring,
        gpg_fingerprint=args.kernel_gpg_fingerprint,
        require_sha256=args.kernel_require_sha256,
        require_gpg=args.kernel_require_gpg,
    )


def _desktop_source_options(project: Project, args: argparse.Namespace) -> DesktopSourceOptions:
    return DesktopSourceOptions(
        enabled=bool(args.desktop_source),
        desktop=args.desktop or project.customization.desktop,
        version=args.desktop_source_version,
        components=[
            DesktopSourceComponent.parse(value)
            for value in getattr(args, "desktop_source_component", [])
        ],
        install_debs=not args.desktop_source_no_install_debs,
        jobs=args.desktop_source_jobs,
        local_suffix=args.desktop_source_local_suffix,
        build_dependencies=_csv_args(getattr(args, "desktop_source_build_dep", [])),
        require_sha256=args.desktop_source_require_sha256,
    )


def _snap_options(args: argparse.Namespace) -> SnapOptions:
    return SnapOptions([SnapSpec.parse(value) for value in args.snap])


def _driver_options(args: argparse.Namespace) -> DriverOptions:
    return DriverOptions(auto=args.drivers_auto)


def _release_track_options(args: argparse.Namespace) -> ReleaseTrackOptions:
    return ReleaseTrackOptions(
        mode=args.release_track,
        devel_suite=args.devel_suite,
        enable_backports=args.enable_backports,
        enable_proposed=args.enable_proposed,
        proposed_pin=args.proposed_pin,
        enable_unattended_upgrades=args.rolling_upgrades,
        full_upgrade=args.rolling_full_upgrade,
    )


def _system_sync_options(args: argparse.Namespace) -> SystemSyncOptions:
    return SystemSyncOptions(
        enabled=bool(args.system_sync),
        strategy=args.system_sync_strategy,
        fallback=not args.system_sync_no_fallback,
        run_during_build=not args.system_sync_post_install_only,
        post_install_tool=not args.system_sync_no_post_install_tool,
        hold_packages=_csv_args(getattr(args, "system_sync_hold", [])),
    )


def _autoinstall_options(project: Project, args: argparse.Namespace) -> AutoinstallOptions:
    return AutoinstallOptions(
        enabled=args.autoinstall,
        username=args.autoinstall_user,
        realname=args.autoinstall_realname,
        hostname=project.customization.hostname,
        password_hash=args.autoinstall_password_hash or "$y$j9T$replace-me$replace-me",
        locale=project.customization.locale,
        keyboard=project.customization.keyboard_layout,
        timezone=project.customization.timezone,
        drivers_install=args.drivers_auto,
        packages=_csv_args(args.autoinstall_package),
        late_commands=args.autoinstall_late_command,
    )


def _branding_options(args: argparse.Namespace) -> BrandingOptions:
    return BrandingOptions(
        name=args.brand_name,
        pretty_name=args.brand_pretty_name,
        product_name=args.brand_product_name,
        vendor=args.brand_vendor,
        os_id=args.brand_os_id,
        id_like=args.brand_id_like,
        version_id=args.brand_version_id,
        version_codename=args.brand_version_codename,
        home_url=args.brand_home_url,
        support_url=args.brand_support_url,
        bug_report_url=args.brand_bug_report_url,
        privacy_policy_url=args.brand_privacy_policy_url,
        ansi_color=args.brand_ansi_color,
        icon_name=args.brand_icon_name,
        palette=args.brand_palette,
        palette_colors=parse_palette_colors(args.brand_palette_colors)
        if args.brand_palette_colors
        else (),
        palette_seed=args.brand_palette_seed,
        logo=args.brand_logo,
        distributor_logo=args.brand_distributor_logo,
        app_icon=args.brand_app_icon,
        grub_background=args.brand_grub_background,
        grub_theme=args.brand_grub_theme,
        grub_distributor=args.brand_grub_distributor,
        grub_menu_label=args.brand_grub_menu_label,
        plymouth_theme=args.brand_plymouth_theme,
        plymouth_logo=args.brand_plymouth_logo,
        plymouth_spinner=args.brand_plymouth_spinner,
        plymouth_background=args.brand_plymouth_background,
        plymouth_main_color=args.brand_plymouth_main_color,
        login_background=args.brand_login_background,
        lightdm_background=args.brand_lightdm_background,
        installer_slideshow=args.brand_installer_slideshow,
        issue_text=args.brand_issue,
        motd_text=args.brand_motd,
    )


def _secure_boot_options(args: argparse.Namespace) -> SecureBootOptions:
    return SecureBootOptions(
        enabled=args.secure_boot,
        mok_key=args.secure_boot_mok_key,
        mok_cert=args.secure_boot_mok_cert,
        sign_modules=args.secure_boot_sign_modules,
    )


def _qa_options(args: argparse.Namespace) -> QaOptions:
    scenarios: list[str] = []
    for value in args.qa:
        scenarios.extend(part.strip() for part in value.split(",") if part.strip())
    return QaOptions(scenarios)


def _prebuild_vm_options(args: argparse.Namespace) -> PrebuildVmOptions:
    return PrebuildVmOptions(
        enabled=bool(args.prebuild_vm),
        profile=args.prebuild_vm_profile,
        firmware=args.prebuild_vm_firmware,
        secure_boot=args.prebuild_vm_secure_boot,
        tpm=args.prebuild_vm_tpm,
        memory_mb=args.prebuild_vm_memory,
        cpus=args.prebuild_vm_cpus,
        disk_size=args.prebuild_vm_disk_size,
        network=args.prebuild_vm_network,
        timeout_seconds=args.prebuild_vm_timeout,
        serial_log=args.prebuild_vm_serial_log,
        screenshot=not args.prebuild_vm_no_screenshot,
        screenshot_name=args.prebuild_vm_screenshot_name,
        success_patterns=args.prebuild_vm_success_pattern or ["login:", "Reached target"],
        qmp_socket=args.prebuild_vm_qmp_socket,
        pid_file=args.prebuild_vm_pid_file,
        report_name=args.prebuild_vm_report_name,
        ovmf_code=args.prebuild_vm_ovmf_code,
        ovmf_vars=args.prebuild_vm_ovmf_vars,
    )


def _ppa_options(args: argparse.Namespace) -> PpaOptions:
    return PpaOptions(
        ppas=[PpaSpec.parse(value) for value in args.ppa],
        auto_fetch_fingerprint=not args.ppa_no_auto_key,
    )


def _apt_cache_options(args: argparse.Namespace) -> AptCacheOptions:
    return AptCacheOptions(
        enabled=args.apt_cache or bool(args.apt_proxy),
        cache_dir=args.apt_cache_dir,
        proxy_url=args.apt_proxy,
    )


def _mirror_options(args: argparse.Namespace) -> MirrorOptions:
    return MirrorOptions(
        enabled=getattr(args, "mirrors", False),
        archive_mirror=getattr(args, "mirror_archive", None),
        security_mirror=getattr(args, "mirror_security", None),
        country=getattr(args, "mirror_country", None),
        require_https=not getattr(args, "mirror_allow_http", False),
        keep_canonical_security=not getattr(args, "mirror_override_ubuntu_security", False),
    )


def _trust_options(args: argparse.Namespace) -> TrustOptions:
    return TrustOptions(
        source_sha256=getattr(args, "source_iso_sha256", None),
        source_signature=getattr(args, "source_iso_signature", None),
        source_gpg_fingerprint=getattr(args, "source_iso_gpg_fingerprint", None),
        require_source_checksum=getattr(args, "require_source_iso_checksum", False),
        require_source_signature=getattr(args, "require_source_iso_signature", False),
    )


def _user_specs(values: list[str]) -> list[UserSpec]:
    users: list[UserSpec] = []
    for value in values:
        name, groups, password_hash = _split_user_spec(value)
        users.append(UserSpec(name=name, groups=groups, password_hash=password_hash))
    return users


def _split_user_spec(value: str) -> tuple[str, list[str], str | None]:
    parts = value.split(":", 2)
    name = parts[0].strip()
    if not name:
        raise ValueError("User spec must start with a username")
    groups = ["sudo", "audio", "video"]
    password_hash = None
    if len(parts) >= 2 and parts[1].strip():
        groups = [part.strip() for part in parts[1].split(",") if part.strip()]
    if len(parts) == 3 and parts[2].strip():
        password_hash = parts[2].strip()
    return name, groups, password_hash


def _apply_persona(args: argparse.Namespace, options: BuildOptions) -> None:
    if not getattr(args, "persona", None):
        return
    persona = get_persona(args.persona)
    options.sanitize.apt_lists = persona.sanitize_apt_lists
    options.sanitize.ssh_host_keys = persona.sanitize_ssh_host_keys
    options.drivers.auto = persona.drivers_auto
    if not options.qa.scenarios:
        options.qa.scenarios = list(persona.qemu_matrix)
    options.provenance.enabled = persona.sbom


def _apply_cli_options(project: Project, args: argparse.Namespace, options: BuildOptions) -> None:
    if args.output_iso:
        options.output_iso = args.output_iso
    if args.preview:
        options.run_preview = True
    if args.synaptic:
        options.run_synaptic = True
    if args.ci:
        options.run_synaptic = False
    options.use_sudo = not args.no_sudo
    if getattr(args, "ppa", None) and not options.ppa.ppas:
        options.ppa.ppas.extend(PpaSpec.parse(value) for value in args.ppa)
        options.ppa.auto_fetch_fingerprint = not args.ppa_no_auto_key
    if getattr(args, "apt_cache", False) or getattr(args, "apt_proxy", None):
        options.apt_cache.enabled = True
        options.apt_cache.cache_dir = args.apt_cache_dir
        options.apt_cache.proxy_url = args.apt_proxy
        options.network.apt_proxy = args.apt_proxy
    if getattr(args, "snapshot", False):
        options.snapshots.enabled = True
    if getattr(args, "oem", False):
        options.oem.enabled = True
    if not options.systemd.enable:
        options.systemd.enable.extend(_csv_args(getattr(args, "enable_service", [])))
    if not options.systemd.disable:
        options.systemd.disable.extend(_csv_args(getattr(args, "disable_service", [])))
    if not options.systemd.mask:
        options.systemd.mask.extend(_csv_args(getattr(args, "mask_service", [])))
    if not options.users.users:
        options.users.users.extend(_user_specs(getattr(args, "user", [])))
    if getattr(args, "netplan_dhcp", False):
        options.network.netplan_dhcp = True
    dns = _csv_args(getattr(args, "dns", []))
    if dns and not options.network.dns:
        options.network.dns = [*(options.network.dns or []), *dns]
    if getattr(args, "kiosk", False):
        options.kiosk.enabled = True
        options.kiosk.browser = args.kiosk_browser
        options.kiosk.url = args.kiosk_url
        options.kiosk.user = args.kiosk_user
    if getattr(args, "mirrors", False):
        options.mirrors = _mirror_options(args)
    if getattr(args, "bootcheck", False):
        options.bootcheck.enabled = True
    if getattr(args, "prebuild_vm", False):
        options.prebuild_vm = _prebuild_vm_options(args)
    if getattr(args, "qemu_screenshot", False):
        options.qemu_screenshot.enabled = True
    if getattr(args, "policy_strict", False):
        options.policy.strict = True
    if getattr(args, "brand_compliance_mode", None):
        options.policy.branding_mode = args.brand_compliance_mode
    if getattr(args, "size_report", False):
        options.size_analysis.enabled = True
        options.size_analysis.top = args.size_top
    if getattr(args, "vuln_scan", False):
        options.vuln_scan.enabled = True
        options.vuln_scan.policy = args.vuln_policy
        options.vuln_scan.db_path = args.vuln_db
    if getattr(args, "sbom_format", "native") != "native":
        options.provenance.sbom_format = args.sbom_format
    if getattr(args, "reproducible", False):
        options.reproducible.enabled = True
        options.reproducible.source_date_epoch = args.source_date_epoch
        options.reproducible.apt_snapshot = args.apt_snapshot
    if getattr(args, "plugin_dir", None):
        options.plugins.plugins_dir = args.plugin_dir
    if getattr(args, "import_script", None) and not options.import_scripts.scripts:
        options.import_scripts.scripts.extend(args.import_script)
    if getattr(args, "no_release_artifacts", False):
        options.release_artifacts.enabled = False
    if getattr(args, "sign_artifacts", False):
        options.release_artifacts.sign = True
        options.release_artifacts.gpg_key = args.artifact_gpg_key
    if getattr(args, "no_html_report", False):
        options.html_report.enabled = False
    if getattr(args, "html_report_name", None):
        options.html_report.filename = args.html_report_name
    if getattr(args, "desktop_source", False):
        options.desktop_source = _desktop_source_options(project, args)
    if getattr(args, "system_sync", False):
        options.system_sync = _system_sync_options(args)
    if getattr(args, "source_iso_sha256", None):
        options.trust.source_sha256 = args.source_iso_sha256
    if getattr(args, "source_iso_signature", None):
        options.trust.source_signature = args.source_iso_signature
    if getattr(args, "source_iso_gpg_fingerprint", None):
        options.trust.source_gpg_fingerprint = args.source_iso_gpg_fingerprint
    if getattr(args, "require_source_iso_checksum", False):
        options.trust.require_source_checksum = True
    if getattr(args, "require_source_iso_signature", False):
        options.trust.require_source_signature = True
