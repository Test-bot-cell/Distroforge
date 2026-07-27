"""Render the current GUI settings as the equivalent ``distroforge build`` line.

The panel used to hand-pick eighteen of the parser's 191 options, so 173 of them
-- kiosk, snaps, PPAs, autoinstall, branding, secure boot, kernel, prebuild VM,
CVE scan, output ISO -- were silently dropped from a command the user is invited
to copy. This module now renders from the same source of truth the build itself
reads: ``build_options_from_window`` plus the project, diffed against the
``BuildOptions()`` defaults that a flagless ``distroforge build`` produces.

Every emitted argument goes through ``shlex.join`` so the string stays safe to
paste into a shell; no hand-rolled quoting belongs here.
"""

from __future__ import annotations

import shlex
from typing import Protocol

from distroforge.core.branding import BrandingOptions
from distroforge.core.build import BuildOptions
from distroforge.core.project import Project
from distroforge.ui.build_options_mapper import build_options_from_window

# Options that cannot appear in the rendered line, with the reason. --help and
# --execute are the parser's own documented exceptions; --profile is resolved
# into the explicit --install/--remove entries it stands for, so re-emitting it
# would install its packages twice.
UNRENDERED_OPTIONS: dict[str, str] = {
    "--help": "argparse-generated help",
    "--execute": "covered by the explicit Execute action",
    "--profile": "expanded into the --install/--remove entries it resolves to",
}

_BRAND_FLAGS: tuple[tuple[str, str], ...] = (
    ("--brand-name", "name"),
    ("--brand-pretty-name", "pretty_name"),
    ("--brand-product-name", "product_name"),
    ("--brand-vendor", "vendor"),
    ("--brand-os-id", "os_id"),
    ("--brand-id-like", "id_like"),
    ("--brand-version-id", "version_id"),
    ("--brand-version-codename", "version_codename"),
    ("--brand-home-url", "home_url"),
    ("--brand-support-url", "support_url"),
    ("--brand-bug-report-url", "bug_report_url"),
    ("--brand-privacy-policy-url", "privacy_policy_url"),
    ("--brand-ansi-color", "ansi_color"),
    ("--brand-icon-name", "icon_name"),
    ("--brand-palette", "palette"),
    ("--brand-palette-seed", "palette_seed"),
    ("--brand-logo", "logo"),
    ("--brand-distributor-logo", "distributor_logo"),
    ("--brand-app-icon", "app_icon"),
    ("--brand-grub-background", "grub_background"),
    ("--brand-grub-theme", "grub_theme"),
    ("--brand-grub-distributor", "grub_distributor"),
    ("--brand-grub-menu-label", "grub_menu_label"),
    ("--brand-plymouth-theme", "plymouth_theme"),
    ("--brand-plymouth-logo", "plymouth_logo"),
    ("--brand-plymouth-spinner", "plymouth_spinner"),
    ("--brand-plymouth-background", "plymouth_background"),
    ("--brand-plymouth-main-color", "plymouth_main_color"),
    ("--brand-login-background", "login_background"),
    ("--brand-lightdm-background", "lightdm_background"),
    ("--brand-installer-slideshow", "installer_slideshow"),
    ("--brand-issue", "issue_text"),
    ("--brand-motd", "motd_text"),
)


class CliEquivalentWindow(Protocol):
    project: Project | None

    def _sync_project_from_ui(self) -> None: ...


def build_cli_equivalent(window: CliEquivalentWindow) -> str:
    if not window.project:
        return "distroforge new NAME PATH"
    window._sync_project_from_ui()
    project = window.project
    options = build_options_from_window(window)
    base = BuildOptions()
    args = ["distroforge", "build", str(project.root)]
    if getattr(window, "loaded_preset_path", None) is not None:
        # Same order as commands/build.py: the definition first, then the flags
        # that override it.
        args.extend(["--definition", str(window.loaded_preset_path)])
    args.extend(_source_args(project, options, base))
    args.extend(_package_args(options, base))
    args.extend(_runtime_args(window, options, base))
    args.extend(_sanitize_args(options, base))
    args.extend(_release_track_args(options, base))
    args.extend(_system_sync_args(options, base))
    args.extend(_cache_and_network_args(options, base))
    args.extend(_autoinstall_args(options, base))
    args.extend(_customization_args(project))
    args.extend(_branding_args(options.branding, base.branding))
    args.extend(_trust_and_secure_boot_args(options, base))
    args.extend(_quality_args(options, base))
    args.extend(_prebuild_vm_args(options, base))
    args.extend(_kernel_args(options, base))
    args.extend(_desktop_source_args(options, base))
    args.extend(_artifact_args(options, base))
    # The panel offers this string for copy-paste into a shell, so every part is
    # quoted unconditionally: a bare value would let the shell expand it.
    return shlex.join(args)


def _source_args(project: Project, options: BuildOptions, base: BuildOptions) -> list[str]:
    return [
        *_value("--source-iso", project.source_iso),
        *_switch("--from-scratch", project.source_mode == "bootstrap"),
        *_value("--output-iso", options.output_iso),
        *_value("--bootstrap-arch", options.bootstrap.arch, base.bootstrap.arch),
        *_value("--bootstrap-variant", options.bootstrap.variant, base.bootstrap.variant),
        *_value("--bootstrap-mirror", options.bootstrap.mirror),
    ]


def _package_args(options: BuildOptions, base: BuildOptions) -> list[str]:
    plan = options.package_plan
    return [
        *_repeat("--install", plan.install),
        *_repeat("--remove", plan.remove),
        *_switch("--purge", plan.purge),
        # seeds.snaps holds the raw "name:channel:classic" specs, which is what
        # --snap takes; SnapOptions is the parsed view of the same text.
        *_repeat("--snap", options.seeds.snaps or [spec.spec() for spec in options.snaps.specs]),
        *_repeat("--ppa", [spec.spec() for spec in options.ppa.ppas]),
        *_switch("--ppa-no-auto-key", not options.ppa.auto_fetch_fingerprint),
        *_switch("--drivers-auto", options.drivers.auto),
        *_repeat("--enable-service", options.systemd.enable),
        *_repeat("--disable-service", options.systemd.disable),
        *_repeat("--mask-service", options.systemd.mask),
        *_repeat("--user", [user.spec() for user in options.users.users]),
        *_repeat("--import-script", options.import_scripts.scripts),
        *_value("--plugin-dir", options.plugins.plugins_dir),
        *_switch("--oem", options.oem.enabled),
        *_switch("--snapshot", options.snapshots.enabled),
        *_switch("--auto-restore-on-failure", options.snapshots.auto_restore_on_failure),
        *_switch("--kiosk", options.kiosk.enabled),
        *_value("--kiosk-url", options.kiosk.url, base.kiosk.url),
        *_value("--kiosk-browser", options.kiosk.browser, base.kiosk.browser),
        *_value("--kiosk-user", options.kiosk.user, base.kiosk.user),
    ]


def _runtime_args(window, options: BuildOptions, base: BuildOptions) -> list[str]:
    persona = window.persona_combo.currentData()
    privilege = "pkexec" if window.pkexec_check.isChecked() else "sudo"
    return [
        *_value("--persona", persona),
        *_switch("--preview", options.run_preview),
        *_switch("--synaptic", options.run_synaptic),
        *_switch("--ci", window.ci_check.isChecked()),
        *_switch("--skip-deps-check", window.skip_deps_check.isChecked()),
        *_switch("--no-sudo", not options.use_sudo),
        *_value("--privilege", privilege, "sudo"),
        *_value("--log-file", window.log_file_edit.text().strip()),
    ]


def _sanitize_args(options: BuildOptions, base: BuildOptions) -> list[str]:
    sanitize = options.sanitize
    return [
        *_switch("--no-sanitize", not sanitize.enabled),
        *_switch("--sanitize-apt-lists", sanitize.apt_lists),
        *_switch("--sanitize-ssh-host-keys", sanitize.ssh_host_keys),
        *_switch("--no-prune-obsolete-packages", not sanitize.package_autoremove),
        *_switch("--keep-logs", not sanitize.logs),
        *_switch("--keep-history", not sanitize.shell_history),
        *_switch("--keep-machine-id", not sanitize.machine_id),
        *_switch("--keep-temp", not sanitize.temp_files),
    ]


def _release_track_args(options: BuildOptions, base: BuildOptions) -> list[str]:
    track = options.release_track
    return [
        *_value(
            "--squashfs-compression",
            options.squashfs.compression,
            base.squashfs.compression,
        ),
        *_value("--release-track", track.mode, base.release_track.mode),
        *_value("--devel-suite", track.devel_suite, base.release_track.devel_suite),
        *_switch("--enable-backports", track.enable_backports),
        *_switch("--enable-proposed", track.enable_proposed),
        *_value("--proposed-pin", track.proposed_pin, base.release_track.proposed_pin),
        *_switch("--rolling-upgrades", track.enable_unattended_upgrades),
        *_switch("--rolling-full-upgrade", track.full_upgrade),
    ]


def _system_sync_args(options: BuildOptions, base: BuildOptions) -> list[str]:
    sync = options.system_sync
    return [
        *_switch("--system-sync", sync.enabled),
        *_value("--system-sync-strategy", sync.strategy, base.system_sync.strategy),
        *_switch("--system-sync-no-fallback", not sync.fallback),
        *_repeat("--system-sync-hold", sync.hold_packages),
        *_switch("--system-sync-post-install-only", not sync.run_during_build),
        *_switch("--system-sync-no-post-install-tool", not sync.post_install_tool),
    ]


def _cache_and_network_args(options: BuildOptions, base: BuildOptions) -> list[str]:
    mirrors = options.mirrors
    return [
        *_switch("--apt-cache", options.apt_cache.enabled),
        *_value("--apt-cache-dir", options.apt_cache.cache_dir),
        *_value("--apt-proxy", options.apt_cache.proxy_url or options.network.apt_proxy),
        *_switch("--netplan-dhcp", options.network.netplan_dhcp),
        *_repeat("--dns", options.network.dns or []),
        *_switch("--mirrors", mirrors.enabled),
        *_value("--mirror-archive", mirrors.archive_mirror),
        *_value("--mirror-security", mirrors.security_mirror),
        *_value("--mirror-country", mirrors.country),
        *_switch("--mirror-allow-http", not mirrors.require_https),
        *_switch("--mirror-override-ubuntu-security", not mirrors.keep_canonical_security),
    ]


def _autoinstall_args(options: BuildOptions, base: BuildOptions) -> list[str]:
    autoinstall = options.autoinstall
    return [
        *_switch("--autoinstall", autoinstall.enabled),
        *_value("--autoinstall-user", autoinstall.username, base.autoinstall.username),
        *_value("--autoinstall-realname", autoinstall.realname, base.autoinstall.realname),
        *_value(
            "--autoinstall-password-hash",
            autoinstall.password_hash,
            base.autoinstall.password_hash,
        ),
        *_repeat("--autoinstall-package", autoinstall.packages),
        *_repeat("--autoinstall-late-command", autoinstall.late_commands),
    ]


def _customization_args(project: Project) -> list[str]:
    custom = project.customization
    return [
        *_value("--desktop", custom.desktop),
        *_value("--display-manager", custom.display_manager),
        *_value("--autologin-user", custom.autologin_user),
        *_value("--wallpaper", custom.wallpaper),
        *_value("--hostname", custom.hostname),
        *_value("--locale", custom.locale),
        *_value("--timezone", custom.timezone),
        *_value("--keyboard-layout", custom.keyboard_layout),
    ]


def _branding_args(branding: BrandingOptions, base: BrandingOptions) -> list[str]:
    args: list[str] = []
    for option, field in _BRAND_FLAGS:
        args.extend(_value(option, getattr(branding, field), getattr(base, field)))
    if branding.palette_colors:
        args.extend(["--brand-palette-colors", ",".join(branding.palette_colors)])
    return args


def _trust_and_secure_boot_args(options: BuildOptions, base: BuildOptions) -> list[str]:
    trust = options.trust
    secure_boot = options.secure_boot
    return [
        *_value("--source-iso-sha256", trust.source_sha256),
        *_value("--source-iso-signature", trust.source_signature),
        *_value("--source-iso-gpg-fingerprint", trust.source_gpg_fingerprint),
        *_switch("--require-source-iso-checksum", trust.require_source_checksum),
        *_switch("--require-source-iso-signature", trust.require_source_signature),
        *_switch("--secure-boot", secure_boot.enabled),
        *_value("--secure-boot-mok-key", secure_boot.mok_key),
        *_value("--secure-boot-mok-cert", secure_boot.mok_cert),
        *_switch("--secure-boot-sign-modules", secure_boot.sign_modules),
    ]


def _quality_args(options: BuildOptions, base: BuildOptions) -> list[str]:
    return [
        *_repeat("--qa", options.qa.scenarios),
        *_switch("--bootcheck", options.bootcheck.enabled),
        *_switch("--qemu-screenshot", options.qemu_screenshot.enabled),
        *_switch("--policy-strict", options.policy.strict),
        *_value(
            "--brand-compliance-mode",
            options.policy.branding_mode,
            base.policy.branding_mode,
        ),
        *_switch("--size-report", options.size_analysis.enabled),
        *_value("--size-top", options.size_analysis.top, base.size_analysis.top),
        *_switch("--vuln-scan", options.vuln_scan.enabled),
        *_value("--vuln-policy", options.vuln_scan.policy, base.vuln_scan.policy),
        *_value("--vuln-db", options.vuln_scan.db_path),
        *_value("--sbom-format", options.provenance.sbom_format, base.provenance.sbom_format),
        *_switch("--reproducible", options.reproducible.enabled),
        *_value("--source-date-epoch", options.reproducible.source_date_epoch),
        *_value("--apt-snapshot", options.reproducible.apt_snapshot),
    ]


def _prebuild_vm_args(options: BuildOptions, base: BuildOptions) -> list[str]:
    vm = options.prebuild_vm
    default = base.prebuild_vm
    return [
        *_switch("--prebuild-vm", vm.enabled),
        *_value("--prebuild-vm-profile", vm.profile, default.profile),
        *_value("--prebuild-vm-firmware", vm.firmware, default.firmware),
        *_switch("--prebuild-vm-secure-boot", vm.secure_boot),
        *_switch("--prebuild-vm-tpm", vm.tpm),
        *_value("--prebuild-vm-memory", vm.memory_mb, default.memory_mb),
        *_value("--prebuild-vm-cpus", vm.cpus, default.cpus),
        *_value("--prebuild-vm-disk-size", vm.disk_size, default.disk_size),
        *_switch("--prebuild-vm-network", vm.network),
        *_value("--prebuild-vm-timeout", vm.timeout_seconds, default.timeout_seconds),
        *_value("--prebuild-vm-serial-log", vm.serial_log, default.serial_log),
        *_switch("--prebuild-vm-no-screenshot", not vm.screenshot),
        *_value("--prebuild-vm-screenshot-name", vm.screenshot_name, default.screenshot_name),
        *_value("--prebuild-vm-qmp-socket", vm.qmp_socket, default.qmp_socket),
        *_value("--prebuild-vm-pid-file", vm.pid_file, default.pid_file),
        *_value("--prebuild-vm-report-name", vm.report_name, default.report_name),
        *_value("--prebuild-vm-ovmf-code", vm.ovmf_code, default.ovmf_code),
        *_value("--prebuild-vm-ovmf-vars", vm.ovmf_vars, default.ovmf_vars),
        *_repeat(
            "--prebuild-vm-success-pattern",
            [] if vm.success_patterns == default.success_patterns else vm.success_patterns,
        ),
    ]


def _kernel_args(options: BuildOptions, base: BuildOptions) -> list[str]:
    kernel = options.kernel_module
    default = base.kernel_module
    return [
        *_value("--kernel-module", kernel.module_source),
        *_value("--kernel-module-subdir", kernel.module_subdir),
        *_value("--kernel-module-name", kernel.module_name),
        *_value("--kernel-channel", kernel.channel, default.channel),
        *_value("--kernel-version", kernel.version),
        *_value("--kernel-source-url", kernel.source_url),
        *_value("--kernel-pgp-url", kernel.pgp_url),
        *_value("--kernel-source-sha256", kernel.source_sha256),
        *_switch("--no-kernel-pgp", not kernel.verify_pgp),
        *_value("--kernel-gpg-keyring", kernel.gpg_keyring),
        *_value("--kernel-gpg-fingerprint", kernel.gpg_fingerprint),
        *_switch("--kernel-require-sha256", kernel.require_sha256),
        *_switch("--kernel-require-gpg", kernel.require_gpg),
        *_switch("--prune-obsolete-kernels", kernel.prune_obsolete_kernels),
        *_switch("--kernel-full-deb", kernel.build_mode == "full-deb"),
        *_value("--kernel-localversion", kernel.localversion, default.localversion),
        *_value("--kernel-jobs", kernel.jobs, default.jobs),
        *_value("--kernel-config-strategy", kernel.config_strategy, default.config_strategy),
        *_switch("--kernel-no-install-debs", not kernel.install_debs),
    ]


def _desktop_source_args(options: BuildOptions, base: BuildOptions) -> list[str]:
    source = options.desktop_source
    default = base.desktop_source
    return [
        *_switch("--desktop-source", source.enabled),
        *_value("--desktop-source-version", source.version),
        *_repeat("--desktop-source-component", [item.spec() for item in source.components]),
        *_repeat("--desktop-source-build-dep", source.build_dependencies),
        *_value("--desktop-source-jobs", source.jobs, default.jobs),
        *_value("--desktop-source-local-suffix", source.local_suffix, default.local_suffix),
        *_switch("--desktop-source-no-install-debs", not source.install_debs),
        *_switch("--desktop-source-require-sha256", source.require_sha256),
    ]


def _artifact_args(options: BuildOptions, base: BuildOptions) -> list[str]:
    return [
        *_switch("--no-release-artifacts", not options.release_artifacts.enabled),
        *_switch("--sign-artifacts", options.release_artifacts.sign),
        *_value("--artifact-gpg-key", options.release_artifacts.gpg_key),
        *_switch("--no-html-report", not options.html_report.enabled),
        *_value("--html-report-name", options.html_report.filename, base.html_report.filename),
    ]


def _value(option: str, value: object, default: object = None) -> list[str]:
    """One value flag, emitted only when it carries more than the CLI default."""
    if value is None or value == "" or value == default:
        return []
    return [option, str(value)]


def _switch(option: str, active: bool) -> list[str]:
    return [option] if active else []


def _repeat(option: str, values) -> list[str]:
    args: list[str] = []
    for value in values:
        args.extend([option, str(value)])
    return args
