from __future__ import annotations

from pathlib import Path
from typing import Protocol

from distroforge.core.apt_cache import AptCacheOptions
from distroforge.core.autoinstall import AutoinstallOptions
from distroforge.core.bootcheck import BootCheckOptions
from distroforge.core.bootstrap import BootstrapOptions
from distroforge.core.branding import BrandingOptions
from distroforge.core.branding_palettes import parse_palette_colors
from distroforge.core.build import BuildOptions
from distroforge.core.desktop_source import DesktopSourceComponent, DesktopSourceOptions
from distroforge.core.drivers import DriverOptions
from distroforge.core.html_report import HtmlReportOptions
from distroforge.core.importer import ImportOptions
from distroforge.core.kernel import KernelModuleOptions
from distroforge.core.kiosk import KioskOptions
from distroforge.core.mirrors import MirrorOptions
from distroforge.core.network import NetworkOptions
from distroforge.core.oem import OemOptions
from distroforge.core.persona import get_persona
from distroforge.core.plugins import PluginOptions
from distroforge.core.policy import PolicyOptions
from distroforge.core.ppa import PpaOptions, PpaSpec
from distroforge.core.prebuild_vm import PrebuildVmOptions
from distroforge.core.provenance import ProvenanceOptions
from distroforge.core.qa import QaOptions
from distroforge.core.qemu_screenshot import QemuScreenshotOptions
from distroforge.core.release_artifacts import ReleaseArtifactOptions
from distroforge.core.release_track import ReleaseTrackOptions
from distroforge.core.reproducible import ReproducibleOptions
from distroforge.core.sanitize import SanitizeOptions
from distroforge.core.secureboot import SecureBootOptions
from distroforge.core.size_analysis import SizeAnalysisOptions
from distroforge.core.snaps import SnapOptions, SnapSpec
from distroforge.core.snapshots import SnapshotOptions
from distroforge.core.system_sync import SystemSyncOptions
from distroforge.core.systemd import SystemdOptions
from distroforge.core.trust import TrustOptions
from distroforge.core.users import UserOptions, UserSpec
from distroforge.core.vulnscan import VulnScanOptions


class BuildOptionsWindow(Protocol):
    loaded_preset_options: BuildOptions | None

    def _package_plan(self): ...


def build_options_from_window(window: BuildOptionsWindow) -> BuildOptions:
    if window.loaded_preset_options is not None:
        return window.loaded_preset_options
    options = BuildOptions(
        output_iso=Path(window.output_iso_edit.text().strip())
        if window.output_iso_edit.text().strip()
        else None,
        package_plan=window._package_plan(),
        run_preview=window.preview_check.isChecked(),
        run_synaptic=window.synaptic_check.isChecked(),
        use_sudo=window.sudo_check.isChecked(),
        sanitize=SanitizeOptions(
            enabled=window.sanitize_check.isChecked(),
            package_autoremove=window.prune_packages_check.isChecked(),
            apt_lists=window.sanitize_apt_lists_check.isChecked(),
            ssh_host_keys=window.sanitize_ssh_keys_check.isChecked(),
            logs=not window.keep_logs_check.isChecked(),
            shell_history=not window.keep_history_check.isChecked(),
            machine_id=not window.keep_machine_id_check.isChecked(),
            temp_files=not window.keep_temp_check.isChecked(),
        ),
        bootstrap=BootstrapOptions(
            arch=window.bootstrap_arch_edit.text().strip() or "amd64",
            variant=window.bootstrap_variant_edit.text().strip() or "minbase",
            mirror=window.bootstrap_mirror_edit.text().strip() or None,
        ),
        release_track=ReleaseTrackOptions(
            mode=window.release_track_combo.currentData(),
            devel_suite=window.devel_suite_edit.text().strip() or "devel",
            enable_backports=window.backports_check.isChecked(),
            enable_proposed=window.proposed_check.isChecked(),
            proposed_pin=_int_or_default(window.proposed_pin_edit.text(), 100),
            enable_unattended_upgrades=window.rolling_upgrades_check.isChecked(),
            full_upgrade=window.rolling_full_upgrade_check.isChecked(),
        ),
        system_sync=SystemSyncOptions(
            enabled=window.system_sync_check.isChecked(),
            strategy=window.system_sync_strategy_combo.currentData(),
            fallback=window.system_sync_fallback_check.isChecked(),
            run_during_build=not window.system_sync_post_install_only_check.isChecked(),
            post_install_tool=window.system_sync_post_install_tool_check.isChecked(),
            hold_packages=_split_values(window.system_sync_hold_edit.text()),
        ),
        apt_cache=AptCacheOptions(
            enabled=window.apt_cache_check.isChecked() or bool(window.apt_proxy_edit.text().strip()),
            cache_dir=Path(window.apt_cache_dir_edit.text().strip())
            if window.apt_cache_dir_edit.text().strip()
            else None,
            proxy_url=window.apt_proxy_edit.text().strip() or None,
        ),
        snapshots=SnapshotOptions(
            enabled=window.snapshots_check.isChecked(),
            auto_restore_on_failure=window.auto_recovery_check.isChecked(),
        ),
        ppa=PpaOptions(
            [PpaSpec.parse(value) for value in _split_values(window.ppa_specs_edit.toPlainText())],
            auto_fetch_fingerprint=window.ppa_auto_key_check.isChecked(),
        ),
        snaps=SnapOptions([SnapSpec.parse(value) for value in _split_values(window.snap_specs_edit.toPlainText())]),
        drivers=DriverOptions(auto=window.drivers_auto_check.isChecked()),
        autoinstall=AutoinstallOptions(
            enabled=window.autoinstall_check.isChecked(),
            username=window.autoinstall_user_edit.text().strip() or "ubuntu",
            realname=window.autoinstall_realname_edit.text().strip() or "Ubuntu User",
            hostname=window.hostname_edit.text().strip() or None,
            password_hash=window.autoinstall_password_hash_edit.text().strip()
            or "$y$j9T$replace-me$replace-me",
            locale=_combo_value(window.locale_combo) or "en_US.UTF-8",
            keyboard=_combo_value(window.keyboard_combo) or "us",
            timezone=_combo_value(window.timezone_combo) or "UTC",
            drivers_install=window.drivers_auto_check.isChecked(),
            packages=_split_values(window.autoinstall_packages_edit.toPlainText()),
            late_commands=_split_values(window.autoinstall_late_commands_edit.toPlainText()),
        ),
        branding=BrandingOptions(
            name=window.brand_name_edit.text().strip() or None,
            pretty_name=window.brand_pretty_name_edit.text().strip() or None,
            product_name=window.brand_product_name_edit.text().strip() or None,
            vendor=window.brand_vendor_edit.text().strip() or None,
            os_id=window.brand_os_id_edit.text().strip() or None,
            id_like=window.brand_id_like_edit.text().strip() or None,
            version_id=window.brand_version_id_edit.text().strip() or None,
            version_codename=window.brand_version_codename_edit.text().strip() or None,
            home_url=window.brand_home_url_edit.text().strip() or None,
            support_url=window.brand_support_url_edit.text().strip() or None,
            bug_report_url=window.brand_bug_report_url_edit.text().strip() or None,
            privacy_policy_url=window.brand_privacy_policy_url_edit.text().strip() or None,
            ansi_color=window.brand_ansi_color_edit.text().strip() or None,
            icon_name=window.brand_icon_name_edit.text().strip() or None,
            palette=window.brand_palette_combo.currentData() or None,
            palette_colors=_safe_parse_palette_colors(window.brand_palette_colors_edit.text()),
            palette_seed=window.brand_palette_seed_edit.text().strip() or None,
            logo=window.brand_logo_edit.text().strip() or None,
            distributor_logo=window.brand_distributor_logo_edit.text().strip() or None,
            app_icon=window.brand_app_icon_edit.text().strip() or None,
            grub_background=window.brand_grub_background_edit.text().strip() or None,
            grub_theme=window.brand_grub_theme_edit.text().strip() or None,
            grub_distributor=window.brand_grub_distributor_edit.text().strip() or None,
            grub_menu_label=window.brand_grub_menu_label_edit.text().strip() or None,
            plymouth_theme=window.brand_plymouth_theme_edit.text().strip() or None,
            plymouth_logo=window.brand_plymouth_logo_edit.text().strip() or None,
            plymouth_spinner=window.brand_plymouth_spinner_edit.text().strip() or None,
            plymouth_background=window.brand_plymouth_background_edit.text().strip() or None,
            plymouth_main_color=window.brand_plymouth_main_color_edit.text().strip() or None,
            login_background=window.brand_login_background_edit.text().strip() or None,
            lightdm_background=window.brand_lightdm_background_edit.text().strip() or None,
            installer_slideshow=window.brand_installer_slideshow_edit.text().strip() or None,
            issue_text=window.brand_issue_edit.text().strip() or None,
            motd_text=window.brand_motd_edit.text().strip() or None,
        ),
        secure_boot=SecureBootOptions(
            enabled=window.secure_boot_check.isChecked(),
            mok_key=window.secure_boot_mok_key_edit.text().strip() or None,
            mok_cert=window.secure_boot_mok_cert_edit.text().strip() or None,
            sign_modules=window.secure_boot_sign_modules_check.isChecked(),
        ),
        qa=QaOptions(_split_values(window.qa_edit.text())),
        bootcheck=BootCheckOptions(enabled=window.bootcheck_check.isChecked()),
        prebuild_vm=PrebuildVmOptions(
            enabled=window.prebuild_vm_check.isChecked(),
            profile=window.prebuild_vm_profile_combo.currentData(),
            firmware=window.prebuild_vm_firmware_combo.currentData(),
            secure_boot=window.prebuild_vm_secure_boot_check.isChecked(),
            tpm=window.prebuild_vm_tpm_check.isChecked(),
            memory_mb=_int_or_default(window.prebuild_vm_memory_edit.text(), 4096),
            cpus=_int_or_default(window.prebuild_vm_cpus_edit.text(), 2),
            disk_size=window.prebuild_vm_disk_size_edit.text().strip() or "24G",
            network=window.prebuild_vm_network_check.isChecked(),
            timeout_seconds=_int_or_default(window.prebuild_vm_timeout_edit.text(), 300),
            serial_log=window.prebuild_vm_serial_log_edit.text().strip() or "prebuild-vm-serial.log",
            screenshot=window.prebuild_vm_screenshot_check.isChecked(),
            screenshot_name=window.prebuild_vm_screenshot_name_edit.text().strip() or "prebuild-vm.ppm",
            success_patterns=_split_values(window.prebuild_vm_success_patterns_edit.text())
            or ["login:", "Reached target"],
            qmp_socket=window.prebuild_vm_qmp_socket_edit.text().strip() or "qemu-lab.qmp",
            pid_file=window.prebuild_vm_pid_file_edit.text().strip() or "qemu-lab.pid",
            report_name=window.prebuild_vm_report_name_edit.text().strip()
            or "qemu-lab-report.json",
            ovmf_code=window.prebuild_vm_ovmf_code_edit.text().strip()
            or "/usr/share/OVMF/OVMF_CODE.fd",
            ovmf_vars=window.prebuild_vm_ovmf_vars_edit.text().strip()
            or "/usr/share/OVMF/OVMF_VARS.fd",
        ),
        qemu_screenshot=QemuScreenshotOptions(enabled=window.qemu_screenshot_check.isChecked()),
        policy=PolicyOptions(
            strict=window.policy_strict_check.isChecked(),
            branding_mode=window.brand_compliance_mode_combo.currentData(),
        ),
        size_analysis=SizeAnalysisOptions(
            enabled=window.size_report_check.isChecked(),
            top=_int_or_default(window.size_top_edit.text(), 50),
        ),
        vuln_scan=VulnScanOptions(
            enabled=window.vuln_scan_check.isChecked(),
            policy=window.vuln_policy_combo.currentData(),
            db_path=Path(window.vuln_db_edit.text().strip())
            if window.vuln_db_edit.text().strip()
            else None,
        ),
        provenance=ProvenanceOptions(sbom_format=window.sbom_format_combo.currentData()),
        reproducible=ReproducibleOptions(
            enabled=window.reproducible_check.isChecked(),
            source_date_epoch=_optional_int(window.source_date_epoch_edit.text()),
            apt_snapshot=window.apt_snapshot_edit.text().strip() or None,
        ),
        plugins=PluginOptions(
            Path(window.plugin_dir_edit.text().strip())
            if window.plugin_dir_edit.text().strip()
            else None
        ),
        release_artifacts=ReleaseArtifactOptions(
            enabled=window.release_artifacts_check.isChecked(),
            sign=window.sign_artifacts_check.isChecked(),
            gpg_key=window.artifact_gpg_key_edit.text().strip() or None,
        ),
        html_report=HtmlReportOptions(
            enabled=window.html_report_check.isChecked(),
            filename=window.html_report_name_edit.text().strip() or "report.html",
        ),
        import_scripts=ImportOptions([Path(value) for value in _split_values(window.import_scripts_edit.toPlainText())]),
        trust=TrustOptions(
            source_sha256=window.source_iso_sha256_edit.text().strip() or None,
            source_signature=Path(window.source_iso_signature_edit.text().strip())
            if window.source_iso_signature_edit.text().strip()
            else None,
            source_gpg_fingerprint=window.source_iso_gpg_fingerprint_edit.text().strip()
            or None,
            require_source_checksum=window.require_source_checksum_check.isChecked(),
            require_source_signature=window.require_source_signature_check.isChecked(),
        ),
        oem=OemOptions(enabled=window.oem_check.isChecked()),
        systemd=SystemdOptions(
            enable=_split_values(window.enable_services_edit.toPlainText()),
            disable=_split_values(window.disable_services_edit.toPlainText()),
            mask=_split_values(window.mask_services_edit.toPlainText()),
        ),
        users=UserOptions(_user_specs_from_text(window.users_edit.toPlainText())),
        network=NetworkOptions(
            netplan_dhcp=window.netplan_dhcp_check.isChecked(),
            dns=_split_values(window.dns_edit.text()) or None,
            apt_proxy=window.apt_proxy_edit.text().strip() or None,
        ),
        mirrors=MirrorOptions(
            enabled=window.mirrors_check.isChecked(),
            archive_mirror=window.mirror_archive_edit.text().strip() or None,
            security_mirror=window.mirror_security_edit.text().strip() or None,
            country=window.mirror_country_edit.text().strip() or None,
            require_https=not window.mirror_allow_http_check.isChecked(),
            keep_canonical_security=not window.mirror_override_security_check.isChecked(),
        ),
        kiosk=KioskOptions(
            enabled=window.kiosk_check.isChecked(),
            browser=window.kiosk_browser_edit.text().strip() or "firefox",
            url=window.kiosk_url_edit.text().strip() or "about:blank",
            user=window.kiosk_user_edit.text().strip() or "ubuntu",
        ),
        kernel_module=KernelModuleOptions(
            enabled=window.kernel_enable_check.isChecked()
            or window.kernel_full_deb_check.isChecked()
            or bool(window.kernel_module_edit.text().strip())
            or bool(window.kernel_module_subdir_edit.text().strip()),
            build_mode="full-deb" if window.kernel_full_deb_check.isChecked() else "module",
            channel=window.kernel_channel_combo.currentData(),
            version=window.kernel_version_edit.text().strip() or None,
            source_url=window.kernel_source_url_edit.text().strip() or None,
            pgp_url=window.kernel_pgp_url_edit.text().strip() or None,
            source_sha256=window.kernel_source_sha256_edit.text().strip() or None,
            module_source=window.kernel_module_edit.text().strip() or None,
            module_subdir=window.kernel_module_subdir_edit.text().strip() or None,
            module_name=window.kernel_module_name_edit.text().strip() or None,
            verify_pgp=window.kernel_verify_pgp_check.isChecked(),
            prune_obsolete_kernels=window.prune_obsolete_kernels_check.isChecked(),
            localversion=window.kernel_localversion_edit.text().strip() or "-dforge",
            jobs=_int_or_default(window.kernel_jobs_edit.text(), 0),
            config_strategy=window.kernel_config_strategy_combo.currentData(),
            install_debs=window.kernel_install_debs_check.isChecked(),
            gpg_keyring=window.kernel_gpg_keyring_edit.text().strip() or None,
            gpg_fingerprint=window.kernel_gpg_fingerprint_edit.text().strip() or None,
            require_sha256=window.kernel_require_sha256_check.isChecked(),
            require_gpg=window.kernel_require_gpg_check.isChecked(),
        ),
        desktop_source=DesktopSourceOptions(
            enabled=window.desktop_source_check.isChecked(),
            desktop=window.desktop_combo.currentData() or None,
            version=window.desktop_source_version_edit.text().strip() or None,
            components=[
                DesktopSourceComponent.parse(value)
                for value in _split_lines(window.desktop_source_components_edit.toPlainText())
            ],
            install_debs=window.desktop_source_install_debs_check.isChecked(),
            jobs=_int_or_default(window.desktop_source_jobs_edit.text(), 0),
            local_suffix=window.desktop_source_local_suffix_edit.text().strip() or "dforge",
            build_dependencies=_split_values(window.desktop_source_build_deps_edit.text()),
            require_sha256=window.desktop_source_require_sha256_check.isChecked(),
        ),
    )
    persona_key = window.persona_combo.currentData()
    if persona_key:
        persona = get_persona(persona_key)
        options.sanitize.apt_lists = persona.sanitize_apt_lists
        options.sanitize.ssh_host_keys = persona.sanitize_ssh_host_keys
        options.drivers.auto = persona.drivers_auto
        if not options.qa.scenarios:
            options.qa.scenarios = list(persona.qemu_matrix)
        options.provenance.enabled = persona.sbom
    if window.ci_check.isChecked():
        options.run_synaptic = False
    return options


def _split_values(text: str) -> list[str]:
    values: list[str] = []
    for raw_line in text.replace(",", "\n").splitlines():
        item = raw_line.strip()
        if item and not item.startswith("#"):
            values.append(item)
    return values


def _split_lines(text: str) -> list[str]:
    values: list[str] = []
    for raw_line in text.splitlines():
        item = raw_line.strip()
        if item and not item.startswith("#"):
            values.append(item)
    return values


def _user_specs_from_text(text: str) -> list[UserSpec]:
    specs: list[UserSpec] = []
    for raw_line in text.splitlines():
        value = raw_line.strip()
        if not value or value.startswith("#"):
            continue
        parts = value.split(":", 2)
        name = parts[0].strip()
        if not name:
            continue
        groups = ["sudo", "audio", "video"]
        password_hash = None
        if len(parts) >= 2 and parts[1].strip():
            groups = [part.strip() for part in parts[1].split(",") if part.strip()]
        if len(parts) == 3 and parts[2].strip():
            password_hash = parts[2].strip()
        specs.append(UserSpec(name=name, groups=groups, password_hash=password_hash))
    return specs


def _combo_value(combo) -> str:
    text = combo.currentText().strip()
    index = combo.currentIndex()
    if index >= 0 and text == combo.itemText(index):
        data = combo.itemData(index)
        return str(data or "").strip()
    return text


def _int_or_default(value: str, default: int) -> int:
    try:
        return int(value)
    except ValueError:
        return default


def _optional_int(value: str) -> int | None:
    text = value.strip()
    if not text:
        return None
    return _int_or_default(text, 0)


def _safe_parse_palette_colors(text: str) -> tuple[str, ...]:
    if not text.strip():
        return ()
    try:
        return parse_palette_colors(text)
    except Exception:
        return ()
