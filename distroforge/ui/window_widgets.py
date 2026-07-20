from __future__ import annotations

from distroforge.ai.backend import backend_names
from distroforge.ai.registers import get_register, register_keys
from distroforge.core.branding_palettes import load_branding_palettes
from distroforge.core.interaction_plan import available_interaction_plans
from distroforge.core.source_starter import list_source_starters
from distroforge.core.workflows import WORKFLOW_LEVELS, get_workflow_level
from distroforge.ui import preferences
from distroforge.ui.build_guidance import SNAPSHOT_STATUS_TEXT, WORKFLOW_LEVEL_STATUS_TEXT
from distroforge.ui.qt import (
    QCheckBox,
    QComboBox,
    QLabel,
    QLineEdit,
    QListWidget,
    QPlainTextEdit,
    QProgressBar,
    Qt,
    QTimer,
)
from distroforge.ui.widgets import ElidingLabel, tame_all_combos

LOCALE_CHOICES = (
    ("English (United States)", "en_US.UTF-8"),
    ("English (United Kingdom)", "en_GB.UTF-8"),
    ("French (France)", "fr_FR.UTF-8"),
    ("French (Belgium)", "fr_BE.UTF-8"),
    ("French (Canada)", "fr_CA.UTF-8"),
    ("German (Germany)", "de_DE.UTF-8"),
    ("Spanish (Spain)", "es_ES.UTF-8"),
    ("Italian (Italy)", "it_IT.UTF-8"),
    ("Portuguese (Brazil)", "pt_BR.UTF-8"),
    ("Dutch (Netherlands)", "nl_NL.UTF-8"),
    ("Arabic", "ar_SA.UTF-8"),
    ("Japanese", "ja_JP.UTF-8"),
)

TIMEZONE_CHOICES = (
    ("UTC", "UTC"),
    ("Paris", "Europe/Paris"),
    ("Brussels", "Europe/Brussels"),
    ("London", "Europe/London"),
    ("Berlin", "Europe/Berlin"),
    ("Madrid", "Europe/Madrid"),
    ("Rome", "Europe/Rome"),
    ("Amsterdam", "Europe/Amsterdam"),
    ("New York", "America/New_York"),
    ("Chicago", "America/Chicago"),
    ("Los Angeles", "America/Los_Angeles"),
    ("Montreal/Toronto", "America/Toronto"),
    ("Tokyo", "Asia/Tokyo"),
)

KEYBOARD_CHOICES = (
    ("US English", "us"),
    ("UK English", "gb"),
    ("French AZERTY", "fr"),
    ("Belgian", "be"),
    ("Canadian multilingual", "ca"),
    ("German", "de"),
    ("Spanish", "es"),
    ("Italian", "it"),
    ("Portuguese", "pt"),
    ("Dutch", "nl"),
    ("Arabic", "ara"),
    ("Japanese", "jp"),
)


def _editable_choice_combo(choices: tuple[tuple[str, str], ...], placeholder: str) -> QComboBox:
    combo = QComboBox()
    combo.setEditable(True)
    combo.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
    combo.addItem("", "")
    for label, value in choices:
        combo.addItem(f"{label} - {value}", value)
    line_edit = combo.lineEdit()
    if line_edit is not None:
        line_edit.setPlaceholderText(placeholder)
    return combo


def build_window_widgets(window) -> None:
    window.project_label = ElidingLabel()
    window.project_label.setObjectName("ProjectState")
    window.header_project_label = ElidingLabel("No project loaded")
    window.header_project_label.setObjectName("ProjectState")
    window.summary_release = ElidingLabel("-")
    window.summary_source = ElidingLabel("-")
    window.summary_packages = ElidingLabel("0")
    window.summary_desktop = ElidingLabel("-")
    window.source_starter_combo = QComboBox()
    for starter in list_source_starters():
        window.source_starter_combo.addItem(starter.label, starter.key)
    window.source_starter_summary = ElidingLabel("-")
    window.source_iso_edit = QLineEdit()
    window.source_iso_sha256_edit = QLineEdit()
    window.source_iso_signature_edit = QLineEdit()
    window.source_iso_gpg_fingerprint_edit = QLineEdit()
    window.require_source_checksum_check = QCheckBox("Require source ISO SHA256")
    window.require_source_signature_check = QCheckBox("Require source ISO GPG signature")
    window.from_scratch_check = QCheckBox("Build from minimal rootfs")
    window.bootstrap_arch_edit = QLineEdit("amd64")
    window.bootstrap_variant_edit = QLineEdit("minbase")
    window.bootstrap_mirror_edit = QLineEdit()
    window.output_iso_edit = QLineEdit()
    window.output_iso_edit.setPlaceholderText("/home/user/Images/distroforge.iso")
    window.repositories_edit = QPlainTextEdit()
    window.install_edit = QPlainTextEdit()
    window.remove_edit = QPlainTextEdit()
    window.snap_specs_edit = QPlainTextEdit()
    window.ppa_specs_edit = QPlainTextEdit()
    window.ppa_auto_key_check = QCheckBox("Auto-verify PPA keys")
    window.ppa_auto_key_check.setChecked(True)
    window.profile_combo = QComboBox()
    window.profile_combo.addItem("No profile", "")
    for profile in window.profiles.values():
        window.profile_combo.addItem(profile.label, profile.key)
    window.derivative_profile_combo = QComboBox()
    window.derivative_profile_combo.addItem("No derivative", "")
    for profile in window.derivative_profiles.values():
        window.derivative_profile_combo.addItem(profile.label, profile.key)
    window.derivative_dockerfile_edit = QLineEdit()
    window.mode_combo = QComboBox()
    for level in WORKFLOW_LEVELS:
        window.mode_combo.addItem(f"{level.label} - {level.summary}", level.key)
    window.mode_combo.currentIndexChanged.connect(window._on_level_changed)
    window.persona_combo = QComboBox()
    window.persona_combo.addItem("No persona", "")
    for persona in window.personas.values():
        window.persona_combo.addItem(persona.label, persona.key)
        window.persona_combo.setItemData(
            window.persona_combo.count() - 1,
            f"{persona.description} (workflow level: {get_workflow_level(persona.level).label})",
            Qt.ItemDataRole.ToolTipRole,
        )
    window.desktop_combo = QComboBox()
    window.desktop_combo.addItem("Keep source ISO desktop", "")
    for desktop in window.desktops.values():
        window.desktop_combo.addItem(desktop.label, desktop.key)
    window.desktop_source_check = QCheckBox("Build selected desktop from upstream source")
    window.desktop_source_version_edit = QLineEdit()
    window.desktop_source_components_edit = QPlainTextEdit()
    window.desktop_source_components_edit.setPlaceholderText(
        "name|version|url[|sha256|build_system|package]"
    )
    window.desktop_source_build_deps_edit = QLineEdit()
    window.desktop_source_jobs_edit = QLineEdit("0")
    window.desktop_source_local_suffix_edit = QLineEdit("dforge")
    window.desktop_source_install_debs_check = QCheckBox("Install generated desktop .deb packages")
    window.desktop_source_install_debs_check.setChecked(True)
    window.desktop_source_require_sha256_check = QCheckBox("Require component SHA256")
    window.desktop_combo.currentIndexChanged.connect(window._sync_desktop_source_hint)
    window.display_manager_combo = QComboBox()
    window.display_manager_combo.addItem("Default for desktop", "")
    for manager in ("gdm3", "lightdm", "sddm"):
        window.display_manager_combo.addItem(manager, manager)
    window.autologin_edit = QLineEdit()
    window.wallpaper_edit = QLineEdit()
    window.hostname_edit = QLineEdit()
    window.hostname_edit.setPlaceholderText("distroforge")
    window.locale_combo = _editable_choice_combo(LOCALE_CHOICES, "Search or type a locale, e.g. fr_FR.UTF-8")
    window.timezone_combo = _editable_choice_combo(TIMEZONE_CHOICES, "Search or type a timezone, e.g. Europe/Paris")
    window.keyboard_combo = _editable_choice_combo(KEYBOARD_CHOICES, "Search or type a keyboard layout, e.g. fr")
    window.preview_check = QCheckBox("QEMU preview after build")
    window.preview_display_combo = QComboBox()
    window.preview_display_combo.addItem("GTK window", "gtk")
    window.preview_display_combo.addItem("SPICE (virt-viewer)", "spice")
    window.preview_display_combo.addItem("Headless (QMP)", "none")
    window.interaction_plan_combo = QComboBox()
    for interaction_plan_name in available_interaction_plans():
        window.interaction_plan_combo.addItem(interaction_plan_name, interaction_plan_name)
    window.synaptic_check = QCheckBox("Open Synaptic during package stage")
    window.sanitize_check = QCheckBox("Sanitize before final ISO")
    window.sanitize_check.setChecked(True)
    window.prune_packages_check = QCheckBox("Prune obsolete packages")
    window.prune_packages_check.setChecked(True)
    window.sanitize_apt_lists_check = QCheckBox("Remove apt lists")
    window.sanitize_ssh_keys_check = QCheckBox("Remove SSH host keys")
    window.release_track_combo = QComboBox()
    window.release_track_combo.addItem("Stable", "stable")
    window.release_track_combo.addItem("Devel (experimental)", "devel")
    window.release_track_combo.addItem("Rolling-like (experimental)", "rolling")
    window.devel_suite_edit = QLineEdit()
    window.devel_suite_edit.setPlaceholderText("(release codename)")
    window.devel_suite_edit.setToolTip(
        "Development suite to track. Leave empty to follow the selected release's "
        'codename (e.g. "resolute" for 26.04). The bare suite "devel" is only a '
        "debootstrap alias, not a real archive suite, so it is resolved to the codename."
    )
    window.backports_check = QCheckBox("Backports")
    window.proposed_check = QCheckBox("Proposed")
    window.proposed_pin_edit = QLineEdit("100")
    window.proposed_pin_edit.setToolTip(
        "APT pin priority for the -proposed pocket. -proposed holds packages still under "
        "validation; this priority controls preference. Keep it low (default 100) so "
        "proposed packages are available but not auto-installed; raise above 500 to prefer them."
    )
    window.rolling_upgrades_check = QCheckBox("Unattended upgrades")
    window.rolling_full_upgrade_check = QCheckBox("Full upgrade during build")
    window.system_sync_check = QCheckBox("System sync")
    window.system_sync_strategy_combo = QComboBox()
    window.system_sync_strategy_combo.addItem("Full sync", "full")
    window.system_sync_strategy_combo.addItem("Safe sync", "safe")
    window.system_sync_fallback_check = QCheckBox("Fallback on package issues")
    window.system_sync_fallback_check.setChecked(True)
    window.system_sync_post_install_only_check = QCheckBox("Post-install only")
    window.system_sync_post_install_tool_check = QCheckBox("Install post-install helper")
    window.system_sync_post_install_tool_check.setChecked(True)
    window.system_sync_hold_edit = QLineEdit()
    window.apt_cache_check = QCheckBox("Use apt package cache")
    window.apt_cache_dir_edit = QLineEdit()
    window.apt_proxy_edit = QLineEdit()
    window.mirrors_check = QCheckBox("Use mirror layer")
    window.mirror_archive_edit = QLineEdit()
    window.mirror_security_edit = QLineEdit()
    window.mirror_country_edit = QLineEdit()
    window.mirror_allow_http_check = QCheckBox("Allow HTTP mirrors")
    window.mirror_override_security_check = QCheckBox("Override Ubuntu security mirror")
    window.snapshots_check = QCheckBox("Create rollback snapshots")
    window.snapshots_check.setChecked(True)
    window.auto_recovery_check = QCheckBox("Auto-restore last snapshot on failure")
    window.sudo_check = QCheckBox("Use sudo for system operations")
    window.sudo_check.setChecked(True)
    window.pkexec_check = QCheckBox("Use pkexec for GUI privilege prompts (advanced)")
    window.pkexec_check.setChecked(False)
    window.workflow_level_status_label = QLabel(WORKFLOW_LEVEL_STATUS_TEXT)
    window.workflow_level_status_label.setWordWrap(True)
    window.privilege_status_label = QLabel()
    window.privilege_status_label.setWordWrap(True)
    window.snapshot_status_label = QLabel(SNAPSHOT_STATUS_TEXT)
    window.snapshot_status_label.setWordWrap(True)
    window.sudo_check.toggled.connect(window._refresh_privilege_status)
    window.pkexec_check.toggled.connect(window._refresh_privilege_status)
    window._refresh_privilege_status()
    window.ci_check = QCheckBox("CI mode")
    window.skip_deps_check = QCheckBox("Skip host dependency precheck")
    window.log_file_edit = QLineEdit()
    window.drivers_auto_check = QCheckBox("Auto-install drivers")
    window.oem_check = QCheckBox("OEM reset on first boot")
    window.enable_services_edit = QPlainTextEdit()
    window.disable_services_edit = QPlainTextEdit()
    window.mask_services_edit = QPlainTextEdit()
    window.users_edit = QPlainTextEdit()
    window.netplan_dhcp_check = QCheckBox("Netplan DHCP")
    window.dns_edit = QLineEdit()
    window.kiosk_check = QCheckBox("Kiosk mode")
    window.kiosk_browser_edit = QLineEdit("firefox")
    window.kiosk_url_edit = QLineEdit("about:blank")
    window.kiosk_user_edit = QLineEdit("ubuntu")
    window.autoinstall_check = QCheckBox("Generate autoinstall")
    window.autoinstall_user_edit = QLineEdit("ubuntu")
    window.autoinstall_realname_edit = QLineEdit("Ubuntu User")
    window.autoinstall_password_hash_edit = QLineEdit()
    window.autoinstall_packages_edit = QPlainTextEdit()
    window.autoinstall_late_commands_edit = QPlainTextEdit()
    window.brand_name_edit = QLineEdit()
    window.brand_pretty_name_edit = QLineEdit()
    window.brand_product_name_edit = QLineEdit()
    window.brand_vendor_edit = QLineEdit()
    window.brand_os_id_edit = QLineEdit()
    window.brand_id_like_edit = QLineEdit()
    window.brand_version_id_edit = QLineEdit()
    window.brand_version_codename_edit = QLineEdit()
    window.brand_home_url_edit = QLineEdit()
    window.brand_support_url_edit = QLineEdit()
    window.brand_bug_report_url_edit = QLineEdit()
    window.brand_privacy_policy_url_edit = QLineEdit()
    window.brand_ansi_color_edit = QLineEdit()
    window.brand_icon_name_edit = QLineEdit()
    window.brand_palette_combo = QComboBox()
    window.brand_palette_combo.addItem("Manual colors", "")
    for palette in load_branding_palettes().values():
        window.brand_palette_combo.addItem(palette.summary(), palette.key)
    window.brand_palette_combo.addItem("Generate from seed", "generate")
    window.brand_palette_colors_edit = QLineEdit()
    window.brand_palette_seed_edit = QLineEdit()
    window.brand_logo_edit = QLineEdit()
    window.brand_distributor_logo_edit = QLineEdit()
    window.brand_app_icon_edit = QLineEdit()
    window.brand_grub_background_edit = QLineEdit()
    window.brand_grub_theme_edit = QLineEdit()
    window.brand_grub_distributor_edit = QLineEdit()
    window.brand_grub_menu_label_edit = QLineEdit()
    window.brand_plymouth_theme_edit = QLineEdit()
    window.brand_plymouth_logo_edit = QLineEdit()
    window.brand_plymouth_spinner_edit = QLineEdit()
    window.brand_plymouth_background_edit = QLineEdit()
    window.brand_plymouth_main_color_edit = QLineEdit("#2e3436")
    window.brand_login_background_edit = QLineEdit()
    window.brand_lightdm_background_edit = QLineEdit()
    window.brand_installer_slideshow_edit = QLineEdit()
    window.brand_issue_edit = QLineEdit()
    window.brand_motd_edit = QLineEdit()
    window.secure_boot_check = QCheckBox("Secure Boot workflow")
    window.secure_boot_mok_key_edit = QLineEdit()
    window.secure_boot_mok_key_edit.setToolTip(
        "Path to the MOK (Machine Owner Key) private key used to sign kernel modules for "
        "Secure Boot. Pairs with the certificate below; enrolled in UEFI via mokutil."
    )
    window.secure_boot_mok_cert_edit = QLineEdit()
    window.secure_boot_mok_cert_edit.setToolTip(
        "Path to the MOK (Machine Owner Key) public certificate (DER) enrolled in UEFI so "
        "firmware trusts modules signed with the matching private key."
    )
    window.secure_boot_sign_modules_check = QCheckBox("Sign kernel modules")
    window.qa_edit = QLineEdit()
    window.bootcheck_check = QCheckBox("Boot smoke test")
    window.prebuild_vm_check = QCheckBox("QEMU Lab")
    window.prebuild_vm_profile_combo = QComboBox()
    for label, key in (("Live", "live"), ("Install", "install"), ("Rescue", "rescue")):
        window.prebuild_vm_profile_combo.addItem(label, key)
    window.prebuild_vm_firmware_combo = QComboBox()
    window.prebuild_vm_firmware_combo.addItem("BIOS", "bios")
    window.prebuild_vm_firmware_combo.addItem("UEFI", "uefi")
    window.prebuild_vm_secure_boot_check = QCheckBox("Secure Boot")
    window.prebuild_vm_tpm_check = QCheckBox("TPM")
    window.prebuild_vm_memory_edit = QLineEdit("4096")
    window.prebuild_vm_cpus_edit = QLineEdit("2")
    window.prebuild_vm_disk_size_edit = QLineEdit("24G")
    window.prebuild_vm_network_check = QCheckBox("Network")
    window.prebuild_vm_timeout_edit = QLineEdit("300")
    window.prebuild_vm_serial_log_edit = QLineEdit("prebuild-vm-serial.log")
    window.prebuild_vm_screenshot_check = QCheckBox("Screenshot")
    window.prebuild_vm_screenshot_check.setChecked(True)
    window.prebuild_vm_screenshot_name_edit = QLineEdit("prebuild-vm.ppm")
    window.prebuild_vm_report_name_edit = QLineEdit("qemu-lab-report.json")
    window.prebuild_vm_qmp_socket_edit = QLineEdit("qemu-lab.qmp")
    window.prebuild_vm_qmp_socket_edit.setToolTip(
        "QMP (QEMU Machine Protocol) control socket. DistroForge connects to it to drive "
        "the lab VM -- capture screenshots, send keys and query state during the boot test."
    )
    window.prebuild_vm_pid_file_edit = QLineEdit("qemu-lab.pid")
    window.prebuild_vm_ovmf_code_edit = QLineEdit("/usr/share/OVMF/OVMF_CODE.fd")
    window.prebuild_vm_ovmf_code_edit.setToolTip(
        "OVMF firmware code image -- the read-only UEFI firmware QEMU runs for UEFI boots. "
        "Provided by the ovmf package."
    )
    window.prebuild_vm_ovmf_vars_edit = QLineEdit("/usr/share/OVMF/OVMF_VARS.fd")
    window.prebuild_vm_ovmf_vars_edit.setToolTip(
        "OVMF UEFI variable store -- the writable NVRAM template holding boot entries and "
        "Secure Boot keys. Copied per run so the system template stays pristine."
    )
    window.prebuild_vm_success_patterns_edit = QLineEdit("login:,Reached target")
    window.artifacts_output_iso_edit = QLineEdit()
    window.artifacts_reports_dir_edit = QLineEdit()
    window.artifacts_livefs_work_dir_edit = QLineEdit()
    window.artifacts_livefs_work_dir_edit.setToolTip(
        "Working directory for the livefs (casper) build -- scratch space where the live "
        "filesystem is assembled before being packed into the ISO."
    )
    window.artifacts_live_build_dir_edit = QLineEdit()
    window.artifacts_screenshot_edit = QLineEdit()
    window.artifacts_serial_log_edit = QLineEdit()
    window.artifacts_buildinfo_edit = QLineEdit()
    window.artifacts_changes_edit = QLineEdit()
    window.boot_proof_backend_combo = QComboBox()
    [window.boot_proof_backend_combo.addItem(label, value) for label, value in (("Auto", "auto"), ("QEMU", "qemu"), ("ISO scan", "iso-scan"))]
    window.hermetic_backend_combo = QComboBox()
    for label, value in (("sbuild", "sbuild"), ("pbuilder", "pbuilder"), ("mmdebstrap", "mmdebstrap")):
        window.hermetic_backend_combo.addItem(label, value)
    window.hermetic_backend_combo.setToolTip(
        "Isolated (hermetic) build backend that builds packages in a clean, network-free "
        "chroot for reproducible results: sbuild, pbuilder or mmdebstrap."
    )
    window.hermetic_suite_edit = QLineEdit("unstable")
    window.terminal_backend_combo = QComboBox()
    for label, value in (("Auto", "auto"), ("Classic chroot", "chroot"), ("systemd-nspawn", "nspawn")):
        window.terminal_backend_combo.addItem(label, value)
    saved_backend = window.terminal_backend_combo.findData(preferences.load_chroot_backend())
    if saved_backend >= 0:
        window.terminal_backend_combo.setCurrentIndex(saved_backend)
    window.terminal_backend_combo.currentIndexChanged.connect(window._on_chroot_backend_changed)
    window.terminal_backend_combo.setToolTip(
        "Maintainer terminal backend. Auto uses systemd-nspawn when available and "
        "falls back to the classic chroot terminal."
    )
    window.artifacts_view = QPlainTextEdit()
    window.artifacts_view.setReadOnly(True)
    window.qemu_screenshot_check = QCheckBox("Capture QEMU screenshot")
    window.policy_strict_check = QCheckBox("Strict safety policy")
    window.brand_compliance_mode_combo = QComboBox()
    window.brand_compliance_mode_combo.addItem("Internal", "internal")
    window.brand_compliance_mode_combo.addItem("Redistributable", "redistributable")
    window.brand_compliance_mode_combo.addItem("Approved", "approved")
    window.size_report_check = QCheckBox("Size report")
    window.size_top_edit = QLineEdit("50")
    window.vuln_scan_check = QCheckBox("Scan packages for known CVEs")
    window.vuln_policy_combo = QComboBox()
    window.vuln_policy_combo.addItem("Off - record only", "off")
    window.vuln_policy_combo.addItem("Warn", "warn")
    window.vuln_policy_combo.addItem("Block high and critical", "block-high")
    window.vuln_policy_combo.addItem("Block critical only", "block-critical")
    window.vuln_policy_combo.setCurrentIndex(1)
    window.vuln_db_edit = QLineEdit()
    window.vuln_db_edit.setPlaceholderText("Custom vulnerability DB JSON (optional)")
    window.sbom_format_combo = QComboBox()
    window.sbom_format_combo.addItem("Native (DistroForge JSON)", "native")
    window.sbom_format_combo.addItem("SPDX 2.3", "spdx")
    window.sbom_format_combo.addItem("CycloneDX 1.5", "cyclonedx")
    window.reproducible_check = QCheckBox("Reproducible hints")
    window.source_date_epoch_edit = QLineEdit()
    window.apt_snapshot_edit = QLineEdit()
    window.plugin_dir_edit = QLineEdit()
    window.import_scripts_edit = QPlainTextEdit()
    window.release_artifacts_check = QCheckBox("Write release artifacts")
    window.release_artifacts_check.setChecked(True)
    window.sign_artifacts_check = QCheckBox("Sign release artifacts")
    window.artifact_gpg_key_edit = QLineEdit()
    window.html_report_check = QCheckBox("Write HTML report")
    window.html_report_check.setChecked(True)
    window.html_report_name_edit = QLineEdit("report.html")
    window.purge_remove_check = QCheckBox("Purge removed packages")
    window.keep_logs_check = QCheckBox("Keep logs")
    window.keep_history_check = QCheckBox("Keep shell history")
    window.keep_machine_id_check = QCheckBox("Keep machine-id")
    window.keep_temp_check = QCheckBox("Keep temp files")
    window.kernel_enable_check = QCheckBox("Kernel phase")
    window.kernel_full_deb_check = QCheckBox("Build full kernel .deb")
    window.kernel_module_edit = QLineEdit()
    window.kernel_module_subdir_edit = QLineEdit()
    window.kernel_module_name_edit = QLineEdit()
    window.kernel_channel_combo = QComboBox()
    for channel in ("stable", "longterm", "mainline"):
        window.kernel_channel_combo.addItem(channel, channel)
    window.kernel_version_edit = QLineEdit()
    window.kernel_source_url_edit = QLineEdit()
    window.kernel_pgp_url_edit = QLineEdit()
    window.kernel_source_sha256_edit = QLineEdit()
    window.kernel_verify_pgp_check = QCheckBox("Verify kernel PGP")
    window.kernel_verify_pgp_check.setChecked(True)
    window.kernel_gpg_keyring_edit = QLineEdit()
    window.kernel_gpg_fingerprint_edit = QLineEdit()
    window.kernel_require_sha256_check = QCheckBox("Require kernel SHA256")
    window.kernel_require_gpg_check = QCheckBox("Require kernel GPG")
    window.prune_obsolete_kernels_check = QCheckBox("Prune obsolete kernels")
    window.kernel_localversion_edit = QLineEdit("-dforge")
    window.kernel_jobs_edit = QLineEdit("0")
    window.kernel_config_strategy_combo = QComboBox()
    window.kernel_config_strategy_combo.addItem("Use current target config", "current")
    window.kernel_config_strategy_combo.addItem("Use defconfig", "defconfig")
    window.kernel_install_debs_check = QCheckBox("Install generated kernel .deb packages")
    window.kernel_install_debs_check.setChecked(True)
    window.plan_view = QPlainTextEdit()
    window.plan_view.setReadOnly(True)
    window.plan_steps_list = QListWidget()
    window.plan_steps_list.setObjectName("PlanSteps")
    window.profile_view = QPlainTextEdit()
    window.profile_view.setReadOnly(True)
    window.ux_audit_view = QPlainTextEdit()
    window.ux_audit_view.setReadOnly(True)
    window.readiness_view = QPlainTextEdit()
    window.readiness_view.setReadOnly(True)
    window.mirrors_view = QPlainTextEdit()
    window.mirrors_view.setReadOnly(True)
    window.compliance_view = QPlainTextEdit()
    window.compliance_view.setReadOnly(True)
    window.advisor_backend_combo = QComboBox()
    for backend_name in backend_names():
        window.advisor_backend_combo.addItem(backend_name.capitalize(), backend_name)
    window.advisor_backend_combo.setToolTip(
        "Local-first AI narration backend. 'Offline' uses deterministic heuristics and always "
        "works; 'Llama'/'Ollama' shell out to an optional local model and silently fall back to "
        "offline if it is unavailable. No model weights ship with DistroForge."
    )
    window.advisor_register_combo = QComboBox()
    for level in register_keys():
        window.advisor_register_combo.addItem(get_register(level).voice, level)
    saved_register = window.advisor_register_combo.findData(preferences.load_workflow_level())
    if saved_register >= 0:
        window.advisor_register_combo.setCurrentIndex(saved_register)
    window.advisor_register_combo.setToolTip(
        "Advisory voice register. It defaults to your saved workflow level so the agent speaks "
        "to you without asking, and you can override it here. The register changes how findings "
        "are explained (plain language for beginners, a Debian/Canonical lens for seniors), never "
        "what the build does."
    )
    window.ai_view = QPlainTextEdit()
    window.ai_view.setReadOnly(True)
    window.evidence_summary_label = ElidingLabel("Evidence status idle")
    window.terminal_view = QPlainTextEdit()
    window.terminal_view.setReadOnly(True)
    window.terminal_status = ElidingLabel("Chroot terminal idle")
    window.terminal_input = QLineEdit()
    window.terminal_input.returnPressed.connect(window._send_terminal_input)
    window.terminal_timer = QTimer(window)
    window.terminal_timer.setInterval(80)
    window.terminal_timer.timeout.connect(window._poll_terminal)
    window.logs = QPlainTextEdit()
    window.logs.setReadOnly(True)
    window.log_filter_edit = QLineEdit()
    window.command_center_view = QPlainTextEdit()
    window.command_center_view.setReadOnly(True)
    window.journey_view = QPlainTextEdit()
    window.journey_view.setReadOnly(True)
    window.capture_target_edit = QLineEdit("/")
    window.capture_output_edit = QLineEdit()
    window.capture_include_configs_edit = QPlainTextEdit()
    window.capture_include_config_globs_edit = QPlainTextEdit()
    window.capture_sanitize_combo = QComboBox()
    window.capture_sanitize_combo.addItem("Strict - exclude secrets/caches/logs", "strict")
    window.capture_sanitize_combo.addItem("Review - report more, capture less", "review")
    window.capture_view = QPlainTextEdit()
    window.capture_view.setReadOnly(True)
    window.capture_profile_path = None
    window.capture_rebuild_root_edit = QLineEdit()
    window.live_build_output_edit = QLineEdit()
    window.livefs_iso_work_dir_edit = QLineEdit()
    window.livefs_iso_dest_edit = QLineEdit()
    window.livefs_iso_series_edit = QLineEdit()
    window.livefs_iso_arch_edit = QLineEdit("amd64")
    window.livefs_iso_mirror_edit = QLineEdit("http://archive.ubuntu.com/ubuntu")
    window.livefs_iso_components_edit = QLineEdit("main restricted universe multiverse")
    window.livefs_iso_project_edit = QLineEdit()
    window.livefs_iso_volume_id_edit = QLineEdit()
    window.upgrade_target_edit = QLineEdit("/")
    window.upgrade_from_edit = QLineEdit()
    window.upgrade_to_edit = QLineEdit("26.04")
    window.image_mode_combo = QComboBox()
    for label, value in (
        ("Appliance", "appliance"),
        ("OEM", "oem"),
        ("Immutable", "immutable"),
    ):
        window.image_mode_combo.addItem(label, value)
    window.image_partition_layout_edit = QLineEdit()
    window.image_update_strategy_combo = QComboBox()
    for label, value in (
        ("Manual", "manual"),
        ("A/B", "ab"),
        ("systemd-sysupdate", "sysupdate"),
    ):
        window.image_update_strategy_combo.addItem(label, value)
    window.progress = QProgressBar()
    window.progress.setRange(0, 0)
    window.progress.setVisible(False)
    window.job_timer = QTimer(window)
    window.job_timer.setInterval(120)
    window.job_timer.timeout.connect(window._poll_job)
    tame_all_combos(window)
    window._init_service_runner()
