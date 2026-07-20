from __future__ import annotations

from distroforge.ui.path_actions import (
    browse_grub_theme_gallery,
    browse_spinner_gallery,
    clear_field_button,
    grub_theme_url_picker,
    image_url_picker,
    picker,
    unsplash_picker,
)
from distroforge.ui.qt import QVBoxLayout, QWidget
from distroforge.ui.step_focus import StepFocusHeader
from distroforge.ui.widgets import button as _button
from distroforge.ui.widgets import responsive_form as _responsive_form
from distroforge.ui.widgets import responsive_row as _responsive_row
from distroforge.ui.widgets import section as _section


def build_advanced_page(window) -> QWidget:
    page = QWidget()
    layout = QVBoxLayout(page)
    layout.setContentsMargins(18, 18, 18, 18)
    layout.addWidget(StepFocusHeader(window, "deployment"))

    source_form = _responsive_form()
    source_form.addRow(window.from_scratch_check)
    source_form.addRow("Bootstrap arch", window.bootstrap_arch_edit)
    source_form.addRow("Bootstrap variant", window.bootstrap_variant_edit)
    source_form.addRow("Bootstrap mirror", window.bootstrap_mirror_edit)
    source_form.addRow(
        "Output ISO",
        _responsive_row(
            window.output_iso_edit,
            _button("Select", window._browse_output_iso, "save"),
            breakpoint=680,
        ),
    )

    ppa_layout = QVBoxLayout()
    ppa_layout.addWidget(window.ppa_auto_key_check)
    ppa_layout.addWidget(window.ppa_specs_edit)
    package_rows = _responsive_row(
        _section("Snaps", window.snap_specs_edit),
        _section("PPAs", ppa_layout),
        breakpoint=900,
    )

    desktop_source_form = _responsive_form()
    desktop_source_form.addRow(window.desktop_source_check)
    desktop_source_form.addRow("Upstream version", window.desktop_source_version_edit)
    desktop_source_form.addRow("Components", window.desktop_source_components_edit)
    desktop_source_form.addRow("Build deps", window.desktop_source_build_deps_edit)
    desktop_source_form.addRow("Jobs", window.desktop_source_jobs_edit)
    desktop_source_form.addRow("Package suffix", window.desktop_source_local_suffix_edit)
    desktop_source_form.addRow(window.desktop_source_install_debs_check)
    desktop_source_form.addRow(window.desktop_source_require_sha256_check)

    system_rows = _responsive_row(
        _section("Enable Services", window.enable_services_edit),
        _section("Disable Services", window.disable_services_edit),
        _section("Mask Services", window.mask_services_edit),
        breakpoint=1100,
    )

    identity_form = _responsive_form()
    identity_form.addRow(window.drivers_auto_check)
    identity_form.addRow(window.oem_check)
    identity_form.addRow("Users", window.users_edit)
    identity_form.addRow(window.netplan_dhcp_check)
    identity_form.addRow("DNS", window.dns_edit)
    identity_form.addRow(window.kiosk_check)
    identity_form.addRow("Kiosk browser", window.kiosk_browser_edit)
    identity_form.addRow("Kiosk URL", window.kiosk_url_edit)
    identity_form.addRow("Kiosk user", window.kiosk_user_edit)

    install_form = _responsive_form()
    install_form.addRow(window.autoinstall_check)
    install_form.addRow("Autoinstall user", window.autoinstall_user_edit)
    install_form.addRow("Real name", window.autoinstall_realname_edit)
    install_form.addRow("Password hash", window.autoinstall_password_hash_edit)
    install_form.addRow("Packages", window.autoinstall_packages_edit)
    install_form.addRow("Late commands", window.autoinstall_late_commands_edit)

    brand_form = _responsive_form()
    brand_form.addRow("OS ID", window.brand_os_id_edit)
    brand_form.addRow("ID like", window.brand_id_like_edit)
    brand_form.addRow("Version ID", window.brand_version_id_edit)
    brand_form.addRow("Version codename", window.brand_version_codename_edit)
    brand_form.addRow("Home URL", window.brand_home_url_edit)
    brand_form.addRow("Support URL", window.brand_support_url_edit)
    brand_form.addRow("Bug URL", window.brand_bug_report_url_edit)
    brand_form.addRow("Privacy URL", window.brand_privacy_policy_url_edit)
    brand_form.addRow("ANSI color", window.brand_ansi_color_edit)
    brand_form.addRow("Icon name", window.brand_icon_name_edit)
    brand_form.addRow("Palette seed", window.brand_palette_seed_edit)
    brand_form.addRow(
        "Distributor logo",
        _responsive_row(
            window.brand_distributor_logo_edit,
            picker(
                window,
                window.brand_distributor_logo_edit,
                title="Select distributor logo image",
                file_filter="Images (*.png *.jpg *.jpeg *.svg *.webp);;All files (*)",
            ),
            image_url_picker(
                window,
                window.brand_distributor_logo_edit,
                title="Import distributor logo from URL",
                prompt="Distributor logo image URL:",
            ),
            unsplash_picker(
                window,
                window.brand_distributor_logo_edit,
                title="Import distributor logo from Unsplash",
                prompt="Distributor logo image URL (from Unsplash):",
            ),
            breakpoint=680,
        ),
    )
    brand_form.addRow(
        "App icon",
        _responsive_row(
            window.brand_app_icon_edit,
            picker(
                window,
                window.brand_app_icon_edit,
                title="Select app icon image",
                file_filter="Images (*.png *.jpg *.jpeg *.svg *.webp);;All files (*)",
            ),
            image_url_picker(
                window,
                window.brand_app_icon_edit,
                title="Import app icon from URL",
                prompt="App icon image URL:",
            ),
            unsplash_picker(
                window,
                window.brand_app_icon_edit,
                title="Import app icon from Unsplash",
                prompt="App icon image URL (from Unsplash):",
            ),
            breakpoint=680,
        ),
    )
    brand_form.addRow(
        "GRUB background",
        _responsive_row(
            window.brand_grub_background_edit,
            picker(
                window,
                window.brand_grub_background_edit,
                title="Select GRUB background image",
                file_filter="Images (*.png *.jpg *.jpeg *.svg *.webp);;All files (*)",
            ),
            image_url_picker(
                window,
                window.brand_grub_background_edit,
                title="Import GRUB background from URL",
                prompt="GRUB background image URL:",
            ),
            unsplash_picker(
                window,
                window.brand_grub_background_edit,
                title="Import GRUB background from Unsplash",
                prompt="GRUB background image URL (from Unsplash):",
            ),
            breakpoint=680,
        ),
    )
    brand_form.addRow(
        "GRUB theme dir",
        _responsive_row(
            window.brand_grub_theme_edit,
            picker(window, window.brand_grub_theme_edit, title="Select GRUB theme dir", mode="dir"),
            grub_theme_url_picker(
                window,
                window.brand_grub_theme_edit,
                title="Import GRUB theme from URL",
                prompt="GRUB theme archive URL (zip/tar):",
            ),
            clear_field_button(window.brand_grub_theme_edit),
            browse_grub_theme_gallery(window),
            breakpoint=680,
        ),
    )
    brand_form.addRow("GRUB distributor", window.brand_grub_distributor_edit)
    brand_form.addRow("GRUB menu label", window.brand_grub_menu_label_edit)
    brand_form.addRow("Plymouth theme", window.brand_plymouth_theme_edit)
    brand_form.addRow(
        "Plymouth logo",
        _responsive_row(
            window.brand_plymouth_logo_edit,
            picker(
                window,
                window.brand_plymouth_logo_edit,
                title="Select Plymouth logo image",
                file_filter="Images (*.png *.jpg *.jpeg *.svg *.webp);;All files (*)",
            ),
            breakpoint=680,
        ),
    )
    brand_form.addRow(
        "Plymouth spinner",
        _responsive_row(
            window.brand_plymouth_spinner_edit,
            picker(
                window,
                window.brand_plymouth_spinner_edit,
                title="Select spinner image",
                file_filter="Images (*.png *.jpg *.jpeg *.svg *.webp);;All files (*)",
            ),
            image_url_picker(
                window,
                window.brand_plymouth_spinner_edit,
                title="Import Plymouth spinner from URL",
                prompt="Plymouth spinner image URL:",
            ),
            unsplash_picker(
                window,
                window.brand_plymouth_spinner_edit,
                title="Import Plymouth spinner from Unsplash",
                prompt="Plymouth spinner image URL (from Unsplash):",
            ),
            clear_field_button(window.brand_plymouth_spinner_edit),
            browse_spinner_gallery(window),
            breakpoint=680,
        ),
    )
    brand_form.addRow(
        "Plymouth background",
        _responsive_row(
            window.brand_plymouth_background_edit,
            picker(
                window,
                window.brand_plymouth_background_edit,
                title="Select Plymouth background image",
                file_filter="Images (*.png *.jpg *.jpeg *.svg *.webp);;All files (*)",
            ),
            image_url_picker(
                window,
                window.brand_plymouth_background_edit,
                title="Import Plymouth background from URL",
                prompt="Plymouth background image URL:",
            ),
            unsplash_picker(
                window,
                window.brand_plymouth_background_edit,
                title="Import Plymouth background from Unsplash",
                prompt="Plymouth background image URL (from Unsplash):",
            ),
            breakpoint=680,
        ),
    )
    brand_form.addRow(
        "LightDM background",
        _responsive_row(
            window.brand_lightdm_background_edit,
            picker(
                window,
                window.brand_lightdm_background_edit,
                title="Select LightDM background image",
                file_filter="Images (*.png *.jpg *.jpeg *.svg *.webp);;All files (*)",
            ),
            image_url_picker(
                window,
                window.brand_lightdm_background_edit,
                title="Import LightDM background from URL",
                prompt="LightDM background image URL:",
            ),
            unsplash_picker(
                window,
                window.brand_lightdm_background_edit,
                title="Import LightDM background from Unsplash",
                prompt="LightDM background image URL (from Unsplash):",
            ),
            breakpoint=680,
        ),
    )
    brand_form.addRow(
        "Installer slideshow",
        _responsive_row(
            window.brand_installer_slideshow_edit,
            picker(
                window,
                window.brand_installer_slideshow_edit,
                title="Select installer slideshow dir",
                mode="dir",
            ),
            breakpoint=680,
        ),
    )
    brand_form.addRow("Issue text", window.brand_issue_edit)
    brand_form.addRow("MOTD text", window.brand_motd_edit)

    release_form = _responsive_form()
    release_form.addRow(window.reproducible_check)
    release_form.addRow("SOURCE_DATE_EPOCH", window.source_date_epoch_edit)
    release_form.addRow("Apt snapshot", window.apt_snapshot_edit)
    release_form.addRow(
        "Plugin dir",
        _responsive_row(
            window.plugin_dir_edit,
            picker(window, window.plugin_dir_edit, title="Select plugin dir", mode="dir"),
            breakpoint=680,
        ),
    )
    release_form.addRow("Import scripts", window.import_scripts_edit)
    release_form.addRow(window.release_artifacts_check)
    release_form.addRow(window.sign_artifacts_check)
    release_form.addRow("Artifact GPG key", window.artifact_gpg_key_edit)
    release_form.addRow(window.html_report_check)
    release_form.addRow("HTML report name", window.html_report_name_edit)
    release_form.addRow(window.ci_check)
    release_form.addRow(window.skip_deps_check)
    release_form.addRow(
        "JSONL log file",
        _responsive_row(
            window.log_file_edit,
            picker(
                window,
                window.log_file_edit,
                title="Select JSONL log file",
                mode="save",
                file_filter="JSONL logs (*.jsonl *.log);;All files (*)",
            ),
            breakpoint=680,
        ),
    )
    release_form.addRow(window.purge_remove_check)
    release_form.addRow(window.keep_logs_check)
    release_form.addRow(window.keep_history_check)
    release_form.addRow(window.keep_machine_id_check)
    release_form.addRow(window.keep_temp_check)

    kernel_form = _responsive_form()
    kernel_form.addRow(window.kernel_enable_check)
    kernel_form.addRow(window.kernel_full_deb_check)
    kernel_form.addRow("Module source", window.kernel_module_edit)
    kernel_form.addRow("Module subdir", window.kernel_module_subdir_edit)
    kernel_form.addRow("Module name", window.kernel_module_name_edit)
    kernel_form.addRow("Channel", window.kernel_channel_combo)
    kernel_form.addRow("Version", window.kernel_version_edit)
    kernel_form.addRow("Source URL", window.kernel_source_url_edit)
    kernel_form.addRow("PGP URL", window.kernel_pgp_url_edit)
    kernel_form.addRow("SHA256", window.kernel_source_sha256_edit)
    kernel_form.addRow(window.kernel_verify_pgp_check)
    kernel_form.addRow("GPG keyring", window.kernel_gpg_keyring_edit)
    kernel_form.addRow("GPG fingerprint", window.kernel_gpg_fingerprint_edit)
    kernel_form.addRow(window.kernel_require_sha256_check)
    kernel_form.addRow(window.kernel_require_gpg_check)
    kernel_form.addRow(window.prune_obsolete_kernels_check)
    kernel_form.addRow("Local version", window.kernel_localversion_edit)
    kernel_form.addRow("Jobs", window.kernel_jobs_edit)
    kernel_form.addRow("Config strategy", window.kernel_config_strategy_combo)
    kernel_form.addRow(window.kernel_install_debs_check)

    top_rows = _responsive_row(
        _section("Source and Output", source_form),
        _section("Identity and Network", identity_form),
        breakpoint=980,
    )
    mid_rows = _responsive_row(
        _section("Autoinstall", install_form),
        _section("Branding", brand_form),
        breakpoint=980,
    )
    layout.addWidget(top_rows)
    layout.addWidget(package_rows)
    layout.addWidget(_section("Desktop Source .deb", desktop_source_form))
    layout.addWidget(system_rows)
    layout.addWidget(mid_rows)
    layout.addWidget(_section("Artifacts", release_form))
    layout.addWidget(_section("Kernel", kernel_form))
    layout.addStretch(1)
    return page
