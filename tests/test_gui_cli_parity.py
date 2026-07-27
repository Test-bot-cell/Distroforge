"""Executable teeth for the CLI/GUI build-option parity contract.

``docs/gui-parity.md`` promises that build options map to widgets and that the
GUI shows a readable CLI equivalent of the current settings. The existing
contract test only checks that each option's GUI token appears somewhere under
``distroforge/ui/``, which a screen can satisfy while still ignoring the widget.
The tests here close that gap by exercising the real window:

* an imported preset must land in the widgets, and a later edit must win;
* the GUI and the CLI must emit the same seed manifest for the same settings;
* the rendered command must re-parse into the very options it was rendered from.
"""

from __future__ import annotations

import argparse
import dataclasses
import os
import re
import shlex
from pathlib import Path

import pytest

from distroforge.commands.build_contracts import BUILD_OPTION_EXCEPTIONS, build_option_contracts
from distroforge.commands.build_options import (
    apply_cli_overrides,
    apply_customization_args,
    build_options_from_args,
    register_build_arguments,
)
from distroforge.core.command import CommandRunner
from distroforge.core.definition import apply_definition, definition_from_project
from distroforge.core.project import Project
from distroforge.core.seeds import SeedService

ROOT = Path(__file__).resolve().parents[1]

# --profile is expanded into the --install/--remove entries it resolves to, so
# re-emitting it would install its packages twice. The parser's own documented
# exceptions cover --help and --execute.
RESOLVED_OPTIONS = {"--profile"}


@pytest.fixture(scope="module")
def qt_app():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from distroforge.ui.qt import QApplication

    return QApplication.instance() or QApplication([])


def _window(tmp_path: Path, name: str):
    from distroforge.ui.main_window import MainWindow

    window = MainWindow()
    window.project = Project.create(name, tmp_path / name.lower(), "26.04")
    window.project.source_mode = "bootstrap"
    window.project.save()
    return window


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="distroforge build")
    register_build_arguments(parser)
    return parser


def _flatten(options) -> dict[str, object]:
    flat: dict[str, object] = {}

    def walk(value, prefix: str) -> None:
        for field in dataclasses.fields(value):
            item = getattr(value, field.name)
            if dataclasses.is_dataclass(item) and not isinstance(item, type):
                walk(item, f"{prefix}{field.name}.")
            else:
                flat[f"{prefix}{field.name}"] = item

    walk(options, "")
    return flat


def _configure_rich_settings(window) -> None:
    """Touch one widget in every group the preview used to drop."""
    window.install_edit.setPlainText("vim\nhtop")
    window.remove_edit.setPlainText("thunderbird")
    window.purge_remove_check.setChecked(True)
    window.snap_specs_edit.setPlainText("firefox:stable\ncode:stable:classic")
    window.ppa_specs_edit.setPlainText("ppa:graphics-drivers/ppa@ABC123")
    window.ppa_auto_key_check.setChecked(False)
    window.sudo_check.setChecked(False)
    window.kiosk_check.setChecked(True)
    window.kiosk_url_edit.setText("https://kiosk.invalid")
    window.kiosk_browser_edit.setText("epiphany")
    window.kiosk_user_edit.setText("demo")
    window.secure_boot_check.setChecked(True)
    window.secure_boot_mok_key_edit.setText("/keys/mok.key")
    window.secure_boot_sign_modules_check.setChecked(True)
    window.vuln_scan_check.setChecked(True)
    window.brand_name_edit.setText("Forge Remix")
    window.brand_pretty_name_edit.setText("Forge Remix 26.04")
    window.brand_palette_colors_edit.setText("#112233,#445566")
    window.autoinstall_check.setChecked(True)
    window.autoinstall_user_edit.setText("forge")
    window.autoinstall_packages_edit.setPlainText("curl")
    window.users_edit.setPlainText("forge:sudo,video:$y$j9T$hash")
    window.dns_edit.setText("1.1.1.1, 9.9.9.9")
    window.enable_services_edit.setPlainText("ssh")
    window.mask_services_edit.setPlainText("bluetooth")
    window.mirrors_check.setChecked(True)
    window.mirror_archive_edit.setText("http://mirror.invalid/ubuntu")
    window.mirror_allow_http_check.setChecked(True)
    window.kernel_full_deb_check.setChecked(True)
    window.kernel_version_edit.setText("6.20")
    window.desktop_source_check.setChecked(True)
    window.desktop_source_components_edit.setPlainText(
        "gnome-shell|50.0|https://example.invalid/gnome-shell-50.0.tar.xz"
    )
    window.prebuild_vm_check.setChecked(True)
    window.prebuild_vm_tpm_check.setChecked(True)
    window.qa_edit.setText("live-bios, live-uefi")
    window.reproducible_check.setChecked(True)
    window.source_date_epoch_edit.setText("1700000000")
    window.apt_snapshot_edit.setText("20250601T030400Z")
    window.keep_logs_check.setChecked(True)
    window.import_scripts_edit.setPlainText("/tmp/distroforge-import.sh")
    window.size_report_check.setChecked(True)
    combo = window.squashfs_compression_combo
    combo.setCurrentIndex(combo.findData("zstd"))


# --- B13: an imported preset must not freeze the screen ---------------------


def test_imported_preset_lands_in_the_widgets(tmp_path, qt_app) -> None:
    from distroforge.ui.recipe_actions import load_build_preset_into_window

    window = _window(tmp_path, "PresetHydrate")
    preset = tmp_path / "preset.yaml"
    options = apply_definition(
        window.project,
        {
            "kiosk": {"enabled": True, "browser": "epiphany", "url": "https://preset.invalid"},
            "sanitize": {"apt_lists": True, "ssh_host_keys": True},
            "branding": {"name": "Preset Remix"},
            "mirrors": {"enabled": True, "archive_mirror": "http://preset.invalid/ubuntu"},
        },
    )

    load_build_preset_into_window(window, options, preset)

    assert window.kiosk_check.isChecked()
    assert window.kiosk_url_edit.text() == "https://preset.invalid"
    assert window.sanitize_apt_lists_check.isChecked()
    assert window.brand_name_edit.text() == "Preset Remix"
    assert window.mirror_archive_edit.text() == "http://preset.invalid/ubuntu"


def test_editing_a_widget_after_a_preset_wins_like_a_cli_flag(tmp_path, qt_app) -> None:
    # This is the CLI contract: --definition first, then the explicit flags.
    # use_sudo is the sharpest case -- definitions never carry it, so unchecking
    # "Use sudo" used to be a guaranteed no-op once a preset was loaded.
    from distroforge.ui.recipe_actions import load_build_preset_into_window

    window = _window(tmp_path, "PresetOverride")
    options = apply_definition(window.project, {"kiosk": {"enabled": True, "url": "https://p"}})
    load_build_preset_into_window(window, options, tmp_path / "preset.yaml")

    window.sudo_check.setChecked(False)
    window.kiosk_check.setChecked(False)
    window.brand_vendor_edit.setText("Edited Vendor")
    rebuilt = window._build_options()

    assert rebuilt.use_sudo is False
    assert rebuilt.kiosk.enabled is False
    assert rebuilt.branding.vendor == "Edited Vendor"


def test_unchecking_sudo_under_a_preset_is_not_a_no_op(tmp_path, qt_app) -> None:
    """Definitions never carry use_sudo, so a loaded preset always defaulted it to
    True: the widget could not lose that race, whatever the user clicked."""
    window = _window(tmp_path, "SudoNoop")
    window.loaded_preset_options = apply_definition(window.project, {"oem": {"enabled": True}})

    window.sudo_check.setChecked(False)

    assert window._build_options().use_sudo is False


def test_build_and_release_states_the_preset_in_words(tmp_path, qt_app) -> None:
    from distroforge.ui.build_guidance import NO_PRESET_STATUS_TEXT
    from distroforge.ui.recipe_actions import load_build_preset_into_window

    window = _window(tmp_path, "PresetStatus")
    assert window.preset_status_label.text() == NO_PRESET_STATUS_TEXT

    options = apply_definition(window.project, {"oem": {"enabled": True}})
    load_build_preset_into_window(window, options, tmp_path / "maintainer.yaml")
    assert "maintainer.yaml" in window.preset_status_label.text()

    window._clear_build_preset()
    assert window.preset_status_label.text() == NO_PRESET_STATUS_TEXT


def test_preset_survives_a_widget_round_trip_except_the_unmapped_settings(
    tmp_path, qt_app
) -> None:
    """A preset exported from a configured screen must re-import to the same options.

    Everything the widgets can hold has to survive; anything left over is a real
    parity gap, so the allowlist below is the whole documented residue.
    """
    from distroforge.ui.recipe_actions import load_build_preset_into_window

    source = _window(tmp_path, "PresetExport")
    _configure_rich_settings(source)
    source._sync_project_from_ui()
    exported = definition_from_project(source.project, source._build_options())

    target = _window(tmp_path, "PresetImport")
    options = apply_definition(target.project, exported)
    load_build_preset_into_window(target, options, tmp_path / "round-trip.yaml")
    rebuilt = target._build_options()

    before, after = _flatten(options), _flatten(rebuilt)
    # Derived on both surfaces from the Desktop & Identity fields, exactly as the
    # CLI derives them from project.customization.
    derived = {
        "autoinstall.hostname",
        "autoinstall.locale",
        "autoinstall.keyboard",
        "autoinstall.timezone",
        "autoinstall.drivers_install",
        "desktop_source.desktop",
        "apt_cache.enabled",
        "apt_cache.proxy_url",
        "package_plan.install",
        "package_plan.remove",
        "seeds.packages",
    }
    drifted = {
        key: (before[key], after[key])
        for key in before
        if key not in derived and list_safe(before[key]) != list_safe(after[key])
    }
    assert drifted == {}
    # The package lists are a union, never a loss.
    assert set(options.package_plan.install) <= set(rebuilt.package_plan.install)


def list_safe(value: object) -> object:
    """Compare sequences by content: a definition round trip turns tuples into lists."""
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return value


# --- B14: the GUI must feed the seed manifest -------------------------------


def test_gui_and_cli_render_the_same_seed_manifest(tmp_path, qt_app) -> None:
    from distroforge.ui.cli_equivalent import build_cli_equivalent

    window = _window(tmp_path, "SeedParity")
    window.install_edit.setPlainText("vim\nhtop")
    window.snap_specs_edit.setPlainText("firefox:stable\ncode:stable:classic")
    gui_options = window._build_options()

    argv = shlex.split(build_cli_equivalent(window))
    args = _build_parser().parse_args(argv[2:])
    project = Project.load(args.root)
    cli_options = build_options_from_args(project, args)

    runner = CommandRunner(dry_run=True)
    gui_manifest = SeedService(runner, window.project, gui_options.seeds).render_manifest()
    cli_manifest = SeedService(runner, project, cli_options.seeds).render_manifest()

    assert gui_manifest == cli_manifest
    assert "firefox:stable" in gui_manifest
    assert "code:stable:classic" in gui_manifest


def test_exported_gui_preset_keeps_its_snaps_in_the_seeds(tmp_path, qt_app) -> None:
    window = _window(tmp_path, "SeedPreset")
    window.snap_specs_edit.setPlainText("firefox:stable")
    window._sync_project_from_ui()

    exported = definition_from_project(window.project, window._build_options())

    assert exported["seeds"]["snaps"] == ["firefox:stable"]


# --- B15: the rendered command must be the current settings -----------------


def test_rendered_command_reparses_into_the_same_options(tmp_path, qt_app) -> None:
    from distroforge.ui.cli_equivalent import build_cli_equivalent

    window = _window(tmp_path, "CommandRoundTrip")
    _configure_rich_settings(window)
    gui_options = window._build_options()

    argv = shlex.split(build_cli_equivalent(window))
    assert argv[:2] == ["distroforge", "build"]
    args = _build_parser().parse_args(argv[2:])
    project = Project.load(args.root)
    if args.source_iso:
        project.source_iso = args.source_iso
    if args.from_scratch:
        project.source_mode = "bootstrap"
    apply_customization_args(project, args)
    cli_options = build_options_from_args(project, args)
    apply_cli_overrides(project, args, cli_options)

    gui, cli = _flatten(gui_options), _flatten(cli_options)
    drifted = {
        key: (gui[key], cli[key])
        for key in gui
        if list_safe(gui[key]) != list_safe(cli[key])
    }
    assert drifted == {}


def test_kiosk_reaches_the_rendered_command(tmp_path, qt_app) -> None:
    # The audit's demonstration: ticking Kiosk and typing a URL produced a command
    # that built an ISO without kiosk mode.
    from distroforge.ui.cli_equivalent import build_cli_equivalent

    window = _window(tmp_path, "KioskPreview")
    window.kiosk_check.setChecked(True)
    window.kiosk_url_edit.setText("https://kiosk.invalid")

    argv = shlex.split(build_cli_equivalent(window))

    assert "--kiosk" in argv
    assert "https://kiosk.invalid" in argv


def test_loaded_preset_appears_in_the_rendered_command(tmp_path, qt_app) -> None:
    from distroforge.ui.cli_equivalent import build_cli_equivalent
    from distroforge.ui.recipe_actions import load_build_preset_into_window

    window = _window(tmp_path, "PresetPreview")
    preset = tmp_path / "shown.yaml"
    options = apply_definition(window.project, {"oem": {"enabled": True}})
    load_build_preset_into_window(window, options, preset)

    argv = shlex.split(build_cli_equivalent(window))

    assert argv.index("--definition") < argv.index("--oem")
    assert str(preset) in argv


def test_the_preview_renders_every_build_option() -> None:
    """The preview is generated from the option set, so coverage is measurable.

    A hand-picked list of flags is exactly how 173 of 191 options went missing;
    this counts what the renderer can emit against the parser's own contract.
    """
    contracts = build_option_contracts(_build_parser())
    documented = {item.option for item in BUILD_OPTION_EXCEPTIONS} | RESOLVED_OPTIONS
    source = (ROOT / "distroforge/ui/cli_equivalent.py").read_text(encoding="utf-8")
    rendered = set(re.findall(r'"(--[a-z0-9-]+)"', source))

    missing = sorted(
        contract.option
        for contract in contracts
        if contract.option not in documented and contract.option not in rendered
    )

    assert missing == []
