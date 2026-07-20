from __future__ import annotations

from pathlib import Path

from distroforge.core.command import CommandRunner
from distroforge.core.qemu_preview import QemuPreviewOptions, QemuPreviewService


def _run(tmp_path, **option_kwargs):
    runner = CommandRunner(dry_run=True)
    iso = tmp_path / "image.iso"
    options = QemuPreviewOptions(enable_kvm=False, **option_kwargs)
    report = QemuPreviewService(runner, iso, tmp_path / "work", tmp_path / "dist", options).run()
    commands = [spec.argv for spec in runner.history]
    qemu = next(argv for argv in commands if argv and argv[0] == "qemu-system-x86_64")
    return report, commands, qemu


def _display_value(qemu: tuple[str, ...]) -> str:
    return qemu[qemu.index("-display") + 1]


def test_preview_dry_run_exposes_qmp_pidfile_and_writes_transcript(tmp_path) -> None:
    report, commands, qemu = _run(tmp_path)

    assert "-qmp" in qemu
    assert "-daemonize" in qemu
    assert "-pidfile" in qemu
    assert "-cdrom" in qemu
    assert f"file:{tmp_path / 'dist' / 'preview-serial.log'}" in qemu
    assert any(argv == ("mkdir", "-p", str(tmp_path / "work" / "preview"), str(tmp_path / "dist")) for argv in commands)
    assert any(argv == ("write-file", str(tmp_path / "dist" / "preview-session.json")) for argv in commands)
    assert any(argv == ("write-file", str(tmp_path / "dist" / "PREVIEW-INTEGRITY")) for argv in commands)
    assert report.argv == qemu


def test_preview_exposes_socket_but_does_not_script_or_stop_qmp(tmp_path) -> None:
    _, commands, _ = _run(tmp_path)

    assert not any(argv[:1] == ("qmp-command",) for argv in commands)
    assert not any(argv[:1] == ("kill",) for argv in commands)


def test_preview_display_modes_map_to_qemu_display_values(tmp_path) -> None:
    assert _display_value(_run(tmp_path, display="gtk")[2]) == "gtk"
    assert _display_value(_run(tmp_path, display="spice")[2]) == "spice-app"
    assert _display_value(_run(tmp_path, display="none")[2]) == "none"


def test_preview_uefi_prepares_writable_ovmf_vars(tmp_path) -> None:
    _, commands, qemu = _run(tmp_path, firmware="uefi")

    assert any(argv[:1] == ("copy-file",) and argv[2].endswith("OVMF_VARS.fd") for argv in commands)
    assert any("if=pflash" in part and "readonly=on" in part for part in qemu)
    assert any(part.startswith("if=pflash,format=raw,file=") and part.endswith("OVMF_VARS.fd") for part in qemu)


def test_preview_bios_uses_no_firmware_or_kvm_flags(tmp_path) -> None:
    _, commands, qemu = _run(tmp_path)

    assert not any("pflash" in part for part in qemu)
    assert "-bios" not in qemu
    assert "-enable-kvm" not in qemu
    assert not any(argv[:1] == ("copy-file",) for argv in commands)


def test_preview_dry_run_writes_no_host_files(tmp_path) -> None:
    _run(tmp_path, firmware="uefi")

    assert not (tmp_path / "dist" / "preview-session.json").exists()
    assert not (tmp_path / "dist" / "PREVIEW-INTEGRITY").exists()
    assert not (tmp_path / "dist" / "preview-serial.log").exists()
    assert not (tmp_path / "work" / "preview" / "OVMF_VARS.fd").exists()


def test_preview_report_is_deterministic_and_schema_pinned(tmp_path) -> None:
    first, _, _ = _run(tmp_path)
    second, _, _ = _run(tmp_path)

    payload = first.to_dict()
    assert payload["schema"] == "distroforge.qemu-preview.v1"
    assert "created_at" not in payload
    assert payload == second.to_dict()


def test_preview_gui_and_registry_expose_the_surface() -> None:
    page = Path("distroforge/ui/virtualization_page.py").read_text(encoding="utf-8")
    widgets = Path("distroforge/ui/window_widgets.py").read_text(encoding="utf-8")
    actions = Path("distroforge/ui/service_actions.py").read_text(encoding="utf-8")
    registry = Path("distroforge/core/command_registry.py").read_text(encoding="utf-8")

    assert "preview_display_combo" in widgets
    assert "preview_display_combo" in page
    assert '"Preview ISO"' in page
    assert "_run_preview" in page
    assert "def run_preview_action" in actions
    assert 'CommandGuiMapping("preview"' in registry
