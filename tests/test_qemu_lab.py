from __future__ import annotations

from pathlib import Path

from distroforge.core.command import CommandRunner
from distroforge.core.prebuild_vm import PrebuildVmOptions, QemuLabService
from distroforge.core.qemu_screenshot import QemuScreenshotOptions, QemuScreenshotService


def test_qemu_lab_dry_run_uses_qmp_and_writes_report(tmp_path) -> None:
    runner = CommandRunner(dry_run=True)
    iso = tmp_path / "image.iso"
    options = PrebuildVmOptions(enabled=True, success_patterns=["login:"])

    QemuLabService(runner, iso, tmp_path / "work", tmp_path / "dist", options).run()

    commands = [spec.argv for spec in runner.history]
    qemu = next(argv for argv in commands if argv and argv[0] == "qemu-system-x86_64")

    assert "-qmp" in qemu
    assert "-daemonize" in qemu
    assert any(argv[:1] == ("qmp-command",) and "query-status" in argv[-1] for argv in commands)
    assert any(argv[:1] == ("qmp-command",) and "screendump" in argv[-1] for argv in commands)
    assert any(argv[:1] == ("qmp-command",) and "quit" in argv[-1] for argv in commands)
    assert any(argv == ("write-file", str(tmp_path / "dist" / "qemu-lab-report.json")) for argv in commands)


def test_qemu_lab_uefi_tpm_artifacts_are_explicit(tmp_path) -> None:
    runner = CommandRunner(dry_run=True)
    options = PrebuildVmOptions(enabled=True, firmware="uefi", secure_boot=True, tpm=True)

    QemuLabService(runner, tmp_path / "image.iso", tmp_path / "work", tmp_path / "dist", options).run()

    commands = [spec.argv for spec in runner.history]
    qemu = next(argv for argv in commands if argv and argv[0] == "qemu-system-x86_64")

    assert any(argv[0] == "copy-file" and "OVMF_VARS.fd" in argv[1] for argv in commands)
    assert any(argv[:2] == ("swtpm", "socket") for argv in commands)
    assert any("if=pflash" in part for part in qemu)
    assert any("tpm-tis" in part for part in qemu)
    assert any(argv[:2] == ("pkill", "-f") for argv in commands)


def test_qemu_lab_gui_exposes_artifacts() -> None:
    window_widgets = Path("distroforge/ui/window_widgets.py").read_text(encoding="utf-8")

    assert "prebuild_vm_qmp_socket_edit" in window_widgets
    assert "prebuild_vm_report_name_edit" in window_widgets
    assert "prebuild_vm_pid_file_edit" in window_widgets
    assert "prebuild_vm_ovmf_code_edit" in window_widgets
    assert "prebuild_vm_ovmf_vars_edit" in window_widgets


def test_qemu_screenshot_uses_qmp_not_stdio_monitor(tmp_path) -> None:
    runner = CommandRunner(dry_run=True)

    QemuScreenshotService(
        runner,
        tmp_path / "image.iso",
        tmp_path / "dist",
        QemuScreenshotOptions(enabled=True),
    ).run()

    commands = [spec.argv for spec in runner.history]
    qemu = next(argv for argv in commands if argv and argv[0] == "qemu-system-x86_64")
    assert "-qmp" in qemu
    assert "-monitor" not in qemu
    screendump = next(argv for argv in commands if argv[:1] == ("qmp-command",) and "screendump" in argv[-1])
    assert '"execute": "screendump"' in screendump[-1]
    assert '"filename"' in screendump[-1] and "qemu-boot.ppm" in screendump[-1]
    assert any(argv[:1] == ("qmp-command",) and argv[-1] == '{"execute": "quit", "arguments": {}}' for argv in commands)
