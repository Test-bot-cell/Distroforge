from __future__ import annotations

from pathlib import Path

from distroforge.core.command import CommandRunner
from distroforge.core.prebuild_vm import PrebuildVmOptions, QemuLabService
from distroforge.core.qemu_screenshot import QemuScreenshotOptions, QemuScreenshotService
from distroforge.core.validate import validate_prebuild_vm_options

# Source paths are anchored here, not at the working directory: pybuild runs the
# test phase from the staged build tree, where a relative "distroforge/..." would
# read the installed copy instead of the file the assertion is about.
ROOT = Path(__file__).resolve().parents[1]


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

    # The enrolled .ms store, not the plain one. Only it carries the Microsoft keys a
    # signed shim chains to, so copying the plain template would boot with Secure Boot
    # off while the report said it was on. Asserted by suffix rather than by full path
    # so the test does not depend on which ovmf is installed on the runner.
    assert any(
        argv[0] == "copy-file" and argv[1].endswith(".ms.fd") and argv[2].endswith("OVMF_VARS.fd")
        for argv in commands
    )
    assert any(argv[:2] == ("swtpm", "socket") for argv in commands)
    assert any("if=pflash" in part for part in qemu)
    assert any("tpm-tis" in part for part in qemu)
    assert any(argv[:2] == ("pkill", "-f") for argv in commands)


def test_qemu_lab_gui_exposes_artifacts() -> None:
    window_widgets = (ROOT / "distroforge/ui/window_widgets.py").read_text(encoding="utf-8")

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


# validate_prebuild_vm_options had no test at all, which is how a firmware default
# pointing at a file no ovmf package ships, and a Secure Boot flag that could be set
# on a firmware build unable to enforce it, both survived.


def _uefi_options(**overrides) -> PrebuildVmOptions:
    return PrebuildVmOptions(enabled=True, firmware="uefi", **overrides)


def test_uefi_validation_refuses_a_firmware_image_that_is_not_installed(tmp_path) -> None:
    options = _uefi_options(ovmf_code=str(tmp_path / "absent.fd"))

    codes = [issue.code for issue in validate_prebuild_vm_options(options)]

    assert "prebuild-vm-ovmf-missing" in codes


def test_secure_boot_refuses_a_firmware_build_that_cannot_enforce_it(tmp_path) -> None:
    plain_code = tmp_path / "OVMF_CODE_4M.fd"
    plain_vars = tmp_path / "OVMF_VARS_4M.fd"
    plain_code.write_bytes(b"")
    plain_vars.write_bytes(b"")
    options = _uefi_options(secure_boot=True, ovmf_code=str(plain_code), ovmf_vars=str(plain_vars))

    issues = validate_prebuild_vm_options(options)

    # Refused rather than silently swapped: the caller named these paths, and a run
    # that reports Secure Boot while the firmware ignores it is worse than no offer.
    assert [issue.code for issue in issues] == ["prebuild-vm-secure-boot-firmware"]


def test_secure_boot_accepts_the_enrolled_pair(tmp_path) -> None:
    code = tmp_path / "OVMF_CODE_4M.secboot.fd"
    store = tmp_path / "OVMF_VARS_4M.ms.fd"
    code.write_bytes(b"")
    store.write_bytes(b"")
    options = _uefi_options(secure_boot=True, ovmf_code=str(code), ovmf_vars=str(store))

    assert validate_prebuild_vm_options(options) == []


def test_a_disabled_lab_is_never_asked_about_firmware(tmp_path) -> None:
    # The gate must stay on `enabled`: a project that never runs a VM must not fail
    # validation because the build host has no ovmf installed.
    options = PrebuildVmOptions(enabled=False, firmware="uefi", ovmf_code=str(tmp_path / "absent.fd"))

    assert validate_prebuild_vm_options(options) == []
