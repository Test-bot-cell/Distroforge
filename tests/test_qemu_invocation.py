from __future__ import annotations

from pathlib import Path

from distroforge.core.qemu_invocation import QemuInvocation

ISO = Path("/img/image.iso")


def test_minimal_invocation_is_a_cdrom_boot() -> None:
    argv = QemuInvocation(iso=ISO).argv()

    assert argv == ("qemu-system-x86_64", "-m", "4096", "-cdrom", str(ISO), "-boot", "d")


def test_bootcheck_shape_keeps_timeout_prefix_and_headless_serial() -> None:
    argv = QemuInvocation(
        iso=ISO,
        memory_mb=2048,
        serial="stdio",
        display="none",
        timeout_seconds=180,
    ).argv()

    assert argv == (
        "timeout",
        "180",
        "qemu-system-x86_64",
        "-m",
        "2048",
        "-cdrom",
        str(ISO),
        "-boot",
        "d",
        "-serial",
        "stdio",
        "-display",
        "none",
    )


def test_smoke_bios_offline_shape() -> None:
    argv = QemuInvocation(iso=ISO, memory_mb=4096, network="none").argv()

    assert argv == (
        "qemu-system-x86_64",
        "-m",
        "4096",
        "-cdrom",
        str(ISO),
        "-boot",
        "d",
        "-nic",
        "none",
    )


def test_smoke_uefi_online_uses_readonly_ovmf_code_only() -> None:
    argv = QemuInvocation(iso=ISO, memory_mb=4096, firmware="uefi").argv()

    assert "-drive" in argv
    assert "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd" in argv
    assert not any(part.startswith("if=pflash,format=raw,file=") for part in argv)
    assert "-nic" not in argv


def test_preview_shape_carries_smp_serial_kvm_and_disk() -> None:
    disk = Path("/work/disk.qcow2")
    argv = QemuInvocation(
        iso=ISO,
        memory_mb=4096,
        cpus=2,
        serial="mon:stdio",
        disk=disk,
        enable_kvm=True,
    ).argv()

    assert ("-smp", "2") == argv[3:5]
    assert "mon:stdio" in argv
    assert f"file={disk},format=qcow2,if=virtio" in argv
    assert "-enable-kvm" in argv


def test_lab_shape_carries_qmp_daemonize_uefi_tpm_and_user_net() -> None:
    argv = QemuInvocation(
        iso=ISO,
        memory_mb=4096,
        cpus=2,
        disk=Path("/work/lab.qcow2"),
        serial="file:/dist/serial.log",
        qmp_socket=Path("/work/qemu.qmp"),
        pid_file=Path("/work/qemu.pid"),
        display="none",
        daemonize=True,
        firmware="uefi",
        ovmf_vars="/work/OVMF_VARS.fd",
        secure_boot=True,
        tpm_socket=Path("/work/swtpm.sock"),
        network="user",
    ).argv()

    assert "-qmp" in argv
    assert "-daemonize" in argv
    assert any(part.startswith("if=pflash") for part in argv)
    assert "if=pflash,format=raw,file=/work/OVMF_VARS.fd" in argv
    assert "driver=cfi.pflash01,property=secure,value=on" in argv
    assert any("tpm-tis" in part for part in argv)
    assert "user,model=virtio-net-pci" in argv


def test_screenshot_shape_is_headless_qmp_without_monitor_or_smp() -> None:
    argv = QemuInvocation(
        iso=ISO,
        memory_mb=2048,
        display="none",
        qmp_socket=Path("/dist/shot.qmp"),
        pid_file=Path("/dist/shot.pid"),
        daemonize=True,
    ).argv()

    assert "-qmp" in argv
    assert "-monitor" not in argv
    assert "-smp" not in argv
    assert "-serial" not in argv


def test_qa_uefi_uses_legacy_bios_not_pflash() -> None:
    argv = QemuInvocation(
        iso=ISO,
        memory_mb=4096,
        serial="stdio",
        display="none",
        firmware="uefi",
        legacy_bios=True,
        disk=Path("/work/qa.qcow2"),
    ).argv()

    assert ("-bios", "/usr/share/OVMF/OVMF_CODE.fd") == argv[argv.index("-bios"):argv.index("-bios") + 2]
    assert not any(part.startswith("if=pflash") for part in argv)


def test_bios_firmware_emits_no_firmware_flags() -> None:
    argv = QemuInvocation(iso=ISO, firmware="bios").argv()

    assert "-bios" not in argv
    assert not any("pflash" in part for part in argv)
