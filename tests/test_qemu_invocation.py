from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from distroforge.core import qemu_invocation
from distroforge.core.qemu_invocation import (
    QEMU_SYSTEM,
    SECURE_BOOT_MACHINE,
    QemuInvocation,
    default_ovmf_code,
    default_ovmf_vars,
    is_secure_boot_firmware,
    kvm_is_usable,
)

ISO = Path("/img/image.iso")
FIRMWARE_DESCRIPTORS = Path("/usr/share/qemu/firmware")


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
    # Resolved on the host, not written out: the literal this used to assert,
    # /usr/share/OVMF/OVMF_CODE.fd, is shipped by no current ovmf package.
    assert f"if=pflash,format=raw,readonly=on,file={default_ovmf_code()}" in argv
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
    assert argv[:3] == (QEMU_SYSTEM, "-M", SECURE_BOOT_MACHINE)


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

    assert ("-bios", default_ovmf_code()) == argv[argv.index("-bios"):argv.index("-bios") + 2]
    assert not any(part.startswith("if=pflash") for part in argv)


def test_bios_firmware_emits_no_firmware_flags() -> None:
    argv = QemuInvocation(iso=ISO, firmware="bios").argv()

    assert "-bios" not in argv
    assert not any("pflash" in part for part in argv)


# The machine type. A Secure Boot run on the machine QEMU picks by default does not
# fail, it hangs: measured against one desktop ISO, the run that reaches a graphical
# target under `-M q35,smm=on` produced an empty serial log on the default i440fx,
# so the lab burned its whole timeout and then blamed the ISO for a missing marker.


def test_secure_boot_selects_the_machine_its_firmware_requires() -> None:
    argv = QemuInvocation(iso=ISO, firmware="uefi", secure_boot=True).argv()

    # First, because -M configures the machine every later flag plugs into.
    assert argv[:3] == (QEMU_SYSTEM, "-M", SECURE_BOOT_MACHINE)
    assert "smm=on" in SECURE_BOOT_MACHINE


@pytest.mark.parametrize(
    "options",
    [
        {"firmware": "bios"},
        {"firmware": "uefi"},
        {"firmware": "uefi", "legacy_bios": True},
    ],
)
def test_every_path_without_secure_boot_keeps_the_default_machine(options) -> None:
    # These are the shapes a boot proof has already returned green on. Moving them to
    # another machine would ask for that proof again and buy nothing: the plain
    # firmware descriptor accepts the default machine as well.
    assert "-M" not in QemuInvocation(iso=ISO, **options).argv()


def test_the_secure_boot_machine_is_the_one_the_installed_firmware_declares() -> None:
    """Check the constant against ovmf's own descriptors, not against a comment.

    /usr/share/qemu/firmware is the packaged, machine-readable description of each
    flash image. Reading it here means an ovmf upload that moves Secure Boot onto
    another machine type, or drops the SMM requirement, turns this test red instead
    of turning every Secure Boot proof into a silent 30-minute hang.
    """
    if not FIRMWARE_DESCRIPTORS.is_dir():
        pytest.skip(f"{FIRMWARE_DESCRIPTORS} is not installed")
    code = Path(default_ovmf_code(secure_boot=True)).resolve()
    ours = []
    for path in sorted(FIRMWARE_DESCRIPTORS.glob("*.json")):
        descriptor = json.loads(path.read_text(encoding="utf-8"))
        # Not every descriptor maps a flash image: the Intel TDX one on this machine
        # carries a `mapping` with no `executable` at all.
        named = descriptor.get("mapping", {}).get("executable", {}).get("filename", "")
        if not named or "secure-boot" not in descriptor.get("features", ()):
            continue
        if Path(named).resolve() == code:
            ours.append(descriptor)
    if not ours:
        pytest.skip(f"no installed firmware descriptor covers {code}")

    machine, _, properties = SECURE_BOOT_MACHINE.partition(",")
    for descriptor in ours:
        targets = [name for target in descriptor["targets"] for name in target["machines"]]
        # `pc-q35-9.2` and friends are the versioned names; `q35` is the alias for the
        # newest of them, which is what a lab that wants today's machine should ask for.
        assert targets, descriptor["description"]
        assert all(name.startswith(f"pc-{machine}-") for name in targets), targets
        if "requires-smm" in descriptor.get("features", ()):
            assert "smm=on" in properties.split(",")


# Hardware acceleration. Every automated launch ran under TCG on hosts that had a
# perfectly usable /dev/kvm, because only the interactive preview ever asked -- and it
# asked a question that was not the one that matters.


def test_kvm_probe_declines_a_device_that_is_not_there(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(qemu_invocation, "KVM_DEVICE", tmp_path / "kvm")

    assert kvm_is_usable() is False


def test_kvm_probe_accepts_a_device_it_can_read_and_write(tmp_path, monkeypatch) -> None:
    device = tmp_path / "kvm"
    device.write_bytes(b"")
    monkeypatch.setattr(qemu_invocation, "KVM_DEVICE", device)

    assert kvm_is_usable() is True


@pytest.mark.unprivileged
def test_kvm_probe_declines_a_device_it_cannot_open(tmp_path, monkeypatch) -> None:
    # Present is not the same as usable, which is the whole reason the check moved off
    # Path.exists(): a host whose /dev/kvm refuses to open must emulate, not die inside
    # QEMU on "Could not access KVM kernel module".
    device = tmp_path / "kvm"
    device.write_bytes(b"")
    device.chmod(0o000)
    monkeypatch.setattr(qemu_invocation, "KVM_DEVICE", device)

    assert kvm_is_usable() is False


def test_acceleration_is_one_flag_and_nothing_else(tmp_path, monkeypatch) -> None:
    device = tmp_path / "kvm"
    device.write_bytes(b"")
    monkeypatch.setattr(qemu_invocation, "KVM_DEVICE", device)

    argv = QemuInvocation(iso=ISO, enable_kvm=kvm_is_usable()).argv()

    assert "-enable-kvm" in argv
    # No -cpu. Measured on this host it bought nothing, and passing it would give the
    # guest a different CPU depending on whether the host could accelerate, which is
    # exactly the kind of difference a boot proof must not have.
    assert "-cpu" not in argv


def _qemu_invocation_calls(source: str) -> list[ast.Call]:
    return [
        node
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "QemuInvocation"
    ]


def test_every_service_that_launches_qemu_decides_whether_to_accelerate() -> None:
    """Found by walking the package, so a seventh launch site cannot quietly emulate.

    Six services build a QEMU command line through this module. Five of them said
    nothing about acceleration and therefore got the dataclass default, which is off:
    the flag was reachable only from the interactive preview, and a maintainer running
    the automated proofs had no way to ask for it.
    """
    core = Path(qemu_invocation.__file__).parent
    checked = 0
    for module in sorted(core.glob("*.py")):
        if module.name == "qemu_invocation.py":
            continue
        calls = _qemu_invocation_calls(module.read_text(encoding="utf-8"))
        for call in calls:
            keywords = {keyword.arg for keyword in call.keywords}
            if module.name == "qemu_smoke.py":
                # The one exception, and not an oversight: the smoke planner emits
                # command lines into a report for someone to run later, possibly on
                # another machine. Baking the planning host's acceleration into a
                # published plan would describe a run nobody performed.
                assert "enable_kvm" not in keywords, module.name
                continue
            assert "enable_kvm" in keywords, f"{module.name} launches QEMU unaccelerated"
            checked += 1
    assert checked >= 6, f"expected every launch site to be covered, saw {checked}"


# The OVMF resolver. Its absence was not a style problem: /usr/share/OVMF/OVMF_CODE.fd
# was the default in nine places and has not been shipped since the firmware was
# rebuilt at 4 MB, so every UEFI launch in the product died on a missing file.


def test_ovmf_default_prefers_an_installed_image_over_the_historical_name(tmp_path, monkeypatch) -> None:
    installed = tmp_path / "OVMF_CODE_4M.fd"
    installed.write_bytes(b"")
    monkeypatch.setattr(
        qemu_invocation, "_OVMF_CODE", (str(installed), "/usr/share/OVMF/OVMF_CODE.fd")
    )

    assert default_ovmf_code() == str(installed)


def test_ovmf_default_skips_a_candidate_that_is_not_installed(tmp_path, monkeypatch) -> None:
    installed = tmp_path / "OVMF_CODE.fd"
    installed.write_bytes(b"")
    monkeypatch.setattr(
        qemu_invocation, "_OVMF_CODE", (str(tmp_path / "absent_4M.fd"), str(installed))
    )

    assert default_ovmf_code() == str(installed)


def test_ovmf_default_names_the_modern_path_when_nothing_is_installed(tmp_path, monkeypatch) -> None:
    modern = str(tmp_path / "OVMF_CODE_4M.fd")
    monkeypatch.setattr(qemu_invocation, "_OVMF_CODE", (modern, str(tmp_path / "OVMF_CODE.fd")))

    # So the error a caller reports and the apt line it suggests name the same file,
    # rather than a path that stopped existing several releases ago.
    assert default_ovmf_code() == modern


def test_an_explicitly_named_firmware_is_never_second_guessed(tmp_path) -> None:
    named = str(tmp_path / "my-own-build.fd")

    assert default_ovmf_code(named) == named
    assert default_ovmf_vars(named, secure_boot=True) == named


def test_secure_boot_resolves_the_enrolled_pair_not_the_plain_one() -> None:
    assert default_ovmf_code(secure_boot=True).endswith(".secboot.fd")
    assert default_ovmf_vars(secure_boot=True).endswith(".ms.fd")
    assert not default_ovmf_code().endswith(".secboot.fd")
    assert not default_ovmf_vars().endswith(".ms.fd")


def test_secure_boot_firmware_needs_both_halves_of_the_pair() -> None:
    assert is_secure_boot_firmware("/x/OVMF_CODE_4M.secboot.fd", "/x/OVMF_VARS_4M.ms.fd")
    # The -global secure=on flag is not what enforces Secure Boot: the plain build
    # ignores it, and plain variables carry none of the enrolled keys.
    assert not is_secure_boot_firmware("/x/OVMF_CODE_4M.fd", "/x/OVMF_VARS_4M.ms.fd")
    assert not is_secure_boot_firmware("/x/OVMF_CODE_4M.secboot.fd", "/x/OVMF_VARS_4M.fd")
