from __future__ import annotations

import json
from pathlib import Path

import pytest

from distroforge.core import boot_proof
from distroforge.core.boot_proof import resolve_firmware, run_boot_proof
from distroforge.core.build import BuildOptions
from distroforge.core.command import CommandRunner
from distroforge.core.prebuild_vm import PrebuildVmOptions, QemuLabService
from distroforge.core.project import Project
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


# The serial-log assertion, and when the journal is allowed to say it passed. Emitted
# on the way in, it wrote `prebuild-vm-assert-log ... rc=0` into the build journal
# before the wait had read one byte, so a run that sat in the firmware until its
# timeout left a log whose last word was a green assertion -- in the very file a
# maintainer opens to find out which step failed.


def _validating_lab(tmp_path, serial_text: str | None, *, dry_run: bool = False):
    runner = CommandRunner(dry_run=dry_run)
    options = PrebuildVmOptions(enabled=True, success_patterns=["login:"], timeout_seconds=1)
    dist = tmp_path / "dist"
    dist.mkdir(exist_ok=True)
    if serial_text is not None:
        (dist / options.serial_log).write_text(serial_text, encoding="utf-8")
    lab = QemuLabService(runner, tmp_path / "image.iso", tmp_path / "work", dist, options)
    return runner, lab


def _asserted(runner: CommandRunner) -> list[tuple[str, ...]]:
    return [spec.argv for spec in runner.history if spec.argv[:1] == ("prebuild-vm-assert-log",)]


def test_the_journal_records_the_serial_assertion_once_the_marker_is_really_there(tmp_path) -> None:
    runner, lab = _validating_lab(tmp_path, "[  OK  ] Reached target getty.target\nhost login: ")

    lab._validate_serial_log()

    assert len(_asserted(runner)) == 1


def test_a_serial_log_that_never_carries_the_marker_records_no_passing_assertion(tmp_path) -> None:
    # What a Secure Boot run on the wrong machine produced: a serial log that exists and
    # stays empty, because the firmware never handed off to anything that could write it.
    runner, lab = _validating_lab(tmp_path, "")

    with pytest.raises(ValueError, match="did not emit expected serial marker"):
        lab._validate_serial_log()

    assert _asserted(runner) == []


def test_a_dry_run_still_plans_the_assertion_it_will_not_perform(tmp_path) -> None:
    # Unchanged on purpose: in a plan the line is the step, not its result, and the
    # printed command list is a documented output.
    runner, lab = _validating_lab(tmp_path, None, dry_run=True)

    lab._validate_serial_log()

    assert len(_asserted(runner)) == 1


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


# boot-proof ran BIOS whatever the ISO carried: run_boot_proof never touched
# prebuild_vm.firmware and its parser had no flag, so UEFI was reachable only through
# a build. On a BIOS host that is the difference between a proof and a green report
# about the half that already worked.


def _proof_project(tmp_path: Path, name: str) -> tuple[Project, Path]:
    project = Project.create(name, tmp_path / name, "26.04")
    iso = project.output_dir / f"{name}.iso"
    iso.write_bytes(b"")
    return project, iso


def _installed_firmware(tmp_path: Path, *, secure: bool) -> tuple[Path, Path]:
    """A firmware pair on disk, named the way ovmf names them.

    Created in the test's own directory rather than resolved from the host: otherwise
    whether /usr/share/OVMF carries the Secure Boot build decides the assertion, and a
    CI runner has no ovmf at all.
    """
    names = ("OVMF_CODE_4M.secboot.fd", "OVMF_VARS_4M.ms.fd") if secure else ("OVMF_CODE_4M.fd", "OVMF_VARS_4M.fd")
    code, store = (tmp_path / name for name in names)
    code.write_bytes(b"")
    store.write_bytes(b"")
    return code, store


def _firmware_options(tmp_path: Path, *, secure: bool, **overrides) -> BuildOptions:
    code, store = _installed_firmware(tmp_path, secure=secure)
    options = BuildOptions()
    options.prebuild_vm.ovmf_code = str(code)
    options.prebuild_vm.ovmf_vars = str(store)
    for name, value in overrides.items():
        setattr(options.prebuild_vm, name, value)
    return options


def _plan_boot_proof(monkeypatch, project: Project, iso: Path, *, options: BuildOptions | None = None, **request):
    """Plan a QEMU boot proof, and hand back the report *and* the argv it planned.

    The service builds its own runner, so a recorder is swapped in rather than injected.
    The report alone cannot answer these tests: a firmware that reaches the report and
    never reaches the command line is precisely the failure being guarded against.
    """
    runner = CommandRunner(dry_run=True)
    monkeypatch.setattr(boot_proof, "CommandRunner", lambda dry_run: runner)
    report = run_boot_proof(project, options, iso=iso, execute=False, **request)
    return report, [spec.argv for spec in runner.history]


def _qemu_argv(commands) -> tuple[str, ...]:
    return next(argv for argv in commands if argv and argv[0] == "qemu-system-x86_64")


def test_a_boot_proof_nobody_configured_runs_bios_and_says_so(tmp_path, monkeypatch) -> None:
    project, iso = _proof_project(tmp_path, "ProofDefault")

    report, commands = _plan_boot_proof(monkeypatch, project, iso, backend="qemu")

    assert not any("if=pflash" in part for part in _qemu_argv(commands))
    assert report.firmware == "bios"
    assert "Firmware: bios" in report.render_text()


def test_the_firmware_flag_reaches_qemu_and_not_only_the_report(tmp_path, monkeypatch) -> None:
    project, iso = _proof_project(tmp_path, "ProofUefi")
    options = _firmware_options(tmp_path, secure=False)

    report, commands = _plan_boot_proof(monkeypatch, project, iso, options=options, backend="qemu", firmware="uefi")
    qemu = _qemu_argv(commands)

    assert any("if=pflash" in part and options.prebuild_vm.ovmf_code in part for part in qemu)
    assert "-global" not in qemu
    assert report.firmware == "uefi"
    assert report.secure_boot is False


def test_secure_boot_asks_for_the_enrolled_pair_and_makes_the_firmware_enforce_it(tmp_path, monkeypatch) -> None:
    project, iso = _proof_project(tmp_path, "ProofSecure")
    options = _firmware_options(tmp_path, secure=True)

    report, commands = _plan_boot_proof(
        monkeypatch, project, iso, options=options, backend="qemu", firmware="uefi", secure_boot=True
    )
    qemu = _qemu_argv(commands)

    assert any(".secboot." in part for part in qemu)
    assert any(argv[0] == "copy-file" and argv[1].endswith(".ms.fd") for argv in commands)
    assert "-global" in qemu
    assert "Firmware: uefi with Secure Boot" in report.render_text()
    # The written proof is what a release gate reads, so the firmware belongs in it too.
    proof = json.loads((project.output_dir / "boot-proof.json").read_text(encoding="utf-8"))
    assert proof["firmware"] == "uefi"
    assert proof["secure_boot"] is True


def test_secure_boot_on_bios_is_refused_before_any_machine_starts(tmp_path, monkeypatch) -> None:
    project, iso = _proof_project(tmp_path, "ProofSbBios")

    report, commands = _plan_boot_proof(monkeypatch, project, iso, backend="qemu", firmware="bios", secure_boot=True)

    assert report.status == "blocked"
    assert any("prebuild-vm-secure-boot" in note for note in report.notes)
    # Before, not after: asking a machine about its firmware once it has booted the
    # wrong one answers nothing, and the report would already read "ready".
    assert not any(argv and argv[0] == "qemu-system-x86_64" for argv in commands)


def test_a_firmware_image_that_is_not_installed_blocks_the_proof(tmp_path, monkeypatch) -> None:
    project, iso = _proof_project(tmp_path, "ProofNoOvmf")
    options = BuildOptions()
    options.prebuild_vm.ovmf_code = str(tmp_path / "absent.fd")

    report, commands = _plan_boot_proof(monkeypatch, project, iso, options=options, backend="qemu", firmware="uefi")

    assert report.status == "blocked"
    assert any("prebuild-vm-ovmf-missing" in note for note in report.notes)
    assert not any(argv and argv[0] == "qemu-system-x86_64" for argv in commands)


def test_a_project_that_already_describes_uefi_keeps_it_without_any_flag(tmp_path, monkeypatch) -> None:
    project, iso = _proof_project(tmp_path, "ProofInherited")
    options = _firmware_options(tmp_path, secure=False, firmware="uefi")

    report, commands = _plan_boot_proof(monkeypatch, project, iso, options=options, backend="qemu")

    assert any("if=pflash" in part for part in _qemu_argv(commands))
    assert report.firmware == "uefi"
    assert resolve_firmware("", "uefi") == "uefi"
    assert resolve_firmware("bios", "uefi") == "bios"


def test_the_command_line_flag_reaches_the_service_and_the_printed_proof(tmp_path, capsys) -> None:
    """argparse to render_boot_proof to run_boot_proof: the link no other test crosses.

    Every other test here calls the service directly, so a flag that was never threaded
    through the command adapter would leave all of them green -- the same blind spot the
    preset exporter had. Status is deliberately not asserted: whether this host has ovmf
    installed decides it, and the question here is whether the word travelled.
    """
    from distroforge.cli import main

    project, iso = _proof_project(tmp_path, "ProofCli")

    main(
        [
            "boot-proof",
            str(project.root),
            "--iso",
            str(iso),
            "--backend",
            "qemu",
            "--firmware",
            "uefi",
            "--dry-run",
            "--json",
        ]
    )

    assert json.loads(capsys.readouterr().out)["firmware"] == "uefi"


def test_a_structural_scan_admits_the_firmware_choice_did_not_apply(tmp_path) -> None:
    project, iso = _proof_project(tmp_path, "ProofScan")

    report = run_boot_proof(project, iso=iso, backend="iso-scan", firmware="uefi", execute=False)

    # Claiming a firmware here would be the worst of both: a green structural report
    # that booted nothing, wearing the word UEFI.
    assert report.firmware == ""
    assert "Firmware:" not in report.render_text()
    assert any("does not apply" in note for note in report.notes)
