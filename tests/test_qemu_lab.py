from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest
from conftest import write_valid_qemu_report

from distroforge.core import boot_proof, evidence_run, prebuild_vm, qemu_invocation
from distroforge.core.artifact_paths import default_output_iso
from distroforge.core.artifact_verification import ArtifactVerificationSession
from distroforge.core.boot_proof import resolve_firmware, run_boot_proof
from distroforge.core.build import BuildOptions
from distroforge.core.command import CommandResult, CommandRunner, CommandSpec
from distroforge.core.hashing import sha256_file
from distroforge.core.prebuild_vm import (
    PrebuildVmOptions,
    QemuLabService,
    first_boot_refusal,
    validate_qemu_report,
)
from distroforge.core.project import Project
from distroforge.core.qemu_screenshot import QemuScreenshotOptions, QemuScreenshotService
from distroforge.core.validate import validate_prebuild_vm_options

# Source paths are anchored here, not at the working directory: pybuild runs the
# test phase from the staged build tree, where a relative "distroforge/..." would
# read the installed copy instead of the file the assertion is about.
ROOT = Path(__file__).resolve().parents[1]


class _BoundedScandir:
    def __init__(self, iterator, *, maximum_yields: int) -> None:
        self._iterator = iterator
        self._maximum_yields = maximum_yields
        self.yields = 0

    def __enter__(self):
        self._iterator.__enter__()
        return self

    def __exit__(self, exc_type, exc, traceback):
        return self._iterator.__exit__(exc_type, exc, traceback)

    def __iter__(self):
        return self

    def __next__(self):
        entry = next(self._iterator)
        self.yields += 1
        if self.yields > self._maximum_yields:
            pytest.fail("inventory enumerated beyond its structural budget")
        return entry


class _ExecutionRecorder(CommandRunner):
    def __init__(self) -> None:
        super().__init__(dry_run=False)
        self.qemu_spec: CommandSpec | None = None
        self.consumed_iso = b""
        self.consumed_firmware_code = b""
        self.initial_firmware_vars = b""

    def run(
        self,
        spec: CommandSpec,
        check: bool = True,
    ) -> CommandResult:
        del check
        self.history.append(spec)
        if spec.argv[:2] == ("mkdir", "-p"):
            for value in spec.argv[2:]:
                Path(value).mkdir(parents=True, exist_ok=True)
        elif spec.argv[:2] == ("rm", "-f"):
            for value in spec.argv[2:]:
                Path(value).unlink(missing_ok=True)
        elif spec.argv[:2] == ("qemu-img", "create"):
            Path(spec.argv[4]).write_bytes(b"qcow2")
        elif spec.argv[:1] == ("qemu-system-x86_64",):
            self.qemu_spec = spec
            cdrom = Path(spec.argv[spec.argv.index("-cdrom") + 1])
            self.consumed_iso = cdrom.read_bytes()
            for descriptor in spec.pass_fds:
                os.fstat(descriptor)
            pflash = [value for value in spec.argv if value.startswith("if=pflash")]
            if pflash:
                code = Path(
                    next(value for value in pflash if "readonly=on" in value).rsplit("file=", 1)[1]
                )
                runtime = Path(
                    next(value for value in pflash if "readonly=on" not in value).rsplit(
                        "file=", 1
                    )[1]
                )
                self.consumed_firmware_code = code.read_bytes()
                self.initial_firmware_vars = runtime.read_bytes()
                runtime.write_bytes(b"runtime vars after boot")
            Path(spec.argv[spec.argv.index("-pidfile") + 1]).write_text(
                "4242\n",
                encoding="utf-8",
            )
            serial = spec.argv[spec.argv.index("-serial") + 1].removeprefix("file:")
            Path(serial).write_text("host login: ", encoding="utf-8")
        return CommandResult(spec, 0, "", "")


def _execute_recorded_lab(
    tmp_path: Path,
    monkeypatch,
    *,
    output_dir: Path,
    iso: Path,
    options: PrebuildVmOptions | None = None,
) -> tuple[QemuLabService, _ExecutionRecorder, Path, dict[str, object]]:
    runner = _ExecutionRecorder()
    selected = options or PrebuildVmOptions(
        enabled=True,
        screenshot=False,
        success_patterns=["login:"],
        timeout_seconds=1,
    )
    lab = QemuLabService(
        runner,
        iso,
        tmp_path / "work",
        output_dir,
        selected,
    )

    def qmp_command(name, _socket, arguments=None):
        if name == "screendump":
            assert isinstance(arguments, dict)
            Path(str(arguments["filename"])).write_bytes(b"P6\n1 1\n255\n\x00\x00\x00")

    monkeypatch.setattr(lab._qmp_control, "command", qmp_command)
    monkeypatch.setattr(prebuild_vm, "stop_by_pidfile", lambda *args, **kwargs: None)
    lab.run()
    immutable = output_dir / "evidence" / "runs" / lab.run_id / selected.report_name
    payload = json.loads(immutable.read_text(encoding="utf-8"))
    return lab, runner, immutable, payload


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
    assert any(
        argv == ("write-file", str(tmp_path / "dist" / "qemu-lab-report.json")) for argv in commands
    )


def test_qemu_runtime_outputs_are_confined_to_one_new_run_scratch(
    tmp_path,
    monkeypatch,
) -> None:
    output_dir = tmp_path / "dist"
    iso = output_dir / "image.iso"
    output_dir.mkdir()
    iso.write_bytes(b"pinned ISO")
    options = PrebuildVmOptions(
        enabled=True,
        screenshot=True,
        success_patterns=["login:"],
        timeout_seconds=1,
    )

    lab, runner, immutable, payload = _execute_recorded_lab(
        tmp_path,
        monkeypatch,
        output_dir=output_dir,
        iso=iso,
        options=options,
    )

    expected_scratch = tmp_path / "work" / "prebuild-vm" / "runs" / lab.run_id
    artifacts = lab._artifacts()
    assert lab.workdir == expected_scratch
    assert artifacts.serial_log.parent == expected_scratch
    assert artifacts.screenshot.parent == expected_scratch
    assert artifacts.disk.parent == expected_scratch
    assert not (output_dir / options.serial_log).exists()
    assert not (output_dir / options.screenshot_name).exists()
    assert (immutable.parent / "qemu" / "serial.log").is_file()
    assert (immutable.parent / "qemu" / "screenshot.ppm").is_file()
    assert payload["artifacts"]["serial_log"]["path"] == "qemu/serial.log"
    assert payload["artifacts"]["screenshot"]["path"] == "qemu/screenshot.ppm"
    assert not any(spec.argv[:2] == ("rm", "-f") for spec in runner.history)


def test_qemu_iso_leaf_collision_is_refused_before_cleanup(
    tmp_path,
) -> None:
    output_dir = tmp_path / "dist"
    output_dir.mkdir()
    iso = output_dir / "protected.iso"
    original = b"the ISO must survive"
    iso.write_bytes(original)
    options = PrebuildVmOptions(
        enabled=True,
        serial_log=iso.name,
        screenshot=False,
    )
    runner = _ExecutionRecorder()
    lab = QemuLabService(
        runner,
        iso,
        tmp_path / "work",
        output_dir,
        options,
    )

    with pytest.raises(ValueError, match="collide with managed artifacts"):
        lab.run()

    assert iso.read_bytes() == original
    assert runner.history == []
    assert not (tmp_path / "work" / "prebuild-vm").exists()


def test_qemu_integrity_leaf_cannot_overwrite_the_input_iso(
    tmp_path,
) -> None:
    output_dir = tmp_path / "dist"
    output_dir.mkdir()
    iso = output_dir / "PREBUILD-VM-INTEGRITY"
    original = b"ISO bytes under a managed leaf"
    iso.write_bytes(original)
    runner = _ExecutionRecorder()
    lab = QemuLabService(
        runner,
        iso,
        tmp_path / "work",
        output_dir,
        PrebuildVmOptions(enabled=True, screenshot=False),
    )

    with pytest.raises(ValueError, match="collide with the input ISO path"):
        lab.run()

    assert iso.read_bytes() == original
    assert runner.history == []


@pytest.mark.parametrize(
    ("field_name", "value"),
    (
        ("serial_log", "SHA256SUMS"),
        ("qmp_socket", "qemu-lab.qcow2"),
        ("report_name", "QEMU-REPORT-ALIAS-PUBLICATION.json"),
    ),
)
def test_qemu_validation_refuses_managed_namespace_collisions(
    tmp_path,
    field_name: str,
    value: str,
) -> None:
    options = PrebuildVmOptions(enabled=True)
    setattr(options, field_name, value)

    issues = validate_prebuild_vm_options(options)

    assert any(issue.code == "prebuild-vm-artifact-collision" for issue in issues)
    with pytest.raises(ValueError, match="collide with managed artifacts"):
        QemuLabService(
            CommandRunner(dry_run=True),
            tmp_path / "image.iso",
            tmp_path / "work",
            tmp_path / "dist",
            options,
        ).run()


def test_qemu_validation_refuses_control_output_leaf_aliasing(
    tmp_path,
) -> None:
    options = PrebuildVmOptions(
        enabled=True,
        qmp_socket="shared-runtime-leaf",
        serial_log="shared-runtime-leaf",
    )

    assert any(
        issue.code == "prebuild-vm-artifact-collision"
        for issue in validate_prebuild_vm_options(options)
    )
    with pytest.raises(ValueError, match="must all be different"):
        QemuLabService(
            CommandRunner(dry_run=True),
            tmp_path / "image.iso",
            tmp_path / "work",
            tmp_path / "dist",
            options,
        ).run()


def test_qemu_refuses_a_symlinked_scratch_ancestor_before_commands(
    tmp_path,
) -> None:
    output_dir = tmp_path / "dist"
    iso = tmp_path / "image.iso"
    iso.write_bytes(b"pinned")
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_bytes(b"untouched")
    work = tmp_path / "work"
    work.mkdir()
    (work / "prebuild-vm").symlink_to(outside, target_is_directory=True)
    runner = _ExecutionRecorder()
    lab = QemuLabService(
        runner,
        iso,
        work,
        output_dir,
        PrebuildVmOptions(enabled=True, screenshot=False),
    )

    with pytest.raises(OSError):
        lab.run()

    assert runner.history == []
    assert sentinel.read_bytes() == b"untouched"


def test_qemu_refuses_to_reuse_an_existing_run_scratch(
    tmp_path,
) -> None:
    run_id = "already-reserved"
    scratch = tmp_path / "work" / "prebuild-vm" / "runs" / run_id
    scratch.mkdir(parents=True)
    sentinel = scratch / "sentinel"
    sentinel.write_bytes(b"foreign runtime state")
    iso = tmp_path / "image.iso"
    iso.write_bytes(b"pinned")
    runner = _ExecutionRecorder()
    lab = QemuLabService(
        runner,
        iso,
        tmp_path / "work",
        tmp_path / "dist",
        PrebuildVmOptions(enabled=True, screenshot=False),
        run_id=run_id,
    )

    with pytest.raises(ValueError, match="refuses to reuse"):
        lab.run()

    assert runner.history == []
    assert sentinel.read_bytes() == b"foreign runtime state"


def test_boot_proof_inventory_stops_enumerating_at_total_entry_budget(
    tmp_path,
    monkeypatch,
) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    for index in range(100):
        (run_dir / f"empty-{index:03d}").mkdir()
    original_scandir = os.scandir
    observed: list[_BoundedScandir] = []

    def bounded_scandir(path):
        iterator = _BoundedScandir(
            original_scandir(path),
            maximum_yields=3,
        )
        observed.append(iterator)
        return iterator

    monkeypatch.setattr(boot_proof, "_BOOT_INVENTORY_MAX_ENTRIES", 2)
    monkeypatch.setattr(boot_proof.os, "scandir", bounded_scandir)

    with pytest.raises(
        prebuild_vm.ArtifactVerificationError,
        match="inventory entry limit",
    ):
        boot_proof._inventory_run_directory(run_dir)

    assert observed[0].yields == 3


def test_qemu_run_inventory_counts_empty_directories_before_sorting(
    tmp_path,
    monkeypatch,
) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    for index in range(100):
        (run_dir / f"empty-{index:03d}").mkdir()
    original_scandir = os.scandir
    observed: list[_BoundedScandir] = []

    def bounded_scandir(path):
        iterator = _BoundedScandir(
            original_scandir(path),
            maximum_yields=3,
        )
        observed.append(iterator)
        return iterator

    monkeypatch.setattr(prebuild_vm.os, "scandir", bounded_scandir)

    with pytest.raises(
        prebuild_vm.ArtifactVerificationError,
        match="2 total entries",
    ):
        prebuild_vm._inventory_regular_tree(
            run_dir,
            excluded=set(),
            max_entries=2,
        )

    assert observed[0].yields == 3


def test_qemu_lab_execution_consumes_the_held_iso_descriptor(
    tmp_path,
    monkeypatch,
) -> None:
    iso = tmp_path / "image.iso"
    iso.write_bytes(b"pinned ISO")
    runner = _ExecutionRecorder()
    options = PrebuildVmOptions(
        enabled=True,
        screenshot=False,
        success_patterns=["login:"],
        timeout_seconds=1,
    )
    lab = QemuLabService(
        runner,
        iso,
        tmp_path / "work",
        tmp_path / "dist",
        options,
    )
    monkeypatch.setattr(lab._qmp_control, "command", lambda *args, **kwargs: None)
    monkeypatch.setattr(prebuild_vm, "stop_by_pidfile", lambda *args, **kwargs: None)

    lab.run()

    assert runner.consumed_iso == b"pinned ISO"
    assert runner.qemu_spec is not None
    assert runner.qemu_spec.pass_fds
    cdrom = runner.qemu_spec.argv[runner.qemu_spec.argv.index("-cdrom") + 1]
    assert cdrom.startswith(f"/proc/{os.getpid()}/fd/")
    report = json.loads((tmp_path / "dist" / options.report_name).read_text(encoding="utf-8"))
    run_dir = tmp_path / "dist" / "evidence" / "runs" / report["run_id"]
    manifest = run_dir / "RUN-MANIFEST.json"
    assert (run_dir / "RUN-MANIFEST.json.sha256").read_text(
        encoding="utf-8"
    ) == f"{sha256_file(manifest)}  RUN-MANIFEST.json\n"


def test_repeated_qemu_runs_preserve_the_first_alias_and_manifest_each_receipt(
    tmp_path,
    monkeypatch,
) -> None:
    output_dir = tmp_path / "dist"
    output_dir.mkdir()
    iso = output_dir / "image.iso"
    iso.write_bytes(b"pinned ISO")

    first_lab, _first_runner, first_report, first_payload = _execute_recorded_lab(
        tmp_path,
        monkeypatch,
        output_dir=output_dir,
        iso=iso,
    )
    alias = output_dir / first_lab.options.report_name
    first_alias_bytes = alias.read_bytes()
    first_receipt = json.loads(
        (first_report.parent / prebuild_vm.QEMU_REPORT_ALIAS_PUBLICATION_NAME).read_text(
            encoding="utf-8"
        )
    )

    second_lab, second_runner, second_report, second_payload = _execute_recorded_lab(
        tmp_path,
        monkeypatch,
        output_dir=output_dir,
        iso=iso,
    )
    second_receipt_path = second_report.parent / prebuild_vm.QEMU_REPORT_ALIAS_PUBLICATION_NAME
    second_receipt = json.loads(second_receipt_path.read_text(encoding="utf-8"))
    manifest_path = second_report.parent / "RUN-MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert first_lab.run_id != second_lab.run_id
    assert first_payload["verdict"] == "passed"
    assert second_payload["verdict"] == "passed"
    assert first_receipt["status"] == "matched"
    assert second_receipt["status"] == "collision-preserved"
    assert alias.read_bytes() == first_alias_bytes
    assert second_report.read_bytes() != first_alias_bytes
    assert any(
        item["path"] == str(second_receipt_path)
        and item["sha256"] == sha256_file(second_receipt_path)
        for item in manifest["files"]
    )
    assert (second_report.parent / "RUN-MANIFEST.json.sha256").read_text(
        encoding="utf-8"
    ) == f"{sha256_file(manifest_path)}  RUN-MANIFEST.json\n"
    assert second_runner.qemu_spec is not None
    for descriptor in second_runner.qemu_spec.pass_fds:
        with pytest.raises(OSError):
            os.fstat(descriptor)


@pytest.mark.parametrize("collision_kind", ("symlink", "fifo"))
def test_qemu_report_alias_special_file_collision_cannot_change_verdict(
    tmp_path,
    monkeypatch,
    collision_kind: str,
) -> None:
    output_dir = tmp_path / "dist"
    output_dir.mkdir()
    iso = tmp_path / "image.iso"
    iso.write_bytes(b"pinned ISO")
    alias = output_dir / "qemu-lab-report.json"
    outside = tmp_path / "outside-report"
    if collision_kind == "symlink":
        outside.write_bytes(b"foreign")
        alias.symlink_to(outside)
    else:
        os.mkfifo(alias)

    _lab, _runner, immutable, payload = _execute_recorded_lab(
        tmp_path,
        monkeypatch,
        output_dir=output_dir,
        iso=iso,
    )
    receipt = json.loads(
        (immutable.parent / prebuild_vm.QEMU_REPORT_ALIAS_PUBLICATION_NAME).read_text(
            encoding="utf-8"
        )
    )

    assert payload["verdict"] == "passed"
    assert receipt["status"] == "collision-preserved"
    if collision_kind == "symlink":
        assert alias.is_symlink()
        assert outside.read_bytes() == b"foreign"
    else:
        assert stat.S_ISFIFO(os.lstat(alias).st_mode)


def test_qemu_report_alias_race_is_preserved_without_blocking_sealed_run(
    tmp_path,
    monkeypatch,
) -> None:
    output_dir = tmp_path / "dist"
    output_dir.mkdir()
    iso = tmp_path / "image.iso"
    iso.write_bytes(b"pinned ISO")
    original = evidence_run.write_text_alias
    raced = False

    def collide_before_link(path, content, **kwargs):
        nonlocal raced
        if not raced:
            raced = True
            path.write_bytes(b"racing publisher")
        return original(path, content, **kwargs)

    monkeypatch.setattr(evidence_run, "write_text_alias", collide_before_link)

    _lab, _runner, immutable, payload = _execute_recorded_lab(
        tmp_path,
        monkeypatch,
        output_dir=output_dir,
        iso=iso,
    )
    receipt = json.loads(
        (immutable.parent / prebuild_vm.QEMU_REPORT_ALIAS_PUBLICATION_NAME).read_text(
            encoding="utf-8"
        )
    )

    assert raced
    assert payload["verdict"] == "passed"
    assert receipt["status"] == "collision-preserved"
    assert (output_dir / "qemu-lab-report.json").read_bytes() == b"racing publisher"


def test_qemu_report_alias_fsync_failure_is_unconfirmed_not_a_qemu_failure(
    tmp_path,
    monkeypatch,
) -> None:
    output_dir = tmp_path / "dist"
    output_dir.mkdir()
    iso = tmp_path / "image.iso"
    iso.write_bytes(b"pinned ISO")

    def fail_alias_fsync(*args, **kwargs):
        raise OSError("simulated alias fsync failure")

    monkeypatch.setattr(evidence_run, "write_text_alias", fail_alias_fsync)

    _lab, _runner, immutable, payload = _execute_recorded_lab(
        tmp_path,
        monkeypatch,
        output_dir=output_dir,
        iso=iso,
    )
    receipt_path = immutable.parent / prebuild_vm.QEMU_REPORT_ALIAS_PUBLICATION_NAME
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    manifest = json.loads((immutable.parent / "RUN-MANIFEST.json").read_text(encoding="utf-8"))

    assert payload["verdict"] == "passed"
    assert receipt["status"] == "unconfirmed"
    assert "fsync" in receipt["detail"]
    assert any(item["path"] == str(receipt_path) for item in manifest["files"])


def test_qemu_iso_witness_allows_proven_sibling_outputs(
    tmp_path,
    monkeypatch,
) -> None:
    output_dir = tmp_path / "dist"
    output_dir.mkdir()
    iso = output_dir / "image.iso"
    iso.write_bytes(b"pinned ISO")
    runner = _ExecutionRecorder()
    lab = QemuLabService(
        runner,
        iso,
        tmp_path / "work",
        output_dir,
        PrebuildVmOptions(
            enabled=True,
            screenshot=False,
            success_patterns=["login:"],
            timeout_seconds=1,
        ),
    )
    monkeypatch.setattr(lab._qmp_control, "command", lambda *args, **kwargs: None)
    monkeypatch.setattr(prebuild_vm, "stop_by_pidfile", lambda *args, **kwargs: None)

    lab.run()

    assert runner.consumed_iso == b"pinned ISO"
    assert (
        json.loads((output_dir / "qemu-lab-report.json").read_text(encoding="utf-8"))["verdict"]
        == "passed"
    )


def test_qemu_lab_execution_pins_and_seals_every_uefi_input(
    tmp_path,
    monkeypatch,
) -> None:
    output_dir = tmp_path / "dist"
    output_dir.mkdir()
    iso = output_dir / "image.iso"
    code = output_dir / "OVMF_CODE_4M.fd"
    template = output_dir / "OVMF_VARS_4M.fd"
    iso.write_bytes(b"pinned ISO")
    code.write_bytes(b"held firmware code")
    template.write_bytes(b"held vars template")
    runner = _ExecutionRecorder()
    options = PrebuildVmOptions(
        enabled=True,
        firmware="uefi",
        ovmf_code=str(code),
        ovmf_vars=str(template),
        screenshot=False,
        success_patterns=["login:"],
        timeout_seconds=1,
    )
    lab = QemuLabService(
        runner,
        iso,
        tmp_path / "work",
        output_dir,
        options,
    )
    monkeypatch.setattr(lab._qmp_control, "command", lambda *args, **kwargs: None)
    monkeypatch.setattr(prebuild_vm, "stop_by_pidfile", lambda *args, **kwargs: None)

    lab.run()

    assert runner.consumed_firmware_code == b"held firmware code"
    assert runner.initial_firmware_vars == b"held vars template"
    assert runner.qemu_spec is not None
    assert len(runner.qemu_spec.pass_fds) == 4
    report = json.loads((output_dir / options.report_name).read_text(encoding="utf-8"))
    firmware = report["execution"]["firmware"]
    assert firmware["consumption"] == {
        "code": "held-descriptor",
        "vars_template": "held-copy-source",
        "vars_runtime": "held-descriptor",
    }
    runtime = output_dir / "evidence" / "runs" / report["run_id"] / firmware["vars_runtime"]["path"]
    assert runtime.read_bytes() == b"runtime vars after boot"
    assert firmware["vars_runtime"]["sha256"] == sha256_file(runtime)


def test_qemu_lab_blocks_firmware_path_swap_around_consumption(
    tmp_path,
    monkeypatch,
) -> None:
    iso = tmp_path / "image.iso"
    code = tmp_path / "OVMF_CODE_4M.fd"
    template = tmp_path / "OVMF_VARS_4M.fd"
    iso.write_bytes(b"pinned ISO")
    code.write_bytes(b"original firmware")
    template.write_bytes(b"vars template")

    class FirmwareSwappingRecorder(_ExecutionRecorder):
        def run(
            self,
            spec: CommandSpec,
            check: bool = True,
        ) -> CommandResult:
            if spec.argv[:1] == ("qemu-system-x86_64",):
                replacement = code.with_name("replacement-code.fd")
                replacement.write_bytes(b"replaced firmware")
                replacement.replace(code)
            return super().run(spec, check=check)

    runner = FirmwareSwappingRecorder()
    options = PrebuildVmOptions(
        enabled=True,
        firmware="uefi",
        ovmf_code=str(code),
        ovmf_vars=str(template),
        screenshot=False,
        success_patterns=["login:"],
        timeout_seconds=1,
    )
    lab = QemuLabService(
        runner,
        iso,
        tmp_path / "work",
        tmp_path / "dist",
        options,
    )
    monkeypatch.setattr(lab._qmp_control, "command", lambda *args, **kwargs: None)
    monkeypatch.setattr(prebuild_vm, "stop_by_pidfile", lambda *args, **kwargs: None)

    with pytest.raises(ValueError, match="runtime artifact sealing failed"):
        lab.run()

    assert runner.consumed_firmware_code == b"original firmware"
    report = json.loads((tmp_path / "dist" / options.report_name).read_text(encoding="utf-8"))
    assert report["verdict"] == "failed"
    assert "OVMF code" in report["error"]


def test_qemu_lab_blocks_serial_path_swap_around_consumption(
    tmp_path,
    monkeypatch,
) -> None:
    iso = tmp_path / "image.iso"
    iso.write_bytes(b"pinned ISO")
    output_dir = tmp_path / "dist"
    serial: Path

    class SerialSwappingRecorder(_ExecutionRecorder):
        def run(
            self,
            spec: CommandSpec,
            check: bool = True,
        ) -> CommandResult:
            if spec.argv[:1] == ("qemu-system-x86_64",):
                replacement = serial.with_name("serial-replacement.log")
                replacement.write_text("host login: ", encoding="utf-8")
                replacement.replace(serial)
            return super().run(spec, check=check)

    runner = SerialSwappingRecorder()
    options = PrebuildVmOptions(
        enabled=True,
        screenshot=False,
        success_patterns=["login:"],
        timeout_seconds=1,
    )
    lab = QemuLabService(
        runner,
        iso,
        tmp_path / "work",
        output_dir,
        options,
    )
    serial = lab._artifacts().serial_log
    monkeypatch.setattr(lab._qmp_control, "command", lambda *args, **kwargs: None)
    monkeypatch.setattr(prebuild_vm, "stop_by_pidfile", lambda *args, **kwargs: None)

    with pytest.raises(ValueError, match="runtime artifact sealing failed"):
        lab.run()

    assert runner.qemu_spec is not None
    serial_argument = runner.qemu_spec.argv[runner.qemu_spec.argv.index("-serial") + 1]
    assert serial_argument.startswith(f"file:/proc/{os.getpid()}/fd/")
    report = json.loads((output_dir / options.report_name).read_text(encoding="utf-8"))
    assert report["verdict"] == "failed"
    assert "serial path" in report["error"]


def test_qemu_cleanup_failure_still_closes_every_artifact_fd(
    tmp_path,
    monkeypatch,
) -> None:
    iso = tmp_path / "image.iso"
    code = tmp_path / "OVMF_CODE_4M.fd"
    template = tmp_path / "OVMF_VARS_4M.fd"
    iso.write_bytes(b"pinned ISO")
    code.write_bytes(b"firmware")
    template.write_bytes(b"vars")
    runner = _ExecutionRecorder()
    lab = QemuLabService(
        runner,
        iso,
        tmp_path / "work",
        tmp_path / "dist",
        PrebuildVmOptions(
            enabled=True,
            firmware="uefi",
            ovmf_code=str(code),
            ovmf_vars=str(template),
            screenshot=False,
            success_patterns=["login:"],
            timeout_seconds=1,
        ),
    )
    monkeypatch.setattr(lab._qmp_control, "command", lambda *args, **kwargs: None)
    monkeypatch.setattr(prebuild_vm, "stop_by_pidfile", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        lab,
        "_stop_tpm",
        lambda artifacts: (_ for _ in ()).throw(RuntimeError("cleanup fault")),
    )

    with pytest.raises(ValueError, match="cleanup fault"):
        lab.run()

    assert runner.qemu_spec is not None
    for descriptor in runner.qemu_spec.pass_fds:
        with pytest.raises(OSError):
            os.fstat(descriptor)


def test_qemu_run_manifest_blocks_same_size_same_mtime_inventory_swap(
    tmp_path,
    monkeypatch,
) -> None:
    output_dir = tmp_path / "dist"
    run_id = "manifest-swap"
    run_dir = output_dir / "evidence" / "runs" / run_id
    run_dir.mkdir(parents=True)
    evidence = run_dir / "commands.jsonl"
    evidence.write_bytes(b"AAAA")
    lab = QemuLabService(
        CommandRunner(dry_run=False),
        tmp_path / "image.iso",
        tmp_path / "work",
        output_dir,
        PrebuildVmOptions(enabled=True),
        run_id=run_id,
    )
    original_inventory = prebuild_vm._inventory_regular_tree
    inventories = 0

    def swap_before_post_publish_inventory(
        root: Path,
        *,
        excluded: set[Path],
        max_files: int = 4096,
        max_depth: int = 64,
    ):
        nonlocal inventories
        inventories += 1
        if inventories == 2:
            timestamp = evidence.stat().st_mtime_ns
            replacement = evidence.with_name("commands.swap")
            replacement.write_bytes(b"BBBB")
            os.utime(replacement, ns=(timestamp, timestamp))
            replacement.replace(evidence)
        return original_inventory(
            root,
            excluded=excluded,
            max_files=max_files,
            max_depth=max_depth,
        )

    monkeypatch.setattr(
        prebuild_vm,
        "_inventory_regular_tree",
        swap_before_post_publish_inventory,
    )

    with pytest.raises(
        prebuild_vm.ArtifactVerificationError,
        match="changed while RUN-MANIFEST",
    ):
        lab._write_run_manifest()

    assert (run_dir / "RUN-MANIFEST.json").is_file()
    assert not (run_dir / "RUN-MANIFEST.json.sha256").exists()


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
    lab = QemuLabService(runner, tmp_path / "image.iso", tmp_path / "work", dist, options)
    if serial_text is not None:
        serial = lab._artifacts().serial_log
        serial.parent.mkdir(parents=True, exist_ok=True)
        serial.write_text(serial_text, encoding="utf-8")
    return runner, lab


def _asserted(runner: CommandRunner) -> list[tuple[str, ...]]:
    return [spec.argv for spec in runner.history if spec.argv[:1] == ("prebuild-vm-assert-log",)]


def test_the_journal_records_the_serial_assertion_once_the_marker_is_really_there(tmp_path) -> None:
    runner, lab = _validating_lab(tmp_path, "[  OK  ] Reached target getty.target\nhost login: ")

    lab._validate_serial_log()

    assert len(_asserted(runner)) == 1


def test_a_login_word_inside_a_diagnostic_is_not_a_login_prompt(tmp_path) -> None:
    runner, lab = _validating_lab(
        tmp_path,
        "audit: previous failed login: root from ttyS0\n",
    )

    with pytest.raises(ValueError, match="did not emit expected serial marker"):
        lab._validate_serial_log()

    assert _asserted(runner) == []


def test_a_false_login_line_before_getty_does_not_hide_the_real_prompt(tmp_path) -> None:
    runner, lab = _validating_lab(
        tmp_path,
        "audit: previous failed login: root\nhost login: ",
    )

    validation = lab._validate_serial_log()

    assert validation is not None
    assert validation.line == "host login:"
    assert validation.byte_offset > len("audit: previous failed login:")
    assert len(_asserted(runner)) == 1


def test_a_serial_log_that_never_carries_the_marker_records_no_passing_assertion(tmp_path) -> None:
    # What a Secure Boot run on the wrong machine produced: a serial log that exists and
    # stays empty, because the firmware never handed off to anything that could write it.
    runner, lab = _validating_lab(tmp_path, "")

    with pytest.raises(ValueError, match="did not emit expected serial marker"):
        lab._validate_serial_log()

    assert _asserted(runner) == []


def test_runtime_serial_reader_refuses_a_fifo_without_waiting(tmp_path) -> None:
    _runner, lab = _validating_lab(tmp_path, None)
    serial = lab._artifacts().serial_log
    serial.parent.mkdir(parents=True, exist_ok=True)
    os.mkfifo(serial)

    with pytest.raises(ValueError, match="not a regular file"):
        lab._validate_serial_log()


def test_runtime_serial_reader_requires_strict_utf8(tmp_path) -> None:
    _runner, lab = _validating_lab(tmp_path, None)
    serial = lab._artifacts().serial_log
    serial.parent.mkdir(parents=True, exist_ok=True)
    serial.write_bytes(b"host login: \xff")

    with pytest.raises(ValueError, match="strict UTF-8"):
        lab._validate_serial_log()


def test_runtime_serial_reader_enforces_its_byte_budget(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(prebuild_vm, "_QEMU_SERIAL_MAX_BYTES", 4)
    _runner, lab = _validating_lab(tmp_path, "login:")

    with pytest.raises(ValueError, match="4-byte limit"):
        lab._validate_serial_log()


def test_a_firmware_that_gave_up_is_quoted_instead_of_waited_out(tmp_path) -> None:
    """The real log from the reference derivative, escapes and all.

    OVMF reached this verdict about three minutes into a 1200 s proof, and the wait --
    which knew only success markers -- sat out the remaining seventeen minutes and then
    reported "did not emit expected serial marker(s): login:, Reached target". The report
    blamed its own deadline for a decision the firmware had already made, and never quoted
    the line that said what was wrong.
    """
    runner, lab = _validating_lab(
        tmp_path,
        '\x1b[2J\x1b[001;001HBdsDxe: failed to load Boot0002 "UEFI QEMU DVD-ROM QM00003 "'
        " from PciRoot(0x0)/Pci(0x1,0x1)/Ata(Secondary,Master,0x0): Not Found\r\n"
        "BdsDxe: No bootable option or device was found.\r\n"
        "BdsDxe: Press any key to enter the Boot Manager Menu.\r\n",
    )

    with pytest.raises(ValueError) as raised:
        lab._validate_serial_log()

    # The firmware's own sentence, cleaned of the cursor addressing it shares the line with.
    assert "BdsDxe: No bootable option or device was found." in str(raised.value)
    assert "did not emit expected serial marker" not in str(raised.value)
    assert _asserted(runner) == []


def test_a_terminal_refusal_after_a_success_marker_invalidates_the_run(tmp_path) -> None:
    runner, lab = _validating_lab(
        tmp_path,
        "host login:\nKernel panic - not syncing: late failure\n",
    )

    with pytest.raises(ValueError, match="Kernel panic"):
        lab._validate_serial_log()

    assert _asserted(runner) == []


def test_qemu_report_validator_rejects_empty_json_and_changed_evidence(tmp_path) -> None:
    iso = tmp_path / "image.iso"
    iso.write_bytes(b"original")
    empty = tmp_path / "empty.json"
    empty.write_text("{}\n", encoding="utf-8")

    assert not validate_qemu_report(empty, iso).ok

    report = write_valid_qemu_report(tmp_path, iso)
    assert validate_qemu_report(report, iso).ok

    iso.write_bytes(b"replacement")
    assert "different ISO bytes" in validate_qemu_report(report, iso).detail


def test_qemu_report_validator_rejects_path_only_iso_claim(tmp_path) -> None:
    iso = tmp_path / "image.iso"
    iso.write_bytes(b"iso")
    report = write_valid_qemu_report(tmp_path, iso)
    payload = json.loads(report.read_text(encoding="utf-8"))
    payload["iso"].pop("consumed_via")
    content = json.dumps(payload, indent=2) + "\n"
    report.write_text(content, encoding="utf-8")
    immutable = tmp_path / "evidence" / "runs" / payload["run_id"] / report.name
    immutable.write_text(content, encoding="utf-8")

    validation = validate_qemu_report(report, iso)

    assert not validation.ok
    assert "consumed ISO" in validation.detail


def test_qemu_report_validator_rejects_path_only_serial_claim(tmp_path) -> None:
    iso = tmp_path / "image.iso"
    iso.write_bytes(b"iso")
    report = write_valid_qemu_report(tmp_path, iso)
    payload = json.loads(report.read_text(encoding="utf-8"))
    payload["artifacts"]["serial_log"].pop("consumed_via")
    content = json.dumps(payload, indent=2) + "\n"
    report.write_text(content, encoding="utf-8")
    immutable = tmp_path / "evidence" / "runs" / payload["run_id"] / report.name
    immutable.write_text(content, encoding="utf-8")

    validation = validate_qemu_report(report, iso)

    assert not validation.ok
    assert "serial evidence" in validation.detail


@pytest.mark.parametrize(
    ("section", "replacement"),
    (
        ("iso", "/proc/4242/fd/70"),
        ("serial", "/proc/4242/fd/80"),
    ),
)
def test_qemu_report_validator_rejects_descriptor_claim_not_used_by_argv(
    tmp_path,
    section: str,
    replacement: str,
) -> None:
    iso = tmp_path / "image.iso"
    iso.write_bytes(b"iso")
    report = write_valid_qemu_report(tmp_path, iso)
    payload = json.loads(report.read_text(encoding="utf-8"))
    if section == "iso":
        payload["iso"]["descriptor_path"] = replacement
    else:
        payload["artifacts"]["serial_log"]["descriptor_path"] = replacement
    content = json.dumps(payload, indent=2) + "\n"
    report.write_text(content, encoding="utf-8")
    immutable = tmp_path / "evidence" / "runs" / payload["run_id"] / report.name
    immutable.write_text(content, encoding="utf-8")

    validation = validate_qemu_report(report, iso)

    assert not validation.ok
    assert "argv is not bound" in validation.detail


@pytest.mark.parametrize(
    "forged_path",
    (
        "qemu//serial.log",
        "qemu/./serial.log",
        "qemu\\serial.log",
        "qemu/\x00serial.log",
    ),
)
def test_qemu_report_validator_rejects_noncanonical_artifact_paths(
    tmp_path,
    forged_path: str,
) -> None:
    iso = tmp_path / "image.iso"
    iso.write_bytes(b"iso")
    report = write_valid_qemu_report(tmp_path, iso)
    payload = json.loads(report.read_text(encoding="utf-8"))
    payload["artifacts"]["serial_log"]["path"] = forged_path
    content = json.dumps(payload, indent=2) + "\n"
    report.write_text(content, encoding="utf-8")
    immutable = tmp_path / "evidence" / "runs" / payload["run_id"] / report.name
    immutable.write_text(content, encoding="utf-8")

    validation = validate_qemu_report(report, iso)

    assert not validation.ok
    assert "escapes its run" in validation.detail


def test_qemu_report_validator_rejects_a_modified_serial_log(tmp_path) -> None:
    iso = tmp_path / "image.iso"
    iso.write_bytes(b"iso")
    report = write_valid_qemu_report(tmp_path, iso)
    payload = json.loads(report.read_text(encoding="utf-8"))
    serial = (
        tmp_path
        / "evidence"
        / "runs"
        / payload["run_id"]
        / payload["artifacts"]["serial_log"]["path"]
    )
    serial.write_text("host login:\nKernel panic - not syncing\n", encoding="utf-8")

    validation = validate_qemu_report(report, iso)

    assert not validation.ok
    assert "serial evidence" in validation.detail


def test_qemu_report_validator_derives_milestone_from_the_marker(tmp_path) -> None:
    iso = tmp_path / "image.iso"
    iso.write_bytes(b"iso")
    report = write_valid_qemu_report(tmp_path, iso)
    payload = json.loads(report.read_text(encoding="utf-8"))
    payload["boot"]["reached_milestone"] = "graphical_session"
    forged = json.dumps(payload, indent=2) + "\n"
    report.write_text(forged, encoding="utf-8")
    immutable = tmp_path / "evidence" / "runs" / payload["run_id"] / report.name
    immutable.write_text(forged, encoding="utf-8")

    validation = validate_qemu_report(report, iso)

    assert not validation.ok
    assert "not implied" in validation.detail


def test_qemu_report_validator_rejects_login_inside_a_diagnostic(tmp_path) -> None:
    iso = tmp_path / "image.iso"
    iso.write_bytes(b"iso")
    report = write_valid_qemu_report(tmp_path, iso)
    payload = json.loads(report.read_text(encoding="utf-8"))
    run_dir = tmp_path / "evidence" / "runs" / payload["run_id"]
    serial = run_dir / payload["artifacts"]["serial_log"]["path"]
    serial.write_text(
        "audit: previous failed login: root from ttyS0\n",
        encoding="utf-8",
    )
    serial_identity = payload["artifacts"]["serial_log"]
    serial_identity["size"] = serial.stat().st_size
    serial_identity["sha256"] = sha256_file(serial)
    marker = payload["boot"]["matched_marker"]
    marker["line"] = "audit: previous failed login: root from ttyS0"
    marker["byte_offset"] = serial.read_bytes().find(b"login:")
    forged = json.dumps(payload, indent=2) + "\n"
    report.write_text(forged, encoding="utf-8")
    (run_dir / report.name).write_text(forged, encoding="utf-8")

    validation = validate_qemu_report(report, iso)

    assert not validation.ok
    assert "diagnostic line" in validation.detail


def test_qemu_report_validator_rejects_a_mutated_alias(tmp_path) -> None:
    iso = tmp_path / "image.iso"
    iso.write_bytes(b"iso")
    report = write_valid_qemu_report(tmp_path, iso)
    report.write_text(report.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    validation = validate_qemu_report(report, iso)

    assert not validation.ok
    assert "alias differs" in validation.detail


def test_qemu_report_validator_rejects_a_symlinked_runs_ancestor(tmp_path) -> None:
    iso = tmp_path / "image.iso"
    iso.write_bytes(b"iso")
    report = write_valid_qemu_report(tmp_path, iso)
    runs = tmp_path / "evidence" / "runs"
    external_runs = tmp_path / "external-runs"
    runs.rename(external_runs)
    runs.symlink_to(external_runs, target_is_directory=True)

    validation = validate_qemu_report(report, iso)

    assert not validation.ok
    assert "unsafe symlink" in validation.detail


def test_qemu_report_validator_rejects_invalid_serial_utf8(tmp_path) -> None:
    iso = tmp_path / "image.iso"
    iso.write_bytes(b"iso")
    report = write_valid_qemu_report(tmp_path, iso)
    payload = json.loads(report.read_text(encoding="utf-8"))
    run_dir = tmp_path / "evidence" / "runs" / payload["run_id"]
    serial = run_dir / payload["artifacts"]["serial_log"]["path"]
    serial.write_bytes(b"host login: \xff")
    payload["artifacts"]["serial_log"].update(
        {
            "size": serial.stat().st_size,
            "sha256": sha256_file(serial),
        }
    )
    content = json.dumps(payload, indent=2) + "\n"
    report.write_text(content, encoding="utf-8")
    (run_dir / report.name).write_text(content, encoding="utf-8")

    validation = validate_qemu_report(report, iso)

    assert not validation.ok
    assert "strict UTF-8" in validation.detail


def test_qemu_report_validator_refuses_fifo_without_opening_its_stream(
    tmp_path,
) -> None:
    iso = tmp_path / "image.iso"
    iso.write_bytes(b"iso")
    report = tmp_path / "qemu-lab-report.json"
    os.mkfifo(report)

    validation = validate_qemu_report(report, iso)

    assert not validation.ok
    assert "not a regular file" in validation.detail


def test_qemu_report_validator_bounds_the_report_before_parsing(tmp_path) -> None:
    iso = tmp_path / "image.iso"
    iso.write_bytes(b"iso")
    report = tmp_path / "qemu-lab-report.json"
    report.write_bytes(b" " * (8 * 1024 * 1024 + 1))

    validation = validate_qemu_report(report, iso)

    assert not validation.ok
    assert "8388608-byte limit" in validation.detail


def test_qemu_report_validator_blocks_same_size_same_mtime_serial_swap(
    tmp_path,
    monkeypatch,
) -> None:
    iso = tmp_path / "image.iso"
    iso.write_bytes(b"iso")
    report = write_valid_qemu_report(tmp_path, iso)
    payload = json.loads(report.read_text(encoding="utf-8"))
    serial = (
        tmp_path
        / "evidence"
        / "runs"
        / payload["run_id"]
        / payload["artifacts"]["serial_log"]["path"]
    )
    original_marker_check = prebuild_vm.marker_line_proves_milestone
    swapped = False

    def swap_after_serial_capture(pattern: str, line: str) -> bool:
        nonlocal swapped
        if not swapped:
            swapped = True
            timestamp = serial.stat().st_mtime_ns
            replacement = serial.with_name("serial.swap")
            replacement.write_bytes(serial.read_bytes())
            os.utime(replacement, ns=(timestamp, timestamp))
            replacement.replace(serial)
        return original_marker_check(pattern, line)

    monkeypatch.setattr(
        prebuild_vm,
        "marker_line_proves_milestone",
        swap_after_serial_capture,
    )

    validation = validate_qemu_report(report, iso)

    assert swapped
    assert not validation.ok
    assert "descriptor closure blocked" in validation.detail


def test_qemu_report_validator_blocks_alias_swap_after_json_parse(
    tmp_path,
    monkeypatch,
) -> None:
    iso = tmp_path / "image.iso"
    iso.write_bytes(b"iso")
    report = write_valid_qemu_report(tmp_path, iso)
    original_scan = prebuild_vm.first_symlink_in_confined_tree
    swapped = False

    def swap_after_report_parse(anchor: Path, target: Path) -> Path | None:
        nonlocal swapped
        if not swapped:
            swapped = True
            timestamp = report.stat().st_mtime_ns
            replacement = report.with_name("report.swap")
            replacement.write_bytes(report.read_bytes())
            os.utime(replacement, ns=(timestamp, timestamp))
            replacement.replace(report)
        return original_scan(anchor, target)

    monkeypatch.setattr(
        prebuild_vm,
        "first_symlink_in_confined_tree",
        swap_after_report_parse,
    )

    validation = validate_qemu_report(report, iso)

    assert swapped
    assert not validation.ok
    assert "descriptor closure blocked" in validation.detail


def test_qemu_report_validator_blocks_iso_swap_after_digest(
    tmp_path,
    monkeypatch,
) -> None:
    iso = tmp_path / "image.iso"
    iso.write_bytes(b"old")
    report = write_valid_qemu_report(tmp_path, iso)
    original_milestone = prebuild_vm.milestone_for_marker
    swapped = False

    def swap_after_iso_digest(pattern: str) -> str:
        nonlocal swapped
        if not swapped:
            swapped = True
            timestamp = iso.stat().st_mtime_ns
            replacement = iso.with_name("image.swap")
            replacement.write_bytes(b"new")
            os.utime(replacement, ns=(timestamp, timestamp))
            replacement.replace(iso)
        return original_milestone(pattern)

    monkeypatch.setattr(
        prebuild_vm,
        "milestone_for_marker",
        swap_after_iso_digest,
    )

    validation = validate_qemu_report(report, iso)

    assert swapped
    assert not validation.ok
    assert "descriptor closure blocked" in validation.detail


def test_qemu_report_reuses_one_session_parse_and_serial_capture(tmp_path) -> None:
    iso = tmp_path / "image.iso"
    iso.write_bytes(b"iso")
    report = write_valid_qemu_report(tmp_path, iso)

    with ArtifactVerificationSession(tmp_path) as session:
        validation = validate_qemu_report(report, iso, session=session)
        metrics = session.metrics

    assert validation.ok
    assert metrics.json_parses == 1
    assert metrics.json_reuse == 0
    assert metrics.digest_reuse >= 2


def test_qemu_report_requires_descriptor_bound_uefi_consumption(tmp_path) -> None:
    iso = tmp_path / "image.iso"
    iso.write_bytes(b"iso")
    report = write_valid_qemu_report(tmp_path, iso)
    payload = json.loads(report.read_text(encoding="utf-8"))
    run_dir = tmp_path / "evidence" / "runs" / payload["run_id"]
    firmware: dict[str, object] = {}
    for name in ("code", "vars_template", "vars_runtime"):
        relative = Path("qemu") / f"{name}.fd"
        artifact = run_dir / relative
        artifact.write_bytes(name.encode("ascii"))
        firmware[name] = {
            "path": relative.as_posix(),
            "size": artifact.stat().st_size,
            "sha256": sha256_file(artifact),
        }
    firmware["consumption"] = {
        "code": "not-held",
        "vars_template": "not-held",
        "vars_runtime": "not-held",
    }
    payload["boot"]["firmware"] = "uefi"
    payload["execution"]["firmware"] = firmware
    content = json.dumps(payload, indent=2) + "\n"
    report.write_text(content, encoding="utf-8")
    (run_dir / report.name).write_text(content, encoding="utf-8")

    unpinned = validate_qemu_report(report, iso)

    assert not unpinned.ok
    assert "does not bind consumed firmware" in unpinned.detail

    firmware["consumption"] = {
        "code": "held-descriptor",
        "vars_template": "held-copy-source",
        "vars_runtime": "held-descriptor",
    }
    code_descriptor = "/proc/4242/fd/9"
    template_descriptor = "/proc/4242/fd/10"
    runtime_descriptor = "/proc/4242/fd/11"
    firmware["code"]["descriptor_path"] = code_descriptor
    firmware["vars_template"]["source_descriptor_path"] = template_descriptor
    firmware["vars_runtime"]["descriptor_path"] = runtime_descriptor
    payload["execution"]["argv"].extend(
        [
            "-drive",
            f"if=pflash,format=raw,readonly=on,file={code_descriptor}",
            "-drive",
            f"if=pflash,format=raw,file={runtime_descriptor}",
        ]
    )
    payload["execution"]["entrypoint"]["argv"] = payload["execution"]["argv"]
    content = json.dumps(payload, indent=2) + "\n"
    report.write_text(content, encoding="utf-8")
    (run_dir / report.name).write_text(content, encoding="utf-8")

    assert validate_qemu_report(report, iso).ok


def test_command_runner_passes_a_pinned_artifact_fd(tmp_path) -> None:
    source = tmp_path / "image.iso"
    source.write_bytes(b"pinned ISO bytes")
    with source.open("rb") as handle:
        descriptor_path = f"/proc/{os.getpid()}/fd/{handle.fileno()}"
        result = CommandRunner(dry_run=False).run(
            CommandSpec(
                argv=(
                    sys.executable,
                    "-c",
                    "import pathlib,sys; print(pathlib.Path(sys.argv[1]).read_text())",
                    descriptor_path,
                ),
                pass_fds=(handle.fileno(),),
                description="Consume held ISO descriptor",
            )
        )

    assert result.stdout.strip() == "pinned ISO bytes"


def test_a_per_option_load_failure_is_not_treated_as_a_verdict(tmp_path) -> None:
    # Firmware prints "failed to load Boot####" once per boot option, so a machine with a
    # disk as well as a CD prints it for the disk on its way to booting the CD. Reading it
    # as terminal would fail a run that goes on to succeed, which is why only the line
    # printed after every option has been exhausted counts.
    text = 'BdsDxe: failed to load Boot0001 "UEFI QEMU HARDDISK": Not Found\r\n'
    assert first_boot_refusal(text) is None
    assert first_boot_refusal(text + "BdsDxe: No bootable option or device was found.\r\n") == (
        "BdsDxe: No bootable option or device was found."
    )


def test_qemu_artifact_paths_are_confined_before_launch(tmp_path) -> None:
    options = PrebuildVmOptions(enabled=True)
    options.pid_file = "../foreign.pid"

    issues = validate_prebuild_vm_options(options)

    assert any(issue.code == "prebuild-vm-artifact-path" for issue in issues)
    with pytest.raises(ValueError, match="plain filename"):
        QemuLabService(
            CommandRunner(dry_run=True),
            tmp_path / "image.iso",
            tmp_path / "work",
            tmp_path / "dist",
            options,
        ).run()


@pytest.mark.parametrize(
    "line",
    [
        "error: no such device: /casper/vmlinuz.\r\nEntering rescue mode...\r\n",
        "Unable to find a medium containing a live file system\r\n",
        "Kernel panic - not syncing: VFS: Unable to mount root fs\r\n",
    ],
)
def test_every_layer_below_the_firmware_can_also_end_the_wait(tmp_path, line: str) -> None:
    # GRUB, casper and the kernel each have one line they print only once they have given
    # up, and each of them is a reason a boot proof would otherwise run to its deadline.
    runner, lab = _validating_lab(tmp_path, line)

    with pytest.raises(ValueError, match="gave up and said so"):
        lab._validate_serial_log()

    assert _asserted(runner) == []


def test_a_dry_run_still_plans_the_assertion_it_will_not_perform(tmp_path) -> None:
    # Unchanged on purpose: in a plan the line is the step, not its result, and the
    # printed command list is a documented output.
    runner, lab = _validating_lab(tmp_path, None, dry_run=True)

    lab._validate_serial_log()

    assert len(_asserted(runner)) == 1


# Acceleration, and a report that says which kind of run produced it. The lab asked
# for none: it launched under TCG on hosts whose /dev/kvm was there and openable, and
# the report it wrote looked identical either way.


def test_the_lab_accelerates_when_the_host_can_and_records_it(tmp_path, monkeypatch) -> None:
    device = tmp_path / "kvm"
    device.write_bytes(b"")
    monkeypatch.setattr(qemu_invocation, "KVM_DEVICE", device)
    _runner, lab = _validating_lab(tmp_path, None)
    artifacts = lab._artifacts()

    lab._write_report(artifacts)

    assert "-enable-kvm" in lab._qemu_argv(artifacts)
    immutable = lab.output_dir / "evidence" / "runs" / lab.run_id / lab.options.report_name
    assert json.loads(immutable.read_text(encoding="utf-8"))["accelerated"] is True


def test_an_emulating_host_still_runs_and_the_report_says_which_it_was(tmp_path) -> None:
    # No monkeypatch: the session fixture aims the probe at a path that cannot exist,
    # which is the CI runner's answer. The proof must still run there -- it just has to
    # stop passing itself off as the same evidence as an accelerated one.
    _runner, lab = _validating_lab(tmp_path, None)
    artifacts = lab._artifacts()

    lab._write_report(artifacts)

    assert "-enable-kvm" not in lab._qemu_argv(artifacts)
    immutable = lab.output_dir / "evidence" / "runs" / lab.run_id / lab.options.report_name
    assert json.loads(immutable.read_text(encoding="utf-8"))["accelerated"] is False


def test_qemu_lab_uefi_tpm_artifacts_are_explicit(tmp_path) -> None:
    runner = CommandRunner(dry_run=True)
    options = PrebuildVmOptions(enabled=True, firmware="uefi", secure_boot=True, tpm=True)

    QemuLabService(
        runner, tmp_path / "image.iso", tmp_path / "work", tmp_path / "dist", options
    ).run()

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
    screendump = next(
        argv for argv in commands if argv[:1] == ("qmp-command",) and "screendump" in argv[-1]
    )
    assert '"execute": "screendump"' in screendump[-1]
    assert '"filename"' in screendump[-1] and "qemu-boot.ppm" in screendump[-1]
    assert any(
        argv[:1] == ("qmp-command",) and argv[-1] == '{"execute": "quit", "arguments": {}}'
        for argv in commands
    )


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
    options = PrebuildVmOptions(
        enabled=False, firmware="uefi", ovmf_code=str(tmp_path / "absent.fd")
    )

    assert validate_prebuild_vm_options(options) == []


# boot-proof ran BIOS whatever the ISO carried: run_boot_proof never touched
# prebuild_vm.firmware and its parser had no flag, so UEFI was reachable only through
# a build. On a BIOS host that is the difference between a proof and a green report
# about the half that already worked.


def _proof_project(tmp_path: Path, name: str) -> tuple[Project, Path]:
    # The name comes from artifact_paths and is not spelled here. This fixture used to
    # build it from the project name and a bare .iso suffix, with no version, which is a
    # path the builder never produces: every proof below was handed an ISO shaped like
    # the unversioned fallback that had boot-proof, release-pipeline, iso-acceptance and
    # publish-drill all reporting a missing ISO that was right there. Harmless while
    # these tests pass the path explicitly, one refactor from testing the wrong name.
    # Described rather than quoted on purpose: the pre-commit ratchet for this defect is
    # a pygrep expression, so it fires on prose about the pattern as readily as on the
    # pattern -- the same trap the lintian-profile grep fell into, per ci.yml.
    project = Project.create(name, tmp_path / name, "26.04")
    iso = default_output_iso(project)
    iso.write_bytes(b"")
    return project, iso


def _installed_firmware(tmp_path: Path, *, secure: bool) -> tuple[Path, Path]:
    """A firmware pair on disk, named the way ovmf names them.

    Created in the test's own directory rather than resolved from the host: otherwise
    whether /usr/share/OVMF carries the Secure Boot build decides the assertion, and a
    CI runner has no ovmf at all.
    """
    names = (
        ("OVMF_CODE_4M.secboot.fd", "OVMF_VARS_4M.ms.fd")
        if secure
        else ("OVMF_CODE_4M.fd", "OVMF_VARS_4M.fd")
    )
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


def _plan_boot_proof(
    monkeypatch, project: Project, iso: Path, *, options: BuildOptions | None = None, **request
):
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

    report, commands = _plan_boot_proof(
        monkeypatch, project, iso, options=options, backend="qemu", firmware="uefi"
    )
    qemu = _qemu_argv(commands)

    assert any("if=pflash" in part and options.prebuild_vm.ovmf_code in part for part in qemu)
    assert "-global" not in qemu
    assert report.firmware == "uefi"
    assert report.secure_boot is False


def test_secure_boot_asks_for_the_enrolled_pair_and_makes_the_firmware_enforce_it(
    tmp_path, monkeypatch
) -> None:
    project, iso = _proof_project(tmp_path, "ProofSecure")
    options = _firmware_options(tmp_path, secure=True)

    report, commands = _plan_boot_proof(
        monkeypatch,
        project,
        iso,
        options=options,
        backend="qemu",
        firmware="uefi",
        secure_boot=True,
    )
    qemu = _qemu_argv(commands)

    assert any(".secboot." in part for part in qemu)
    assert any(argv[0] == "copy-file" and argv[1].endswith(".ms.fd") for argv in commands)
    assert "-global" in qemu
    assert "Firmware: uefi with Secure Boot" in report.render_text()
    # The written proof is what a release gate reads, so the firmware belongs in it too.
    proof = json.loads(report.proof.read_text(encoding="utf-8"))
    assert proof["firmware"] == "uefi"
    assert proof["secure_boot"] is True


def test_secure_boot_on_bios_is_refused_before_any_machine_starts(tmp_path, monkeypatch) -> None:
    project, iso = _proof_project(tmp_path, "ProofSbBios")

    report, commands = _plan_boot_proof(
        monkeypatch, project, iso, backend="qemu", firmware="bios", secure_boot=True
    )

    assert report.status == "blocked"
    assert any("prebuild-vm-secure-boot" in note for note in report.notes)
    # Before, not after: asking a machine about its firmware once it has booted the
    # wrong one answers nothing, and the report would already read "ready".
    assert not any(argv and argv[0] == "qemu-system-x86_64" for argv in commands)


def test_a_firmware_image_that_is_not_installed_blocks_the_proof(tmp_path, monkeypatch) -> None:
    project, iso = _proof_project(tmp_path, "ProofNoOvmf")
    options = BuildOptions()
    options.prebuild_vm.ovmf_code = str(tmp_path / "absent.fd")

    report, commands = _plan_boot_proof(
        monkeypatch, project, iso, options=options, backend="qemu", firmware="uefi"
    )

    assert report.status == "blocked"
    assert any("prebuild-vm-ovmf-missing" in note for note in report.notes)
    assert not any(argv and argv[0] == "qemu-system-x86_64" for argv in commands)


def test_a_project_that_already_describes_uefi_keeps_it_without_any_flag(
    tmp_path, monkeypatch
) -> None:
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
