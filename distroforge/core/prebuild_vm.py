from __future__ import annotations

import json
import re
import shutil
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from .command import CommandRunner, CommandSpec
from .evidence_run import (
    artifact_identity,
    copy_immutable_file,
    evidence_run_path,
    first_symlink_in_confined_tree,
    new_run_id,
    reserve_evidence_run,
    toolchain_identity,
    write_immutable_text,
    write_text_alias,
)
from .hashing import sha256_file
from .integrity import IntegrityService
from .qemu_invocation import (
    QemuInvocation,
    default_ovmf_code,
    default_ovmf_vars,
    kvm_is_usable,
)
from .qmp import QmpControl, stop_by_pidfile

# Lines that mean a layer of the boot has given up for good. Each is emitted only once its
# layer has exhausted every option it had, so none of them can appear on a run that goes on
# to succeed -- which is why "BdsDxe: failed to load Boot0002 ... Not Found" is deliberately
# absent: firmware prints that per boot option, and a machine with a disk as well as a CD
# prints it for the disk on its way to booting the CD.
#
# Without these the wait below only ever looked for success, so a verdict the firmware had
# already delivered bought nothing: measured on the reference derivative, OVMF said
# "No bootable option or device was found." about three minutes in, and the proof then sat
# out the rest of its 1200 s before reporting "did not emit expected serial marker(s):
# login:, Reached target" -- blaming its own deadline for a decision made at minute three,
# and never quoting the one line that said what was wrong.
BOOT_REFUSALS: tuple[str, ...] = (
    # EDK2 BdsDxe, after every boot option has been tried and none loaded.
    "No bootable option or device was found",
    # GRUB, once it cannot find its own configuration or root device.
    "Entering rescue mode...",
    # casper, when no medium on the machine carries the live filesystem.
    "Unable to find a medium containing a live file system",
    "Kernel panic - not syncing",
)

# Serial consoles carry the firmware's cursor addressing inline with its text, so the line
# holding a refusal also holds several CSI sequences. Stripped, so the quoted evidence in a
# report is the sentence the firmware wrote and not a screenful of escapes.
_CSI = re.compile(r"\x1b\[[0-9;=?]*[A-Za-z]")
_UNPRINTABLE = re.compile(r"[^\x20-\x7e]+")
# A getty prompt is a complete console line, optionally prefixed by the hostname.  Merely
# finding the substring ``login:`` proves nothing: PAM, sshd and audit diagnostics all
# write lines such as "failed login:" before getty has necessarily started.
_LOGIN_PROMPT_LINE = re.compile(
    r"^(?:[A-Za-z0-9][A-Za-z0-9._-]*[ \t]+)?login:[ \t]*$",
    re.IGNORECASE,
)
QEMU_REPORT_SCHEMA = "distroforge.qemu-lab.v2"
QEMU_RUN_MANIFEST_SCHEMA = "distroforge.qemu-run-manifest.v1"
_MILESTONE_ORDER = {
    "bootloader": 1,
    "kernel_started": 2,
    "live_userspace": 3,
    "login_prompt": 4,
    "installer_ready": 4,
    "graphical_session": 5,
}


def first_boot_refusal(text: str) -> str | None:
    """The first line of ``text`` that states a boot layer gave up, cleaned for quoting."""
    for raw in text.splitlines():
        line = _UNPRINTABLE.sub("", _CSI.sub("", raw)).strip()
        if any(refusal in line for refusal in BOOT_REFUSALS):
            return line
    return None


def milestone_for_marker(pattern: str) -> str:
    normalised = pattern.strip().lower()
    if _LOGIN_PROMPT_LINE.fullmatch(normalised):
        return "login_prompt"
    if "graphical.target" in normalised or "graphical interface" in normalised:
        return "graphical_session"
    if "installer" in normalised and ("ready" in normalised or "welcome" in normalised):
        return "installer_ready"
    if "casper" in normalised and ("started" in normalised or "ready" in normalised):
        return "live_userspace"
    if "linux version" in normalised or "kernel started" in normalised:
        return "kernel_started"
    if "grub" in normalised and ("welcome" in normalised or "normal" in normalised):
        return "bootloader"
    return "custom"


def marker_line_proves_milestone(pattern: str, line: str) -> bool:
    """Return whether a literal marker occurs in a line that proves its milestone."""
    milestone = milestone_for_marker(pattern)
    if milestone == "login_prompt":
        return _LOGIN_PROMPT_LINE.fullmatch(line) is not None
    return milestone != "custom"


@dataclass(frozen=True)
class SerialValidation:
    pattern: str
    line: str
    byte_offset: int
    milestone: str


@dataclass(frozen=True)
class QemuReportValidation:
    ok: bool
    detail: str
    payload: dict[str, object] | None = None


@dataclass
class PrebuildVmOptions:
    enabled: bool = False
    profile: str = "live"
    firmware: str = "bios"
    secure_boot: bool = False
    tpm: bool = False
    memory_mb: int = 4096
    cpus: int = 2
    disk_size: str = "24G"
    network: bool = False
    timeout_seconds: int = 300
    serial_log: str = "prebuild-vm-serial.log"
    screenshot: bool = True
    screenshot_name: str = "prebuild-vm.ppm"
    success_patterns: list[str] = field(default_factory=lambda: ["login:"])
    qmp_socket: str = "qemu-lab.qmp"
    pid_file: str = "qemu-lab.pid"
    report_name: str = "qemu-lab-report.json"
    # Empty means auto-detect through default_ovmf_code/default_ovmf_vars, which is
    # what an unset flag and an empty GUI field already meant.
    ovmf_code: str = ""
    ovmf_vars: str = ""

    def summary(self) -> str:
        if not self.enabled:
            return "disabled"
        flags = [self.profile, self.firmware, f"{self.memory_mb}M", f"{self.cpus} cpu"]
        if self.secure_boot:
            flags.append("secure-boot")
        if self.tpm:
            flags.append("tpm")
        if self.network:
            flags.append("net")
        return ", ".join(flags)


@dataclass(frozen=True)
class QemuLabArtifacts:
    disk: Path
    qmp_socket: Path
    pid_file: Path
    serial_log: Path
    screenshot: Path
    report: Path
    ovmf_vars: Path
    tpm_socket: Path


class QemuLabService:
    def __init__(
        self,
        runner: CommandRunner,
        iso_path: Path,
        workdir: Path,
        output_dir: Path,
        options: PrebuildVmOptions,
        run_id: str | None = None,
    ) -> None:
        self.runner = runner
        self.iso_path = iso_path
        self.workdir = workdir / "prebuild-vm"
        self.output_dir = output_dir
        self.options = options
        self._owns_run = run_id is None
        self.run_id = run_id or new_run_id()
        self.started_at = datetime.now(UTC)
        self._qmp_control = QmpControl(runner, options.timeout_seconds)
        self._launched_argv: tuple[str, ...] = ()
        self._launched_pid: int | None = None

    def run(self) -> None:
        if not self.options.enabled:
            self.runner.run(
                CommandSpec(
                    argv=("prebuild-vm-skip", str(self.iso_path)),
                    description="Prebuild VM lab disabled",
                )
            )
            return
        if self._owns_run and self.runner.log_path is None:
            self.runner.log_path = evidence_run_path(
                self.output_dir,
                self.run_id,
                "commands.jsonl",
                executed=not self.runner.dry_run,
            )
        if self._owns_run:
            reserve_evidence_run(
                self.output_dir,
                self.run_id,
                executed=not self.runner.dry_run,
            )
        artifacts = self._artifacts()
        initial_validation: SerialValidation | None = None
        failure: Exception | None = None
        iso_before = self._iso_identity() if not self.runner.dry_run else {}
        try:
            self.runner.run(
                CommandSpec(
                    argv=("mkdir", "-p", str(self.workdir), str(self.output_dir)),
                    description="Prepare QEMU lab artifact directories",
                )
            )
            self.runner.run(
                CommandSpec(
                    argv=(
                        "rm",
                        "-f",
                        str(artifacts.pid_file),
                        str(artifacts.qmp_socket),
                        str(artifacts.tpm_socket),
                    ),
                    description="Remove stale QEMU lab control files",
                )
            )
            self.runner.run(
                CommandSpec(
                    argv=(
                        "qemu-img",
                        "create",
                        "-f",
                        "qcow2",
                        str(artifacts.disk),
                        self.options.disk_size,
                    ),
                    description="Create QEMU lab disk",
                )
            )
            self._prepare_firmware(artifacts)
            self._prepare_tpm(artifacts)
            self._launched_argv = tuple(self._qemu_argv(artifacts))
            self.runner.run(
                CommandSpec(
                    argv=self._launched_argv,
                    description="Run QEMU lab boot with QMP control",
                )
            )
            if not self.runner.dry_run:
                raw_pid = artifacts.pid_file.read_text(encoding="utf-8").strip()
                if not raw_pid.isdigit() or int(raw_pid) <= 1:
                    raise ValueError(
                        f"QEMU did not write a valid PID file: {artifacts.pid_file}"
                    )
                self._launched_pid = int(raw_pid)
            self._qmp_control.command("query-status", artifacts.qmp_socket)
            initial_validation = self._validate_serial_log()
            if self.options.screenshot:
                self._qmp_control.command(
                    "screendump",
                    artifacts.qmp_socket,
                    {"filename": str(artifacts.screenshot)},
                )
                self.runner.run(
                    CommandSpec(
                        argv=("sha256sum", str(artifacts.screenshot)),
                        description="Record QEMU lab screenshot checksum",
                    )
                )
            self.runner.run(
                CommandSpec(
                    argv=("sha256sum", str(artifacts.serial_log)),
                    description="Record QEMU lab serial log checksum",
                )
            )
            self._qmp_control.command("quit", artifacts.qmp_socket)
        except Exception as exc:
            failure = exc
        finally:
            if self._launched_pid is not None:
                stop_by_pidfile(
                    self.runner,
                    artifacts.pid_file,
                    "Stop QEMU lab VM",
                    known_pid=self._launched_pid,
                )
            self._stop_tpm(artifacts)
        final_validation: SerialValidation | None = initial_validation
        if failure is None and not self.runner.dry_run:
            try:
                final_validation = self._final_serial_validation(initial_validation)
                iso_after = self._iso_identity()
                if iso_before != iso_after:
                    raise ValueError("ISO changed while the QEMU proof was running")
            except Exception as exc:
                failure = exc
        status = "planned" if self.runner.dry_run else "completed" if failure is None else "aborted"
        verdict = "unproven" if self.runner.dry_run else "passed" if failure is None else "failed"
        self._write_report(
            artifacts,
            status=status,
            verdict=verdict,
            validation=final_validation,
            error=str(failure) if failure else None,
            iso_before=iso_before,
        )
        if failure is not None:
            raise failure
        IntegrityService(self.runner).write_manifest(
            self.output_dir / "PREBUILD-VM-INTEGRITY",
            {
                "iso": self.iso_path.name,
                "serial_log": self.options.serial_log,
                "screenshot": self.options.screenshot_name if self.options.screenshot else "disabled",
                "qmp_socket": str(artifacts.qmp_socket),
                "report": self.options.report_name,
                "success_patterns": "|".join(self.options.success_patterns),
            },
        )
        if not self.runner.dry_run:
            copy_immutable_file(
                self.output_dir / "PREBUILD-VM-INTEGRITY",
                evidence_run_path(
                    self.output_dir,
                    self.run_id,
                    "qemu/integrity.txt",
                    executed=True,
                ),
            )
        if self._owns_run and not self.runner.dry_run:
            self._write_run_manifest()

    def _iso_identity(self) -> dict[str, object]:
        if not self.iso_path.is_file():
            return {"path": str(self.iso_path), "size": 0, "sha256": ""}
        return {
            "path": str(self.iso_path),
            "size": self.iso_path.stat().st_size,
            "sha256": sha256_file(self.iso_path),
        }

    def _artifacts(self) -> QemuLabArtifacts:
        names = {
            field_name: value
            for field_name, value in (
            ("qmp_socket", self.options.qmp_socket),
            ("pid_file", self.options.pid_file),
            ("serial_log", self.options.serial_log),
            ("screenshot_name", self.options.screenshot_name),
            ("report_name", self.options.report_name),
            )
        }
        for field_name, value in names.items():
            if not _safe_artifact_name(value):
                raise ValueError(
                    f"QEMU lab {field_name} must be a plain filename inside its "
                    f"managed directory, not {value!r}"
                )
        output_names = {
            names["serial_log"],
            names["screenshot_name"],
            names["report_name"],
        }
        if len(output_names) != 3 or output_names & {
            "ISO-BUILD.json",
            "ISO-BUILD.plan.json",
            "boot-proof.json",
            "boot-proof.plan.json",
            "distroforge-provenance.json",
            "RUN-MANIFEST.json",
            "commands.jsonl",
        }:
            raise ValueError("QEMU report, serial and screenshot names collide with managed evidence")
        if names["qmp_socket"] == names["pid_file"]:
            raise ValueError("QEMU QMP socket and PID file names must be different")
        return QemuLabArtifacts(
            disk=self.workdir / "qemu-lab.qcow2",
            qmp_socket=self.workdir / self.options.qmp_socket,
            pid_file=self.workdir / self.options.pid_file,
            serial_log=self.output_dir / self.options.serial_log,
            screenshot=self.output_dir / self.options.screenshot_name,
            report=self.output_dir / self.options.report_name,
            ovmf_vars=self.workdir / "OVMF_VARS.fd",
            tpm_socket=self.workdir / "swtpm.sock",
        )

    def _qemu_argv(self, artifacts: QemuLabArtifacts) -> list[str]:
        return list(
            QemuInvocation(
                iso=self.iso_path,
                memory_mb=self.options.memory_mb,
                cpus=self.options.cpus,
                disk=artifacts.disk,
                serial=f"file:{artifacts.serial_log}",
                qmp_socket=artifacts.qmp_socket,
                pid_file=artifacts.pid_file,
                display="none",
                daemonize=True,
                firmware=self.options.firmware,
                ovmf_code=default_ovmf_code(self.options.ovmf_code, secure_boot=self.options.secure_boot),
                ovmf_vars=str(artifacts.ovmf_vars),
                secure_boot=self.options.secure_boot,
                tpm_socket=artifacts.tpm_socket if self.options.tpm else None,
                network="user" if self.options.network else "none",
                enable_kvm=kvm_is_usable(),
            ).argv()
        )

    def _prepare_firmware(self, artifacts: QemuLabArtifacts) -> None:
        if self.options.firmware != "uefi":
            return
        template = default_ovmf_vars(self.options.ovmf_vars, secure_boot=self.options.secure_boot)
        self.runner.run(
            CommandSpec(
                argv=("copy-file", template, str(artifacts.ovmf_vars)),
                description="Prepare writable OVMF variables store",
            )
        )
        if not self.runner.dry_run:
            shutil.copy2(template, artifacts.ovmf_vars)

    def _prepare_tpm(self, artifacts: QemuLabArtifacts) -> None:
        if not self.options.tpm:
            return
        state_dir = self.workdir / "swtpm-state"
        self.runner.run(
            CommandSpec(
                argv=("mkdir", "-p", str(state_dir)),
                description="Prepare swtpm state directory",
            )
        )
        self.runner.run(
            CommandSpec(
                argv=(
                    "swtpm",
                    "socket",
                    "--tpm2",
                    "--tpmstate",
                    f"dir={state_dir}",
                    "--ctrl",
                    f"type=unixio,path={artifacts.tpm_socket}",
                    "--daemon",
                ),
                description="Start swtpm for QEMU lab",
            )
        )

    def _stop_tpm(self, artifacts: QemuLabArtifacts) -> None:
        if not self.options.tpm:
            return
        self.runner.run(
            CommandSpec(
                argv=("pkill", "-f", str(artifacts.tpm_socket)),
                description="Stop swtpm for QEMU lab",
            ),
            check=False,
        )

    def _validate_serial_log(self) -> SerialValidation | None:
        serial = self.output_dir / self.options.serial_log
        patterns = self.options.success_patterns
        if not patterns:
            raise ValueError("QEMU lab needs at least one explicit serial success marker")
        if any(pattern.strip().lower() == "reached target" for pattern in patterns):
            raise ValueError(
                "The generic 'Reached target' marker is not a boot milestone; "
                "use an explicit login, installer or graphical-session marker"
            )
        pattern_text = "|".join(patterns)
        # Recorded once the markers are really there, not on the way in. Emitted first,
        # this event put `prebuild-vm-assert-log ... rc=0` in the build journal before
        # the wait below had read a single byte, so a run that then sat in the firmware
        # for its whole timeout left a log whose last word was a green assertion. That
        # is the log a maintainer opens to find out what went wrong, and it lied about
        # the one step that failed. A dry run still records it here, where it is a plan
        # line rather than a result, so the planned command list is unchanged.
        found = CommandSpec(
            argv=("prebuild-vm-assert-log", str(serial), pattern_text),
            description="Validate QEMU lab serial log success markers",
        )
        if self.runner.dry_run:
            self.runner.run(found)
            return None
        deadline = time.monotonic() + self.options.timeout_seconds
        while not serial.exists() and time.monotonic() <= deadline:
            time.sleep(0.2)
        if not serial.exists():
            raise ValueError(f"QEMU lab serial log does not exist: {serial}")
        while time.monotonic() <= deadline:
            text = serial.read_text(encoding="utf-8", errors="replace")
            refusal = first_boot_refusal(text)
            if refusal is not None:
                # A terminal refusal wins even when an earlier, unrelated line happened
                # to contain the requested marker.
                raise ValueError(f"QEMU lab boot gave up and said so: {refusal}")
            validation = self._matched_serial(text)
            if validation is not None:
                self.runner.run(found)
                return validation
            time.sleep(0.5)
        raise ValueError(
            f"QEMU lab did not emit expected serial marker(s): {', '.join(patterns)} "
            f"within {self.options.timeout_seconds}s, and emitted none of the known "
            "give-up lines either -- so it was still trying when the deadline passed"
        )

    def _matched_serial(self, text: str) -> SerialValidation | None:
        for pattern in self.options.success_patterns:
            if not pattern:
                continue
            search_from = 0
            while (offset := text.find(pattern, search_from)) >= 0:
                line_start = text.rfind("\n", 0, offset) + 1
                line_end = text.find("\n", offset)
                if line_end < 0:
                    line_end = len(text)
                line = _UNPRINTABLE.sub(
                    "",
                    _CSI.sub("", text[line_start:line_end]),
                ).strip()
                if marker_line_proves_milestone(pattern, line):
                    return SerialValidation(
                        pattern=pattern,
                        line=line,
                        byte_offset=len(
                            text[:offset].encode("utf-8", errors="replace")
                        ),
                        milestone=milestone_for_marker(pattern),
                    )
                search_from = offset + len(pattern)
        return None

    def _final_serial_validation(
        self,
        initial: SerialValidation | None,
    ) -> SerialValidation:
        serial = self.output_dir / self.options.serial_log
        if not serial.is_file():
            raise ValueError(f"QEMU lab serial log does not exist after VM stop: {serial}")
        text = serial.read_text(encoding="utf-8", errors="replace")
        refusal = first_boot_refusal(text)
        if refusal is not None:
            raise ValueError(f"QEMU lab boot gave up after a success marker: {refusal}")
        final = self._matched_serial(text)
        if final is None or initial is None:
            raise ValueError("QEMU lab final serial log does not contain the proven success marker")
        if final.pattern != initial.pattern:
            raise ValueError("QEMU lab success marker changed while the serial log was being sealed")
        return final

    def _write_report(
        self,
        artifacts: QemuLabArtifacts,
        *,
        status: str = "aborted",
        verdict: str = "unproven",
        validation: SerialValidation | None = None,
        error: str | None = None,
        iso_before: dict[str, object] | None = None,
    ) -> None:
        immutable = evidence_run_path(
            self.output_dir,
            self.run_id,
            self.options.report_name,
            executed=status != "planned",
        )
        evidence_dir = immutable.parent
        serial_artifact, screenshot_artifact, firmware = self._seal_runtime_artifacts(
            artifacts,
            evidence_dir,
        )
        serial_text = (
            artifacts.serial_log.read_text(encoding="utf-8", errors="replace")
            if artifacts.serial_log.is_file()
            else ""
        )
        terminal_refusal = first_boot_refusal(serial_text)
        qemu_entrypoint = next(
            (
                identity
                for identity in reversed(self.runner.execution_identities)
                if identity.get("argv") == list(self._launched_argv)
            ),
            None,
        )
        payload = {
            "schema": QEMU_REPORT_SCHEMA,
            "run_id": self.run_id,
            "status": status,
            "verdict": verdict,
            "started_at": self.started_at.isoformat(),
            "finished_at": datetime.now(UTC).isoformat(),
            "iso": iso_before or self._iso_identity(),
            "accelerated": kvm_is_usable(),
            "boot": {
                "profile": self.options.profile,
                "firmware": self.options.firmware,
                "secure_boot": self.options.secure_boot,
                "required_milestone": "login_prompt",
                "reached_milestone": validation.milestone if validation else None,
                "matched_marker": {
                    "pattern": validation.pattern,
                    "line": validation.line,
                    "byte_offset": validation.byte_offset,
                }
                if validation
                else None,
                "terminal_refusal": terminal_refusal,
                "sealed_after_vm_stop": not self.runner.dry_run,
            },
            "artifacts": {
                "serial_log": serial_artifact,
                "screenshot": screenshot_artifact,
            },
            "execution": {
                "accelerated": kvm_is_usable(),
                "memory_mb": self.options.memory_mb,
                "cpus": self.options.cpus,
                "disk_size": self.options.disk_size,
                "network": self.options.network,
                "tpm": self.options.tpm,
                "timeout_seconds": self.options.timeout_seconds,
                "qmp_socket": str(artifacts.qmp_socket),
                "pid_file": str(artifacts.pid_file),
                "toolchain": toolchain_identity(("qemu-system-x86_64",)),
                "argv": list(self._launched_argv),
                "entrypoint": qemu_entrypoint,
                "firmware": firmware,
            },
            "error": error,
        }
        content = json.dumps(payload, indent=2) + "\n"
        for target in (immutable, artifacts.report):
            self.runner.run(
                CommandSpec(
                    argv=("write-file", str(target)),
                    description="Write QEMU lab JSON report",
                )
            )
        if not self.runner.dry_run:
            write_immutable_text(immutable, content)
            write_text_alias(artifacts.report, content)

    def _seal_runtime_artifacts(
        self,
        artifacts: QemuLabArtifacts,
        evidence_dir: Path,
    ) -> tuple[dict[str, object], dict[str, object] | None, dict[str, object]]:
        serial = self._sealed_artifact(
            artifacts.serial_log,
            evidence_dir,
            Path("qemu") / "serial.log",
        )
        screenshot = (
            self._sealed_artifact(
                artifacts.screenshot,
                evidence_dir,
                Path("qemu") / "screenshot.ppm",
            )
            if self.options.screenshot
            else None
        )
        firmware: dict[str, object] = {}
        if self.options.firmware == "uefi":
            code = Path(
                default_ovmf_code(
                    self.options.ovmf_code,
                    secure_boot=self.options.secure_boot,
                )
            )
            template = Path(
                default_ovmf_vars(
                    self.options.ovmf_vars,
                    secure_boot=self.options.secure_boot,
                )
            )
            firmware = {
                "code": self._sealed_artifact(
                    code,
                    evidence_dir,
                    Path("qemu") / "firmware-code.fd",
                ),
                "vars_template": self._sealed_artifact(
                    template,
                    evidence_dir,
                    Path("qemu") / "firmware-vars-template.fd",
                ),
                "vars_runtime": self._sealed_artifact(
                    artifacts.ovmf_vars,
                    evidence_dir,
                    Path("qemu") / "firmware-vars-runtime.fd",
                ),
            }
        return serial, screenshot, firmware

    def _write_run_manifest(self) -> None:
        run_dir = evidence_run_path(
            self.output_dir,
            self.run_id,
            self.options.report_name,
            executed=True,
        ).parent
        manifest = run_dir / "RUN-MANIFEST.json"
        sidecar = run_dir / "RUN-MANIFEST.json.sha256"
        files = [
            artifact_identity(path, role="qemu-run-evidence")
            for path in sorted(run_dir.rglob("*"))
            if path.is_file() and path not in {manifest, sidecar}
        ]
        if self.iso_path.is_file():
            files.append(artifact_identity(self.iso_path, role="proven-iso"))
        payload = {
            "schema": QEMU_RUN_MANIFEST_SCHEMA,
            "run_id": self.run_id,
            "mode": "execute",
            "status": "completed",
            "created_at": self.started_at.isoformat(),
            "files": files,
        }
        write_immutable_text(manifest, json.dumps(payload, indent=2) + "\n")
        write_immutable_text(
            sidecar,
            f"{sha256_file(manifest)}  {manifest.name}\n",
        )

    def _sealed_artifact(
        self,
        source: Path,
        evidence_dir: Path,
        relative: Path,
    ) -> dict[str, object]:
        target = evidence_dir / relative
        if not self.runner.dry_run and source.is_file():
            copy_immutable_file(source, target)
        return self._artifact_identity(target, recorded_path=relative.as_posix())

    @staticmethod
    def _artifact_identity(
        path: Path,
        *,
        recorded_path: str | None = None,
    ) -> dict[str, object]:
        if not path.is_file():
            return {
                "path": recorded_path or str(path),
                "size": 0,
                "sha256": "",
            }
        return {
            "path": recorded_path or str(path),
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
        }


def validate_qemu_report(
    report_path: Path,
    iso_path: Path,
    *,
    minimum_milestone: str = "login_prompt",
) -> QemuReportValidation:
    """Validate bytes and semantics, not merely the presence of a QEMU report."""
    try:
        payload = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return QemuReportValidation(False, f"cannot read QEMU report: {exc}")
    if not isinstance(payload, dict):
        return QemuReportValidation(False, "QEMU report is not a JSON object")
    if payload.get("schema") != QEMU_REPORT_SCHEMA:
        return QemuReportValidation(False, f"unsupported QEMU report schema: {payload.get('schema')!r}")
    if (
        not isinstance(payload.get("run_id"), str)
        or not payload["run_id"]
        or Path(str(payload["run_id"])).name != payload["run_id"]
    ):
        return QemuReportValidation(False, "QEMU report has no immutable run_id", payload)
    run_id = str(payload["run_id"])
    if report_path.parent.name == run_id and report_path.parent.parent.name == "runs":
        evidence_dir = report_path.parent
    else:
        evidence_dir = report_path.parent / "evidence" / "runs" / run_id
        immutable_report = evidence_dir / report_path.name
        if not immutable_report.is_file():
            return QemuReportValidation(
                False,
                f"immutable QEMU report is missing: {immutable_report}",
                payload,
            )
        if sha256_file(immutable_report) != sha256_file(report_path):
            return QemuReportValidation(
                False,
                "QEMU report alias differs from immutable evidence",
                payload,
            )
    if (
        evidence_dir.parent.name != "runs"
        or evidence_dir.parent.parent.name != "evidence"
    ):
        return QemuReportValidation(
            False,
            "QEMU evidence directory is outside the expected run tree",
            payload,
        )
    evidence_anchor = evidence_dir.parent.parent.parent
    unsafe_symlink = first_symlink_in_confined_tree(
        evidence_anchor,
        evidence_dir,
    )
    if unsafe_symlink is not None:
        return QemuReportValidation(
            False,
            f"QEMU evidence run contains unsafe symlink: {unsafe_symlink}",
            payload,
        )
    if payload.get("status") != "completed" or payload.get("verdict") != "passed":
        return QemuReportValidation(
            False,
            f"QEMU run is not a completed pass: {payload.get('status')}/{payload.get('verdict')}",
            payload,
        )
    if not iso_path.is_file():
        return QemuReportValidation(False, f"proven ISO is missing: {iso_path}", payload)
    iso = payload.get("iso")
    if not isinstance(iso, dict):
        return QemuReportValidation(False, "QEMU report has no ISO identity", payload)
    expected_iso_sha = sha256_file(iso_path)
    if iso.get("sha256") != expected_iso_sha or iso.get("size") != iso_path.stat().st_size:
        return QemuReportValidation(False, "QEMU report belongs to different ISO bytes", payload)
    boot = payload.get("boot")
    if not isinstance(boot, dict):
        return QemuReportValidation(False, "QEMU report has no boot contract", payload)
    reached = str(boot.get("reached_milestone", ""))
    required = str(boot.get("required_milestone", ""))
    if reached not in _MILESTONE_ORDER:
        return QemuReportValidation(False, f"unknown or unproven boot milestone: {reached!r}", payload)
    if minimum_milestone not in _MILESTONE_ORDER:
        return QemuReportValidation(False, f"invalid gate milestone: {minimum_milestone}", payload)
    if (
        required not in _MILESTONE_ORDER
        or _MILESTONE_ORDER[required] < _MILESTONE_ORDER[minimum_milestone]
        or _MILESTONE_ORDER[reached] < _MILESTONE_ORDER[required]
    ):
        return QemuReportValidation(
            False,
            f"QEMU run required {required!r}, which does not satisfy gate "
            f"milestone {minimum_milestone}",
            payload,
        )
    if _MILESTONE_ORDER[reached] < _MILESTONE_ORDER[minimum_milestone]:
        return QemuReportValidation(
            False,
            f"QEMU reached {reached}, below required {minimum_milestone}",
            payload,
        )
    if boot.get("terminal_refusal") not in (None, ""):
        return QemuReportValidation(False, "QEMU report contains a terminal boot refusal", payload)
    if boot.get("sealed_after_vm_stop") is not True:
        return QemuReportValidation(False, "QEMU serial evidence was not sealed after VM stop", payload)
    marker = boot.get("matched_marker")
    if not isinstance(marker, dict):
        return QemuReportValidation(False, "QEMU report has no matched boot marker", payload)
    pattern = marker.get("pattern")
    offset = marker.get("byte_offset")
    if not isinstance(pattern, str) or not pattern or not isinstance(offset, int) or offset < 0:
        return QemuReportValidation(False, "QEMU matched marker is incomplete", payload)
    marker_milestone = milestone_for_marker(pattern)
    if marker_milestone == "custom" or marker_milestone != reached:
        return QemuReportValidation(
            False,
            "QEMU milestone is not implied by its recorded success marker",
            payload,
        )
    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, dict):
        return QemuReportValidation(False, "QEMU report has no artifact identities", payload)
    serial_result = _validate_report_artifact(
        artifacts.get("serial_log"),
        required=True,
        base_dir=evidence_dir,
    )
    if not serial_result.ok:
        return QemuReportValidation(False, f"serial evidence: {serial_result.detail}", payload)
    serial_path = evidence_dir / Path(str(serial_result.payload["path"]))  # type: ignore[index]
    serial_bytes = serial_path.read_bytes()
    encoded_pattern = pattern.encode("utf-8")
    if offset > len(serial_bytes) or serial_bytes[offset : offset + len(encoded_pattern)] != encoded_pattern:
        return QemuReportValidation(False, "serial marker is absent at the recorded byte offset", payload)
    line_start = serial_bytes.rfind(b"\n", 0, offset) + 1
    line_end = serial_bytes.find(b"\n", offset)
    if line_end < 0:
        line_end = len(serial_bytes)
    actual_line = _UNPRINTABLE.sub(
        "",
        _CSI.sub(
            "",
            serial_bytes[line_start:line_end].decode("utf-8", errors="replace"),
        ),
    ).strip()
    if marker.get("line") != actual_line:
        return QemuReportValidation(
            False,
            "QEMU matched-marker line does not match the sealed serial log",
            payload,
        )
    if not marker_line_proves_milestone(pattern, actual_line):
        return QemuReportValidation(
            False,
            "QEMU marker occurs in a diagnostic line, not a real boot milestone",
            payload,
        )
    serial_text = serial_bytes.decode("utf-8", errors="replace")
    refusal = first_boot_refusal(serial_text)
    if refusal is not None:
        return QemuReportValidation(False, f"terminal refusal in sealed serial log: {refusal}", payload)
    screenshot = artifacts.get("screenshot")
    if screenshot is not None:
        screenshot_result = _validate_report_artifact(
            screenshot,
            required=True,
            base_dir=evidence_dir,
        )
        if not screenshot_result.ok:
            return QemuReportValidation(False, f"screenshot evidence: {screenshot_result.detail}", payload)
    execution = payload.get("execution")
    if not isinstance(execution, dict):
        return QemuReportValidation(False, "QEMU report has no execution identity", payload)
    tools = execution.get("toolchain")
    qemu = tools.get("qemu-system-x86_64") if isinstance(tools, dict) else None
    argv = execution.get("argv")
    entrypoint = execution.get("entrypoint")
    if (
        not isinstance(qemu, dict)
        or qemu.get("available") is not True
        or not _is_sha256(qemu.get("sha256"))
        or not qemu.get("version")
        or not isinstance(argv, list)
        or not argv
        or Path(str(argv[0])).name != "qemu-system-x86_64"
        or not isinstance(entrypoint, dict)
        or entrypoint.get("scope") != "host-entrypoint-pre-dispatch"
        or entrypoint.get("argv") != argv
        or entrypoint.get("available") is not True
        or entrypoint.get("stable_while_hashed") is not True
        or entrypoint.get("sha256") != qemu.get("sha256")
    ):
        return QemuReportValidation(False, "QEMU binary identity is incomplete", payload)
    if boot.get("firmware") == "uefi":
        firmware = execution.get("firmware")
        if not isinstance(firmware, dict):
            return QemuReportValidation(False, "UEFI proof has no firmware identity", payload)
        for name in ("code", "vars_template", "vars_runtime"):
            result = _validate_report_artifact(
                firmware.get(name),
                required=True,
                base_dir=evidence_dir,
            )
            if not result.ok:
                return QemuReportValidation(
                    False,
                    f"UEFI {name} identity is incomplete: {result.detail}",
                    payload,
                )
    return QemuReportValidation(
        True,
        f"runtime {reached} proof matches ISO SHA256 {expected_iso_sha}",
        payload,
    )


def _validate_report_artifact(
    value: object,
    *,
    required: bool,
    base_dir: Path,
) -> QemuReportValidation:
    if not isinstance(value, dict):
        detail = "identity is missing" if required else "not recorded"
        return QemuReportValidation(not required, detail)
    path_value = value.get("path")
    if not isinstance(path_value, str) or not path_value:
        return QemuReportValidation(False, "path is missing", value)
    relative = Path(path_value)
    if relative.is_absolute() or ".." in relative.parts:
        return QemuReportValidation(False, f"artifact path escapes its run: {path_value}", value)
    path = base_dir / relative
    if not path.is_file():
        return QemuReportValidation(False, f"file is missing: {path}", value)
    if value.get("size") != path.stat().st_size:
        return QemuReportValidation(False, f"size mismatch: {path}", value)
    expected = value.get("sha256")
    if not _is_sha256(expected) or expected != sha256_file(path):
        return QemuReportValidation(False, f"SHA256 mismatch: {path}", value)
    return QemuReportValidation(True, "verified", value)


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _safe_artifact_name(value: object) -> bool:
    if not isinstance(value, str) or not value or value in {".", ".."}:
        return False
    path = Path(value)
    return not path.is_absolute() and path.name == value


PrebuildVmService = QemuLabService
