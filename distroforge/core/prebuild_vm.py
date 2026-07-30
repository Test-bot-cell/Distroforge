from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from .artifact_verification import (
    ArtifactHandle,
    ArtifactIdentity,
    ArtifactVerificationError,
    ArtifactVerificationSession,
)
from .command import CommandRunner, CommandSpec
from .evidence_run import (
    copy_immutable_file,
    copy_immutable_file_descriptor,
    ensure_directory_nofollow,
    evidence_run_path,
    first_symlink_in_confined_tree,
    is_safe_run_id,
    new_run_id,
    publish_optional_text_alias_receipt,
    reserve_evidence_run,
    stable_parent_identity,
    toolchain_identity,
    write_immutable_text,
)
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
QEMU_REPORT_ALIAS_PUBLICATION_SCHEMA = "distroforge.qemu-report-alias-publication.v1"
QEMU_REPORT_ALIAS_PUBLICATION_NAME = "QEMU-REPORT-ALIAS-PUBLICATION.json"
_QEMU_REPORT_MAX_BYTES = 8 * 1024 * 1024
_QEMU_SERIAL_MAX_BYTES = 64 * 1024 * 1024
_QEMU_SCREENSHOT_MAX_BYTES = 512 * 1024 * 1024
_QEMU_FIRMWARE_MAX_BYTES = 128 * 1024 * 1024
_MILESTONE_ORDER = {
    "bootloader": 1,
    "kernel_started": 2,
    "live_userspace": 3,
    "login_prompt": 4,
    "installer_ready": 4,
    "graphical_session": 5,
}

# Every configurable leaf is validated as one namespace even though runtime
# controls now live in a run-scoped scratch directory and the compatibility
# report alias lives in the output directory.  Keeping the namespace disjoint
# prevents a future path migration from turning a harmless-looking option into
# an overwrite primitive, and makes the pre-launch refusal independent of which
# backend happens to consume the leaf.
_QEMU_FIXED_RUNTIME_LEAVES = {
    "qemu-lab.qcow2",
    "OVMF_VARS.fd",
    "swtpm.sock",
    "swtpm-state",
}
_QEMU_MANAGED_EVIDENCE_LEAVES = {
    "ISO-BUILD.json",
    "ISO-BUILD.plan.json",
    "boot-proof.json",
    "boot-proof.plan.json",
    "distroforge-provenance.json",
    "RUN-MANIFEST.json",
    "RUN-MANIFEST.json.sha256",
    "commands.jsonl",
    "SHA256SUMS",
    "BUILDINFO",
    "PREBUILD-VM-INTEGRITY",
    "ISO-BUILD-ALIAS-PUBLICATION.json",
    "BOOT-PROOF-ALIAS-PUBLICATION.json",
    "distroforge-provenance.json.alias-publication.json",
    "distroforge-sbom.spdx.json.alias-publication.json",
    "distroforge-sbom.cdx.json.alias-publication.json",
    "qemu",
    QEMU_REPORT_ALIAS_PUBLICATION_NAME,
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


@dataclass(frozen=True)
class _VerifiedReportArtifact:
    validation: QemuReportValidation
    body: bytes | None = None


@dataclass(frozen=True)
class _RunTreeInventory:
    files: dict[Path, ArtifactIdentity]
    directories: dict[Path, tuple[int, int, int, int, int, int, int]]


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
    report_alias_receipt: Path
    ovmf_vars: Path
    tpm_socket: Path


@dataclass
class _QemuFirmwarePins:
    session: ArtifactVerificationSession
    code: ArtifactHandle
    template: ArtifactHandle
    runtime_descriptor: int
    runtime_device: int
    runtime_inode: int

    @property
    def runtime_proc_path(self) -> Path:
        return Path(f"/proc/{os.getpid()}/fd/{self.runtime_descriptor}")

    @property
    def pass_fds(self) -> tuple[int, ...]:
        return (
            *self.code.pass_fds,
            self.runtime_descriptor,
        )

    def close(self) -> None:
        if self.runtime_descriptor >= 0:
            os.close(self.runtime_descriptor)
            self.runtime_descriptor = -1
        self.session.close()


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
        self.output_dir = output_dir
        self.options = options
        self._owns_run = run_id is None
        self.run_id = new_run_id() if run_id is None else run_id
        if not is_safe_run_id(self.run_id):
            raise ValueError(f"QEMU lab requires a safe run_id: {self.run_id!r}")
        self.workdir = workdir / "prebuild-vm" / "runs" / self.run_id
        self._workdir_identity: tuple[int, int, int, int, int, int, int] | None = None
        self.started_at = datetime.now(UTC)
        self._qmp_control = QmpControl(runner, options.timeout_seconds)
        self._launched_argv: tuple[str, ...] = ()
        self._launched_pid: int | None = None
        self._last_serial_text = ""
        self._sealed_serial_artifact: dict[str, object] | None = None
        self._serial_runtime_descriptor: int | None = None
        self._serial_runtime_device: int | None = None
        self._serial_runtime_inode: int | None = None
        self._serial_descriptor_path: str | None = None
        self._proven_iso_identity: dict[str, object] | None = None
        self._firmware_pins: _QemuFirmwarePins | None = None

    def run(self) -> None:
        if not self.options.enabled:
            self.runner.run(
                CommandSpec(
                    argv=("prebuild-vm-skip", str(self.iso_path)),
                    description="Prebuild VM lab disabled",
                )
            )
            return
        # Resolve and validate every leaf before reserving evidence or recording a
        # cleanup command.  In particular, a forged serial/report name equal to the
        # ISO leaf must be refused while the ISO is still untouched.
        artifacts = self._artifacts()
        if not self.runner.dry_run:
            ensure_directory_nofollow(self.output_dir)
            self._workdir_identity = self._reserve_workdir()
            if stable_parent_identity(self.workdir) != self._workdir_identity:
                raise ValueError("QEMU run scratch path changed while it was being prepared")
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
        initial_validation: SerialValidation | None = None
        failure: Exception | None = None
        iso_before: dict[str, object] = {}
        iso_session: ArtifactVerificationSession | None = None
        iso_handle: ArtifactHandle | None = None
        launched_iso = self.iso_path
        try:
            if self.runner.dry_run:
                self.runner.run(
                    CommandSpec(
                        argv=("mkdir", "-p", str(self.workdir), str(self.output_dir)),
                        description="Prepare run-scoped QEMU lab artifact directories",
                    )
                )
            if not self.runner.dry_run and (
                self._workdir_identity is None
                or stable_parent_identity(self.workdir) != self._workdir_identity
            ):
                raise ValueError("QEMU run scratch path changed before runtime use")
            if not self.runner.dry_run:
                absolute_iso = Path(os.path.abspath(self.iso_path))
                iso_session = ArtifactVerificationSession(
                    absolute_iso.parent,
                    label="QEMU ISO consumption",
                )
                iso_handle = iso_session.file_path(
                    absolute_iso,
                    label="QEMU boot ISO",
                )
                iso_before = {
                    "path": str(self.iso_path),
                    "size": iso_handle.identity.size,
                    "sha256": iso_handle.digest(),
                    "device": iso_handle.identity.dev,
                    "inode": iso_handle.identity.ino,
                    "consumed_via": "held-descriptor",
                }
                self._proven_iso_identity = {
                    "path": str(self.iso_path),
                    "size": iso_handle.identity.size,
                    "sha256": iso_before["sha256"],
                    "role": "proven-iso",
                }
                launched_iso = iso_handle.proc_fd_path
                iso_before["descriptor_path"] = str(launched_iso)
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
            if not self.runner.dry_run:
                self._prepare_serial_pin(artifacts)
            self._firmware_pins = self._prepare_firmware(artifacts)
            self._prepare_tpm(artifacts)
            self._launched_argv = tuple(
                self._qemu_argv(
                    artifacts,
                    iso_path=launched_iso,
                    ovmf_code=(
                        str(self._firmware_pins.code.proc_fd_path)
                        if self._firmware_pins is not None
                        else None
                    ),
                    ovmf_vars=(
                        str(self._firmware_pins.runtime_proc_path)
                        if self._firmware_pins is not None
                        else None
                    ),
                    serial_path=(
                        Path(self._serial_descriptor_path)
                        if self._serial_descriptor_path is not None
                        else None
                    ),
                )
            )
            passed_fds = (
                *(iso_handle.pass_fds if iso_handle is not None else ()),
                *(
                    (self._serial_runtime_descriptor,)
                    if self._serial_runtime_descriptor is not None
                    else ()
                ),
                *(self._firmware_pins.pass_fds if self._firmware_pins is not None else ()),
            )
            self.runner.run(
                CommandSpec(
                    argv=self._launched_argv,
                    description="Run QEMU lab boot with QMP control",
                    pass_fds=tuple(dict.fromkeys(passed_fds)),
                )
            )
            if not self.runner.dry_run:
                raw_pid_text = _read_regular_text_bounded(
                    artifacts.pid_file,
                    max_bytes=64,
                    label="QEMU PID file",
                    missing_ok=False,
                )
                assert raw_pid_text is not None
                raw_pid = raw_pid_text.strip()
                if not raw_pid.isdigit() or int(raw_pid) <= 1:
                    raise ValueError(f"QEMU did not write a valid PID file: {artifacts.pid_file}")
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
                try:
                    stop_by_pidfile(
                        self.runner,
                        artifacts.pid_file,
                        "Stop QEMU lab VM",
                        known_pid=self._launched_pid,
                    )
                except Exception as exc:
                    failure = _combine_failures(
                        failure,
                        exc,
                        "QEMU process cleanup",
                    )
            try:
                self._stop_tpm(artifacts)
            except Exception as exc:
                failure = _combine_failures(
                    failure,
                    exc,
                    "QEMU TPM cleanup",
                )
        final_validation: SerialValidation | None = initial_validation
        if failure is None and not self.runner.dry_run:
            try:
                final_validation = self._final_serial_validation(initial_validation)
            except Exception as exc:
                failure = exc
        if iso_session is not None:
            try:
                assert iso_handle is not None
                _revalidate_consumed_artifact(
                    iso_session,
                    iso_handle,
                    Path(os.path.abspath(self.iso_path)),
                    expected_digest=str(iso_before["sha256"]),
                    label="QEMU boot ISO",
                )
            except ArtifactVerificationError as exc:
                if failure is None:
                    failure = ValueError(f"ISO changed while the QEMU proof was running: {exc}")
            finally:
                iso_session.close()
        status = "planned" if self.runner.dry_run else "completed" if failure is None else "aborted"
        verdict = "unproven" if self.runner.dry_run else "passed" if failure is None else "failed"
        try:
            self._write_report(
                artifacts,
                status=status,
                verdict=verdict,
                validation=final_validation,
                error=str(failure) if failure else None,
                iso_before=iso_before,
            )
        finally:
            self._close_serial_runtime_descriptor()
            if self._firmware_pins is not None:
                self._firmware_pins.close()
                self._firmware_pins = None
        if failure is not None:
            raise failure
        IntegrityService(self.runner).write_manifest(
            self.output_dir / "PREBUILD-VM-INTEGRITY",
            {
                "iso": self.iso_path.name,
                "serial_log": self.options.serial_log,
                "screenshot": self.options.screenshot_name
                if self.options.screenshot
                else "disabled",
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

    def _reserve_workdir(self) -> tuple[int, int, int, int, int, int, int]:
        """Reserve one empty scratch namespace descriptor-relatively.

        A QEMU run never reuses a prior scratch tree.  That makes the later cleanup
        command both bounded and non-authoritative: every leaf it names is inside a
        newly-created directory whose exact inode was held and synced here.
        """

        parent = Path(os.path.abspath(self.workdir.parent))
        parent_identity = ensure_directory_nofollow(parent)
        parent_fd = _open_absolute_directory_nofollow(parent)
        child_fd = -1
        created = False
        try:
            if _stable_parent_stat(os.fstat(parent_fd)) != parent_identity:
                raise ValueError("QEMU scratch parent changed before run reservation")
            try:
                os.mkdir(self.run_id, 0o700, dir_fd=parent_fd)
            except FileExistsError as exc:
                raise ValueError(
                    f"QEMU refuses to reuse an existing run scratch directory: {self.workdir}"
                ) from exc
            created = True
            child_fd = os.open(
                self.run_id,
                os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
            os.fchmod(child_fd, 0o700)
            child_identity = ArtifactIdentity.from_stat(os.fstat(child_fd))
            named_identity = ArtifactIdentity.from_stat(
                os.stat(
                    self.run_id,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
            )
            if child_identity != named_identity:
                raise ValueError("QEMU scratch leaf changed while its descriptor was acquired")
            os.fsync(child_fd)
            os.fsync(parent_fd)
            closing_parent = _stable_parent_stat(os.fstat(parent_fd))
            if closing_parent[:5] != parent_identity[:5] or closing_parent[6] != parent_identity[6]:
                raise ValueError("QEMU scratch parent changed while the run was reserved")
            return _stable_parent_stat(os.fstat(child_fd))
        except BaseException:
            if created:
                try:
                    os.rmdir(self.run_id, dir_fd=parent_fd)
                    os.fsync(parent_fd)
                except OSError:
                    pass
            raise
        finally:
            if child_fd >= 0:
                os.close(child_fd)
            os.close(parent_fd)

    def _iso_identity(self) -> dict[str, object]:
        absolute_iso = Path(os.path.abspath(self.iso_path))
        try:
            session = ArtifactVerificationSession(
                absolute_iso.parent,
                label="QEMU report ISO identity",
            )
        except ArtifactVerificationError:
            return {"path": str(self.iso_path), "size": 0, "sha256": ""}
        try:
            try:
                handle = session.file_path(
                    absolute_iso,
                    label="QEMU report ISO",
                )
                identity = {
                    "path": str(self.iso_path),
                    "size": handle.identity.size,
                    "sha256": handle.digest(),
                }
                session.seal()
                return identity
            except ArtifactVerificationError:
                return {"path": str(self.iso_path), "size": 0, "sha256": ""}
        finally:
            session.close()

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
        configurable_names = set(names.values())
        reserved_names = {
            *_QEMU_FIXED_RUNTIME_LEAVES,
            *_QEMU_MANAGED_EVIDENCE_LEAVES,
            self.iso_path.name,
        }
        if len(configurable_names) != len(names):
            raise ValueError(
                "QEMU control, report, serial and screenshot names must all be different"
            )
        collisions = sorted(configurable_names & reserved_names)
        if collisions:
            raise ValueError(
                "QEMU control or output names collide with managed artifacts: "
                + ", ".join(collisions)
            )
        immutable_report = evidence_run_path(
            self.output_dir,
            self.run_id,
            self.options.report_name,
            executed=not self.runner.dry_run,
        )
        artifacts = QemuLabArtifacts(
            disk=self.workdir / "qemu-lab.qcow2",
            qmp_socket=self.workdir / self.options.qmp_socket,
            pid_file=self.workdir / self.options.pid_file,
            serial_log=self.workdir / self.options.serial_log,
            screenshot=self.workdir / self.options.screenshot_name,
            report=self.output_dir / self.options.report_name,
            report_alias_receipt=(immutable_report.parent / QEMU_REPORT_ALIAS_PUBLICATION_NAME),
            ovmf_vars=self.workdir / "OVMF_VARS.fd",
            tpm_socket=self.workdir / "swtpm.sock",
        )
        absolute_iso = Path(os.path.abspath(self.iso_path))
        managed_runtime_paths = {
            Path(os.path.abspath(path))
            for path in (
                artifacts.disk,
                artifacts.qmp_socket,
                artifacts.pid_file,
                artifacts.serial_log,
                artifacts.screenshot,
                artifacts.report,
                artifacts.ovmf_vars,
                artifacts.tpm_socket,
                self.workdir / "swtpm-state",
                self.output_dir / "PREBUILD-VM-INTEGRITY",
            )
        }
        if absolute_iso in managed_runtime_paths:
            raise ValueError("QEMU runtime/control outputs collide with the input ISO path")
        return artifacts

    def _qemu_argv(
        self,
        artifacts: QemuLabArtifacts,
        *,
        iso_path: Path | None = None,
        ovmf_code: str | None = None,
        ovmf_vars: str | None = None,
        serial_path: Path | None = None,
    ) -> list[str]:
        return list(
            QemuInvocation(
                iso=iso_path or self.iso_path,
                memory_mb=self.options.memory_mb,
                cpus=self.options.cpus,
                disk=artifacts.disk,
                serial=f"file:{serial_path or artifacts.serial_log}",
                qmp_socket=artifacts.qmp_socket,
                pid_file=artifacts.pid_file,
                display="none",
                daemonize=True,
                firmware=self.options.firmware,
                ovmf_code=ovmf_code
                or default_ovmf_code(
                    self.options.ovmf_code,
                    secure_boot=self.options.secure_boot,
                ),
                ovmf_vars=ovmf_vars or str(artifacts.ovmf_vars),
                secure_boot=self.options.secure_boot,
                tpm_socket=artifacts.tpm_socket if self.options.tpm else None,
                network="user" if self.options.network else "none",
                enable_kvm=kvm_is_usable(),
            ).argv()
        )

    def _prepare_firmware(
        self,
        artifacts: QemuLabArtifacts,
    ) -> _QemuFirmwarePins | None:
        if self.options.firmware != "uefi":
            return None
        template = default_ovmf_vars(self.options.ovmf_vars, secure_boot=self.options.secure_boot)
        code = default_ovmf_code(
            self.options.ovmf_code,
            secure_boot=self.options.secure_boot,
        )
        self.runner.run(
            CommandSpec(
                argv=("copy-file", template, str(artifacts.ovmf_vars)),
                description="Prepare writable OVMF variables store",
            )
        )
        if self.runner.dry_run:
            return None

        absolute_code = Path(os.path.abspath(code))
        absolute_template = Path(os.path.abspath(template))
        anchor = Path(
            os.path.commonpath((str(absolute_code.parent), str(absolute_template.parent)))
        )
        session = ArtifactVerificationSession(
            anchor,
            label="QEMU firmware consumption",
        )
        runtime_descriptor = -1
        try:
            code_handle = session.file_path(
                absolute_code,
                label="QEMU OVMF code",
                max_bytes=_QEMU_FIRMWARE_MAX_BYTES,
            )
            template_handle = session.file_path(
                absolute_template,
                label="QEMU OVMF variable-store template",
                max_bytes=_QEMU_FIRMWARE_MAX_BYTES,
            )
            code_handle.digest()
            template_digest = template_handle.digest()
            receipt = copy_immutable_file_descriptor(
                template_handle.fileno,
                artifacts.ovmf_vars,
            )
            if receipt.size != template_handle.identity.size or receipt.sha256 != template_digest:
                raise ValueError("writable OVMF store differs from its held template")

            absolute_runtime = Path(os.path.abspath(artifacts.ovmf_vars))
            runtime_session = ArtifactVerificationSession(
                absolute_runtime.parent,
                label="QEMU writable firmware preparation",
            )
            try:
                runtime_handle = runtime_session.file_path(
                    absolute_runtime,
                    label="QEMU writable OVMF variable store",
                    max_bytes=_QEMU_FIRMWARE_MAX_BYTES,
                )
                if runtime_handle.digest() != receipt.sha256:
                    raise ValueError("writable OVMF store changed before descriptor pinning")
                runtime_descriptor = os.open(
                    runtime_handle.proc_fd_path,
                    os.O_RDWR | os.O_CLOEXEC | os.O_NONBLOCK,
                )
                runtime_identity = os.fstat(runtime_descriptor)
                if (
                    runtime_identity.st_dev != runtime_handle.identity.dev
                    or runtime_identity.st_ino != runtime_handle.identity.ino
                    or not stat.S_ISREG(runtime_identity.st_mode)
                ):
                    raise ValueError("writable OVMF descriptor differs from its verified inode")
                runtime_session.seal()
            finally:
                runtime_session.close()
            pins = _QemuFirmwarePins(
                session=session,
                code=code_handle,
                template=template_handle,
                runtime_descriptor=runtime_descriptor,
                runtime_device=runtime_identity.st_dev,
                runtime_inode=runtime_identity.st_ino,
            )
            runtime_descriptor = -1
            return pins
        except BaseException:
            if runtime_descriptor >= 0:
                os.close(runtime_descriptor)
            session.close()
            raise

    def _prepare_serial_pin(self, artifacts: QemuLabArtifacts) -> None:
        write_immutable_text(artifacts.serial_log, "")
        absolute_serial = Path(os.path.abspath(artifacts.serial_log))
        session = ArtifactVerificationSession(
            absolute_serial.parent,
            label="QEMU serial output preparation",
        )
        descriptor = -1
        try:
            handle = session.file_path(
                absolute_serial,
                label="QEMU serial output inode",
                max_bytes=_QEMU_SERIAL_MAX_BYTES,
                allow_empty=True,
            )
            descriptor = os.open(
                handle.proc_fd_path,
                os.O_RDWR | os.O_CLOEXEC | os.O_NONBLOCK,
            )
            identity = ArtifactIdentity.from_stat(os.fstat(descriptor))
            if identity != handle.identity:
                raise ArtifactVerificationError(
                    "QEMU serial descriptor differs from its prepared inode"
                )
            session.seal()
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            raise
        finally:
            session.close()
        self._serial_runtime_descriptor = descriptor
        self._serial_runtime_device = identity.dev
        self._serial_runtime_inode = identity.ino
        self._serial_descriptor_path = f"/proc/{os.getpid()}/fd/{descriptor}"

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
        serial = self._artifacts().serial_log
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
        while time.monotonic() <= deadline:
            text: str | None
            if self._serial_runtime_descriptor is not None:
                text = _read_growing_held_text(
                    self._serial_runtime_descriptor,
                    expected_device=self._serial_runtime_device,
                    expected_inode=self._serial_runtime_inode,
                    max_bytes=_QEMU_SERIAL_MAX_BYTES,
                    label="QEMU lab serial log",
                )
            else:
                text = _read_regular_text_bounded(
                    serial,
                    max_bytes=_QEMU_SERIAL_MAX_BYTES,
                    label="QEMU lab serial log",
                    missing_ok=True,
                )
            if text is None:
                time.sleep(0.2)
                continue
            self._last_serial_text = text
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
                        byte_offset=len(text[:offset].encode("utf-8", errors="strict")),
                        milestone=milestone_for_marker(pattern),
                    )
                search_from = offset + len(pattern)
        return None

    def _final_serial_validation(
        self,
        initial: SerialValidation | None,
    ) -> SerialValidation:
        serial = self._artifacts().serial_log
        absolute_serial = Path(os.path.abspath(serial))
        session = ArtifactVerificationSession(
            absolute_serial.parent,
            label="QEMU final serial verification",
        )
        try:
            handle = session.file_path(
                absolute_serial,
                label="QEMU final serial log",
                max_bytes=_QEMU_SERIAL_MAX_BYTES,
            )
            text = handle.read_text()
            source_descriptor = handle.fileno
            if self._serial_runtime_descriptor is not None:
                runtime_identity = ArtifactIdentity.from_stat(
                    os.fstat(self._serial_runtime_descriptor)
                )
                if (
                    runtime_identity != handle.identity
                    or runtime_identity.dev != self._serial_runtime_device
                    or runtime_identity.ino != self._serial_runtime_inode
                ):
                    raise ArtifactVerificationError(
                        "QEMU final serial path no longer names the consumed inode"
                    )
                source_descriptor = self._serial_runtime_descriptor
            self._last_serial_text = text
            refusal = first_boot_refusal(text)
            if refusal is not None:
                raise ValueError(f"QEMU lab boot gave up after a success marker: {refusal}")
            final = self._matched_serial(text)
            if final is None or initial is None:
                raise ValueError(
                    "QEMU lab final serial log does not contain the proven success marker"
                )
            if final.pattern != initial.pattern:
                raise ValueError(
                    "QEMU lab success marker changed while the serial log was being sealed"
                )
            serial_relative = Path("qemu") / "serial.log"
            serial_target = (
                evidence_run_path(
                    self.output_dir,
                    self.run_id,
                    self.options.report_name,
                    executed=True,
                ).parent
                / serial_relative
            )
            receipt = copy_immutable_file_descriptor(
                source_descriptor,
                serial_target,
            )
            self._sealed_serial_artifact = {
                "path": serial_relative.as_posix(),
                "size": receipt.size,
                "sha256": receipt.sha256,
                "consumed_via": "held-descriptor",
                "descriptor_path": self._serial_descriptor_path,
            }
            session.seal()
            self._close_serial_runtime_descriptor()
            return final
        except ArtifactVerificationError as exc:
            raise ValueError(f"QEMU final serial evidence is blocked: {exc}") from exc
        finally:
            session.close()
            if self._sealed_serial_artifact is not None:
                self._close_serial_runtime_descriptor()

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
        sealing_failure: Exception | None = None
        try:
            serial_artifact, screenshot_artifact, firmware = self._seal_runtime_artifacts(
                artifacts,
                evidence_dir,
                required=status == "completed" and verdict == "passed",
            )
        except (ArtifactVerificationError, OSError, ValueError) as exc:
            sealing_failure = exc
            status = "aborted"
            verdict = "failed"
            error = f"QEMU runtime artifact sealing failed: {exc}"
            serial_artifact, screenshot_artifact, firmware = self._seal_runtime_artifacts(
                artifacts,
                evidence_dir,
                required=False,
            )
        terminal_refusal = first_boot_refusal(self._last_serial_text)
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
        for target in (
            immutable,
            artifacts.report,
            artifacts.report_alias_receipt,
        ):
            self.runner.run(
                CommandSpec(
                    argv=("write-file", str(target)),
                    description="Write QEMU lab JSON report",
                )
            )
        if not self.runner.dry_run:
            immutable_receipt = write_immutable_text(immutable, content)
            alias_parent_identity = stable_parent_identity(artifacts.report.parent)
            alias_payload = publish_optional_text_alias_receipt(
                artifacts.report,
                content,
                schema=QEMU_REPORT_ALIAS_PUBLICATION_SCHEMA,
                run_id=self.run_id,
                authoritative_source_path=immutable,
                authoritative_source_receipt=immutable_receipt,
                authoritative_source_key="authoritative_report",
                expected_parent_identity=alias_parent_identity,
            )
            write_immutable_text(
                artifacts.report_alias_receipt,
                json.dumps(alias_payload, indent=2) + "\n",
            )
        if sealing_failure is not None:
            raise ValueError(str(error)) from sealing_failure

    def _seal_runtime_artifacts(
        self,
        artifacts: QemuLabArtifacts,
        evidence_dir: Path,
        *,
        required: bool,
    ) -> tuple[dict[str, object], dict[str, object] | None, dict[str, object]]:
        if self._sealed_serial_artifact is not None:
            serial = self._sealed_serial_artifact
        elif self._serial_runtime_descriptor is not None:
            serial = self._seal_pinned_serial(artifacts, evidence_dir)
        else:
            serial = self._sealed_artifact(
                artifacts.serial_log,
                evidence_dir,
                Path("qemu") / "serial.log",
                max_bytes=_QEMU_SERIAL_MAX_BYTES,
                required=required,
            )
        screenshot = (
            self._sealed_artifact(
                artifacts.screenshot,
                evidence_dir,
                Path("qemu") / "screenshot.ppm",
                max_bytes=_QEMU_SCREENSHOT_MAX_BYTES,
                required=required,
            )
            if self.options.screenshot
            else None
        )
        firmware: dict[str, object] = {}
        if self.options.firmware == "uefi":
            if self._firmware_pins is not None:
                try:
                    firmware = self._seal_pinned_firmware(
                        artifacts,
                        evidence_dir,
                    )
                finally:
                    self._firmware_pins.close()
                    self._firmware_pins = None
            else:
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
                        max_bytes=_QEMU_FIRMWARE_MAX_BYTES,
                        required=required,
                    ),
                    "vars_template": self._sealed_artifact(
                        template,
                        evidence_dir,
                        Path("qemu") / "firmware-vars-template.fd",
                        max_bytes=_QEMU_FIRMWARE_MAX_BYTES,
                        required=required,
                    ),
                    "vars_runtime": self._sealed_artifact(
                        artifacts.ovmf_vars,
                        evidence_dir,
                        Path("qemu") / "firmware-vars-runtime.fd",
                        max_bytes=_QEMU_FIRMWARE_MAX_BYTES,
                        required=required,
                    ),
                    "consumption": {
                        "code": "not-held",
                        "vars_template": "not-held",
                        "vars_runtime": "not-held",
                    },
                }
        return serial, screenshot, firmware

    def _seal_pinned_serial(
        self,
        artifacts: QemuLabArtifacts,
        evidence_dir: Path,
    ) -> dict[str, object]:
        descriptor = self._serial_runtime_descriptor
        assert descriptor is not None
        serial_path = Path(os.path.abspath(artifacts.serial_log))
        try:
            session = ArtifactVerificationSession(
                serial_path.parent,
                label="QEMU stopped serial sealing",
            )
        except BaseException:
            self._close_serial_runtime_descriptor()
            raise
        try:
            handle = session.file_path(
                serial_path,
                label="QEMU stopped serial output",
                max_bytes=_QEMU_SERIAL_MAX_BYTES,
                allow_empty=True,
            )
            runtime_identity = ArtifactIdentity.from_stat(os.fstat(descriptor))
            if (
                runtime_identity != handle.identity
                or runtime_identity.dev != self._serial_runtime_device
                or runtime_identity.ino != self._serial_runtime_inode
            ):
                raise ArtifactVerificationError(
                    "QEMU serial path no longer names the consumed output inode"
                )
            receipt = copy_immutable_file_descriptor(
                descriptor,
                evidence_dir / "qemu" / "serial.log",
            )
            session.seal()
            return {
                "path": "qemu/serial.log",
                "size": receipt.size,
                "sha256": receipt.sha256,
                "consumed_via": "held-descriptor",
                "descriptor_path": self._serial_descriptor_path,
            }
        finally:
            session.close()
            self._close_serial_runtime_descriptor()

    def _close_serial_runtime_descriptor(self) -> None:
        if self._serial_runtime_descriptor is not None:
            os.close(self._serial_runtime_descriptor)
            self._serial_runtime_descriptor = None
        self._serial_runtime_device = None
        self._serial_runtime_inode = None

    def _seal_pinned_firmware(
        self,
        artifacts: QemuLabArtifacts,
        evidence_dir: Path,
    ) -> dict[str, object]:
        pins = self._firmware_pins
        assert pins is not None
        code_descriptor_path = str(pins.code.proc_fd_path)
        template_descriptor_path = str(pins.template.proc_fd_path)
        runtime_descriptor_path = str(pins.runtime_proc_path)
        runtime_path = Path(os.path.abspath(artifacts.ovmf_vars))
        runtime_session = ArtifactVerificationSession(
            runtime_path.parent,
            label="QEMU stopped firmware sealing",
        )
        try:
            runtime_handle = runtime_session.file_path(
                runtime_path,
                label="QEMU stopped writable OVMF variable store",
                max_bytes=_QEMU_FIRMWARE_MAX_BYTES,
            )
            runtime_identity = ArtifactIdentity.from_stat(os.fstat(pins.runtime_descriptor))
            if (
                runtime_identity != runtime_handle.identity
                or runtime_identity.dev != pins.runtime_device
                or runtime_identity.ino != pins.runtime_inode
            ):
                raise ArtifactVerificationError(
                    "QEMU writable firmware path no longer names the consumed inode"
                )
            code_receipt = copy_immutable_file_descriptor(
                pins.code.fileno,
                evidence_dir / "qemu" / "firmware-code.fd",
            )
            template_receipt = copy_immutable_file_descriptor(
                pins.template.fileno,
                evidence_dir / "qemu" / "firmware-vars-template.fd",
            )
            runtime_receipt = copy_immutable_file_descriptor(
                pins.runtime_descriptor,
                evidence_dir / "qemu" / "firmware-vars-runtime.fd",
            )
            runtime_session.seal()
            _revalidate_consumed_artifact(
                pins.session,
                pins.code,
                pins.code.logical_path,
                expected_digest=pins.code.digest(),
                label="QEMU OVMF code",
            )
            _revalidate_consumed_artifact(
                pins.session,
                pins.template,
                pins.template.logical_path,
                expected_digest=pins.template.digest(),
                label="QEMU OVMF variable-store template",
            )
        finally:
            runtime_session.close()
        return {
            "code": {
                "path": "qemu/firmware-code.fd",
                "size": code_receipt.size,
                "sha256": code_receipt.sha256,
                "descriptor_path": code_descriptor_path,
            },
            "vars_template": {
                "path": "qemu/firmware-vars-template.fd",
                "size": template_receipt.size,
                "sha256": template_receipt.sha256,
                "source_descriptor_path": template_descriptor_path,
            },
            "vars_runtime": {
                "path": "qemu/firmware-vars-runtime.fd",
                "size": runtime_receipt.size,
                "sha256": runtime_receipt.sha256,
                "descriptor_path": runtime_descriptor_path,
            },
            "consumption": {
                "code": "held-descriptor",
                "vars_template": "held-copy-source",
                "vars_runtime": "held-descriptor",
            },
        }

    def _write_run_manifest(self) -> None:
        run_dir = evidence_run_path(
            self.output_dir,
            self.run_id,
            self.options.report_name,
            executed=True,
        ).parent
        manifest = run_dir / "RUN-MANIFEST.json"
        sidecar = run_dir / "RUN-MANIFEST.json.sha256"
        excluded = {Path(manifest.name), Path(sidecar.name)}
        opening = _inventory_regular_tree(run_dir, excluded=excluded)
        session = ArtifactVerificationSession(
            Path(os.path.abspath(run_dir)),
            label="QEMU run manifest inventory",
        )
        files: list[dict[str, object]] = []
        try:
            for relative, opening_identity in sorted(
                opening.files.items(),
                key=lambda item: item[0].as_posix(),
            ):
                handle = session.file(
                    relative,
                    label=f"QEMU run artifact {relative.as_posix()}",
                )
                if handle.identity != opening_identity:
                    raise ArtifactVerificationError(
                        f"QEMU run artifact changed during inventory: {relative}"
                    )
                files.append(
                    {
                        "path": str(run_dir / relative),
                        "size": handle.identity.size,
                        "sha256": handle.digest(),
                        "role": "qemu-run-evidence",
                    }
                )
            session.seal()
        finally:
            session.close()
        if self._proven_iso_identity is not None:
            files.append(dict(self._proven_iso_identity))
        payload = {
            "schema": QEMU_RUN_MANIFEST_SCHEMA,
            "run_id": self.run_id,
            "mode": "execute",
            "status": "completed",
            "created_at": self.started_at.isoformat(),
            "files": files,
        }
        write_immutable_text(manifest, json.dumps(payload, indent=2) + "\n")
        after_manifest = _inventory_regular_tree(run_dir, excluded=excluded)
        _assert_same_run_inventory(
            opening,
            after_manifest,
            label="QEMU evidence changed while RUN-MANIFEST.json was published",
        )

        manifest_session = ArtifactVerificationSession(
            Path(os.path.abspath(run_dir)),
            label="QEMU run manifest sidecar",
        )
        try:
            manifest_handle = manifest_session.file(
                Path(manifest.name),
                label="QEMU RUN-MANIFEST.json",
                max_bytes=_QEMU_REPORT_MAX_BYTES,
            )
            manifest_digest = manifest_handle.digest()
            manifest_identity = manifest_handle.identity
            manifest_session.seal()
        finally:
            manifest_session.close()
        write_immutable_text(
            sidecar,
            f"{manifest_digest}  {manifest.name}\n",
        )
        final_inventory = _inventory_regular_tree(
            run_dir,
            excluded={Path(sidecar.name)},
        )
        expected_final_files = {
            **opening.files,
            Path(manifest.name): manifest_identity,
        }
        if (
            final_inventory.files != expected_final_files
            or final_inventory.directories != opening.directories
        ):
            raise ArtifactVerificationError(
                "QEMU evidence or RUN-MANIFEST.json changed while its sidecar was published"
            )

    def _sealed_artifact(
        self,
        source: Path,
        evidence_dir: Path,
        relative: Path,
        *,
        max_bytes: int,
        required: bool,
    ) -> dict[str, object]:
        target = evidence_dir / relative
        missing = {
            "path": relative.as_posix(),
            "size": 0,
            "sha256": "",
        }
        if self.runner.dry_run:
            return missing
        absolute_source = Path(os.path.abspath(source))
        try:
            session = ArtifactVerificationSession(
                absolute_source.parent,
                label=f"QEMU {relative.as_posix()} sealing",
            )
        except ArtifactVerificationError:
            if required:
                raise
            return missing
        try:
            try:
                handle = session.file_path(
                    absolute_source,
                    label=f"QEMU source artifact {source}",
                    max_bytes=max_bytes,
                )
                receipt = copy_immutable_file_descriptor(
                    handle.fileno,
                    target,
                )
                session.seal()
            except (ArtifactVerificationError, OSError, ValueError):
                if required:
                    raise
                return missing
            return {
                "path": relative.as_posix(),
                "size": receipt.size,
                "sha256": receipt.sha256,
            }
        finally:
            session.close()


def validate_qemu_report(
    report_path: Path,
    iso_path: Path,
    *,
    minimum_milestone: str = "login_prompt",
    session: ArtifactVerificationSession | None = None,
) -> QemuReportValidation:
    """Validate one QEMU proof from descriptor-held, bounded artifact bytes."""
    absolute_report = Path(os.path.abspath(report_path))
    absolute_iso = Path(os.path.abspath(iso_path))
    if session is not None:
        try:
            return _validate_qemu_report_in_session(
                absolute_report,
                absolute_iso,
                minimum_milestone=minimum_milestone,
                session=session,
            )
        except ArtifactVerificationError as exc:
            return QemuReportValidation(
                False,
                f"QEMU artifact verification blocked: {exc}",
            )

    anchor = Path(os.path.commonpath((str(absolute_report.parent), str(absolute_iso.parent))))
    try:
        owned_session = ArtifactVerificationSession(
            anchor,
            label="QEMU report verification",
        )
    except ArtifactVerificationError as exc:
        return QemuReportValidation(
            False,
            f"QEMU artifact verification blocked: {exc}",
        )
    try:
        try:
            result = _validate_qemu_report_in_session(
                absolute_report,
                absolute_iso,
                minimum_milestone=minimum_milestone,
                session=owned_session,
            )
        except ArtifactVerificationError as exc:
            result = QemuReportValidation(
                False,
                f"QEMU artifact verification blocked: {exc}",
            )
        try:
            owned_session.seal()
        except ArtifactVerificationError as exc:
            return QemuReportValidation(
                False,
                f"{result.detail}; QEMU descriptor closure blocked: {exc}",
                result.payload,
            )
        return result
    finally:
        owned_session.close()


def _validate_qemu_report_in_session(
    report_path: Path,
    iso_path: Path,
    *,
    minimum_milestone: str,
    session: ArtifactVerificationSession,
) -> QemuReportValidation:
    report_handle = session.file_path(
        report_path,
        label="QEMU report",
        max_bytes=_QEMU_REPORT_MAX_BYTES,
    )
    payload = report_handle.json_object()
    if payload.get("schema") != QEMU_REPORT_SCHEMA:
        return QemuReportValidation(
            False, f"unsupported QEMU report schema: {payload.get('schema')!r}"
        )
    run_id_value = payload.get("run_id")
    if not is_safe_run_id(run_id_value):
        return QemuReportValidation(False, "QEMU report has no immutable run_id", payload)
    assert isinstance(run_id_value, str)
    run_id = run_id_value
    if report_path.parent.name == run_id and report_path.parent.parent.name == "runs":
        evidence_dir = report_path.parent
    else:
        evidence_dir = report_path.parent / "evidence" / "runs" / run_id
    if evidence_dir.parent.name != "runs" or evidence_dir.parent.parent.name != "evidence":
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
    immutable_report = evidence_dir / report_path.name
    if immutable_report != report_path:
        immutable_handle = session.file_path(
            immutable_report,
            label="immutable QEMU report",
            max_bytes=_QEMU_REPORT_MAX_BYTES,
        )
        if immutable_handle.digest() != report_handle.digest():
            return QemuReportValidation(
                False,
                "QEMU report alias differs from immutable evidence",
                payload,
            )
    if payload.get("status") != "completed" or payload.get("verdict") != "passed":
        return QemuReportValidation(
            False,
            f"QEMU run is not a completed pass: {payload.get('status')}/{payload.get('verdict')}",
            payload,
        )
    iso = payload.get("iso")
    if not isinstance(iso, dict):
        return QemuReportValidation(False, "QEMU report has no ISO identity", payload)
    if iso.get("consumed_via") != "held-descriptor":
        return QemuReportValidation(
            False,
            "QEMU report does not bind the consumed ISO to a held descriptor",
            payload,
        )
    iso_descriptor_path = iso.get("descriptor_path")
    if not _is_proc_fd_path(iso_descriptor_path):
        return QemuReportValidation(
            False,
            "QEMU report has no canonical held ISO descriptor path",
            payload,
        )
    iso_handle = session.file_path(
        iso_path,
        label="QEMU proven ISO",
    )
    expected_iso_sha = iso_handle.digest()
    recorded_iso_size = iso.get("size")
    if (
        iso.get("sha256") != expected_iso_sha
        or type(recorded_iso_size) is not int
        or recorded_iso_size != iso_handle.identity.size
    ):
        return QemuReportValidation(False, "QEMU report belongs to different ISO bytes", payload)
    boot = payload.get("boot")
    if not isinstance(boot, dict):
        return QemuReportValidation(False, "QEMU report has no boot contract", payload)
    reached = str(boot.get("reached_milestone", ""))
    required = str(boot.get("required_milestone", ""))
    if reached not in _MILESTONE_ORDER:
        return QemuReportValidation(
            False, f"unknown or unproven boot milestone: {reached!r}", payload
        )
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
        return QemuReportValidation(
            False, "QEMU serial evidence was not sealed after VM stop", payload
        )
    marker = boot.get("matched_marker")
    if not isinstance(marker, dict):
        return QemuReportValidation(False, "QEMU report has no matched boot marker", payload)
    pattern = marker.get("pattern")
    offset = marker.get("byte_offset")
    if not isinstance(pattern, str) or not pattern or type(offset) is not int or offset < 0:
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
    serial_identity = artifacts.get("serial_log")
    if (
        not isinstance(serial_identity, dict)
        or serial_identity.get("consumed_via") != "held-descriptor"
    ):
        return QemuReportValidation(
            False,
            "QEMU report does not bind serial evidence to the consumed output inode",
            payload,
        )
    serial_descriptor_path = serial_identity.get("descriptor_path")
    if not _is_proc_fd_path(serial_descriptor_path):
        return QemuReportValidation(
            False,
            "QEMU report has no canonical held serial descriptor path",
            payload,
        )
    serial_artifact = _validate_report_artifact(
        serial_identity,
        required=True,
        base_dir=evidence_dir,
        session=session,
        max_bytes=_QEMU_SERIAL_MAX_BYTES,
        capture=True,
    )
    serial_result = serial_artifact.validation
    if not serial_result.ok:
        return QemuReportValidation(False, f"serial evidence: {serial_result.detail}", payload)
    assert serial_artifact.body is not None
    serial_bytes = serial_artifact.body
    try:
        serial_text = serial_bytes.decode("utf-8", errors="strict")
    except UnicodeError:
        return QemuReportValidation(
            False,
            "sealed serial log is not strict UTF-8",
            payload,
        )
    encoded_pattern = pattern.encode("utf-8")
    if (
        offset > len(serial_bytes)
        or serial_bytes[offset : offset + len(encoded_pattern)] != encoded_pattern
    ):
        return QemuReportValidation(
            False, "serial marker is absent at the recorded byte offset", payload
        )
    line_start = serial_bytes.rfind(b"\n", 0, offset) + 1
    line_end = serial_bytes.find(b"\n", offset)
    if line_end < 0:
        line_end = len(serial_bytes)
    actual_line = _UNPRINTABLE.sub(
        "",
        _CSI.sub(
            "",
            serial_bytes[line_start:line_end].decode("utf-8", errors="strict"),
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
    refusal = first_boot_refusal(serial_text)
    if refusal is not None:
        return QemuReportValidation(
            False, f"terminal refusal in sealed serial log: {refusal}", payload
        )
    screenshot = artifacts.get("screenshot")
    if screenshot is not None:
        screenshot_result = _validate_report_artifact(
            screenshot,
            required=True,
            base_dir=evidence_dir,
            session=session,
            max_bytes=_QEMU_SCREENSHOT_MAX_BYTES,
        ).validation
        if not screenshot_result.ok:
            return QemuReportValidation(
                False,
                f"screenshot evidence: {screenshot_result.detail}",
                payload,
            )
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
        or not all(isinstance(value, str) for value in argv)
        or Path(str(argv[0])).name != "qemu-system-x86_64"
        or not isinstance(entrypoint, dict)
        or entrypoint.get("scope") != "host-entrypoint-pre-dispatch"
        or entrypoint.get("argv") != argv
        or entrypoint.get("available") is not True
        or entrypoint.get("stable_while_hashed") is not True
        or entrypoint.get("sha256") != qemu.get("sha256")
    ):
        return QemuReportValidation(False, "QEMU binary identity is incomplete", payload)
    argv_text = [str(value) for value in argv]
    if (
        _argv_option(argv_text, "-cdrom") != iso_descriptor_path
        or _argv_option(argv_text, "-serial") != f"file:{serial_descriptor_path}"
    ):
        return QemuReportValidation(
            False,
            "QEMU argv is not bound to the held ISO and serial descriptors",
            payload,
        )
    if boot.get("firmware") == "uefi":
        firmware = execution.get("firmware")
        if not isinstance(firmware, dict):
            return QemuReportValidation(False, "UEFI proof has no firmware identity", payload)
        if firmware.get("consumption") != {
            "code": "held-descriptor",
            "vars_template": "held-copy-source",
            "vars_runtime": "held-descriptor",
        }:
            return QemuReportValidation(
                False,
                "UEFI proof does not bind consumed firmware to held descriptors",
                payload,
            )
        code_identity = firmware.get("code")
        template_identity = firmware.get("vars_template")
        runtime_identity = firmware.get("vars_runtime")
        code_descriptor = (
            code_identity.get("descriptor_path") if isinstance(code_identity, dict) else None
        )
        template_descriptor = (
            template_identity.get("source_descriptor_path")
            if isinstance(template_identity, dict)
            else None
        )
        runtime_descriptor = (
            runtime_identity.get("descriptor_path") if isinstance(runtime_identity, dict) else None
        )
        if (
            not _is_proc_fd_path(code_descriptor)
            or not _is_proc_fd_path(template_descriptor)
            or not _is_proc_fd_path(runtime_descriptor)
            or (f"if=pflash,format=raw,readonly=on,file={code_descriptor}") not in argv_text
            or f"if=pflash,format=raw,file={runtime_descriptor}" not in argv_text
        ):
            return QemuReportValidation(
                False,
                "UEFI argv is not bound to held firmware descriptors",
                payload,
            )
        for name in ("code", "vars_template", "vars_runtime"):
            result = _validate_report_artifact(
                firmware.get(name),
                required=True,
                base_dir=evidence_dir,
                session=session,
                max_bytes=_QEMU_FIRMWARE_MAX_BYTES,
            ).validation
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
    session: ArtifactVerificationSession,
    max_bytes: int,
    capture: bool = False,
) -> _VerifiedReportArtifact:
    if not isinstance(value, dict):
        detail = "identity is missing" if required else "not recorded"
        return _VerifiedReportArtifact(QemuReportValidation(not required, detail))
    path_value = value.get("path")
    if not isinstance(path_value, str) or not path_value:
        return _VerifiedReportArtifact(QemuReportValidation(False, "path is missing", value))
    raw_parts = path_value.split("/")
    relative = Path(path_value)
    if (
        "\\" in path_value
        or "\x00" in path_value
        or any(part in {"", ".", ".."} for part in raw_parts)
        or relative == Path(".")
        or relative.is_absolute()
        or relative.as_posix() != path_value
    ):
        return _VerifiedReportArtifact(
            QemuReportValidation(
                False,
                f"artifact path escapes its run: {path_value}",
                value,
            )
        )
    path = base_dir / relative
    handle = session.file_path(
        path,
        label=f"QEMU evidence artifact {path_value}",
        max_bytes=max_bytes,
    )
    body = handle.read_bytes() if capture else None
    recorded_size = value.get("size")
    if type(recorded_size) is not int or recorded_size != handle.identity.size:
        return _VerifiedReportArtifact(
            QemuReportValidation(False, f"size mismatch: {path}", value),
            body,
        )
    expected = value.get("sha256")
    if not _is_sha256(expected) or expected != handle.digest():
        return _VerifiedReportArtifact(
            QemuReportValidation(False, f"SHA256 mismatch: {path}", value),
            body,
        )
    return _VerifiedReportArtifact(
        QemuReportValidation(True, "verified", value),
        body,
    )


def _read_regular_text_bounded(
    path: Path,
    *,
    max_bytes: int,
    label: str,
    missing_ok: bool,
) -> str | None:
    """Read a growing runtime log without following links or waiting on a FIFO."""
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        if missing_ok:
            return None
        raise ValueError(f"{label} does not exist: {path}") from None
    except OSError as exc:
        raise ValueError(f"{label} cannot be opened safely: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"{label} is not a regular file: {path}")
        if before.st_size > max_bytes:
            raise ValueError(f"{label} exceeds its {max_bytes}-byte limit")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, max_bytes + 1 - total),
            )
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(f"{label} exceeds its {max_bytes}-byte limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            stat.S_IFMT(before.st_mode),
        ) != (
            after.st_dev,
            after.st_ino,
            stat.S_IFMT(after.st_mode),
        ):
            raise ValueError(f"{label} identity changed while it was read")
    except OSError as exc:
        raise ValueError(f"{label} cannot be read safely: {exc}") from exc
    finally:
        os.close(descriptor)
    try:
        return b"".join(chunks).decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ValueError(f"{label} is not strict UTF-8") from exc


def _inventory_regular_tree(
    root: Path,
    *,
    excluded: set[Path],
    max_files: int = 4096,
    max_entries: int = 4096,
    max_depth: int = 64,
) -> _RunTreeInventory:
    if max_files < 0 or max_entries < 0 or max_depth < 0:
        raise ValueError("QEMU run inventory budgets must be non-negative")
    root_descriptor = _open_absolute_directory_nofollow(root)
    files: dict[Path, ArtifactIdentity] = {}
    directories: dict[Path, tuple[int, int, int, int, int, int, int]] = {}
    entries_seen = 0

    def walk(directory: int, relative: Path, depth: int) -> None:
        nonlocal entries_seen
        if depth > max_depth:
            raise ArtifactVerificationError(
                f"QEMU run evidence exceeds directory depth {max_depth}"
            )
        directory_identity = ArtifactIdentity.from_stat(os.fstat(directory))
        directories[relative] = _stable_directory_binding(directory_identity)
        names: list[str] = []
        try:
            with os.scandir(directory) as iterator:
                for entry in iterator:
                    entries_seen += 1
                    if entries_seen > max_entries:
                        raise ArtifactVerificationError(
                            f"QEMU run evidence exceeds {max_entries} total entries"
                        )
                    name = entry.name
                    if name in {"", ".", ".."} or "/" in name or "\\" in name:
                        raise ArtifactVerificationError(
                            f"QEMU run evidence has a non-canonical name: {name!r}"
                        )
                    names.append(name)
            names.sort()
        except OSError as exc:
            raise ArtifactVerificationError(
                f"QEMU run evidence directory cannot be enumerated: {exc}"
            ) from exc
        for name in names:
            child_relative = Path(name) if relative == Path(".") else relative / name
            if child_relative in excluded:
                continue
            probe = -1
            try:
                probe = os.open(
                    name,
                    os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=directory,
                )
                identity = ArtifactIdentity.from_stat(os.fstat(probe))
                if stat.S_ISLNK(identity.mode):
                    raise ArtifactVerificationError(
                        f"QEMU run evidence contains a symlink: {child_relative}"
                    )
                if stat.S_ISDIR(identity.mode):
                    child = os.open(
                        name,
                        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=directory,
                    )
                    try:
                        if ArtifactIdentity.from_stat(os.fstat(child)) != identity:
                            raise ArtifactVerificationError(
                                "QEMU run evidence directory changed while it "
                                f"was opened: {child_relative}"
                            )
                        walk(child, child_relative, depth + 1)
                    finally:
                        os.close(child)
                elif stat.S_ISREG(identity.mode):
                    files[child_relative] = identity
                    if len(files) > max_files:
                        raise ArtifactVerificationError(
                            f"QEMU run evidence exceeds {max_files} files"
                        )
                else:
                    raise ArtifactVerificationError(
                        f"QEMU run evidence contains a non-regular entry: {child_relative}"
                    )
            except OSError as exc:
                raise ArtifactVerificationError(
                    f"QEMU run evidence changed during inventory: {child_relative}: {exc}"
                ) from exc
            finally:
                if probe >= 0:
                    os.close(probe)

    try:
        walk(root_descriptor, Path("."), 0)
    finally:
        os.close(root_descriptor)
    return _RunTreeInventory(files=files, directories=directories)


def _open_absolute_directory_nofollow(path: Path) -> int:
    absolute = Path(os.path.abspath(path))
    descriptor = os.open(
        "/",
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        for component in absolute.parts[1:]:
            child = os.open(
                component,
                os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _stable_directory_binding(
    identity: ArtifactIdentity,
) -> tuple[int, int, int, int, int, int, int]:
    return (
        identity.dev,
        identity.ino,
        identity.mode,
        identity.uid,
        identity.gid,
        identity.nlink,
        identity.rdev,
    )


def _stable_parent_stat(
    info: os.stat_result,
) -> tuple[int, int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        stat.S_IFMT(info.st_mode),
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_rdev,
    )


def _assert_same_run_inventory(
    opening: _RunTreeInventory,
    closing: _RunTreeInventory,
    *,
    label: str,
) -> None:
    if opening.files != closing.files or opening.directories != closing.directories:
        raise ArtifactVerificationError(label)


def _combine_failures(
    existing: Exception | None,
    cleanup: Exception,
    stage: str,
) -> Exception:
    if existing is None:
        return ValueError(f"{stage} failed: {cleanup}")
    return ValueError(f"{existing}; additionally, {stage} failed: {cleanup}")


def _read_growing_held_text(
    descriptor: int,
    *,
    expected_device: int | None,
    expected_inode: int | None,
    max_bytes: int,
    label: str,
) -> str:
    try:
        reader = os.open(
            f"/proc/{os.getpid()}/fd/{descriptor}",
            os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK,
        )
    except OSError as exc:
        raise ValueError(f"{label} held inode cannot be opened: {exc}") from exc
    try:
        before = os.fstat(reader)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_dev != expected_device
            or before.st_ino != expected_inode
        ):
            raise ValueError(f"{label} held inode identity changed")
        if before.st_size > max_bytes:
            raise ValueError(f"{label} exceeds its {max_bytes}-byte limit")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(
                reader,
                min(1024 * 1024, max_bytes + 1 - total),
            )
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(f"{label} exceeds its {max_bytes}-byte limit")
            chunks.append(chunk)
        after = os.fstat(reader)
        held_after = os.fstat(descriptor)
        if (
            after.st_dev,
            after.st_ino,
            stat.S_IFMT(after.st_mode),
        ) != (
            before.st_dev,
            before.st_ino,
            stat.S_IFMT(before.st_mode),
        ) or (
            held_after.st_dev,
            held_after.st_ino,
            stat.S_IFMT(held_after.st_mode),
        ) != (
            before.st_dev,
            before.st_ino,
            stat.S_IFMT(before.st_mode),
        ):
            raise ValueError(f"{label} identity changed while it was read")
    except OSError as exc:
        raise ValueError(f"{label} cannot be read safely: {exc}") from exc
    finally:
        os.close(reader)
    try:
        return b"".join(chunks).decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ValueError(f"{label} is not strict UTF-8") from exc


def _revalidate_consumed_artifact(
    opening_session: ArtifactVerificationSession,
    opening_handle: ArtifactHandle,
    path: Path,
    *,
    expected_digest: str,
    label: str,
) -> None:
    """Close an execution witness while allowing legitimate sibling outputs.

    A VM writes serial, screenshots and reports beside its input ISO, which changes
    parent-directory timestamps.  The generic read-only session deliberately treats
    that as drift.  For an execution input, re-hash the exact held inode instead,
    then open the final pathname through a fresh descriptor-relative session and
    require the same complete leaf identity and digest.
    """
    held_identity, held_digest = _digest_held_descriptor(
        opening_handle.fileno,
        max_bytes=opening_session.limits.max_file_bytes,
        label=f"{label} held descriptor",
    )
    if held_identity != opening_handle.identity or held_digest != expected_digest:
        raise ArtifactVerificationError(f"{label} held inode changed while it was consumed")
    closing_session = ArtifactVerificationSession(
        path.parent,
        label=f"{label} closing path",
    )
    try:
        closing_handle = closing_session.file_path(
            path,
            label=f"{label} closing path",
            max_bytes=opening_session.limits.max_file_bytes,
        )
        if (
            closing_handle.identity != opening_handle.identity
            or closing_handle.digest() != expected_digest
        ):
            raise ArtifactVerificationError(
                f"{label} path resolves to different bytes after consumption"
            )
        closing_session.seal()
    finally:
        closing_session.close()


def _digest_held_descriptor(
    descriptor: int,
    *,
    max_bytes: int,
    label: str,
) -> tuple[ArtifactIdentity, str]:
    try:
        before = ArtifactIdentity.from_stat(os.fstat(descriptor))
        if not stat.S_ISREG(before.mode):
            raise ArtifactVerificationError(f"{label} is not a regular file")
        if before.size > max_bytes:
            raise ArtifactVerificationError(f"{label} exceeds its {max_bytes}-byte limit")
        reader = os.open(
            f"/proc/{os.getpid()}/fd/{descriptor}",
            os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK,
        )
    except OSError as exc:
        raise ArtifactVerificationError(
            f"{label} cannot be reopened from its held inode: {exc}"
        ) from exc
    try:
        if ArtifactIdentity.from_stat(os.fstat(reader)) != before:
            raise ArtifactVerificationError(f"{label} changed while its closing reader was opened")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(reader, min(1024 * 1024, max_bytes + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ArtifactVerificationError(f"{label} exceeds its {max_bytes}-byte limit")
            digest.update(chunk)
        after = ArtifactIdentity.from_stat(os.fstat(reader))
        held_after = ArtifactIdentity.from_stat(os.fstat(descriptor))
    except OSError as exc:
        raise ArtifactVerificationError(f"{label} cannot be re-hashed safely: {exc}") from exc
    finally:
        os.close(reader)
    if before != after or before != held_after or total != before.size:
        raise ArtifactVerificationError(f"{label} changed while it was re-hashed")
    return before, digest.hexdigest()


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _is_proc_fd_path(value: object) -> bool:
    return (
        isinstance(value, str) and re.fullmatch(r"/proc/[1-9][0-9]*/fd/[0-9]+", value) is not None
    )


def _argv_option(argv: list[str], flag: str) -> str | None:
    indexes = [index for index, value in enumerate(argv) if value == flag]
    if len(indexes) != 1 or indexes[0] + 1 >= len(argv):
        return None
    return argv[indexes[0] + 1]


def _safe_artifact_name(value: object) -> bool:
    if not isinstance(value, str) or not value or value in {".", ".."}:
        return False
    if (
        "\x00" in value
        or "\\" in value
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        return False
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeError:
        return False
    path = Path(value)
    return not path.is_absolute() and path.name == value


PrebuildVmService = QemuLabService
