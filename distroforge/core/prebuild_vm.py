from __future__ import annotations

import json
import shutil
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from .command import CommandRunner, CommandSpec
from .integrity import IntegrityService
from .qemu_invocation import QemuInvocation
from .qmp import QmpControl, stop_by_pidfile


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
    success_patterns: list[str] = field(default_factory=lambda: ["login:", "Reached target"])
    qmp_socket: str = "qemu-lab.qmp"
    pid_file: str = "qemu-lab.pid"
    report_name: str = "qemu-lab-report.json"
    ovmf_code: str = "/usr/share/OVMF/OVMF_CODE.fd"
    ovmf_vars: str = "/usr/share/OVMF/OVMF_VARS.fd"

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
    ) -> None:
        self.runner = runner
        self.iso_path = iso_path
        self.workdir = workdir / "prebuild-vm"
        self.output_dir = output_dir
        self.options = options
        self._qmp_control = QmpControl(runner, options.timeout_seconds)

    def run(self) -> None:
        if not self.options.enabled:
            self.runner.run(
                CommandSpec(
                    argv=("prebuild-vm-skip", str(self.iso_path)),
                    description="Prebuild VM lab disabled",
                )
            )
            return
        artifacts = self._artifacts()
        self.runner.run(
            CommandSpec(
                argv=("mkdir", "-p", str(self.workdir), str(self.output_dir)),
                description="Prepare QEMU lab artifact directories",
            )
        )
        self.runner.run(
            CommandSpec(
                argv=("qemu-img", "create", "-f", "qcow2", str(artifacts.disk), self.options.disk_size),
                description="Create QEMU lab disk",
            )
        )
        self._prepare_firmware(artifacts)
        self._prepare_tpm(artifacts)
        try:
            self.runner.run(
                CommandSpec(
                    argv=tuple(self._qemu_argv(artifacts)),
                    description="Run QEMU lab boot with QMP control",
                )
            )
            self._qmp_control.command("query-status", artifacts.qmp_socket)
            self._validate_serial_log()
            if self.options.screenshot:
                self._qmp_control.command("screendump", artifacts.qmp_socket, {"filename": str(artifacts.screenshot)})
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
        finally:
            stop_by_pidfile(self.runner, artifacts.pid_file, "Stop QEMU lab VM")
            self._stop_tpm(artifacts)
        self._write_report(artifacts)
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

    def _artifacts(self) -> QemuLabArtifacts:
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
                ovmf_code=self.options.ovmf_code,
                ovmf_vars=str(artifacts.ovmf_vars),
                secure_boot=self.options.secure_boot,
                tpm_socket=artifacts.tpm_socket if self.options.tpm else None,
                network="user" if self.options.network else "none",
            ).argv()
        )

    def _prepare_firmware(self, artifacts: QemuLabArtifacts) -> None:
        if self.options.firmware != "uefi":
            return
        self.runner.run(
            CommandSpec(
                argv=("copy-file", self.options.ovmf_vars, str(artifacts.ovmf_vars)),
                description="Prepare writable OVMF variables store",
            )
        )
        if not self.runner.dry_run:
            shutil.copy2(self.options.ovmf_vars, artifacts.ovmf_vars)

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

    def _validate_serial_log(self) -> None:
        serial = self.output_dir / self.options.serial_log
        patterns = self.options.success_patterns
        pattern_text = "|".join(patterns) if patterns else "<any>"
        self.runner.run(
            CommandSpec(
                argv=("prebuild-vm-assert-log", str(serial), pattern_text),
                description="Validate QEMU lab serial log success markers",
            )
        )
        if self.runner.dry_run or not patterns:
            return
        deadline = time.monotonic() + self.options.timeout_seconds
        while not serial.exists() and time.monotonic() <= deadline:
            time.sleep(0.2)
        if not serial.exists():
            raise ValueError(f"QEMU lab serial log does not exist: {serial}")
        while time.monotonic() <= deadline:
            text = serial.read_text(encoding="utf-8", errors="replace")
            if any(pattern in text for pattern in patterns):
                return
            time.sleep(0.5)
        raise ValueError(f"QEMU lab did not emit expected serial marker(s): {', '.join(patterns)}")

    def _write_report(self, artifacts: QemuLabArtifacts) -> None:
        payload = {
            "schema": "distroforge.qemu-lab.v1",
            "created_at": datetime.now(UTC).isoformat(),
            "iso": str(self.iso_path),
            "profile": self.options.profile,
            "firmware": self.options.firmware,
            "secure_boot": self.options.secure_boot,
            "tpm": self.options.tpm,
            "network": self.options.network,
            "memory_mb": self.options.memory_mb,
            "cpus": self.options.cpus,
            "disk_size": self.options.disk_size,
            "timeout_seconds": self.options.timeout_seconds,
            "artifacts": {
                "disk": str(artifacts.disk),
                "qmp_socket": str(artifacts.qmp_socket),
                "pid_file": str(artifacts.pid_file),
                "serial_log": str(artifacts.serial_log),
                "screenshot": str(artifacts.screenshot) if self.options.screenshot else None,
                "report": str(artifacts.report),
            },
            "success_patterns": list(self.options.success_patterns),
        }
        self.runner.run(
            CommandSpec(
                argv=("write-file", str(artifacts.report)),
                description="Write QEMU lab JSON report",
            )
        )
        if not self.runner.dry_run:
            artifacts.report.parent.mkdir(parents=True, exist_ok=True)
            artifacts.report.write_text(json.dumps(payload, indent=2), encoding="utf-8")


PrebuildVmService = QemuLabService
