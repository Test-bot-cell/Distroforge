from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .command import CommandRunner, CommandSpec
from .integrity import IntegrityService
from .qemu_invocation import QemuInvocation

# QEMU `-display` value for each user-facing preview display mode. SPICE maps to
# `spice-app`, which starts a SPICE server and opens the bundled viewer; it needs
# `virt-viewer` on the host. `none` is the headless, QMP-driven mode.
_DISPLAY_ARGS = {"gtk": "gtk", "spice": "spice-app", "none": "none"}


@dataclass
class QemuPreviewOptions:
    display: str = "gtk"
    memory_mb: int = 4096
    cpus: int = 2
    network: bool = False
    firmware: str = "bios"
    secure_boot: bool = False
    enable_kvm: bool = True
    serial_log: str = "preview-serial.log"
    qmp_socket: str = "preview.qmp"
    pid_file: str = "preview.pid"
    transcript_name: str = "preview-session.json"
    ovmf_code: str = "/usr/share/OVMF/OVMF_CODE.fd"
    ovmf_vars: str = "/usr/share/OVMF/OVMF_VARS.fd"

    def display_arg(self) -> str:
        return _DISPLAY_ARGS.get(self.display, self.display)


@dataclass(frozen=True)
class QemuPreviewArtifacts:
    qmp_socket: Path
    pid_file: Path
    serial_log: Path
    transcript: Path
    ovmf_vars: Path


@dataclass(frozen=True)
class QemuPreviewReport:
    iso: Path
    display: str
    firmware: str
    secure_boot: bool
    network: bool
    memory_mb: int
    cpus: int
    enable_kvm: bool
    dry_run: bool
    argv: tuple[str, ...]
    artifacts: QemuPreviewArtifacts

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": "distroforge.qemu-preview.v1",
            "iso": str(self.iso),
            "display": self.display,
            "firmware": self.firmware,
            "secure_boot": self.secure_boot,
            "network": self.network,
            "memory_mb": self.memory_mb,
            "cpus": self.cpus,
            "enable_kvm": self.enable_kvm,
            "dry_run": self.dry_run,
            "command": list(self.argv),
            "artifacts": {
                "qmp_socket": str(self.artifacts.qmp_socket),
                "pid_file": str(self.artifacts.pid_file),
                "serial_log": str(self.artifacts.serial_log),
                "transcript": str(self.artifacts.transcript),
            },
        }

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def render_text(self) -> str:
        mode = "Planned (dry-run)" if self.dry_run else "Launched"
        net = "online" if self.network else "offline"
        lines = [
            "Interactive ISO preview",
            f"ISO: {self.iso}",
            f"Status: {mode}",
            f"Display: {self.display}",
            f"Firmware: {self.firmware}, secure-boot={self.secure_boot}",
            f"Resources: {self.memory_mb}M, {self.cpus} cpu, kvm={self.enable_kvm}, {net}",
            "",
            "Command:",
            "  " + " ".join(self.argv),
            "",
            "Drive and trace handles:",
            f"- QMP socket: {self.artifacts.qmp_socket}",
            f"- PID file: {self.artifacts.pid_file}",
            f"- Serial log: {self.artifacts.serial_log}",
            f"- Session transcript: {self.artifacts.transcript}",
        ]
        return "\n".join(lines)


class QemuPreviewService:
    """Interactive ISO preview at lab standard.

    One auditable :class:`QemuInvocation` describes the machine; a QMP socket and
    pidfile keep the session drivable and stoppable; a JSON session transcript and
    integrity manifest keep it traceable. The service launches and exposes the
    session — driving it through QMP is the declarative interaction plan's job.
    """

    def __init__(
        self,
        runner: CommandRunner,
        iso_path: Path,
        workdir: Path,
        output_dir: Path,
        options: QemuPreviewOptions | None = None,
    ) -> None:
        self.runner = runner
        self.iso_path = iso_path
        self.workdir = workdir / "preview"
        self.output_dir = output_dir
        self.options = options or QemuPreviewOptions()

    def run(self) -> QemuPreviewReport:
        artifacts = self._artifacts()
        self.runner.run(
            CommandSpec(
                argv=("mkdir", "-p", str(self.workdir), str(self.output_dir)),
                description="Prepare interactive preview artifact directories",
            )
        )
        self._prepare_firmware(artifacts)
        enable_kvm = self.options.enable_kvm and (
            Path("/dev/kvm").exists() or self.runner.has_binary("kvm")
        )
        argv = QemuInvocation(
            iso=self.iso_path,
            memory_mb=self.options.memory_mb,
            cpus=self.options.cpus,
            serial=f"file:{artifacts.serial_log}",
            display=self.options.display_arg(),
            qmp_socket=artifacts.qmp_socket,
            pid_file=artifacts.pid_file,
            daemonize=True,
            firmware=self.options.firmware,
            ovmf_code=self.options.ovmf_code,
            ovmf_vars=str(artifacts.ovmf_vars) if self.options.firmware == "uefi" else None,
            secure_boot=self.options.secure_boot,
            network="user" if self.options.network else "none",
            enable_kvm=enable_kvm,
        ).argv()
        self.runner.run(
            CommandSpec(
                argv=argv,
                description="Launch interactive ISO preview VM under QMP control",
            )
        )
        self._write_transcript(artifacts, argv, enable_kvm)
        IntegrityService(self.runner).write_manifest(
            self.output_dir / "PREVIEW-INTEGRITY",
            {
                "iso": self.iso_path.name,
                "display": self.options.display,
                "serial_log": self.options.serial_log,
                "transcript": self.options.transcript_name,
                "qmp_socket": str(artifacts.qmp_socket),
                "pid_file": str(artifacts.pid_file),
            },
        )
        return QemuPreviewReport(
            iso=self.iso_path,
            display=self.options.display,
            firmware=self.options.firmware,
            secure_boot=self.options.secure_boot,
            network=self.options.network,
            memory_mb=self.options.memory_mb,
            cpus=self.options.cpus,
            enable_kvm=enable_kvm,
            dry_run=self.runner.dry_run,
            argv=argv,
            artifacts=artifacts,
        )

    def _artifacts(self) -> QemuPreviewArtifacts:
        return QemuPreviewArtifacts(
            qmp_socket=self.workdir / self.options.qmp_socket,
            pid_file=self.workdir / self.options.pid_file,
            serial_log=self.output_dir / self.options.serial_log,
            transcript=self.output_dir / self.options.transcript_name,
            ovmf_vars=self.workdir / "OVMF_VARS.fd",
        )

    def _prepare_firmware(self, artifacts: QemuPreviewArtifacts) -> None:
        if self.options.firmware != "uefi":
            return
        self.runner.run(
            CommandSpec(
                argv=("copy-file", self.options.ovmf_vars, str(artifacts.ovmf_vars)),
                description="Prepare writable OVMF variables store for preview",
            )
        )
        if not self.runner.dry_run:
            shutil.copy2(self.options.ovmf_vars, artifacts.ovmf_vars)

    def _write_transcript(
        self, artifacts: QemuPreviewArtifacts, argv: tuple[str, ...], enable_kvm: bool
    ) -> None:
        payload = {
            "schema": "distroforge.qemu-preview.v1",
            "created_at": datetime.now(UTC).isoformat(),
            "iso": str(self.iso_path),
            "display": self.options.display,
            "firmware": self.options.firmware,
            "secure_boot": self.options.secure_boot,
            "network": self.options.network,
            "memory_mb": self.options.memory_mb,
            "cpus": self.options.cpus,
            "enable_kvm": enable_kvm,
            "command": list(argv),
            "artifacts": {
                "qmp_socket": str(artifacts.qmp_socket),
                "pid_file": str(artifacts.pid_file),
                "serial_log": str(artifacts.serial_log),
                "transcript": str(artifacts.transcript),
            },
        }
        self.runner.run(
            CommandSpec(
                argv=("write-file", str(artifacts.transcript)),
                description="Write interactive preview session transcript",
            )
        )
        if not self.runner.dry_run:
            artifacts.transcript.parent.mkdir(parents=True, exist_ok=True)
            artifacts.transcript.write_text(json.dumps(payload, indent=2), encoding="utf-8")
