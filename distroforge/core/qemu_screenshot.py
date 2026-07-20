from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .command import CommandRunner, CommandSpec
from .qemu_invocation import QemuInvocation
from .qmp import QmpControl, stop_by_pidfile


@dataclass
class QemuScreenshotOptions:
    enabled: bool = False
    timeout_seconds: int = 60
    filename: str = "qemu-boot.ppm"
    qmp_socket: str = "qemu-screenshot.qmp"
    pid_file: str = "qemu-screenshot.pid"


class QemuScreenshotService:
    def __init__(
        self,
        runner: CommandRunner,
        iso_path: Path,
        output_dir: Path,
        options: QemuScreenshotOptions,
    ) -> None:
        self.runner = runner
        self.iso_path = iso_path
        self.output_dir = output_dir
        self.options = options
        self._qmp = QmpControl(runner, options.timeout_seconds)

    def run(self) -> None:
        if not self.options.enabled:
            return
        target = self.output_dir / self.options.filename
        qmp_socket = self.output_dir / self.options.qmp_socket
        pid_file = self.output_dir / self.options.pid_file
        try:
            self.runner.run(
                CommandSpec(
                    argv=QemuInvocation(
                        iso=self.iso_path,
                        memory_mb=2048,
                        display="none",
                        qmp_socket=qmp_socket,
                        pid_file=pid_file,
                        daemonize=True,
                    ).argv(),
                    description=f"Boot ISO for screenshot capture into {target}",
                )
            )
            self._qmp.command("screendump", qmp_socket, {"filename": str(target)})
            self._qmp.command("quit", qmp_socket)
        finally:
            stop_by_pidfile(self.runner, pid_file, "Stop QEMU screenshot VM")
