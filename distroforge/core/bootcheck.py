from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .command import CommandRunner, CommandSpec
from .qemu_invocation import QemuInvocation


@dataclass
class BootCheckOptions:
    enabled: bool = False
    timeout_seconds: int = 180


class BootCheckService:
    def __init__(self, runner: CommandRunner, iso: Path, options: BootCheckOptions) -> None:
        self.runner = runner
        self.iso = iso
        self.options = options

    def run(self) -> None:
        if not self.options.enabled:
            return
        self.runner.run(
            CommandSpec(
                argv=QemuInvocation(
                    iso=self.iso,
                    memory_mb=2048,
                    serial="stdio",
                    display="none",
                    timeout_seconds=self.options.timeout_seconds,
                ).argv(),
                description="Boot smoke test generated ISO",
            )
        )

