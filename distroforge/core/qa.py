from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .command import CommandRunner, CommandSpec
from .qemu_invocation import QemuInvocation


@dataclass(frozen=True)
class QemuScenario:
    key: str
    label: str
    firmware: str = "bios"
    memory_mb: int = 2048
    install_disk: bool = False


SCENARIOS = {
    "live-bios": QemuScenario("live-bios", "Live boot BIOS", "bios", 2048, False),
    "live-uefi": QemuScenario("live-uefi", "Live boot UEFI", "uefi", 2048, False),
    "install-bios": QemuScenario("install-bios", "Installer BIOS", "bios", 4096, True),
    "install-uefi": QemuScenario("install-uefi", "Installer UEFI", "uefi", 4096, True),
    "lowram-live": QemuScenario("lowram-live", "Low RAM live boot", "bios", 1024, False),
}


@dataclass
class QaOptions:
    scenarios: list[str] = field(default_factory=list)


class QaMatrixService:
    def __init__(self, runner: CommandRunner, iso_path: Path, workdir: Path, options: QaOptions) -> None:
        self.runner = runner
        self.iso_path = iso_path
        self.workdir = workdir
        self.options = options

    def run(self) -> None:
        for key in self.options.scenarios:
            scenario = SCENARIOS[key]
            disk: Path | None = None
            if scenario.install_disk:
                disk = self.workdir / f"qa-{scenario.key}.qcow2"
                self.runner.run(
                    CommandSpec(
                        argv=("qemu-img", "create", "-f", "qcow2", str(disk), "20G"),
                        description=f"Create QA disk for {scenario.label}",
                    )
                )
            argv = QemuInvocation(
                iso=self.iso_path,
                memory_mb=scenario.memory_mb,
                serial="stdio",
                display="none",
                firmware=scenario.firmware,
                legacy_bios=True,
                disk=disk,
            ).argv()
            self.runner.run(
                CommandSpec(
                    argv=argv,
                    description=f"QA QEMU scenario: {scenario.label}",
                )
            )

