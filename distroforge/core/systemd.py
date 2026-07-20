from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .chroot import ChrootService
from .command import CommandRunner


@dataclass
class SystemdOptions:
    enable: list[str] = field(default_factory=list)
    disable: list[str] = field(default_factory=list)
    mask: list[str] = field(default_factory=list)


class SystemdService:
    def __init__(self, runner: CommandRunner, root: Path, options: SystemdOptions, use_sudo: bool = True) -> None:
        self.runner = runner
        self.root = root
        self.options = options
        self.use_sudo = use_sudo

    def apply(self) -> None:
        chroot = ChrootService(self.runner, self.root, self.use_sudo)
        for service in self.options.enable:
            chroot.run("systemctl", "enable", service)
        for service in self.options.disable:
            chroot.run("systemctl", "disable", service)
        for service in self.options.mask:
            chroot.run("systemctl", "mask", service)

