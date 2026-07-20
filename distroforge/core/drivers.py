from __future__ import annotations

from dataclasses import dataclass

from .chroot import ChrootService
from .command import CommandRunner


@dataclass
class DriverOptions:
    auto: bool = False
    install_common: bool = True


class DriverService:
    def __init__(self, runner: CommandRunner, root, options: DriverOptions, use_sudo: bool = True) -> None:
        self.runner = runner
        self.root = root
        self.options = options
        self.use_sudo = use_sudo

    def install(self) -> None:
        if not self.options.auto:
            return
        chroot = ChrootService(self.runner, self.root, self.use_sudo)
        if self.options.install_common:
            chroot.run("apt-get", "-y", "install", "ubuntu-drivers-common")
        chroot.run("ubuntu-drivers", "install")

