from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .chroot import ChrootService
from .command import CommandRunner
from .fsops import FileSystemOps


@dataclass
class OemOptions:
    enabled: bool = False
    first_boot_reset: bool = True


class OemService:
    def __init__(
        self,
        runner: CommandRunner,
        root: Path,
        options: OemOptions,
        use_sudo: bool = True,
    ) -> None:
        self.runner = runner
        self.root = root
        self.options = options
        self.use_sudo = use_sudo
        self.fs = FileSystemOps(runner, use_sudo)

    def apply(self) -> None:
        if not self.options.enabled:
            return
        ChrootService(self.runner, self.root, self.use_sudo).run("apt-get", "-y", "install", "oem-config")
        if self.options.first_boot_reset:
            marker = self.root / "etc" / "distroforge-oem-reset"
            self.fs.write_text(marker, "reset-on-first-boot=true\n", "Write OEM first boot reset marker")
