from __future__ import annotations

from dataclasses import dataclass, field

from .chroot import ChrootService
from .command import CommandRunner


@dataclass(frozen=True)
class SnapSpec:
    name: str
    channel: str = "stable"
    classic: bool = False

    @classmethod
    def parse(cls, value: str) -> SnapSpec:
        parts = [part.strip() for part in value.split(":") if part.strip()]
        name = parts[0]
        channel = parts[1] if len(parts) > 1 else "stable"
        classic = "classic" in parts[2:] if len(parts) > 2 else False
        return cls(name=name, channel=channel, classic=classic)


@dataclass
class SnapOptions:
    specs: list[SnapSpec] = field(default_factory=list)


class SnapService:
    def __init__(self, runner: CommandRunner, root, options: SnapOptions, use_sudo: bool = True) -> None:
        self.runner = runner
        self.root = root
        self.options = options
        self.use_sudo = use_sudo

    def install(self) -> None:
        if not self.options.specs:
            return
        chroot = ChrootService(self.runner, self.root, self.use_sudo)
        chroot.run("apt-get", "-y", "install", "snapd")
        for snap in self.options.specs:
            argv = ["snap", "install", snap.name, f"--channel={snap.channel}"]
            if snap.classic:
                argv.append("--classic")
            chroot.run(*argv)

