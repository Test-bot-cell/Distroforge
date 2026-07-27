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

    def spec(self) -> str:
        """The ``--snap`` / definition text form, the inverse of :meth:`parse`."""
        parts = [self.name]
        if self.channel != "stable" or self.classic:
            parts.append(self.channel)
        if self.classic:
            parts.append("classic")
        return ":".join(parts)


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
        # `snap install` inside the chroot used to talk to the HOST snapd: chroot.py
        # bind-mounted the host /run for the whole phase, so /run/snapd.socket was
        # the build machine's, and policy-rc.d exit 101 keeps the chroot's own snapd
        # from ever starting. The snaps landed in the build host's /var/lib/snapd and
        # /snap, as root, with no polkit barrier -- while the ISO shipped without
        # them. The chroot now gets a private tmpfs /run instead, so that socket is
        # out of reach and the command would simply fail. The phase stays refused
        # regardless: a chroot has no snapd of its own to install into, and failing
        # mid-build says nothing a maintainer can act on. Planning still records the
        # intent and SeedService still writes them to the manifest.
        if not self.runner.dry_run:
            names = ", ".join(spec.name for spec in self.options.specs)
            raise ValueError(
                f"Cannot install snaps ({names}) into the target root: a chroot "
                "shares the host snapd socket, so this would install them on the "
                "build machine instead of the image. Seed them from the host with "
                "`snap download` into <root>/var/lib/snapd/seed/, or drop --snap."
            )
        chroot = ChrootService(self.runner, self.root, self.use_sudo)
        chroot.run("apt-get", "-y", "install", "snapd")
        for snap in self.options.specs:
            argv = ["snap", "install", snap.name, f"--channel={snap.channel}"]
            if snap.classic:
                argv.append("--classic")
            chroot.run(*argv)

