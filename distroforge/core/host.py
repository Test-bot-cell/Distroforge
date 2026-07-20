from __future__ import annotations

import platform
from dataclasses import dataclass

from .command import CommandRunner


@dataclass(frozen=True)
class HostCapability:
    name: str
    available: bool
    detail: str


def detect_host_capabilities(runner: CommandRunner) -> list[HostCapability]:
    system = platform.system()
    linux = system == "Linux"
    return [
        HostCapability("host", True, system),
        HostCapability("real-build", linux, "requires Linux mount/chroot/squashfs tooling"),
        HostCapability("kvm", linux and runner.has_binary("qemu-system-x86_64"), "QEMU/KVM preview"),
        HostCapability("xorriso", runner.has_binary("xorriso"), "ISO rebuild"),
        HostCapability("squashfs-tools", runner.has_binary("mksquashfs"), "live filesystem repack"),
        HostCapability("chroot-terminal", linux, "interactive PTY chroot terminal"),
        HostCapability(
            "nspawn-terminal",
            linux and runner.has_binary("systemd-nspawn"),
            "optional stronger maintainer shell via systemd-container",
        ),
    ]
