from __future__ import annotations

import json
from dataclasses import dataclass

from .command import CommandRunner, CommandSpec, sudo
from .doctor import apt_install_command


@dataclass(frozen=True)
class IsoToolchainItem:
    binary: str
    available: bool
    package: str
    reason: str

    def to_dict(self) -> dict[str, object]:
        return self.__dict__


@dataclass(frozen=True)
class IsoToolchainReport:
    status: str
    items: tuple[IsoToolchainItem, ...]
    packages: tuple[str, ...]
    install_command: str
    installed: bool = False

    @property
    def blocked(self) -> bool:
        return self.status == "blocked"

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "blocked": self.blocked,
            "items": [item.to_dict() for item in self.items],
            "packages": list(self.packages),
            "install_command": self.install_command,
            "installed": self.installed,
        }

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def render_text(self) -> str:
        lines = ["ISO toolchain", f"Status: {self.status.upper()}", ""]
        lines.extend(f"{'ok' if item.available else 'missing':8} {item.binary:18} {item.reason}" for item in self.items)
        lines.extend(["", "Install command:", self.install_command or "none"])
        if self.installed:
            lines.append("Install requested: yes")
        return "\n".join(lines)


def check_iso_toolchain(*, install: bool = False, use_sudo: bool = True) -> IsoToolchainReport:
    runner = CommandRunner(dry_run=not install)
    items = _items(runner)
    packages = _packages(items)
    if install and packages:
        _install_packages(runner, packages, use_sudo=use_sudo)
        items = _items(CommandRunner(dry_run=True))
        packages = _packages(items)
    status = "ready" if not packages else "blocked"
    return IsoToolchainReport(status, tuple(items), tuple(packages), apt_install_command(packages), installed=install)


def _items(runner: CommandRunner) -> list[IsoToolchainItem]:
    definitions = (
        ("xorriso", "xorriso", "ISO image creation and inspection"),
        ("mksquashfs", "squashfs-tools", "live filesystem compression"),
        ("unsquashfs", "squashfs-tools", "live filesystem extraction"),
        ("chroot", "coreutils", "target filesystem operations"),
        ("apt-get", "apt", "package installation in the target"),
    )
    items = [IsoToolchainItem(binary, runner.has_binary(binary), package, reason) for binary, package, reason in definitions]
    bootstrap_available = runner.has_binary("mmdebstrap") or runner.has_binary("debootstrap")
    items.append(IsoToolchainItem("mmdebstrap-or-debootstrap", bootstrap_available, "mmdebstrap", "bootstrap root filesystem creation"))
    return items


def _packages(items: list[IsoToolchainItem]) -> list[str]:
    return sorted({item.package for item in items if not item.available})


def _install_packages(runner: CommandRunner, packages: list[str], *, use_sudo: bool) -> None:
    runner.run(CommandSpec(argv=sudo(("apt-get", "update"), use_sudo), needs_root=use_sudo, description="Update apt package index before ISO toolchain install"))
    runner.run(CommandSpec(argv=sudo(("apt-get", "install", "-y", *packages), use_sudo), needs_root=use_sudo, description="Install ISO build toolchain"))
