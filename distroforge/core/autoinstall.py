from __future__ import annotations

from dataclasses import dataclass, field

from .command import CommandRunner, CommandSpec
from .fsops import FileSystemOps
from .project import Project


@dataclass
class AutoinstallOptions:
    enabled: bool = False
    username: str = "ubuntu"
    realname: str = "Ubuntu User"
    hostname: str | None = None
    password_hash: str = "$y$j9T$replace-me$replace-me"
    locale: str | None = None
    keyboard: str | None = None
    timezone: str | None = None
    drivers_install: bool = False
    packages: list[str] = field(default_factory=list)
    late_commands: list[str] = field(default_factory=list)


class AutoinstallService:
    def __init__(self, runner: CommandRunner, project: Project, options: AutoinstallOptions, use_sudo: bool = True) -> None:
        self.runner = runner
        self.project = project
        self.options = options
        self.use_sudo = use_sudo
        self.iso = FileSystemOps(runner, use_sudo)

    def write(self) -> None:
        if not self.options.enabled:
            self.runner.run(
                CommandSpec(
                    argv=("autoinstall-skip", str(self.project.iso_root)),
                    description="Autoinstall disabled",
                )
            )
            return
        target = self.project.iso_root / "autoinstall.yaml"
        self.iso.write_text(target, self.render(), "Write Subiquity autoinstall config")

    def render(self) -> str:
        hostname = self.options.hostname or self.project.customization.hostname or self.project.name
        locale = self.options.locale or self.project.customization.locale or "en_US.UTF-8"
        keyboard = self.options.keyboard or self.project.customization.keyboard_layout or "us"
        timezone = self.options.timezone or self.project.customization.timezone or "UTC"
        lines = [
            "#cloud-config",
            "autoinstall:",
            "  version: 1",
            f"  locale: {locale}",
            "  keyboard:",
            f"    layout: {keyboard}",
            f"  timezone: {timezone}",
            "  identity:",
            f"    hostname: {hostname}",
            f"    username: {self.options.username}",
            f"    realname: {self.options.realname}",
            f"    password: '{self.options.password_hash}'",
            "  storage:",
            "    layout:",
            "      name: direct",
        ]
        if self.options.drivers_install:
            lines.extend(["  drivers:", "    install: true"])
        if self.options.packages:
            lines.append("  packages:")
            lines.extend(f"    - {package}" for package in self.options.packages)
        if self.options.late_commands:
            lines.append("  late-commands:")
            lines.extend(f"    - {command}" for command in self.options.late_commands)
        return "\n".join(lines) + "\n"
