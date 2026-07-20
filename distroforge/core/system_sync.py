from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .chroot import ChrootService
from .command import CommandRunner, CommandSpec
from .fsops import FileSystemOps


@dataclass
class SystemSyncOptions:
    enabled: bool = False
    strategy: str = "full"
    fallback: bool = True
    run_during_build: bool = True
    post_install_tool: bool = True
    hold_packages: list[str] = field(default_factory=list)

    def summary(self) -> str:
        if not self.enabled:
            return "disabled"
        flags = [self.strategy]
        if self.fallback:
            flags.append("fallback")
        if self.run_during_build:
            flags.append("build")
        if self.post_install_tool:
            flags.append("post-install-tool")
        if self.hold_packages:
            flags.append(f"hold={len(self.hold_packages)}")
        return ", ".join(flags)


class SystemSyncService:
    def __init__(
        self,
        runner: CommandRunner,
        root: Path,
        options: SystemSyncOptions,
        use_sudo: bool = True,
    ) -> None:
        self.runner = runner
        self.root = root
        self.options = options
        self.use_sudo = use_sudo
        self.fs = FileSystemOps(runner, use_sudo)

    def run(self) -> None:
        if not self.options.enabled:
            self.runner.run(
                CommandSpec(
                    argv=("system-sync-skip", str(self.root)),
                    description="System sync phase disabled",
                )
            )
            return
        if self.options.post_install_tool:
            self._install_post_install_tool()
        if not self.options.run_during_build:
            self.runner.run(
                CommandSpec(
                    argv=("system-sync-build-skip", str(self.root)),
                    description="System sync reserved for post-install tool",
                )
            )
            return
        chroot = ChrootService(self.runner, self.root, self.use_sudo)
        chroot.run("apt-get", "update")
        chroot.run("/bin/bash", "-lc", self._sync_command())

    def _sync_command(self) -> str:
        action = self._action()
        hold = ""
        if self.options.hold_packages:
            hold = "apt-mark hold " + " ".join(_shell_quote(item) for item in self.options.hold_packages) + "; "
        if not self.options.fallback:
            return f"set -e; apt-get -s {action}; {hold}apt-get -y {action}"
        return (
            f"set -e; apt-get -s {action}; {hold}"
            f"if ! apt-get -y {action}; then "
            "apt-get -f -y install; "
            "dpkg --configure -a; "
            "apt-get -y --with-new-pkgs upgrade; "
            "apt-get -y autoremove; "
            "fi"
        )

    def _install_post_install_tool(self) -> None:
        target = self.root / "usr" / "local" / "sbin" / "distroforge-system-sync"
        self.fs.write_text(
            target,
            self._script(),
            "Install post-install system sync helper",
            mode="0755",
        )

    def _script(self) -> str:
        return "\n".join(
            [
                "#!/bin/sh",
                "set -eu",
                "if [ \"$(id -u)\" -ne 0 ]; then",
                "  exec sudo \"$0\" \"$@\"",
                "fi",
                "apt-get update",
                f"apt-get -s {self._action()}",
                self._post_install_action(),
                "",
            ]
        )

    def _post_install_action(self) -> str:
        action = self._action()
        hold = ""
        if self.options.hold_packages:
            hold = "apt-mark hold " + " ".join(_shell_quote(item) for item in self.options.hold_packages) + "\n"
        if not self.options.fallback:
            return f"{hold}apt-get -y {action}"
        return (
            f"{hold}"
            f"apt-get -y {action} || "
            "(apt-get -f -y install && dpkg --configure -a && "
            "apt-get -y --with-new-pkgs upgrade && apt-get -y autoremove)"
        )

    def _action(self) -> str:
        if self.options.strategy == "safe":
            return "--with-new-pkgs upgrade"
        return "full-upgrade"


def _shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"
