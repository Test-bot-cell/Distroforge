from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .chroot import ChrootService
from .command import CommandRunner, CommandSpec


@dataclass
class SanitizeOptions:
    enabled: bool = True
    package_autoremove: bool = True
    apt_cache: bool = True
    apt_lists: bool = False
    logs: bool = True
    shell_history: bool = True
    machine_id: bool = True
    temp_files: bool = True
    ssh_host_keys: bool = False

    def summary(self) -> str:
        enabled = [
            name
            for name, value in [
                ("apt-cache", self.apt_cache),
                ("package-autoremove", self.package_autoremove),
                ("apt-lists", self.apt_lists),
                ("logs", self.logs),
                ("shell-history", self.shell_history),
                ("machine-id", self.machine_id),
                ("temp-files", self.temp_files),
                ("ssh-host-keys", self.ssh_host_keys),
            ]
            if value
        ]
        return ", ".join(enabled) if enabled else "disabled"


class SanitizeService:
    def __init__(
        self,
        runner: CommandRunner,
        root: Path,
        options: SanitizeOptions,
        use_sudo: bool = True,
    ) -> None:
        self.runner = runner
        self.root = root
        self.options = options
        self.use_sudo = use_sudo

    def run(self) -> None:
        if not self.options.enabled:
            self.runner.run(
                CommandSpec(
                    argv=("sanitize-skip", str(self.root)),
                    description="Sanitize disabled",
                )
            )
            return
        chroot = ChrootService(self.runner, self.root, self.use_sudo)
        if self.options.package_autoremove:
            self._guarded_autoremove(chroot)
        if self.options.apt_cache:
            self.runner.run(
                CommandSpec(
                    argv=chroot.command("apt-get", "clean").argv,
                    needs_root=self.use_sudo,
                    description="Clean apt caches",
                ),
                check=False,
            )
            chroot.run(
                "rm",
                "-rf",
                "/var/cache/apt/archives",
            )
            chroot.run("mkdir", "-p", "/var/cache/apt/archives/partial")
        if self.options.apt_lists:
            chroot.run("rm", "-rf", "/var/lib/apt/lists")
            chroot.run("mkdir", "-p", "/var/lib/apt/lists/partial")
        if self.options.logs:
            chroot.run("find", "/var/log", "-type", "f", "-exec", "truncate", "-s", "0", "{}", "+")
            chroot.run(
                "find",
                "/var/log",
                "-maxdepth",
                "1",
                "-type",
                "f",
                "(",
                "-name",
                "*.[0-9]",
                "-o",
                "-name",
                "*.gz",
                "-o",
                "-name",
                "*.old",
                ")",
                "-delete",
            )
        if self.options.shell_history:
            chroot.run("find", "/root", "/home", "-maxdepth", "2", "-type", "f", "-name", ".bash_history", "-delete")
            chroot.run("find", "/root", "/home", "-maxdepth", "2", "-type", "f", "-name", ".zsh_history", "-delete")
        if self.options.machine_id:
            chroot.run("rm", "-f", "/etc/machine-id", "/var/lib/dbus/machine-id")
            chroot.run("touch", "/etc/machine-id")
        if self.options.temp_files:
            chroot.run("find", "/tmp", "/var/tmp", "-mindepth", "1", "-maxdepth", "1", "-exec", "rm", "-rf", "{}", "+")
        if self.options.ssh_host_keys:
            chroot.run("find", "/etc/ssh", "-maxdepth", "1", "-type", "f", "-name", "ssh_host_*", "-delete")

    def _guarded_autoremove(self, chroot: ChrootService) -> None:
        protected = {
            "ubuntu-minimal",
            "ubuntu-standard",
            "systemd",
            "systemd-sysv",
            "sudo",
            "network-manager",
            "casper",
            "live-boot",
            "linux-generic",
            "shim-signed",
            "gdm3",
            "lightdm",
            "sddm",
            "kubuntu-desktop",
            "xubuntu-desktop",
            "lubuntu-desktop",
            "ubuntu-mate-desktop",
            "ubuntu-budgie-desktop",
            "ubuntucinnamon-desktop",
            "ubuntu-unity-desktop",
        }
        protected_prefixes = (
            "linux-image",
            "linux-modules",
            "grub",
            "ubuntu-desktop",
        )
        simulated = self.runner.run(
            CommandSpec(
                argv=chroot.command("apt-get", "-s", "autoremove", "--purge").argv,
                needs_root=self.use_sudo,
                description="Simulate apt autoremove",
            ),
            check=False,
        )
        planned: list[str] = []
        for line in simulated.stdout.splitlines():
            if not line.startswith("Remv "):
                continue
            parts = line.split()
            if len(parts) >= 2:
                planned.append(parts[1])
        if any(
            pkg in protected or pkg.startswith(protected_prefixes)
            for pkg in planned
        ):
            raise RuntimeError(
                "DistroForge refused autoremove: protected package would be removed: "
                + ", ".join(sorted({pkg for pkg in planned if pkg in protected or pkg.startswith(protected_prefixes)}))
            )
        if planned:
            chroot.run("apt-get", "-y", "autoremove", "--purge")
