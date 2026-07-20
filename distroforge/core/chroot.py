from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .command import CommandRunner, CommandSpec, sudo
from .fsops import FileSystemOps

ChrootBackend = Literal["chroot", "nspawn", "auto"]

BIND_MOUNTS = (
    ("/dev", "dev"),
    ("/dev/pts", "dev/pts"),
    ("/proc", "proc"),
    ("/sys", "sys"),
    ("/run", "run"),
)

POLICY_RC_D = "usr/sbin/policy-rc.d"
_POLICY_RC_D_BODY = "#!/bin/sh\nexit 101\n"


@dataclass(frozen=True)
class ChrootBackendCapability:
    name: str
    available: bool
    selected: bool
    active: bool
    detail: str
    package: str

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "available": self.available,
            "selected": self.selected,
            "active": self.active,
            "detail": self.detail,
            "package": self.package,
        }


def resolve_chroot_backend(backend: ChrootBackend) -> Literal["chroot", "nspawn"]:
    if backend == "auto":
        return "nspawn" if CommandRunner.has_binary("systemd-nspawn") else "chroot"
    return backend


def detect_chroot_backends(backend: ChrootBackend = "auto") -> tuple[ChrootBackendCapability, ...]:
    selected = resolve_chroot_backend(backend)
    return (
        ChrootBackendCapability(
            "auto",
            True,
            backend == "auto",
            False,
            f"selects {selected} on this host",
            "",
        ),
        ChrootBackendCapability(
            "chroot",
            CommandRunner.has_binary("chroot"),
            backend == "chroot",
            selected == "chroot",
            "classic maintainer shell and package-operation backend",
            "coreutils",
        ),
        ChrootBackendCapability(
            "nspawn",
            CommandRunner.has_binary("systemd-nspawn"),
            backend == "nspawn",
            selected == "nspawn",
            "optional stronger maintainer shell via systemd-nspawn",
            "systemd-container",
        ),
    )


@dataclass
class ChrootService:
    runner: CommandRunner
    root: Path
    use_sudo: bool = True
    backend: ChrootBackend = "chroot"

    def resolved_backend(self) -> Literal["chroot", "nspawn"]:
        return resolve_chroot_backend(self.backend)

    def mount_runtime(self) -> None:
        if self.resolved_backend() == "nspawn":
            self._block_service_starts()
            return
        for source, target in BIND_MOUNTS:
            destination = self.root / target
            FileSystemOps(self.runner, self.use_sudo).mkdir(destination, f"Create bind mount target {target}")
            self.runner.run(
                CommandSpec(
                    argv=sudo(
                        ("mount", "--bind", source, str(destination)), self.use_sudo
                    ),
                    needs_root=self.use_sudo,
                    description=f"Bind mount {source}",
                )
            )
            # Detach propagation so an unmount or new mount inside the chroot can
            # never leak into the host namespace (systemd shares / by default).
            self.runner.run(
                CommandSpec(
                    argv=sudo(("mount", "--make-rslave", str(destination)), self.use_sudo),
                    needs_root=self.use_sudo,
                    description=f"Isolate mount propagation for {target}",
                )
            )
        self._block_service_starts()

    def unmount_runtime(self) -> None:
        self._unblock_service_starts()
        if self.resolved_backend() == "nspawn":
            return
        for _, target in reversed(BIND_MOUNTS):
            destination = self.root / target
            self.runner.run(
                CommandSpec(
                    argv=sudo(("umount", "-lf", str(destination)), self.use_sudo),
                    needs_root=self.use_sudo,
                    description=f"Unmount {target}",
                ),
                check=False,
            )

    def _block_service_starts(self) -> None:
        # Package postinst scripts call invoke-rc.d to start daemons; inside a
        # chroot with no real init that hangs or fails, so policy-rc.d exits 101.
        FileSystemOps(self.runner, self.use_sudo).write_text(
            self.root / POLICY_RC_D,
            _POLICY_RC_D_BODY,
            "Block service starts during chroot package operations",
            mode="0755",
        )

    def _unblock_service_starts(self) -> None:
        FileSystemOps(self.runner, self.use_sudo).remove(
            self.root / POLICY_RC_D,
            "Remove chroot service-start block",
        )

    def command(self, *argv: str) -> CommandSpec:
        if self.resolved_backend() == "nspawn":
            return CommandSpec(
                argv=sudo(
                    (
                        "systemd-nspawn",
                        "--quiet",
                        "--register=no",
                        "--as-pid2",
                        "--directory",
                        str(self.root),
                        *argv,
                    ),
                    self.use_sudo,
                ),
                needs_root=self.use_sudo,
                description="Run command in target root with systemd-nspawn",
            )
        return CommandSpec(
            argv=sudo(("chroot", str(self.root), *argv), self.use_sudo),
            needs_root=self.use_sudo,
            description="Run command in target root",
        )

    def run(self, *argv: str) -> None:
        self.runner.run(self.command(*argv))

    def shell(self, shell: str = "/bin/bash") -> CommandSpec:
        return self.command(shell)
