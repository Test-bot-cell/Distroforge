from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .chroot import ChrootService
from .command import CommandRunner, CommandSpec
from .validate import validate_username


@dataclass
class UserSpec:
    name: str
    password_hash: str | None = None
    groups: list[str] = field(default_factory=lambda: ["sudo", "audio", "video"])
    shell: str = "/bin/bash"


@dataclass
class UserOptions:
    users: list[UserSpec] = field(default_factory=list)


class UserService:
    def __init__(self, runner: CommandRunner, root: Path, options: UserOptions, use_sudo: bool = True) -> None:
        self.runner = runner
        self.root = root
        self.options = options
        self.use_sudo = use_sudo

    def apply(self) -> None:
        chroot = ChrootService(self.runner, self.root, self.use_sudo)
        for user in self.options.users:
            _validate_username(user.name)
            chroot.run("useradd", "-m", "-s", user.shell, "-G", ",".join(user.groups), user.name)
            if user.password_hash:
                payload = f"{user.name}:{user.password_hash}\n"
                self.runner.run(
                    CommandSpec(
                        argv=chroot.command("chpasswd", "-e").argv,
                        needs_root=self.use_sudo,
                        description="Set user password hash (chpasswd -e)",
                        stdin=payload,
                    )
                )


def _validate_username(name: str) -> None:
    if not validate_username(name):
        raise ValueError(f"Invalid username: {name!r}")

