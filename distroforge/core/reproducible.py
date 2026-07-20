from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .command import CommandRunner
from .fsops import FileSystemOps


@dataclass
class ReproducibleOptions:
    enabled: bool = False
    source_date_epoch: int | None = None
    apt_snapshot: str | None = None


class ReproducibleService:
    def __init__(self, runner: CommandRunner, root: Path, options: ReproducibleOptions, use_sudo: bool = True) -> None:
        self.runner = runner
        self.root = root
        self.options = options
        self.use_sudo = use_sudo
        self.fs = FileSystemOps(runner, use_sudo)

    def apply(self) -> None:
        if not self.options.enabled:
            return
        env_file = self.root / "etc" / "distroforge-reproducible.env"
        lines = []
        if self.options.source_date_epoch is not None:
            lines.append(f"SOURCE_DATE_EPOCH={self.options.source_date_epoch}\n")
        if self.options.apt_snapshot:
            lines.append(f"APT_SNAPSHOT={self.options.apt_snapshot}\n")
        self.fs.write_text(env_file, "".join(lines), "Write reproducible build environment hints")
