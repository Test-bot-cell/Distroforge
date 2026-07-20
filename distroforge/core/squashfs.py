from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .command import CommandRunner, CommandSpec, sudo
from .progress_parsers import squashfs_progress


@dataclass
class SquashfsService:
    runner: CommandRunner
    use_sudo: bool = True

    def unpack(
        self,
        squashfs_image: Path,
        destination: Path,
        *,
        on_progress: Callable[[float], None] | None = None,
    ) -> None:
        if not self.runner.dry_run:
            destination.parent.mkdir(parents=True, exist_ok=True)
        spec = CommandSpec(
            argv=sudo(
                (
                    "unsquashfs",
                    "-f",
                    "-d",
                    str(destination),
                    str(squashfs_image),
                ),
                self.use_sudo,
            ),
            needs_root=self.use_sudo,
            description="Unpack live filesystem",
        )
        self._run(spec, on_progress)

    def pack(
        self,
        source: Path,
        squashfs_image: Path,
        compression: str = "xz",
        *,
        on_progress: Callable[[float], None] | None = None,
    ) -> None:
        if not self.runner.dry_run:
            squashfs_image.parent.mkdir(parents=True, exist_ok=True)
        spec = CommandSpec(
            argv=sudo(
                (
                    "mksquashfs",
                    str(source),
                    str(squashfs_image),
                    "-noappend",
                    "-comp",
                    compression,
                ),
                self.use_sudo,
            ),
            needs_root=self.use_sudo,
            description="Repack live filesystem",
        )
        self._run(spec, on_progress)

    def _run(self, spec: CommandSpec, on_progress: Callable[[float], None] | None) -> None:
        if on_progress is None or self.runner.dry_run:
            self.runner.run(spec)
            return

        def on_line(line: str) -> None:
            fraction = squashfs_progress(line)
            if fraction is not None:
                on_progress(fraction)

        self.runner.run_streaming(spec, on_line)
