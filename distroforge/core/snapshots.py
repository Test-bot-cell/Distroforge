from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .command import CommandRunner, CommandSpec, sudo


@dataclass
class SnapshotOptions:
    enabled: bool = False
    phases: tuple[str, ...] = (
        "after-apt",
        "after-customize",
        "before-kernel",
        "after-kernel",
        "after-sanitize",
    )
    auto_restore_on_failure: bool = False


class SnapshotService:
    # Pseudo-filesystems and mutable runtime mounts should not be part of rollback
    # snapshots. Excluding them avoids hangs while preserving actual filesystem state.
    _EXCLUDED_PATHS = (
        "./proc",
        "./sys",
        "./dev",
        "./run",
        "./tmp",
    )

    def __init__(
        self,
        runner: CommandRunner,
        root: Path,
        snapshots_dir: Path,
        options: SnapshotOptions,
        use_sudo: bool = True,
    ) -> None:
        self.runner = runner
        self.root = root
        self.snapshots_dir = snapshots_dir
        self.options = options
        self.use_sudo = use_sudo

    def create(self, name: str) -> None:
        if not self.options.enabled or name not in self.options.phases:
            return
        target = self.snapshots_dir / f"{name}.tar.zst"
        temp_target = target.with_suffix(target.suffix + ".part")
        if self.runner.dry_run:
            self.runner.run(
                CommandSpec(
                    argv=("mkdir", "-p", str(self.snapshots_dir)),
                    description="Prepare rollback snapshot directory",
                )
            )
        else:
            self.snapshots_dir.mkdir(parents=True, exist_ok=True)
            if temp_target.exists():
                temp_target.unlink()

        exclude_args = tuple(
            value
            for path in self._EXCLUDED_PATHS
            if (self.root / path.removeprefix("./")).is_dir()
            for value in ("--exclude", path)
        )
        self.runner.run(
            CommandSpec(
                argv=sudo(
                    (
                        "tar",
                        "--zstd",
                        "--one-file-system",
                        "-cpf",
                        str(temp_target),
                        "-C",
                        str(self.root),
                        *exclude_args,
                        ".",
                    ),
                    self.use_sudo,
                ),
                needs_root=self.use_sudo,
                description=f"Create rollback snapshot {name}",
            )
        )
        self.runner.run(
            CommandSpec(
                argv=("mv", "-f", str(temp_target), str(target)),
                description=f"Publish rollback snapshot {name}",
            )
        )

    def restore_latest(self) -> None:
        if not self.options.enabled:
            return
        for name in reversed(self.options.phases):
            snapshot = self.snapshots_dir / f"{name}.tar.zst"
            if not snapshot.exists():
                continue
            self.runner.run(
                CommandSpec(
                    argv=sudo(("tar", "--zstd", "-xpf", str(snapshot), "-C", str(self.root)), self.use_sudo),
                    needs_root=self.use_sudo,
                    description=f"Restore rollback snapshot {name}",
                )
            )
            return
