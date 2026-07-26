from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .command import CommandRunner
from .snapshots import SnapshotOptions, SnapshotService


@dataclass(frozen=True)
class RestoreRequest:
    project_root: Path
    snapshot: str


class RollbackService:
    def __init__(self, runner: CommandRunner, use_sudo: bool = True) -> None:
        self.runner = runner
        self.use_sudo = use_sudo

    def restore(self, request: RestoreRequest) -> None:
        # Delegated rather than reimplemented: this module used to run tar with no
        # sudo() wrapper over a root-owned tree, so a real restore failed with
        # EACCES on the first entry while SnapshotService.restore_latest did the
        # same job correctly a few lines away.
        work = request.project_root / "work"
        SnapshotService(
            self.runner,
            work / "filesystem",
            work / "snapshots",
            SnapshotOptions(),
            use_sudo=self.use_sudo,
        ).restore(request.snapshot)
