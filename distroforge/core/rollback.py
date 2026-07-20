from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .command import CommandRunner, CommandSpec


@dataclass(frozen=True)
class RestoreRequest:
    project_root: Path
    snapshot: str


class RollbackService:
    def __init__(self, runner: CommandRunner) -> None:
        self.runner = runner

    def restore(self, request: RestoreRequest) -> None:
        snapshot = request.project_root / "work" / "snapshots" / f"{request.snapshot}.tar.zst"
        target = request.project_root / "work" / "filesystem"
        self.runner.run(
            CommandSpec(
                argv=("tar", "--zstd", "-xpf", str(snapshot), "-C", str(target)),
                description=f"Restore rollback snapshot {request.snapshot}",
            )
        )
