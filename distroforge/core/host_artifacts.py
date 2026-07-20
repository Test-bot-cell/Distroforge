from __future__ import annotations

from pathlib import Path

from .command import CommandRunner, CommandSpec


class HostArtifactWriter:
    """Host-side artifact writes: reports, plans, previews and output scaffolding.

    The host analogue of FileSystemOps. It is never privileged and stays
    dry-run-pure: every write records a ``write-file`` command in history, but
    the real filesystem mutation happens only when the runner is executing, so
    planning a build produces no host filesystem side effects.
    """

    def __init__(self, runner: CommandRunner) -> None:
        self.runner = runner

    def write_text(self, target: Path, content: str, description: str) -> None:
        self.runner.run(CommandSpec(argv=("write-file", str(target)), description=description))
        if self.runner.dry_run:
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def write_host_artifact(target: Path, content: str, description: str) -> None:
    """Write a standalone, execute-now host artifact through the boundary.

    The in-build writers gate on the build's dry-run runner so planning a build
    touches no host files. Standalone report/bundle/recipe/preset writers are
    different: they always write when their own command runs, so they route
    through the boundary with an executing runner, keeping one canonical
    host-owned write path for every artifact.
    """
    HostArtifactWriter(CommandRunner(dry_run=False)).write_text(target, content, description)
