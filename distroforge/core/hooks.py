from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .command import CommandRunner, CommandSpec


@dataclass(frozen=True)
class Hook:
    name: str
    script: Path
    phase: str


class HookRunner:
    def __init__(self, runner: CommandRunner) -> None:
        self.runner = runner

    def discover(self, hooks_dir: Path, phase: str) -> list[Hook]:
        if not hooks_dir.exists():
            return []
        hooks = []
        for script in sorted(hooks_dir.glob(f"{phase}.*")):
            if script.is_file():
                hooks.append(Hook(name=script.name, script=script, phase=phase))
        return hooks

    def run_phase(self, hooks_dir: Path, phase: str) -> None:
        for hook in self.discover(hooks_dir, phase):
            self.runner.run(
                CommandSpec(
                    argv=(str(hook.script),),
                    cwd=hooks_dir,
                    description=f"Run hook {hook.name}",
                )
            )

