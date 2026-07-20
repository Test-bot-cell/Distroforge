from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from .command import CommandRunner, CommandSpec


@dataclass
class ImportOptions:
    scripts: list[Path]


class ImportService:
    def __init__(self, runner: CommandRunner, project_root: Path, options: ImportOptions) -> None:
        self.runner = runner
        self.project_root = project_root
        self.options = options

    def import_scripts(self) -> None:
        hooks = self.project_root / "hooks" / "chroot"
        for script in self.options.scripts:
            target = hooks / script.name
            if self.runner.dry_run:
                self.runner.run(
                    CommandSpec(
                        argv=("copy-file", str(script), str(target)),
                        description="Import legacy script as chroot hook",
                    )
                )
            else:
                hooks.mkdir(parents=True, exist_ok=True)
                shutil.copy2(script, target)
