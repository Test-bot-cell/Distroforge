from __future__ import annotations

import sys
from dataclasses import dataclass

from .build import BuildOptions, BuildOrchestrator
from .command import CommandRunner, CommandSpec
from .packaging import run_packaging_ci
from .project import Project


@dataclass
class CiOptions:
    run_pytest: bool = True
    run_ruff: bool = True
    build_dry_run: bool = True
    debian_package: bool = False


class CiService:
    def __init__(self, project: Project, runner: CommandRunner, options: CiOptions) -> None:
        self.project = project
        self.runner = runner
        self.options = options

    def run(self) -> None:
        if self.options.run_ruff:
            self.runner.run(
                CommandSpec(argv=(sys.executable, "-m", "ruff", "check", "."), description="Run Ruff lint")
            )
        if self.options.run_pytest:
            self.runner.run(
                CommandSpec(argv=(sys.executable, "-m", "pytest"), description="Run pytest suite")
            )
        if self.options.build_dry_run:
            # `ci --execute` executes lint/package checks, but this option is explicitly
            # a build *dry run*. Reusing self.runner made it a hidden real ISO build
            # whenever --execute was present, bypassing run_iso_build and its evidence
            # manifest. Keep the preview structurally non-executing and copy its history
            # back only so the CLI can still display the planned commands.
            preview = CommandRunner(dry_run=True)
            BuildOrchestrator(
                self.project,
                preview,
                BuildOptions(use_sudo=False),
            ).run()
            self.runner.history.extend(preview.history)
        if self.options.debian_package:
            report = run_packaging_ci(self.runner, self.project.root, execute=not self.runner.dry_run)
            self.runner.run(
                CommandSpec(
                    argv=("packaging-policy-report", "blocked" if report.blocked else "review-required"),
                    description="Summarize packaging policy report",
                )
            )
