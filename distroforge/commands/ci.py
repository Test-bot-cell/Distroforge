from __future__ import annotations

import argparse

from distroforge.commands.output_policy import print_command_history
from distroforge.core.ci import CiOptions, CiService
from distroforge.core.command import CommandRunner
from distroforge.core.project import Project


def run_ci(args: argparse.Namespace) -> None:
    project = Project.load(args.root)
    runner = CommandRunner(dry_run=not args.execute)
    CiService(
        project,
        runner,
        CiOptions(
            run_pytest=not args.no_pytest,
            run_ruff=not args.no_ruff,
            build_dry_run=not args.no_build_dry_run,
            debian_package=args.debian_package,
        ),
    ).run()
    print_command_history(runner)
