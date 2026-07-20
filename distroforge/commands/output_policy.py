from __future__ import annotations

from distroforge.core.command import CommandRunner


def print_command_history(runner: CommandRunner) -> None:
    for spec in runner.history:
        print(f"- {spec.display()}")
