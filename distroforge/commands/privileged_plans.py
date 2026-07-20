from __future__ import annotations

import argparse

from distroforge.commands.output_policy import print_command_history
from distroforge.core.command import CommandRunner
from distroforge.core.rollback import RestoreRequest, RollbackService
from distroforge.core.secureboot_assistant import (
    SecureBootAssistant,
    SecureBootAssistantOptions,
)


def run_restore_snapshot(args: argparse.Namespace) -> None:
    runner = CommandRunner(dry_run=not args.execute)
    RollbackService(runner).restore(RestoreRequest(args.root, args.snapshot))
    print_command_history(runner)


def run_secureboot_assist(args: argparse.Namespace) -> None:
    runner = CommandRunner(dry_run=not args.execute)
    SecureBootAssistant(
        runner,
        SecureBootAssistantOptions(args.output_dir, args.common_name),
    ).plan()
    print_command_history(runner)
