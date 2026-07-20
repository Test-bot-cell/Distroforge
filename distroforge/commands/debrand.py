from __future__ import annotations

import argparse

from distroforge.commands.build_options import project_options_from_args
from distroforge.commands.output_policy import print_command_history
from distroforge.core.command import CommandRunner


def run_debrand(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    from distroforge.core.debrand import DebrandService

    if not args.debrand_command:
        parser.parse_args(["debrand", "--help"])
        return
    project, options = project_options_from_args(args)
    runner = CommandRunner(dry_run=args.debrand_command != "apply")
    service = DebrandService(runner)
    if args.debrand_command == "apply":
        report = service.apply(project, options.branding, strict=args.strict, output=args.output)
    else:
        report = service.scan(project, options.branding)
    print(report.render_json() if args.json else report.render_text())
    if args.debrand_command == "apply" and runner.dry_run:
        print_command_history(runner)
    if args.debrand_command != "apply" and args.strict and report.findings:
        raise SystemExit(2)
