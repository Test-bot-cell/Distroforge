from __future__ import annotations

import argparse
import json
import os
import sys

from distroforge.commands.build_options import (
    apply_cli_overrides,
    apply_customization_args,
    build_options_from_args,
)
from distroforge.core.build import BuildOptions, BuildOrchestrator
from distroforge.core.command import CommandRunner
from distroforge.core.definition import apply_definition, load_definition
from distroforge.core.doctor import (
    apt_install_command,
    install_packages_for,
    missing_required,
    run_doctor,
)
from distroforge.core.iso_build import IsoBuildReport, run_iso_build
from distroforge.core.project import Project
from distroforge.core.validate import format_issues, has_errors, validate_for_build


def _resolve_project(args: argparse.Namespace) -> Project:
    project = Project.load(args.root)
    sanitize_message = project.desktop_sanitization_message()
    if sanitize_message:
        print(sanitize_message)
    if args.source_iso:
        project.source_iso = args.source_iso
    if args.from_scratch:
        project.source_mode = "bootstrap"
    apply_customization_args(project, args)
    return project


def run_plan(args: argparse.Namespace) -> None:
    project = _resolve_project(args)
    options = BuildOptions(run_preview=args.preview)
    orchestrator = BuildOrchestrator(project, CommandRunner(dry_run=True), options)
    for index, step in enumerate(orchestrator.plan(), start=1):
        print(f"{index:02d}. {step.phase.value:18} {step.title} - {step.detail}")


def run_validate(args: argparse.Namespace) -> None:
    project = _resolve_project(args)
    runner = CommandRunner(dry_run=not args.execute)
    issues = validate_for_build(project, runner, execute=args.execute)
    print(format_issues(issues))
    if has_errors(issues):
        raise SystemExit(2)


def run_build(args: argparse.Namespace) -> None:
    os.environ["DISTROFORGE_PRIVILEGE"] = "none" if args.no_sudo else args.privilege
    if args.execute and not args.skip_deps_check:
        deps = run_doctor(CommandRunner(dry_run=True))
        missing = missing_required(deps)
        if missing:
            packages = install_packages_for(deps)
            print("Missing required host tools:")
            for item in missing:
                print(f"- {item.binary}: {item.reason}")
            print("\nInstall them with:")
            print("  " + apt_install_command(packages))
            print("\nOr run:")
            print("  distroforge doctor --install")
            raise SystemExit(2)
    project = _resolve_project(args)
    if args.definition:
        options = apply_definition(project, load_definition(args.definition))
    else:
        options = build_options_from_args(project, args)
    apply_cli_overrides(project, args, options)
    report = run_iso_build(
        project,
        options,
        execute=args.execute,
        definition=args.definition,
        log_path=args.log_file,
    )
    _print_sealed_result(report)
    if not args.execute:
        _print_planned_commands(report)
    if report.failed or (args.execute and report.blocked):
        detail = (
            report.failure.output
            if report.failure and report.failure.output
            else report.doctor.next_command
        )
        print(f"distroforge: error: {detail}", file=sys.stderr)
        raise SystemExit(2)


def _print_sealed_result(report: IsoBuildReport) -> None:
    """Describe the evidence outcome without claiming an absent ISO was built."""

    done = len(report.build_steps)
    total = max(done, 1)
    if report.status == "built":
        label = "ISO built; sealed build evidence written"
    elif report.status == "planned":
        label = "sealed build plan written; no ISO was produced"
    elif report.status == "failed":
        label = "build failed; failure evidence sealed"
    else:
        label = "build blocked; no ISO was produced"
    print(f"[{done:02d}/{total} 100.0%] {label}")
    print(f"ISO-BUILD: {report.report}")
    print(f"RUN-MANIFEST: {report.run_manifest}")
    if report.failure:
        print(
            f"Failure: {report.failure.description or 'command'} "
            f"(exit {report.failure.returncode})"
        )


def _print_planned_commands(report: IsoBuildReport) -> None:
    """Render commands from the sealed JSONL instead of keeping a second runner."""

    print("\nDry-run commands:")
    if report.command_log is None or not report.command_log.is_file():
        print("- none (the build was blocked before command planning)")
        return
    for line in report.command_log.read_text(encoding="utf-8").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("event") == "start" and isinstance(event.get("command"), str):
            print(f"- {event['command']}")
