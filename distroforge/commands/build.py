from __future__ import annotations

import argparse
import os

from distroforge.commands.build_options import (
    apply_cli_overrides,
    apply_customization_args,
    build_options_from_args,
)
from distroforge.commands.output_policy import print_command_history
from distroforge.core.build import BuildOptions, BuildOrchestrator, BuildProgress
from distroforge.core.command import CommandRunner
from distroforge.core.definition import apply_definition, load_definition
from distroforge.core.doctor import (
    apt_install_command,
    install_packages_for,
    missing_required,
    run_doctor,
)
from distroforge.core.project import Project
from distroforge.core.snapshots import SnapshotService
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
    log_path = args.log_file or project.root / "logs" / "build.jsonl"
    runner = CommandRunner(dry_run=not args.execute, log_path=log_path)

    def report_progress(update: BuildProgress) -> None:
        if update.phase_fraction:
            return
        step = update.step
        print(
            f"[{update.index:02d}/{update.total} {update.fraction * 100:5.1f}%] "
            f"{step.phase.value}: {step.title}"
        )

    orchestrator = BuildOrchestrator(project, runner, options, progress=report_progress)
    try:
        orchestrator.run()
    except Exception:
        if options.snapshots.enabled and options.snapshots.auto_restore_on_failure:
            SnapshotService(
                runner,
                project.squashfs_root,
                project.workdir / "snapshots",
                options.snapshots,
                use_sudo=options.use_sudo,
            ).restore_latest()
        raise
    done = len(orchestrator.report.steps)
    label = "plan walkthrough complete" if runner.dry_run else "build complete"
    print(f"[{done:02d}/{done} 100.0%] {label}")
    if runner.dry_run:
        print("\nDry-run commands:")
        print_command_history(runner)
