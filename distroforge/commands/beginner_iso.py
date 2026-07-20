from __future__ import annotations

from pathlib import Path

from distroforge.core.beginner_iso import (
    explain_beginner_iso_failure,
    prepare_beginner_iso_path,
    repair_beginner_iso_release_artifacts,
    run_beginner_iso_boot_proof,
)
from distroforge.core.build import BuildOptions
from distroforge.core.build_memory import BuildMemory, default_corpus_path
from distroforge.core.command import CommandRunner
from distroforge.core.definition import apply_definition, load_definition
from distroforge.core.doctor import (
    apt_install_command,
    install_missing,
    install_packages_for,
    missing_required,
    run_doctor,
)
from distroforge.core.project import Project


def register_beginner_iso_parser(subparsers) -> None:
    parser = subparsers.add_parser("beginner-iso", help="Prepare a safe beginner source-to-ISO path")
    parser.add_argument("root", type=Path)
    parser.add_argument("--apply-safe-defaults", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--definition", type=Path)
    parser.add_argument("--dry-run-output", type=Path)
    parser.add_argument("--command-log", type=Path)
    parser.add_argument("--doctor", action="store_true", help="Check host tools needed by the beginner ISO path")
    parser.add_argument("--install-missing-tools", action="store_true", help="Install missing required host tools")
    parser.add_argument("--explain-last-failure", action="store_true")
    parser.add_argument("--repair-release-artifacts", action="store_true")
    parser.add_argument("--run-boot-proof", action="store_true")
    parser.add_argument("--json", action="store_true")


def render_beginner_iso(args) -> str:
    if args.doctor or args.install_missing_tools:
        return render_beginner_iso_doctor(args.install_missing_tools, args.json)
    if args.explain_last_failure:
        report = explain_beginner_iso_failure(Project.load(args.root), args.command_log)
        return report.render_json() if args.json else report.render_text()
    if args.repair_release_artifacts:
        project = Project.load(args.root)
        options = apply_definition(project, load_definition(args.definition)) if args.definition else BuildOptions()
        report = repair_beginner_iso_release_artifacts(project, options)
        return report.render_json() if args.json else report.render_text()
    if args.run_boot_proof:
        project = Project.load(args.root)
        options = apply_definition(project, load_definition(args.definition)) if args.definition else BuildOptions()
        report = run_beginner_iso_boot_proof(project, options, execute=not args.dry_run)
        return report.render_json() if args.json else report.render_text()
    report = prepare_beginner_iso_path(
        Project.load(args.root),
        apply_safe_defaults=args.apply_safe_defaults,
        dry_run=args.dry_run,
        execute=args.execute,
        definition_path=args.definition,
        dry_run_path=args.dry_run_output,
        command_log_path=args.command_log,
        memory=BuildMemory(default_corpus_path()) if args.execute else None,
    )
    return report.render_json() if args.json else report.render_text()


def render_beginner_iso_doctor(install: bool = False, json_output: bool = False) -> str:
    import json

    runner = CommandRunner(dry_run=not install)
    before = run_doctor(CommandRunner(dry_run=True))
    missing = missing_required(before)
    packages = install_packages_for(before)
    if install:
        install_missing(runner, before)
    after = run_doctor(CommandRunner(dry_run=True)) if install else before
    data = {
        "status": "blocked" if missing else "ready",
        "missing": [item.__dict__ for item in missing],
        "install_packages": packages,
        "install_command": apt_install_command(packages),
        "installed": install,
        "commands": [spec.display() for spec in runner.history],
        "after_missing": [item.__dict__ for item in missing_required(after)],
    }
    if json_output:
        return json.dumps(data, indent=2)
    lines = ["Beginner ISO host readiness", f"Status: {data['status']}"]
    if missing:
        lines.extend(["", "Missing required tools:"])
        lines.extend(f"- {item.binary}: {item.reason}" for item in missing)
        lines.extend(["", "Install command:", data["install_command"]])
    else:
        lines.append("All required host tools are available.")
    if install:
        lines.extend(["", "Installation commands:", *[f"- {cmd}" for cmd in data["commands"]]])
    return "\n".join(lines)
