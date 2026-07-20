from __future__ import annotations

from pathlib import Path

from distroforge.core.poweruser_iso import prepare_poweruser_iso_path
from distroforge.core.project import Project


def register_poweruser_iso_parser(subparsers) -> None:
    parser = subparsers.add_parser("poweruser-iso", help="Prepare a guarded power-user source-to-ISO path")
    parser.add_argument("root", type=Path)
    parser.add_argument("--apply-safe-defaults", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--definition", type=Path)
    parser.add_argument("--dry-run-output", type=Path)
    parser.add_argument("--json", action="store_true")


def render_poweruser_iso(args) -> str:
    report = prepare_poweruser_iso_path(
        Project.load(args.root),
        apply_safe_defaults=args.apply_safe_defaults,
        dry_run=args.dry_run,
        definition_path=args.definition,
        dry_run_path=args.dry_run_output,
    )
    return report.render_json() if args.json else report.render_text()
