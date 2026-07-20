from __future__ import annotations

from pathlib import Path

from distroforge.core.build import BuildOptions
from distroforge.core.build_journey import (
    JOURNEY_ACTION_IDS,
    apply_journey_step,
    build_journey,
    check_journey_step,
)
from distroforge.core.definition import (
    apply_definition,
    definition_from_project,
    load_definition,
    write_definition,
)
from distroforge.core.project import Project
from distroforge.core.workflows import LEVEL_KEYS


def register_journey_parser(subparsers) -> None:
    parser = subparsers.add_parser("journey", help="Show guided distro build journey")
    parser.add_argument("root", type=Path)
    parser.add_argument("--definition", type=Path)
    parser.add_argument("--level", choices=list(LEVEL_KEYS), default="beginner")
    parser.add_argument("--apply", choices=JOURNEY_ACTION_IDS)
    parser.add_argument("--check", choices=JOURNEY_ACTION_IDS)
    parser.add_argument("--output", type=Path, help="Write the updated build definition when --apply changes options")
    parser.add_argument("--json", action="store_true")


def render_from_args(args) -> str:
    if args.apply:
        return apply_from_args(args)
    if args.check:
        return check_from_args(args)
    return render_build_journey(args.root, level=args.level, definition=args.definition, json_output=args.json)


def check_from_args(args) -> str:
    project = Project.load(args.root)
    options = BuildOptions()
    if args.definition:
        options = apply_definition(project, load_definition(args.definition))
    report = check_journey_step(project, options, args.check)
    if args.json:
        import json

        return json.dumps(report.to_dict(), indent=2)
    return report.render_text()


def apply_from_args(args) -> str:
    project = Project.load(args.root)
    options = BuildOptions()
    if args.definition:
        options = apply_definition(project, load_definition(args.definition))
    report = apply_journey_step(project, options, args.apply)
    output = args.output or args.definition or project.root / f"journey-{args.apply}.yaml"
    if report.changed_options:
        write_definition(definition_from_project(project, options), output)
    lines = [report.render_text()]
    if report.changed_options:
        lines.append(f"\nWrote build definition: {output}")
    if report.changed_project:
        lines.append(f"\nUpdated project: {project.root / 'project.json'}")
    lines.append("\nNext journey state:")
    lines.append(build_journey(project, options, args.level).render_text())
    return "\n".join(lines)


def render_build_journey(
    root: Path,
    *,
    level: str = "beginner",
    definition: Path | None = None,
    json_output: bool = False,
) -> str:
    project = Project.load(root)
    options = BuildOptions()
    if definition:
        options = apply_definition(project, load_definition(definition))
    report = build_journey(project, options, level)
    return report.render_json() if json_output else report.render_text()
