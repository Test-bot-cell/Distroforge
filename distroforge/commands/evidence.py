from __future__ import annotations

from pathlib import Path

from distroforge.core.evidence import (
    EVIDENCE_PROFILES,
    EvidenceStatusService,
    validate_evidence_contract,
)
from distroforge.core.project import Project


def register_evidence_commands(subparsers) -> None:
    status = subparsers.add_parser("evidence-status", help="Summarize maintainer evidence without building")
    status.add_argument("root", type=Path)
    status.add_argument("--definition", type=Path)
    status.add_argument("--iso", type=Path)
    status.add_argument("--output-dir", type=Path)
    status.add_argument("--profile", choices=EVIDENCE_PROFILES, default="publish")
    status.add_argument("--fix-plan", action="store_true")
    status.add_argument("--verbose", action="store_true")
    status.add_argument("--json", action="store_true")

    verify = subparsers.add_parser("evidence-verify", help="Validate an evidence bundle contract")
    verify.add_argument("path", type=Path)
    verify.add_argument("--json", action="store_true")


def render_evidence_command(args) -> tuple[str, bool] | None:
    if args.command == "evidence-status":
        return render_evidence_status(
            args.root,
            args.definition,
            args.iso,
            args.output_dir,
            args.profile,
            args.fix_plan,
            args.verbose,
            args.json,
        )
    if args.command == "evidence-verify":
        return render_evidence_verify(args.path, args.json)
    return None


def render_evidence_status(
    root: Path,
    definition: Path | None,
    iso: Path | None,
    output_dir: Path | None,
    profile: str = "publish",
    fix_plan: bool = False,
    verbose: bool = False,
    json_output: bool = False,
) -> tuple[str, bool]:
    from distroforge.core.build import BuildOptions
    from distroforge.core.definition import apply_definition, load_definition

    try:
        project = Project.load(root)
    except FileNotFoundError:
        if definition:
            raise
        report = EvidenceStatusService().check_source_tree(root, iso=iso, output_dir=output_dir, profile=profile)
    else:
        options = apply_definition(project, load_definition(definition)) if definition else BuildOptions()
        report = EvidenceStatusService().check(project, options, iso=iso, output_dir=output_dir, profile=profile)
    if json_output:
        return report.render_json(), report.blocked
    if fix_plan:
        return report.render_fix_plan_text(), report.blocked
    return report.render_text(verbose=verbose), report.blocked


def render_evidence_verify(path: Path, json_output: bool = False) -> tuple[str, bool]:
    report = validate_evidence_contract(path)
    return (report.render_json() if json_output else report.render_text(), report.blocked)
