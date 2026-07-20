from __future__ import annotations

import argparse

from distroforge.commands.build_options import project_options_from_args


def run_dry_run_report(args: argparse.Namespace) -> None:
    from distroforge.core.dry_run_report import generate_dry_run_report

    project, options = project_options_from_args(args)
    report = generate_dry_run_report(
        project,
        options,
        run_orchestrator=not args.no_command_simulation,
    )
    rendered = report.render_json() if args.json else report.render_text()
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
        print(f"Wrote {args.output}")
    else:
        print(rendered)
