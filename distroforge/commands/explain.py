from __future__ import annotations

import argparse

from distroforge.commands.build_options import project_options_from_args
from distroforge.core.explain import explain_build


def _build_report(args: argparse.Namespace):
    project, options = project_options_from_args(args)
    return explain_build(project, options, strict=getattr(args, "strict", False))


def render_explain(args: argparse.Namespace) -> str:
    report = _build_report(args)
    return report.render_json() if args.json else report.render_text()


def run_explain(args: argparse.Namespace) -> bool:
    report = _build_report(args)
    output = report.render_json() if args.json else report.render_text()
    print(output)
    return bool(report.blocked)
