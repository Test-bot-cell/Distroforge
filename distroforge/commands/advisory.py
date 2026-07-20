from __future__ import annotations

import argparse

from distroforge.commands.build_options import project_options_from_args


def render_readiness(args: argparse.Namespace) -> str:
    from distroforge.core.readiness import ReadinessService

    project, options = project_options_from_args(args)
    report = ReadinessService().check(project, options)
    return report.render_json() if args.json else report.render_text()


def render_explain_risk(args: argparse.Namespace) -> str:
    from distroforge.core.education import explain_risks

    project, options = project_options_from_args(args)
    return explain_risks(project, options)


def render_ai_review(args: argparse.Namespace) -> str:
    from distroforge.ai.review import PlanReviewer
    from distroforge.core.dry_run_report import generate_dry_run_report
    from distroforge.core.readiness import ReadinessService

    project, options = project_options_from_args(args)
    readiness = ReadinessService().check(project, options)
    dry_run = generate_dry_run_report(project, options, run_orchestrator=False)
    review = PlanReviewer().review(readiness, dry_run)
    return review.render_json() if args.json else review.render_text()
