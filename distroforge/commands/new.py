from __future__ import annotations

import argparse

from distroforge.commands.build_options import apply_trust_args
from distroforge.core.build_history import append_history
from distroforge.core.definition import definition_from_project
from distroforge.core.noob_flow import apply_noob_profile, plan_noob_profile
from distroforge.core.project import Project
from distroforge.core.releases import get_release
from distroforge.core.source_starter import apply_source_starter, default_starter_for_release
from distroforge.core.trust import TrustOptions


def run_new(args: argparse.Namespace) -> None:
    if getattr(args, "plan_only", False):
        if args.profile is None:
            raise ValueError("--plan-only requires --profile with one of portable|desktop|dev|kiosk")
        project = Project(args.name, args.root, get_release(args.release))
        apply_noob_profile(project, args.profile, persist=False)
        report = plan_noob_profile(project, args.profile, write=False)
        print(report.render_json() if args.json else report.render_text(), end="")
        return
    project = Project.create(args.name, args.root, args.release)
    starter_key = args.starter or default_starter_for_release(args.release)
    if args.from_scratch:
        starter_key = default_starter_for_release(args.release)
    trust = TrustOptions()
    apply_trust_args(trust, args)
    apply_source_starter(
        project,
        starter_key,
        source_iso=args.source_iso,
        previous_project=args.previous_project,
        trust=trust,
    )
    if getattr(args, "profile", None):
        apply_noob_profile(project, args.profile, persist=True)
        report = plan_noob_profile(project, args.profile, write=True)
        append_history(
            project,
            kind="noob-first-plan",
            summary=f"{report.choice.label} profile plan",
            command=f"distroforge wizard {project.name} {project.root} --profile {report.choice.key}",
            definition=definition_from_project(project, metadata={"history": "noob-first", "profile": report.choice.key}),
        )
        print(report.render_json() if args.json else report.render_text(), end="")
        return
    print(f"Created {project.name} at {project.root}")
    print(f"Source starter: {project.source_starter.get('label') if project.source_starter else starter_key}")
