from __future__ import annotations

import argparse

from distroforge.commands.build_options import apply_trust_args
from distroforge.core.project import Project
from distroforge.core.source_starter import apply_source_starter, default_starter_for_release
from distroforge.core.trust import TrustOptions


def run_new(args: argparse.Namespace) -> None:
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
    print(f"Created {project.name} at {project.root}")
    print(f"Source starter: {project.source_starter.get('label') if project.source_starter else starter_key}")
