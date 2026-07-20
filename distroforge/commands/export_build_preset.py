from __future__ import annotations

import argparse

from distroforge.core.build import BuildOptions
from distroforge.core.definition import (
    apply_definition,
    definition_from_project,
    load_definition,
    write_definition,
)
from distroforge.core.project import Project


def run_export_build_preset(args: argparse.Namespace) -> None:
    project = Project.load(args.root)
    options = BuildOptions()
    if args.definition:
        options = apply_definition(project, load_definition(args.definition))
    metadata = {
        key: value
        for key, value in {
            "channel": args.channel,
            "revision": args.revision,
            "notes": args.notes,
        }.items()
        if value
    }
    write_definition(definition_from_project(project, options, metadata), args.target)
    print(f"Wrote {args.target}")
