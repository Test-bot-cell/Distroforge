from __future__ import annotations

import argparse
import json

from distroforge.core.build import BuildOptions
from distroforge.core.definition import apply_definition, load_definition
from distroforge.core.project import Project
from distroforge.core.ux_audit import audit_experience, gui_source_root


def run_ux_audit(args: argparse.Namespace) -> None:
    project = Project.load(args.root)
    options = BuildOptions()
    if args.definition:
        options = apply_definition(project, load_definition(args.definition))
    gui_source = gui_source_root()
    report = audit_experience(project, options, gui_source)
    if args.json:
        print(
            json.dumps(
                {
                    "score": report.score,
                    "findings": [finding.__dict__ for finding in report.findings],
                },
                indent=2,
            )
        )
    else:
        print(report.render_text())
