from __future__ import annotations

import argparse

from distroforge.core.build import BuildOptions
from distroforge.core.definition import apply_definition, load_definition
from distroforge.core.policy import CompatibilityService
from distroforge.core.ppa import PpaOptions, PpaSpec
from distroforge.core.project import Project


def run_compat(args: argparse.Namespace) -> None:
    project = Project.load(args.root)
    if args.definition:
        options = apply_definition(project, load_definition(args.definition))
    else:
        options = BuildOptions(ppa=PpaOptions([PpaSpec.parse(value) for value in args.ppa]))
    report = CompatibilityService().check(project, options)
    state = "supported" if report.supported else "planned"
    print(f"{report.release} {report.codename} {state}")
    for message in report.messages:
        print(f"- {message}")
