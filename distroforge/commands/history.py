from __future__ import annotations

import argparse

from distroforge.core.build_history import render_history, replay_history
from distroforge.core.project import Project


def run_history(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if not args.history_command:
        parser.parse_args(["history", "--help"])
        return
    project = Project.load(args.root)
    if args.history_command == "list":
        print(render_history(project, json_output=args.json), end="")
        return
    print(replay_history(project, args.entry, output=args.output, json_output=args.json), end="")
