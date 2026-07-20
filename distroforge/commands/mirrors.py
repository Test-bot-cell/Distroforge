from __future__ import annotations

import argparse

from distroforge.commands.build_options import project_options_from_args
from distroforge.core.command import CommandRunner


def run_mirrors(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    from distroforge.core.mirrors import MirrorService

    if not args.mirrors_command:
        parser.parse_args(["mirrors", "--help"])
        return
    project, options = project_options_from_args(args)
    mirror_options = options.mirrors
    mirror_options.enabled = True
    mirror_options.archive_mirror = args.archive or mirror_options.archive_mirror
    mirror_options.security_mirror = args.security or mirror_options.security_mirror
    mirror_options.country = args.country or mirror_options.country
    mirror_options.require_https = not args.allow_http
    mirror_options.keep_canonical_security = not args.override_ubuntu_security
    runner = CommandRunner(dry_run=args.mirrors_command != "apply" and args.mirrors_command != "restore")
    service = MirrorService(runner, project, mirror_options, use_sudo=options.use_sudo)
    if args.mirrors_command == "render":
        print(service.render_sources(), end="")
        return
    if args.mirrors_command == "apply":
        report = service.apply(strict=args.strict)
    elif args.mirrors_command == "restore":
        service.restore()
        print(f"Restored {project.workdir / 'apt-sources.backup'}")
        return
    else:
        report = service.doctor()
    print(report.render_json() if args.json else report.render_text(), end="")
    if args.strict and report.status == "blocked":
        raise SystemExit(2)
