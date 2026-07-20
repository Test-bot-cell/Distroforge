from __future__ import annotations

import argparse

from distroforge.commands.build_options import project_options_from_args


def run_profile(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    from distroforge.core.distro_profile import DistroProfileService

    if not args.profile_command:
        parser.parse_args(["profile", "--help"])
        return
    project, options = project_options_from_args(args)
    service = DistroProfileService()
    if args.profile_command in {"create", "apply"}:
        output = args.output or project.root / f"{args.profile}-profile.json"
        plan = service.write_definition(project, args.profile, output, options.branding)
        print(plan.render_text() if not args.json else service.render_json(project, args.profile, options.branding))
        print(f"Wrote {output}")
        return
    plan = service.plan(project, args.profile, options.branding)
    print(service.render_json(project, args.profile, options.branding) if args.json else plan.render_text())
    return
