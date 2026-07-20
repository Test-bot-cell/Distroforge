from __future__ import annotations

import argparse

from distroforge.commands.build_options import project_options_from_args


def run_profile(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    from distroforge.core.distro_profile import DistroProfileService
    from distroforge.core.profile_resolver import (
        diff_profiles,
        render_profile_show,
        resolve_profiles,
    )
    from distroforge.core.project import Project

    if not args.profile_command:
        parser.parse_args(["profile", "--help"])
        return
    if args.profile_command == "show":
        if args.root is not None:
            project = Project.load(args.root)
            resolution = resolve_profiles(
                project,
                base=args.base or args.profile,
                layers=args.layer,
                overrides=args.override,
                config=args.config,
            )
            print(resolution.render_json() if args.json else resolution.render_text(), end="")
            return
        print(render_profile_show(args.profile, json_output=args.json), end="")
        return
    if args.profile_command == "resolve":
        project = Project.load(args.root)
        resolution = resolve_profiles(
            project,
            base=args.base,
            layers=args.layer,
            overrides=args.override,
            config=args.config,
        )
        print(resolution.render_json() if args.json else resolution.render_text(), end="")
        return

    if args.profile_command == "diff":
        project = Project.load(args.root)
        resolution = diff_profiles(
            project,
            args.profile,
            args.against,
            config=args.config,
            layers=args.layer,
            overrides=args.override,
            right_config=args.against_config,
            right_base=args.against_base,
            right_layers=args.against_layer,
            right_overrides=args.against_override,
        )
        print(resolution.render_json() if args.json else resolution.render_text(), end="")
        return

    project, options = project_options_from_args(args)
    service = DistroProfileService()
    if args.profile_command in {"create", "apply"}:
        output = args.output or project.root / f"{args.profile}-profile.json"
        plan = service.write_definition(project, args.profile, output, options.branding)
        print(plan.render_text() if not args.json else service.render_json(project, args.profile, options.branding))
        print(f"Wrote {output}")
        return
    raise ValueError(f"Unknown profile command: {args.profile_command}")
