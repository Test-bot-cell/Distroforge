from __future__ import annotations

import argparse

from distroforge.commands.build_options import project_options_from_args
from distroforge.core.definition import definition_from_project, write_definition


def run_branding(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    from distroforge.core.brand_identity import (
        load_identity,
        write_identity,
        write_identity_preview,
    )
    from distroforge.core.branding_compliance import BrandingComplianceService

    if not args.branding_command:
        parser.parse_args(["branding", "--help"])
        return
    project, options = project_options_from_args(args)
    branding_command = "audit" if args.branding_command == "compliance" else args.branding_command
    if branding_command in {"set", "export"}:
        identity = write_identity(project, options.branding, args.output)
        print(identity.render_manifest(), end="")
        print(f"Wrote {args.output or project.output_dir / 'BRANDING-MANIFEST.json'}")
        return
    if branding_command == "import":
        identity = load_identity(args.identity)
        options.branding = identity.to_branding_options()
        output = args.output or project.root / "branding-definition.json"
        write_definition(definition_from_project(project, options), output)
        print(f"Wrote {output}")
        return
    if branding_command == "preview":
        identity = write_identity_preview(project, options.branding, args.output_dir)
        preview_dir = args.output_dir or project.output_dir / "branding-preview"
        if args.target == "grub":
            print((preview_dir / "grub.cfg").read_text(encoding="utf-8") if (preview_dir / "grub.cfg").exists() else identity.render_preview())
        elif args.target == "plymouth":
            print((preview_dir / "plymouth.txt").read_text(encoding="utf-8") if (preview_dir / "plymouth.txt").exists() else identity.render_preview())
        elif args.target == "metadata":
            print((preview_dir / "os-release").read_text(encoding="utf-8") if (preview_dir / "os-release").exists() else identity.render_preview())
        else:
            print(identity.render_preview(), end="")
        print(f"Wrote {preview_dir}")
        return
    service = BrandingComplianceService()
    if branding_command == "clearance":
        report = service.write_clearance(project, options.branding, args.output, args.mode)
        print(report.render_text())
        print(f"Wrote {args.output or project.output_dir / 'TRADEMARK-CLEARANCE.json'}")
        if report.status == "blocked":
            raise SystemExit(2)
        return
    report = service.audit(project, options.branding, args.mode)
    print(report.render_json() if getattr(args, "json", False) else report.render_text())
    if branding_command == "validate" and report.status == "blocked":
        raise SystemExit(2)
