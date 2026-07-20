from __future__ import annotations

import argparse

from distroforge.commands.build_options import project_options_from_args


def run_forgeadvisor(args: argparse.Namespace) -> None:
    from distroforge.ai.backend import select_backend
    from distroforge.ai.forgeadvisor import ForgeAdvisor
    from distroforge.core.build_memory import BuildMemory, default_corpus_path

    if args.forgeadvisor_command == "memory":
        summary = BuildMemory(default_corpus_path()).summarize(limit=args.limit)
        print(summary.render_json() if args.json else summary.render_text())
        return

    from distroforge.ui.preferences import load_workflow_level

    # Ring 0: an explicit --register overrides; otherwise speak in the saved
    # workflow level's voice so the CLI and GUI share one register source.
    level = args.register or load_workflow_level()
    advisor = ForgeAdvisor(select_backend(args.backend), BuildMemory(default_corpus_path()), level)
    if args.forgeadvisor_command == "explain-log":
        report = advisor.explain_log(args.log)
    elif args.forgeadvisor_command == "triage-log":
        report = advisor.triage_log(args.log)
    elif args.forgeadvisor_command == "explain-evidence":
        report = advisor.explain_evidence(
            args.root,
            iso=args.iso,
            output_dir=args.output_dir,
            profile=args.profile,
        )
    elif args.forgeadvisor_command == "fix-plan":
        report = advisor.narrate_fix_plan(
            args.root,
            iso=args.iso,
            output_dir=args.output_dir,
            profile=args.profile,
        )
    elif args.forgeadvisor_command == "review-definition":
        report = advisor.review_definition(args.definition)
    elif args.forgeadvisor_command == "search-local":
        report = advisor.search_local(args.root, args.query, limit=args.limit)
    elif args.forgeadvisor_command == "copilot":
        report = advisor.maintainer_copilot(
            args.root,
            iso=args.iso,
            output_dir=args.output_dir,
            profile=args.profile,
            query=args.query,
            limit=args.limit,
        )
    elif args.forgeadvisor_command == "review-build":
        project, options = project_options_from_args(args)
        report = advisor.review_build(project, options)
    elif args.forgeadvisor_command == "propose-fixes":
        project, options = project_options_from_args(args)
        report = advisor.propose_fixes(project, options)
    elif args.forgeadvisor_command == "doctor-ai":
        report = advisor.doctor()
    else:  # pragma: no cover - argparse enforces choices.
        raise ValueError(f"Unknown ForgeAdvisor command: {args.forgeadvisor_command}")
    print(report.render_json() if args.json else report.render_text())
