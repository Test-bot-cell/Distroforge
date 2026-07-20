from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from yaml import YAMLError

from .ai.backend import backend_names
from .ai.registers import register_keys
from .commands.build_options import (
    register_build_arguments,
    register_customization_arguments,
    register_trust_arguments,
)
from .core.autoinstall_templates import TEMPLATES
from .core.definition import (
    example_definition,
    write_definition,
)
from .core.presets import BUILTIN_PRESETS
from .core.recipe_ai import RecipeAdvisor
from .core.source_starter import BUILTIN_SOURCE_STARTERS


def main(argv: list[str] | None = None) -> None:
    try:
        _main(argv)
    except (FileNotFoundError, json.JSONDecodeError, KeyError, OSError, ValueError, YAMLError) as exc:
        print(f"distroforge: error: {_friendly_error(exc)}", file=sys.stderr)
        raise SystemExit(2) from None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="distroforge")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("releases", help="List known Ubuntu releases")
    sub.add_parser("profiles", help="List built-in remix profiles")
    sub.add_parser("derivative-profiles", help="List derivative distro profiles")
    derivative_parser = sub.add_parser("derivative-profile", help="Plan or export a derivative distro profile")
    derivative_sub = derivative_parser.add_subparsers(dest="derivative_command")
    for command, help_text in (
        ("plan", "Show derivative profile intent"),
        ("validate", "Validate derivative profile policy"),
        ("export", "Write a derivative profile build definition"),
        ("create-project", "Create a project from a derivative profile"),
    ):
        derivative_command = derivative_sub.add_parser(command, help=help_text)
        derivative_command.add_argument("profile")
        derivative_command.add_argument("--output", type=Path)
        derivative_command.add_argument("--root", type=Path)
        derivative_command.add_argument("--name")
        derivative_command.add_argument("--dockerfile", type=Path)
        derivative_command.add_argument("--json", action="store_true")
    profile_parser = sub.add_parser("profile", help="Create, apply or diff distro profiles")
    profile_sub = profile_parser.add_subparsers(dest="profile_command")
    for command, help_text in (
        ("create", "Write a profile-backed build definition"),
        ("apply", "Write a profile-backed build definition"),
        ("diff", "Show profile package and identity impact"),
    ):
        profile_command = profile_sub.add_parser(command, help=help_text)
        profile_command.add_argument("root", type=Path)
        profile_command.add_argument("profile")
        profile_command.add_argument("--definition", type=Path)
        profile_command.add_argument("--output", type=Path)
        profile_command.add_argument("--json", action="store_true")
    sub.add_parser("personas", help="List beginner-to-pro workflow personas")
    sub.add_parser("desktops", help="List desktop/flavor personalization targets")
    starter_parser = sub.add_parser("source-starters", help="List project source starters")
    starter_parser.add_argument("--release")
    starter_parser.add_argument("--json", action="store_true")
    sub.add_parser("branding-palettes", help="List built-in branding color palettes")
    mirrors_parser = sub.add_parser("mirrors", help="Diagnose, render and manage APT mirrors")
    mirrors_sub = mirrors_parser.add_subparsers(dest="mirrors_command")
    for command, help_text in (
        ("doctor", "Diagnose current APT mirror policy"),
        ("render", "Render deb822 .sources without applying"),
        ("apply", "Backup current sources and apply deb822 mirror policy"),
        ("restore", "Restore the last mirror backup"),
    ):
        mirror_command = mirrors_sub.add_parser(command, help=help_text)
        mirror_command.add_argument("root", type=Path)
        mirror_command.add_argument("--definition", type=Path)
        mirror_command.add_argument("--archive")
        mirror_command.add_argument("--security")
        mirror_command.add_argument("--country")
        mirror_command.add_argument("--allow-http", action="store_true")
        mirror_command.add_argument("--override-ubuntu-security", action="store_true")
        mirror_command.add_argument("--json", action="store_true")
        mirror_command.add_argument("--strict", action="store_true")
    branding_parser = sub.add_parser("branding", help="Audit branding compliance and clearance")
    branding_sub = branding_parser.add_subparsers(dest="branding_command")
    branding_audit = branding_sub.add_parser(
        "audit",
        aliases=["compliance"],
        help="Audit current branding options",
    )
    branding_audit.add_argument("root", type=Path)
    branding_audit.add_argument("--definition", type=Path)
    branding_audit.add_argument("--mode", choices=["internal", "redistributable", "approved"], default="internal")
    branding_audit.add_argument("--json", action="store_true")
    branding_validate = branding_sub.add_parser("validate", help="Fail if branding is not clear for the selected mode")
    branding_validate.add_argument("root", type=Path)
    branding_validate.add_argument("--definition", type=Path)
    branding_validate.add_argument("--mode", choices=["internal", "redistributable", "approved"], default="redistributable")
    branding_clearance = branding_sub.add_parser("clearance", help="Write TRADEMARK-CLEARANCE.json")
    branding_clearance.add_argument("root", type=Path)
    branding_clearance.add_argument("--definition", type=Path)
    branding_clearance.add_argument("--mode", choices=["internal", "redistributable", "approved"], default="redistributable")
    branding_clearance.add_argument("--output", type=Path)
    branding_set = branding_sub.add_parser("set", help="Render an identity from build options")
    branding_set.add_argument("root", type=Path)
    branding_set.add_argument("--definition", type=Path)
    branding_set.add_argument("--output", type=Path)
    branding_export = branding_sub.add_parser("export", help="Export BRANDING-MANIFEST.json")
    branding_export.add_argument("root", type=Path)
    branding_export.add_argument("--definition", type=Path)
    branding_export.add_argument("--output", type=Path)
    branding_import = branding_sub.add_parser("import", help="Import a BRANDING-MANIFEST.json as build definition")
    branding_import.add_argument("root", type=Path)
    branding_import.add_argument("identity", type=Path)
    branding_import.add_argument("--output", type=Path)
    branding_preview = branding_sub.add_parser("preview", help="Export branding previews")
    branding_preview.add_argument("root", type=Path)
    branding_preview.add_argument("--definition", type=Path)
    branding_preview.add_argument("--target", choices=["grub", "plymouth", "metadata", "all"], default="all")
    branding_preview.add_argument("--output-dir", type=Path)

    debrand_parser = sub.add_parser("debrand", help="Scan, plan or apply source ISO debranding")
    debrand_sub = debrand_parser.add_subparsers(dest="debrand_command")
    for command, help_text in (
        ("scan", "Scan extracted ISO/rootfs identity traces"),
        ("plan", "Print debranding replacement plan"),
        ("apply", "Apply text replacements to extracted ISO/rootfs"),
    ):
        debrand_command = debrand_sub.add_parser(command, help=help_text)
        debrand_command.add_argument("root", type=Path)
        debrand_command.add_argument("--definition", type=Path)
        debrand_command.add_argument("--json", action="store_true")
        debrand_command.add_argument("--strict", action="store_true")
        debrand_command.add_argument("--output", type=Path)
    sub.add_parser("frameworks", help="Show optional framework integration status")
    doctor_parser = sub.add_parser("doctor", help="Check host tooling")
    doctor_parser.add_argument("--install", action="store_true", help="Install missing required apt packages")
    doctor_parser.add_argument("--include-optional", action="store_true")
    doctor_parser.add_argument("--no-sudo", action="store_true")
    doctor_parser.add_argument("--python", action="store_true", help="Check Python package dependencies")
    doctor_parser.add_argument("--debian-dev", action="store_true", help="Check Debian/Ubuntu maintainer tooling")
    doctor_parser.add_argument("--fix-python", action="store_true", help="Print venv install commands")
    from .commands.host import register_host_commands

    register_host_commands(sub)

    preset_parser = sub.add_parser("presets", help="List or export built-in customization presets")
    preset_parser.add_argument("--export", choices=list(BUILTIN_PRESETS))
    preset_parser.add_argument("--output", type=Path)

    compat_parser = sub.add_parser("compat", help="Check DistroForge release compatibility")
    compat_parser.add_argument("root", type=Path)
    compat_parser.add_argument("--definition", type=Path)
    compat_parser.add_argument("--ppa", action="append", default=[])

    ci_parser = sub.add_parser("ci", help="Run lint/test/dry-run CI checks")
    ci_parser.add_argument("root", type=Path)
    ci_parser.add_argument("--no-pytest", action="store_true")
    ci_parser.add_argument("--no-ruff", action="store_true")
    ci_parser.add_argument("--no-build-dry-run", action="store_true")
    ci_parser.add_argument("--debian-package", action="store_true")
    ci_parser.add_argument("--execute", action="store_true")

    from .commands.packaging import register_packaging_commands

    register_packaging_commands(sub)

    restore_parser = sub.add_parser("restore-snapshot", help="Restore a rootfs rollback snapshot")
    restore_parser.add_argument("root", type=Path)
    restore_parser.add_argument("snapshot")
    restore_parser.add_argument("--execute", action="store_true")

    templates_parser = sub.add_parser("autoinstall-templates", help="List or render autoinstall templates")
    templates_parser.add_argument("--render", choices=list(TEMPLATES))

    plugins_parser = sub.add_parser("plugins", help="List local DistroForge plugins")
    plugins_parser.add_argument("root", type=Path)

    secureboot_parser = sub.add_parser("secureboot-assist", help="Plan Secure Boot MOK key workflow")
    secureboot_parser.add_argument("output_dir", type=Path)
    secureboot_parser.add_argument("--common-name", default="DistroForge MOK")
    secureboot_parser.add_argument("--execute", action="store_true")

    init_def_parser = sub.add_parser("init-definition", help="Write an example image definition")
    init_def_parser.add_argument("path", type=Path)

    recipe_parser = sub.add_parser("recipe", help="Suggest an image definition from a short prompt")
    recipe_parser.add_argument("text")

    explain_parser = sub.add_parser("explain", help="Explain what a build would do in plain language")
    explain_parser.add_argument("root", type=Path)

    ux_parser = sub.add_parser("ux-audit", help="Audit persona UX, safety and CLI/GUI parity")
    ux_parser.add_argument("root", type=Path)
    ux_parser.add_argument("--definition", type=Path)
    ux_parser.add_argument("--json", action="store_true")

    readiness_parser = sub.add_parser("readiness", help="Show build readiness dashboard")
    readiness_parser.add_argument("root", type=Path)
    readiness_parser.add_argument("--definition", type=Path)
    readiness_parser.add_argument("--json", action="store_true")
    register_trust_arguments(readiness_parser)
    from .commands.journey import register_journey_parser
    register_journey_parser(sub)
    from .commands.beginner_iso import register_beginner_iso_parser
    register_beginner_iso_parser(sub)
    from .commands.poweruser_iso import register_poweruser_iso_parser
    register_poweruser_iso_parser(sub)

    dry_run_parser = sub.add_parser("dry-run-report", help="Write a structured dry-run report")
    dry_run_parser.add_argument("root", type=Path)
    dry_run_parser.add_argument("--definition", type=Path)
    dry_run_parser.add_argument("--json", action="store_true")
    dry_run_parser.add_argument("--output", type=Path, help="Write the report to a file")
    dry_run_parser.add_argument("--no-command-simulation", action="store_true")
    register_trust_arguments(dry_run_parser)

    risk_parser = sub.add_parser("explain-risk", help="Explain risky options in plain language")
    risk_parser.add_argument("root", type=Path)
    risk_parser.add_argument("--definition", type=Path)
    register_trust_arguments(risk_parser)

    glossary_parser = sub.add_parser("glossary", help="Explain DistroForge and ISO build terms")
    glossary_parser.add_argument("term", nargs="?")

    from .core.phase_contracts import PIPELINE_STAGES

    phases_parser = sub.add_parser(
        "build-phases",
        help="Show build phase contracts (inputs, artifacts, privileges, rollback)",
    )
    phases_parser.add_argument(
        "--stage",
        choices=[stage for stage in PIPELINE_STAGES if stage != "build_services"],
        help="Limit output to a single pipeline stage",
    )

    guided_parser = sub.add_parser("guided-recipe", help="List or render guided recipe prompts")
    guided_parser.add_argument("name", nargs="?")
    guided_parser.add_argument("--json", action="store_true")

    review_parser = sub.add_parser("ai-review", help="Local AI-assisted maintainer review")
    review_parser.add_argument("root", type=Path)
    review_parser.add_argument("--definition", type=Path)
    review_parser.add_argument("--json", action="store_true")
    register_trust_arguments(review_parser)

    forgeadvisor_parser = sub.add_parser(
        "forgeadvisor",
        help="Local-first advisory explanations for logs and build reports",
    )
    forgeadvisor_sub = forgeadvisor_parser.add_subparsers(dest="forgeadvisor_command", required=True)
    backend_help = "Local-first narration backend; degrades to offline if unavailable"
    register_help = (
        "Advisory voice register; defaults to the saved workflow level (silent, overridable)"
    )
    forgeadvisor_explain = forgeadvisor_sub.add_parser("explain-log", help="Explain a build log with citations")
    forgeadvisor_explain.add_argument("log", type=Path)
    forgeadvisor_explain.add_argument("--backend", choices=backend_names(), default="offline", help=backend_help)
    forgeadvisor_explain.add_argument("--register", choices=register_keys(), default=None, help=register_help)
    forgeadvisor_explain.add_argument("--json", action="store_true")
    forgeadvisor_triage = forgeadvisor_sub.add_parser("triage-log", help="Triage a build log into likely causes")
    forgeadvisor_triage.add_argument("log", type=Path)
    forgeadvisor_triage.add_argument("--backend", choices=backend_names(), default="offline", help=backend_help)
    forgeadvisor_triage.add_argument("--register", choices=register_keys(), default=None, help=register_help)
    forgeadvisor_triage.add_argument("--json", action="store_true")
    forgeadvisor_evidence = forgeadvisor_sub.add_parser("explain-evidence", help="Explain evidence-status findings")
    forgeadvisor_evidence.add_argument("root", type=Path)
    forgeadvisor_evidence.add_argument("--iso", type=Path)
    forgeadvisor_evidence.add_argument("--output-dir", type=Path)
    forgeadvisor_evidence.add_argument("--profile", choices=["dev", "package", "iso", "publish"], default="publish")
    forgeadvisor_evidence.add_argument("--backend", choices=backend_names(), default="offline", help=backend_help)
    forgeadvisor_evidence.add_argument("--register", choices=register_keys(), default=None, help=register_help)
    forgeadvisor_evidence.add_argument("--json", action="store_true")
    forgeadvisor_fix_plan = forgeadvisor_sub.add_parser("fix-plan", help="Narrate the evidence fix plan without running it")
    forgeadvisor_fix_plan.add_argument("root", type=Path)
    forgeadvisor_fix_plan.add_argument("--iso", type=Path)
    forgeadvisor_fix_plan.add_argument("--output-dir", type=Path)
    forgeadvisor_fix_plan.add_argument("--profile", choices=["dev", "package", "iso", "publish"], default="publish")
    forgeadvisor_fix_plan.add_argument("--backend", choices=backend_names(), default="offline", help=backend_help)
    forgeadvisor_fix_plan.add_argument("--register", choices=register_keys(), default=None, help=register_help)
    forgeadvisor_fix_plan.add_argument("--json", action="store_true")
    forgeadvisor_definition = forgeadvisor_sub.add_parser("review-definition", help="Review a build definition or recipe")
    forgeadvisor_definition.add_argument("definition", type=Path)
    forgeadvisor_definition.add_argument("--backend", choices=backend_names(), default="offline", help=backend_help)
    forgeadvisor_definition.add_argument("--register", choices=register_keys(), default=None, help=register_help)
    forgeadvisor_definition.add_argument("--json", action="store_true")
    forgeadvisor_search = forgeadvisor_sub.add_parser("search-local", help="Search local docs, reports, tests, and source with citations")
    forgeadvisor_search.add_argument("root", type=Path)
    forgeadvisor_search.add_argument("query")
    forgeadvisor_search.add_argument("--limit", type=int, default=8)
    forgeadvisor_search.add_argument("--backend", choices=backend_names(), default="offline", help=backend_help)
    forgeadvisor_search.add_argument("--register", choices=register_keys(), default=None, help=register_help)
    forgeadvisor_search.add_argument("--json", action="store_true")
    forgeadvisor_copilot = forgeadvisor_sub.add_parser("copilot", help="Run the read-only Maintainer Copilot view")
    forgeadvisor_copilot.add_argument("root", type=Path)
    forgeadvisor_copilot.add_argument("--iso", type=Path)
    forgeadvisor_copilot.add_argument("--output-dir", type=Path)
    forgeadvisor_copilot.add_argument("--profile", choices=["dev", "package", "iso", "publish"], default="publish")
    forgeadvisor_copilot.add_argument("--query", default="evidence release readiness")
    forgeadvisor_copilot.add_argument("--limit", type=int, default=5)
    forgeadvisor_copilot.add_argument("--backend", choices=backend_names(), default="offline", help=backend_help)
    forgeadvisor_copilot.add_argument("--register", choices=register_keys(), default=None, help=register_help)
    forgeadvisor_copilot.add_argument("--json", action="store_true")
    forgeadvisor_review = forgeadvisor_sub.add_parser("review-build", help="Review readiness and dry-run findings")
    forgeadvisor_review.add_argument("root", type=Path)
    forgeadvisor_review.add_argument("--definition", type=Path)
    forgeadvisor_review.add_argument(
        "--no-sudo",
        action="store_true",
        help="Review a build that runs without the privilege helper (mirrors the GUI sudo toggle)",
    )
    forgeadvisor_review.add_argument("--backend", choices=backend_names(), default="offline", help=backend_help)
    forgeadvisor_review.add_argument("--register", choices=register_keys(), default=None, help=register_help)
    forgeadvisor_review.add_argument("--json", action="store_true")
    register_trust_arguments(forgeadvisor_review)
    forgeadvisor_propose = forgeadvisor_sub.add_parser(
        "propose-fixes",
        help="Preview a remediation plan and option diff (never applied)",
    )
    forgeadvisor_propose.add_argument("root", type=Path)
    forgeadvisor_propose.add_argument("--definition", type=Path)
    forgeadvisor_propose.add_argument(
        "--no-sudo",
        action="store_true",
        help="Preview fixes for a build that runs without the privilege helper (mirrors the GUI sudo toggle)",
    )
    forgeadvisor_propose.add_argument("--backend", choices=backend_names(), default="offline", help=backend_help)
    forgeadvisor_propose.add_argument("--register", choices=register_keys(), default=None, help=register_help)
    forgeadvisor_propose.add_argument("--json", action="store_true")
    register_trust_arguments(forgeadvisor_propose)
    forgeadvisor_doctor = forgeadvisor_sub.add_parser("doctor-ai", help="Show optional local AI backend status")
    forgeadvisor_doctor.add_argument("--backend", choices=backend_names(), default="offline", help=backend_help)
    forgeadvisor_doctor.add_argument("--register", choices=register_keys(), default=None, help=register_help)
    forgeadvisor_doctor.add_argument("--json", action="store_true")
    forgeadvisor_memory = forgeadvisor_sub.add_parser(
        "memory",
        help="Summarize the host-owned build-memory corpus with a citation",
    )
    forgeadvisor_memory.add_argument("--limit", type=int, default=5, help="How many recent attempts to summarize")
    forgeadvisor_memory.add_argument("--json", action="store_true")

    export_recipe_parser = sub.add_parser("export-recipe", help="Export project and current defaults as a recipe")
    export_recipe_parser.add_argument("root", type=Path)
    export_recipe_parser.add_argument("target", type=Path)

    export_preset_parser = sub.add_parser(
        "export-build-preset",
        help="Export a reproducible maintainer build preset",
    )
    export_preset_parser.add_argument("root", type=Path)
    export_preset_parser.add_argument("target", type=Path)
    export_preset_parser.add_argument("--definition", type=Path)
    export_preset_parser.add_argument("--channel")
    export_preset_parser.add_argument("--revision")
    export_preset_parser.add_argument("--notes")

    capture_parser = sub.add_parser(
        "capture",
        help="Capture installed system intent as a sanitized profile",
    )
    capture_parser.add_argument("target", type=Path)
    capture_parser.add_argument("--output", type=Path)
    capture_parser.add_argument("--sanitize", choices=["strict", "review"], default="strict")
    capture_parser.add_argument("--include-config", action="append", default=[], type=Path)
    capture_parser.add_argument("--include-config-glob", action="append", default=[])
    capture_parser.add_argument("--json", action="store_true")

    capture_diff_parser = sub.add_parser("capture-diff", help="Show captured profile package/config/finding diff")
    capture_diff_parser.add_argument("profile", type=Path)
    capture_diff_parser.add_argument("--json", action="store_true")

    rebuild_parser = sub.add_parser(
        "rebuild-from-capture",
        help="Create a project that builds from a captured profile",
    )
    rebuild_parser.add_argument("profile", type=Path)
    rebuild_parser.add_argument("root", type=Path)
    rebuild_parser.add_argument("--name")
    rebuild_parser.add_argument("--release")

    live_build_parser = sub.add_parser(
        "live-build-plan",
        help="Generate a Debian live-build config plan from a profile",
    )
    live_build_parser.add_argument("profile", type=Path)
    live_build_parser.add_argument("--output-dir", type=Path, required=True)
    live_build_parser.add_argument("--write", action="store_true")
    live_build_parser.add_argument("--json", action="store_true")

    artifacts_parser = sub.add_parser("artifact-paths", help="Show host artifact paths")
    artifacts_parser.add_argument("root", type=Path)
    artifacts_parser.add_argument("--json", action="store_true")
    release_ready_parser = sub.add_parser("release-readiness", help="Summarize release artifact readiness")
    release_ready_parser.add_argument("--iso", type=Path, required=True)
    release_ready_parser.add_argument("--output-dir", type=Path, required=True)
    release_ready_parser.add_argument("--json", action="store_true")
    from .commands.iso import register_iso_commands

    register_iso_commands(sub)
    from .commands.artifacts import (
        register_boot_proof_parser,
        register_explain_release_parser,
        register_preview_parser,
        register_publish_bundle_parser,
        register_publish_drill_baseline_parser,
        register_publish_drill_diff_parser,
        register_publish_drill_parser,
        register_qemu_interaction_parser,
        register_release_gate_parser,
        register_release_notes_parser,
        register_release_pipeline_parser,
        register_sign_release_parser,
        register_verify_release_parser,
    )
    from .commands.evidence import register_evidence_commands

    register_evidence_commands(sub)
    register_release_gate_parser(sub)
    register_publish_bundle_parser(sub)
    register_sign_release_parser(sub)
    register_release_notes_parser(sub)
    register_verify_release_parser(sub)
    register_explain_release_parser(sub)
    register_publish_drill_parser(sub)
    register_publish_drill_diff_parser(sub)
    register_publish_drill_baseline_parser(sub)
    register_release_pipeline_parser(sub)
    register_boot_proof_parser(sub)
    register_preview_parser(sub)
    register_qemu_interaction_parser(sub)
    qemu_smoke_parser = sub.add_parser("qemu-smoke-plan", help="Plan QEMU live/install smoke scenarios")
    qemu_smoke_parser.add_argument("--iso", type=Path, required=True)
    qemu_smoke_parser.add_argument("--json", action="store_true")

    livefs_iso_plan_parser = sub.add_parser(
        "livefs-iso-plan",
        help="Plan an Ubuntu livefs-built ISO pipeline",
    )
    _add_livefs_iso_args(livefs_iso_plan_parser)

    livefs_iso_build_parser = sub.add_parser(
        "livefs-iso-build",
        help="Write a reviewable Ubuntu livefs ISO build workspace",
    )
    _add_livefs_iso_args(livefs_iso_build_parser)
    livefs_iso_build_parser.add_argument("--write", action="store_true")

    upgrade_parser = sub.add_parser(
        "upgrade-media",
        help="Run read-only upgrade media preflight checks",
    )
    upgrade_parser.add_argument("--target", type=Path, default=Path("/"))
    upgrade_parser.add_argument("--from", dest="from_release")
    upgrade_parser.add_argument("--to", dest="to_release", required=True)
    upgrade_parser.add_argument("--json", action="store_true")

    image_parser = sub.add_parser(
        "image-plan",
        help="Plan an OEM/systemd image workflow",
    )
    image_parser.add_argument("--mode", choices=["appliance", "oem", "immutable"], default="appliance")
    image_parser.add_argument("--partition-layout", type=Path)
    image_parser.add_argument("--update-strategy", choices=["manual", "ab", "sysupdate"], default="manual")
    image_parser.add_argument("--json", action="store_true")

    new_parser = sub.add_parser("new", help="Create a project")
    new_parser.add_argument("name")
    new_parser.add_argument("root", type=Path)
    new_parser.add_argument("--release", default="26.04")
    new_parser.add_argument(
        "--starter",
        choices=[*BUILTIN_SOURCE_STARTERS, "local-iso", "previous-project"],
        help="Initial source starter. Defaults to the release skeleton.",
    )
    new_parser.add_argument("--source-iso", type=Path)
    new_parser.add_argument("--previous-project", type=Path)
    new_parser.add_argument("--from-scratch", action="store_true")
    register_trust_arguments(new_parser)

    plan_parser = sub.add_parser("plan", help="Print the build pipeline for a project")
    plan_parser.add_argument("root", type=Path)
    plan_parser.add_argument("--source-iso", type=Path)
    plan_parser.add_argument("--from-scratch", action="store_true")
    plan_parser.add_argument("--preview", action="store_true")
    register_customization_arguments(plan_parser)

    validate_parser = sub.add_parser("validate", help="Validate a project and host")
    validate_parser.add_argument("root", type=Path)
    validate_parser.add_argument("--source-iso", type=Path)
    validate_parser.add_argument("--from-scratch", action="store_true")
    validate_parser.add_argument("--execute", action="store_true")
    register_customization_arguments(validate_parser)

    build_parser = sub.add_parser("build", help="Run or dry-run a project build")
    register_build_arguments(build_parser)

    sub.add_parser("gui", help="Launch the Qt desktop UI")
    return parser


def _main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "releases":
        from .commands.releases import run_releases
        run_releases()
        return

    if args.command == "frameworks":
        from .commands.frameworks import run_frameworks
        run_frameworks()
        return

    if args.command == "doctor":
        from .commands.doctor import run_doctor_command
        run_doctor_command(
            fix_python=args.fix_python,
            python=args.python,
            debian_dev=args.debian_dev,
            install=args.install,
            include_optional=args.include_optional,
            no_sudo=args.no_sudo,
        )
        return

    from .commands.host import render_host_command
    host_output = render_host_command(args)
    if host_output is not None:
        print(host_output)
        return

    if args.command == "profiles":
        from .commands.catalog import render_profiles
        print(render_profiles())
        return

    if args.command == "derivative-profiles":
        from .commands.derivative import list_derivative_profiles

        print(list_derivative_profiles())
        return

    if args.command == "derivative-profile":
        from .commands.derivative import (
            create_derivative_project,
            export_derivative_profile,
            render_derivative_profile,
        )

        if not args.derivative_command:
            parser.parse_args(["derivative-profile", "--help"])
            return
        if args.derivative_command == "create-project":
            print(
                create_derivative_project(
                    args.profile,
                    args.root or Path(f"{args.profile}-project"),
                    args.name,
                    args.dockerfile,
                    args.json,
                ),
                end="",
            )
            return
        if args.derivative_command == "export":
            target = args.output or Path(f"{args.profile}-derivative.yaml")
            print(export_derivative_profile(args.profile, target, args.dockerfile, args.json), end="")
            return
        print(render_derivative_profile(args.profile, args.dockerfile, args.json))
        return

    if args.command == "profile":
        from .commands.profile import run_profile
        run_profile(args, parser)
        return

    if args.command == "presets":
        from .commands.presets import run_presets
        run_presets(args)
        return

    from .commands.packaging import render_packaging_command

    output = render_packaging_command(args)
    if output is not None:
        print(output)
        return

    if args.command == "compat":
        from .commands.compat import run_compat
        run_compat(args)
        return

    if args.command == "ci":
        from .commands.ci import run_ci
        run_ci(args)
        return

    if args.command == "restore-snapshot":
        from .commands.privileged_plans import run_restore_snapshot
        run_restore_snapshot(args)
        return

    if args.command == "autoinstall-templates":
        from .commands.catalog import render_autoinstall_templates
        print(render_autoinstall_templates(args.render))
        return

    if args.command == "plugins":
        from .commands.plugins import render_plugins
        print(render_plugins(args.root))
        return

    if args.command == "secureboot-assist":
        from .commands.privileged_plans import run_secureboot_assist
        run_secureboot_assist(args)
        return

    if args.command == "personas":
        from .commands.catalog import render_personas
        print(render_personas())
        return

    if args.command == "init-definition":
        write_definition(json.loads(example_definition()), args.path)
        print(f"Wrote {args.path}")
        return

    if args.command == "recipe":
        print(RecipeAdvisor().render_json(args.text))
        return

    if args.command == "explain":
        from .commands.explain import render_explain

        print(render_explain(args.root))
        return

    if args.command == "ux-audit":
        from .commands.ux_audit import run_ux_audit
        run_ux_audit(args)
        return

    if args.command == "readiness":
        from .commands.advisory import render_readiness
        print(render_readiness(args))
        return

    if args.command == "journey":
        from .commands.journey import render_from_args
        print(render_from_args(args))
        return
    if args.command == "beginner-iso":
        from .commands.beginner_iso import render_beginner_iso
        print(render_beginner_iso(args))
        return
    if args.command == "poweruser-iso":
        from .commands.poweruser_iso import render_poweruser_iso
        print(render_poweruser_iso(args))
        return

    if args.command == "dry-run-report":
        from .commands.dry_run_report import run_dry_run_report
        run_dry_run_report(args)
        return

    if args.command == "explain-risk":
        from .commands.advisory import render_explain_risk
        print(render_explain_risk(args))
        return

    if args.command == "glossary":
        from .core.education import render_glossary

        print(render_glossary(args.term))
        return

    if args.command == "build-phases":
        from .core.phase_contracts import render_phase_contracts

        print(render_phase_contracts(args.stage))
        return

    if args.command == "guided-recipe":
        from .commands.guided_recipe import run_guided_recipe
        run_guided_recipe(args)
        return

    if args.command == "ai-review":
        from .commands.advisory import render_ai_review
        print(render_ai_review(args))
        return

    if args.command == "forgeadvisor":
        from .commands.forgeadvisor import run_forgeadvisor
        run_forgeadvisor(args)
        return

    if args.command == "export-recipe":
        from .commands.recipes import export_project_recipe

        export_project_recipe(args.root, args.target)
        print(f"Wrote {args.target}")
        return

    if args.command == "export-build-preset":
        from .commands.export_build_preset import run_export_build_preset
        run_export_build_preset(args)
        return

    if args.command == "capture":
        from .commands.capture import run_capture

        print(run_capture(
            args.target,
            sanitize=args.sanitize,
            include_configs=args.include_config,
            include_config_globs=args.include_config_glob,
            output=args.output,
            json_output=args.json,
        ), end="")
        return

    if args.command == "capture-diff":
        from .commands.capture import render_capture_diff

        print(render_capture_diff(args.profile, args.json))
        return

    if args.command == "rebuild-from-capture":
        from .commands.capture import run_rebuild_from_capture
        run_rebuild_from_capture(args)
        return

    if args.command == "live-build-plan":
        from .commands.livefs import render_live_build_plan

        print(render_live_build_plan(args.profile, args.output_dir, write=args.write, json_output=args.json))
        return

    from .commands.evidence import render_evidence_command
    evidence_output = render_evidence_command(args)
    if evidence_output is not None:
        rendered, blocked = evidence_output
        print(rendered)
        if blocked:
            raise SystemExit(2)
        return

    from .commands.artifacts import render_artifacts_command
    artifacts_output = render_artifacts_command(args)
    if artifacts_output is not None:
        rendered, blocked = artifacts_output
        print(rendered)
        if blocked:
            raise SystemExit(2)
        return

    from .commands.iso import render_iso_command
    iso_output = render_iso_command(args)
    if iso_output is not None:
        rendered, blocked = iso_output
        print(rendered)
        if blocked:
            raise SystemExit(2)
        return
    if args.command in {"livefs-iso-plan", "livefs-iso-build"}:
        from .commands.livefs import render_livefs_iso
        print(render_livefs_iso(
            args.profile,
            args.work_dir,
            args.dest,
            command=args.command,
            write=getattr(args, "write", False),
            json_output=args.json,
            series=args.series,
            arch=args.arch,
            mirror=args.mirror,
            components=args.components,
            disk_id=args.disk_id,
            project=args.project,
            volume_id=args.volume_id,
        ), end="")
        return

    if args.command == "upgrade-media":
        from .core.upgrade_media import UpgradeMediaPreflight

        report = UpgradeMediaPreflight().check(args.target, args.from_release, args.to_release)
        print(report.render_json() if args.json else report.render_text())
        if report.blocked:
            raise SystemExit(2)
        return

    if args.command == "image-plan":
        from .core.systemd_image import SystemdImagePlan

        plan = SystemdImagePlan(
            mode=args.mode,
            partition_layout=args.partition_layout,
            update_strategy=args.update_strategy,
        )
        print(plan.render_json() if args.json else plan.render_text())
        return

    if args.command == "desktops":
        from .commands.catalog import render_desktops
        print(render_desktops())
        return

    if args.command == "source-starters":
        from .commands.catalog import render_source_starters
        print(render_source_starters(args.release, args.json))
        return

    if args.command == "branding-palettes":
        from .commands.catalog import render_branding_palettes
        print(render_branding_palettes())
        return

    if args.command == "mirrors":
        from .commands.mirrors import run_mirrors
        run_mirrors(args, parser)
        return

    if args.command == "branding":
        from .commands.branding import run_branding
        run_branding(args, parser)
        return

    if args.command == "debrand":
        from .commands.debrand import run_debrand
        run_debrand(args, parser)
        return

    if args.command == "new":
        from .commands.new import run_new
        run_new(args)
        return

    if args.command == "plan":
        from .commands.build import run_plan
        run_plan(args)
        return

    if args.command == "validate":
        from .commands.build import run_validate
        run_validate(args)
        return

    if args.command == "build":
        from .commands.build import run_build
        run_build(args)
        return

    if args.command == "gui":
        from .ui.app import run

        raise SystemExit(run())

    parser.print_help()
    if argv is None:
        raise SystemExit(1)
    sys.exit(1)


def _friendly_error(exc: BaseException) -> str:
    if isinstance(exc, FileNotFoundError):
        return str(exc)
    if isinstance(exc, json.JSONDecodeError):
        return f"Invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
    return str(exc) or exc.__class__.__name__


def _add_livefs_iso_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("profile", type=Path)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--dest", type=Path, required=True)
    parser.add_argument("--series")
    parser.add_argument("--arch", default="amd64")
    parser.add_argument("--mirror", default="http://archive.ubuntu.com/ubuntu")
    parser.add_argument("--component", dest="components", action="append")
    parser.add_argument("--disk-id")
    parser.add_argument("--project")
    parser.add_argument("--volume-id")
    parser.add_argument("--json", action="store_true")
