from __future__ import annotations

from pathlib import Path

from distroforge.core.artifact_paths import default_artifact_paths
from distroforge.core.boot_proof import run_boot_proof
from distroforge.core.command import CommandRunner
from distroforge.core.interaction_plan import available_interaction_plans, resolve_interaction_plan
from distroforge.core.project import Project
from distroforge.core.publish_bundle import create_publish_bundle
from distroforge.core.publish_drill import run_publish_drill
from distroforge.core.publish_drill_baseline import promote_publish_drill_baseline
from distroforge.core.publish_drill_diff import diff_publish_drills
from distroforge.core.qemu_interaction import QemuInteractionOptions, QemuInteractionService
from distroforge.core.qemu_preview import QemuPreviewOptions, QemuPreviewService
from distroforge.core.qemu_smoke import QemuSmokePlanner
from distroforge.core.release_explain import explain_release
from distroforge.core.release_gate import ReleaseGateService
from distroforge.core.release_notes import write_release_notes
from distroforge.core.release_pipeline import run_release_pipeline
from distroforge.core.release_readiness import ReleaseReadinessService
from distroforge.core.release_signing import sign_release_bundle
from distroforge.core.release_verification import verify_release_bundle


def render_artifact_paths(root: Path, json_output: bool = False) -> str:
    paths = default_artifact_paths(Project.load(root))
    return paths.render_json() if json_output else paths.render_text()


def render_artifacts_command(args) -> tuple[str, bool] | None:
    if args.command == "artifact-paths":
        return render_artifact_paths(args.root, args.json), False
    if args.command == "release-readiness":
        return render_release_readiness(args.iso, args.output_dir, args.json)
    if args.command == "release-gate":
        return render_release_gate(args.root, args.definition, args.iso, args.output_dir, args.json)
    if args.command == "publish-bundle":
        return render_publish_bundle(args.root, args.definition, args.iso, args.output_dir, args.bundle_dir, args.json), False
    if args.command == "sign-release":
        return render_sign_release(args.root, args.bundle_dir, args.gpg_key, args.execute, args.json), False
    if args.command == "release-notes":
        return render_release_notes(args.root, args.bundle_dir, args.json), False
    if args.command == "verify-release":
        return render_verify_release(args.root, args.bundle_dir, args.json), False
    if args.command == "explain-release":
        return render_explain_release(args.root, args.iso, args.bundle_dir, args.json), False
    if args.command == "publish-drill":
        return render_publish_drill(args.root, args.definition, args.iso, args.bundle_dir, args.gpg_key, args.execute_signing, args.boot_backend, args.json), False
    if args.command == "publish-drill-diff":
        return render_publish_drill_diff(args.old, args.new, args.json), False
    if args.command == "publish-drill-baseline":
        return render_publish_drill_baseline(args.root, args.bundle_dir, args.allow_blocked, args.json), False
    if args.command == "release-pipeline":
        return render_release_pipeline(args.root, args.definition, args.iso, args.output_dir, args.bundle_dir, args.gpg_key, args.execute_signing, args.run_boot_proof, args.boot_proof_dry_run, args.boot_backend, args.json), False
    if args.command == "boot-proof":
        return render_boot_proof(args.root, args.definition, args.iso, args.backend, args.timeout, args.dry_run, args.json), False
    if args.command == "preview":
        return render_preview(args.root, args.definition, args.iso, args.display, args.execute, args.json), False
    if args.command == "qemu-interaction":
        return render_qemu_interaction(args.root, args.definition, args.iso, args.plan, args.display, args.list, args.execute, args.json), False
    if args.command == "qemu-smoke-plan":
        return render_qemu_smoke_plan(args.iso, args.json), False
    return None


def render_release_readiness(iso: Path, output_dir: Path, json_output: bool = False) -> tuple[str, bool]:
    report = ReleaseReadinessService().check(iso, output_dir)
    return (report.render_json() if json_output else report.render_text(), report.blocked)


def render_qemu_smoke_plan(iso: Path, json_output: bool = False) -> str:
    plan = QemuSmokePlanner().plan(iso)
    return plan.render_json() if json_output else plan.render_text()


def register_release_gate_parser(subparsers) -> None:
    parser = subparsers.add_parser("release-gate", help="Check maintainer release publication gate")
    parser.add_argument("root", type=Path)
    parser.add_argument("--definition", type=Path)
    parser.add_argument("--iso", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--json", action="store_true")


def register_publish_bundle_parser(subparsers) -> None:
    parser = subparsers.add_parser("publish-bundle", help="Create a maintainer publish inspection bundle")
    parser.add_argument("root", type=Path)
    parser.add_argument("--definition", type=Path)
    parser.add_argument("--iso", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--bundle-dir", type=Path)
    parser.add_argument("--json", action="store_true")


def register_sign_release_parser(subparsers) -> None:
    parser = subparsers.add_parser("sign-release", help="Generate manifest and sign maintainer publish bundle")
    parser.add_argument("root", type=Path)
    parser.add_argument("--bundle-dir", type=Path)
    parser.add_argument("--gpg-key")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--json", action="store_true")


def register_release_notes_parser(subparsers) -> None:
    parser = subparsers.add_parser("release-notes", help="Write maintainer release notes and changelog")
    parser.add_argument("root", type=Path)
    parser.add_argument("--bundle-dir", type=Path)
    parser.add_argument("--json", action="store_true")


def register_verify_release_parser(subparsers) -> None:
    parser = subparsers.add_parser("verify-release", help="Verify a maintainer publish bundle")
    parser.add_argument("root", type=Path)
    parser.add_argument("--bundle-dir", type=Path)
    parser.add_argument("--json", action="store_true")


def register_explain_release_parser(subparsers) -> None:
    parser = subparsers.add_parser("explain-release", help="Explain release evidence for maintainer publication")
    parser.add_argument("root", type=Path)
    parser.add_argument("--iso", type=Path)
    parser.add_argument("--bundle-dir", type=Path)
    parser.add_argument("--json", action="store_true")


def register_publish_drill_parser(subparsers) -> None:
    parser = subparsers.add_parser("publish-drill", help="Run a safe one-button maintainer publish drill")
    parser.add_argument("root", type=Path)
    parser.add_argument("--definition", type=Path)
    parser.add_argument("--iso", type=Path)
    parser.add_argument("--bundle-dir", type=Path)
    parser.add_argument("--gpg-key")
    parser.add_argument("--execute-signing", action="store_true")
    parser.add_argument("--boot-backend", default="auto", choices=["auto", "qemu", "iso-scan"])
    parser.add_argument("--json", action="store_true")


def register_publish_drill_diff_parser(subparsers) -> None:
    parser = subparsers.add_parser("publish-drill-diff", help="Compare two publish drill JSON reports")
    parser.add_argument("old", type=Path)
    parser.add_argument("new", type=Path)
    parser.add_argument("--json", action="store_true")


def register_publish_drill_baseline_parser(subparsers) -> None:
    parser = subparsers.add_parser("publish-drill-baseline", help="Promote current publish drill as comparison baseline")
    parser.add_argument("root", type=Path)
    parser.add_argument("--bundle-dir", type=Path)
    parser.add_argument("--allow-blocked", action="store_true")
    parser.add_argument("--json", action="store_true")


def register_release_pipeline_parser(subparsers) -> None:
    parser = subparsers.add_parser("release-pipeline", help="Run the maintainer publish pipeline")
    parser.add_argument("root", type=Path)
    parser.add_argument("--definition", type=Path)
    parser.add_argument("--iso", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--bundle-dir", type=Path)
    parser.add_argument("--gpg-key")
    parser.add_argument("--execute-signing", action="store_true")
    parser.add_argument("--run-boot-proof", action="store_true")
    parser.add_argument("--boot-backend", default="auto", choices=["auto", "qemu", "iso-scan"])
    parser.add_argument("--boot-proof-dry-run", action="store_true")
    parser.add_argument("--json", action="store_true")


def register_boot_proof_parser(subparsers) -> None:
    parser = subparsers.add_parser("boot-proof", help="Run or plan normalized ISO boot proof")
    parser.add_argument("root", type=Path)
    parser.add_argument("--definition", type=Path)
    parser.add_argument("--iso", type=Path)
    parser.add_argument("--backend", default="auto", choices=["auto", "qemu", "iso-scan"])
    parser.add_argument("--timeout", type=int)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json", action="store_true")


def register_preview_parser(subparsers) -> None:
    parser = subparsers.add_parser("preview", help="Launch or plan an interactive ISO preview VM")
    parser.add_argument("root", type=Path)
    parser.add_argument("--definition", type=Path)
    parser.add_argument("--iso", type=Path)
    parser.add_argument("--display", default="gtk", choices=["gtk", "spice", "none"])
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--json", action="store_true")


def register_qemu_interaction_parser(subparsers) -> None:
    parser = subparsers.add_parser("qemu-interaction", help="Plan or run a declarative QMP-driven ISO interaction")
    parser.add_argument("root", type=Path, nargs="?")
    parser.add_argument("--definition", type=Path)
    parser.add_argument("--iso", type=Path)
    parser.add_argument("--plan", default="boot-capture")
    parser.add_argument("--display", default="none", choices=["none", "gtk"])
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--json", action="store_true")


def render_release_gate(root: Path, definition: Path | None, iso: Path | None, output_dir: Path | None, json_output: bool = False) -> tuple[str, bool]:
    from distroforge.core.build import BuildOptions
    from distroforge.core.definition import apply_definition, load_definition

    project = Project.load(root)
    options = BuildOptions()
    if definition:
        options = apply_definition(project, load_definition(definition))
    report = ReleaseGateService().check(project, options, iso=iso, output_dir=output_dir)
    return (report.render_json() if json_output else report.render_text(), report.blocked)


def render_publish_bundle(root: Path, definition: Path | None, iso: Path | None, output_dir: Path | None, bundle_dir: Path | None, json_output: bool = False) -> str:
    from distroforge.core.build import BuildOptions
    from distroforge.core.definition import apply_definition, load_definition

    project = Project.load(root)
    options = apply_definition(project, load_definition(definition)) if definition else BuildOptions()
    report = create_publish_bundle(project, options, iso=iso, output_dir=output_dir, bundle_dir=bundle_dir)
    return report.render_json() if json_output else report.render_text()


def render_sign_release(root: Path, bundle_dir: Path | None, gpg_key: str | None, execute: bool = False, json_output: bool = False) -> str:
    report = sign_release_bundle(Project.load(root), bundle_dir=bundle_dir, execute=execute, gpg_key=gpg_key)
    return report.render_json() if json_output else report.render_text()


def render_release_notes(root: Path, bundle_dir: Path | None, json_output: bool = False) -> str:
    report = write_release_notes(Project.load(root), bundle_dir=bundle_dir)
    return report.render_json() if json_output else report.render_text()


def render_verify_release(root: Path, bundle_dir: Path | None, json_output: bool = False) -> str:
    report = verify_release_bundle(Project.load(root), bundle_dir=bundle_dir)
    return report.render_json() if json_output else report.render_text()


def render_explain_release(root: Path, iso: Path | None, bundle_dir: Path | None, json_output: bool = False) -> str:
    report = explain_release(Project.load(root), iso=iso, bundle_dir=bundle_dir)
    return report.render_json() if json_output else report.render_text()


def render_publish_drill(root: Path, definition: Path | None, iso: Path | None, bundle_dir: Path | None, gpg_key: str | None, execute_signing: bool = False, boot_backend: str = "auto", json_output: bool = False) -> str:
    from distroforge.core.build import BuildOptions
    from distroforge.core.definition import apply_definition, load_definition

    project = Project.load(root)
    options = apply_definition(project, load_definition(definition)) if definition else BuildOptions()
    report = run_publish_drill(project, options, iso=iso, bundle_dir=bundle_dir, execute_signing=execute_signing, gpg_key=gpg_key, boot_backend=boot_backend)
    return report.render_json() if json_output else report.render_text()


def render_publish_drill_diff(old: Path, new: Path, json_output: bool = False) -> str:
    report = diff_publish_drills(old, new)
    return report.render_json() if json_output else report.render_text()


def render_publish_drill_baseline(root: Path, bundle_dir: Path | None, allow_blocked: bool = False, json_output: bool = False) -> str:
    report = promote_publish_drill_baseline(Project.load(root), bundle_dir=bundle_dir, allow_blocked=allow_blocked)
    return report.render_json() if json_output else report.render_text()


def render_release_pipeline(root: Path, definition: Path | None, iso: Path | None, output_dir: Path | None, bundle_dir: Path | None, gpg_key: str | None, execute_signing: bool = False, run_boot: bool = False, boot_dry: bool = False, boot_backend: str = "auto", json_output: bool = False) -> str:
    from distroforge.core.build import BuildOptions
    from distroforge.core.definition import apply_definition, load_definition

    project = Project.load(root)
    options = apply_definition(project, load_definition(definition)) if definition else BuildOptions()
    report = run_release_pipeline(project, options, iso=iso, output_dir=output_dir, bundle_dir=bundle_dir, gpg_key=gpg_key, execute_signing=execute_signing, run_boot_proof=run_boot, boot_proof_execute=not boot_dry, boot_proof_backend=boot_backend)
    return report.render_json() if json_output else report.render_text()


def render_boot_proof(root: Path, definition: Path | None, iso: Path | None, backend: str, timeout: int | None, dry_run: bool = False, json_output: bool = False) -> str:
    from distroforge.core.build import BuildOptions
    from distroforge.core.definition import apply_definition, load_definition

    project = Project.load(root)
    options = apply_definition(project, load_definition(definition)) if definition else BuildOptions()
    report = run_boot_proof(project, options, iso=iso, backend=backend, timeout=timeout, execute=not dry_run)
    return report.render_json() if json_output else report.render_text()


def render_preview(root: Path, definition: Path | None, iso: Path | None, display: str, execute: bool = False, json_output: bool = False) -> str:
    from distroforge.core.build import BuildOptions
    from distroforge.core.definition import apply_definition, load_definition

    project = Project.load(root)
    options = apply_definition(project, load_definition(definition)) if definition else BuildOptions()
    target_iso = iso or options.output_iso or project.output_dir / f"{project.name}.iso"
    runner = CommandRunner(dry_run=not execute)
    report = QemuPreviewService(runner, target_iso, project.workdir, project.output_dir, QemuPreviewOptions(display=display)).run()
    return report.render_json() if json_output else report.render_text()


def render_qemu_interaction(root: Path | None, definition: Path | None, iso: Path | None, plan: str, display: str = "none", list_plans: bool = False, execute: bool = False, json_output: bool = False) -> str:
    from distroforge.core.build import BuildOptions
    from distroforge.core.definition import apply_definition, load_definition

    if list_plans:
        return "\n".join(available_interaction_plans())
    assert root is not None
    project = Project.load(root)
    options = apply_definition(project, load_definition(definition)) if definition else BuildOptions()
    target_iso = iso or options.output_iso or project.output_dir / f"{project.name}.iso"
    resolved = resolve_interaction_plan(plan, target_iso)
    runner = CommandRunner(dry_run=not execute)
    report = QemuInteractionService(runner, target_iso, project.workdir, project.output_dir, resolved, QemuInteractionOptions(display=display)).run()
    return report.render_json() if json_output else report.render_text()
