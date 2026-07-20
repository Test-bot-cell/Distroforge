from __future__ import annotations

from pathlib import Path

from distroforge.core.buildinfo import read_buildinfo
from distroforge.core.packaging import (
    HermeticBuildPlan,
    build_debian_package,
    create_hermetic_release_bundle,
    diagnose_autopkgtest,
    packaging_policy_report,
)


def register_packaging_commands(sub) -> None:
    buildinfo_parser = sub.add_parser(
        "buildinfo-report",
        help="Inspect Debian .buildinfo taint and optional .changes suite",
    )
    buildinfo_parser.add_argument("buildinfo", type=Path)
    buildinfo_parser.add_argument("--changes", type=Path)
    buildinfo_parser.add_argument("--json", action="store_true")

    packaging_parser = sub.add_parser("packaging-policy", help="Inspect packaging release policy")
    packaging_parser.add_argument("root", type=Path)
    packaging_parser.add_argument("--buildinfo", type=Path)
    packaging_parser.add_argument("--changes", type=Path)
    packaging_parser.add_argument("--json", action="store_true")

    debian_package_parser = sub.add_parser(
        "debian-package",
        help="Build Debian package and maintainer checks",
    )
    debian_package_parser.add_argument("root", type=Path)
    debian_package_parser.add_argument("--execute", action="store_true")
    debian_package_parser.add_argument("--json", action="store_true")

    autopkgtest_parser = sub.add_parser(
        "autopkgtest-doctor",
        help="Diagnose autopkgtest host/testbed/package failures",
    )
    autopkgtest_parser.add_argument("root", type=Path)
    autopkgtest_parser.add_argument("--deb", type=Path)
    autopkgtest_parser.add_argument("--backend", choices=["null", "schroot", "qemu"], default="null")
    autopkgtest_parser.add_argument("--testbed")
    autopkgtest_parser.add_argument("--execute", action="store_true")
    autopkgtest_parser.add_argument("--output", type=Path)
    autopkgtest_parser.add_argument("--json", action="store_true")

    hermetic_parser = sub.add_parser("hermetic-build-plan", help="Plan a clean Debian package build")
    hermetic_parser.add_argument("root", type=Path)
    hermetic_parser.add_argument("--backend", choices=["sbuild", "pbuilder", "mmdebstrap"], default="sbuild")
    hermetic_parser.add_argument("--suite", default="unstable")
    hermetic_parser.add_argument("--arch", default="amd64")

    bundle_parser = sub.add_parser(
        "hermetic-release-bundle",
        help="Create a local hermetic package release evidence bundle",
    )
    bundle_parser.add_argument("root", type=Path)
    bundle_parser.add_argument("--artifact-dir", type=Path)
    bundle_parser.add_argument("--output", type=Path, required=True)
    bundle_parser.add_argument("--version")
    bundle_parser.add_argument("--suite", default="resolute")
    bundle_parser.add_argument("--arch", default="all")
    bundle_parser.add_argument("--build-timestamp")
    bundle_parser.add_argument("--autopkgtest-dir", type=Path)
    bundle_parser.add_argument("--autopkgtest-report", type=Path)
    bundle_parser.add_argument("--iso", type=Path)
    bundle_parser.add_argument("--replace", action="store_true")
    bundle_parser.add_argument("--json", action="store_true")


def render_packaging_command(args) -> str | None:
    if args.command == "buildinfo-report":
        return render_buildinfo(args.buildinfo, args.json, args.changes)
    if args.command == "packaging-policy":
        return render_packaging_policy(args.root, args.buildinfo, args.json, args.changes)
    if args.command == "debian-package":
        return render_debian_package_build(args.root, execute=args.execute, json_output=args.json)
    if args.command == "autopkgtest-doctor":
        return render_autopkgtest_doctor(
            args.root,
            deb=args.deb,
            backend=args.backend,
            testbed=args.testbed,
            execute=args.execute,
            output=args.output,
            json_output=args.json,
        )
    if args.command == "hermetic-build-plan":
        return render_hermetic_build_plan(args.root, args.backend, args.suite, args.arch)
    if args.command == "hermetic-release-bundle":
        return render_hermetic_release_bundle(
            args.root,
            output=args.output,
            artifact_dir=args.artifact_dir,
            version=args.version,
            suite=args.suite,
            arch=args.arch,
            build_timestamp=args.build_timestamp,
            autopkgtest_dir=args.autopkgtest_dir,
            autopkgtest_report=args.autopkgtest_report,
            iso=args.iso,
            replace=args.replace,
            json_output=args.json,
        )
    return None


def render_buildinfo(path: Path, json_output: bool = False, changes: Path | None = None) -> str:
    report = read_buildinfo(path, changes)
    return report.render_json() if json_output else report.render_text()


def render_packaging_policy(
    root: Path,
    buildinfo: Path | None = None,
    json_output: bool = False,
    changes: Path | None = None,
) -> str:
    report = packaging_policy_report(root, buildinfo, changes)
    return report.render_json() if json_output else report.render_text()


def render_debian_package_build(
    root: Path,
    *,
    execute: bool = False,
    json_output: bool = False,
) -> str:
    report = build_debian_package(root, execute=execute)
    return report.render_json() if json_output else report.render_text()


def render_autopkgtest_doctor(
    root: Path,
    *,
    deb: Path | None = None,
    backend: str = "null",
    testbed: str | None = None,
    execute: bool = False,
    output: Path | None = None,
    json_output: bool = False,
) -> str:
    report = diagnose_autopkgtest(
        root,
        deb=deb,
        backend=backend,
        testbed=testbed,
        execute=execute,
    )
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(report.render_json() + "\n", encoding="utf-8")
    return report.render_json() if json_output else report.render_text()


def render_hermetic_build_plan(
    root: Path,
    backend: str = "sbuild",
    suite: str = "unstable",
    arch: str = "amd64",
) -> str:
    return HermeticBuildPlan(root=root, backend=backend, suite=suite, arch=arch).render_text()


def render_hermetic_release_bundle(
    root: Path,
    *,
    output: Path,
    artifact_dir: Path | None,
    version: str | None,
    suite: str,
    arch: str,
    build_timestamp: str | None,
    autopkgtest_dir: Path | None,
    autopkgtest_report: Path | None,
    iso: Path | None,
    replace: bool = False,
    json_output: bool = False,
) -> str:
    report = create_hermetic_release_bundle(
        root,
        output_dir=output,
        artifact_dir=artifact_dir,
        version=version,
        suite=suite,
        architecture=arch,
        build_timestamp=build_timestamp,
        autopkgtest_dir=autopkgtest_dir,
        autopkgtest_report=autopkgtest_report,
        iso=iso,
        replace=replace,
    )
    return report.render_json() if json_output else report.render_text()
