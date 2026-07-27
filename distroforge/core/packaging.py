from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import yaml

from .artifact_paths import package_artifact_dir
from .buildinfo import AutopkgtestPolicy, PackagingPolicyReport, read_buildinfo, read_changes
from .command import CommandRunner, CommandSpec
from .qemu_smoke import QemuSmokePlanner
from .schema import validate_definition_data

IMPORTANT_DOCS = (
    "docs/acceptance-matrix.md",
    "docs/definitions.md",
    "docs/artifacts-release-readiness.md",
    "docs/derivative-profiles.md",
    "docs/gui-parity.md",
    "docs/maintainer-copilot.md",
    "docs/packaging-release.md",
    "docs/ux-cognitive-ergonomics.md",
    "docs/velocity-responsiveness.md",
    "docs/advisory-agent.md",
)

# lintian profiles are vendors, never suites: /usr/share/lintian/profiles holds
# debian, ubuntu, kali, pureos and friends, so passing the target suite name as the
# profile simply aborts with "Could not find a profile matching: <suite>/main".
# Left unset, the profile comes from dpkg-vendor on whichever host happens to run
# the check, so the same .dsc and .changes can pass on one machine and fail on the
# next.
#
# Pinning "debian" outright was the first answer to that, and it was wrong in one
# specific way: the vendor also decides which suite names the .changes Distribution
# field may hold. Checking a package that targets an Ubuntu suite against the Debian
# profile therefore raised bad-distribution-in-changes-file for a field that was
# correct -- and because the verdict is graded from tags, DistroForge rated its own
# compliant package "failed".
#
# So the profile is derived from the package's own changelog, which travels with the
# source, rather than from the host, which does not. lintian records the suites each
# vendor accepts under LINTIAN_VENDORS_ROOT, so the mapping is read from the checker
# itself instead of being duplicated here. "debian" stays the fallback for a suite no
# installed vendor claims, which keeps that verdict reproducible.
#
# --no-tag-display-limit matters just as much: without it lintian truncates repeated
# tags, and a truncated report cannot be turned into a reason string.
LINTIAN_PROFILE = "debian"
LINTIAN_VENDORS_ROOT = Path("/usr/share/lintian/vendors")


def lintian_vendor_for_suite(suite: str, *, vendors_root: Path | None = None) -> str:
    """The lintian vendor whose profile knows ``suite``, else :data:`LINTIAN_PROFILE`.

    A suite may be qualified (``resolute-updates``), so the base name is tried too.
    """
    root = LINTIAN_VENDORS_ROOT if vendors_root is None else vendors_root
    candidates = [name for name in (suite.strip(), suite.strip().split("-", 1)[0]) if name]
    if not candidates or not root.is_dir():
        return LINTIAN_PROFILE
    # sorted() so two vendors claiming one suite still resolve the same way everywhere.
    for vendor in sorted(entry.name for entry in root.iterdir() if entry.is_dir()):
        known = root / vendor / "main/data/changes-file/known-dists"
        if not known.is_file():
            continue
        dists = {
            line.strip()
            for line in known.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        }
        if any(candidate in dists for candidate in candidates):
            return vendor
    return LINTIAN_PROFILE


def lintian_argv(suite: str = "", *, vendors_root: Path | None = None) -> tuple[str, ...]:
    """The one lintian invocation every call site must use."""
    return ("lintian", "--profile", lintian_vendor_for_suite(suite, vendors_root=vendors_root), "--no-tag-display-limit")


LINTIAN_ARGV = lintian_argv()
# E error, W warning, I info, P pedantic, X experimental, O overridden, N classification.
_LINTIAN_TAG = re.compile(r"^[EWIPXON]: \S")

HERMETIC_BUNDLE_COMMANDS = {
    "LINTIAN.txt": "lintian",
    "BUILDINFO-REPORT.txt": "buildinfo-report",
    "PACKAGING-POLICY.txt": "packaging-policy",
    "HERMETIC-BUILD-PLAN.txt": "hermetic-build-plan",
    "CLI-HELP.txt": "cli-help",
    "HOST-CAPABILITIES.json": "host-capabilities",
    "CHROOT-BACKENDS.json": "chroot-backends",
    "DESKTOP-VALIDATE.txt": "desktop-validate",
    "INSTALLED-PACKAGE.txt": "installed-package",
    "GNOME-FAVORITES.txt": "gnome-favorites",
    "GUI-OFFSCREEN-SMOKE.txt": "gui-offscreen-smoke",
}

HERMETIC_BUNDLE_EVIDENCE = (
    *HERMETIC_BUNDLE_COMMANDS,
    "SOURCE-EXTRACT-REPORT.txt",
    "DEB-CONTENT-REPORT.txt",
    "OPENAI-SECRET-AUDIT.txt",
    "ISO-VALIDATION-PLAN.txt",
    "LOCAL-PROVENANCE.json",
    "RELEASE-NOTES.md",
    "VERIFY-REPORT.txt",
)
HERMETIC_BUNDLE_OPTIONAL_EVIDENCE = (
    "AUTOPKGTEST-DOCTOR.json",
)


@dataclass(frozen=True)
class PackageBuildArtifact:
    path: Path
    kind: str
    size: int
    sha256: str

    @classmethod
    def from_path(cls, path: Path) -> PackageBuildArtifact:
        return cls(
            path=path,
            kind=_artifact_kind(path),
            size=path.stat().st_size,
            sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "kind": self.kind,
            "size": self.size,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class PackageBuildCheck:
    name: str
    status: str
    command: tuple[str, ...]
    returncode: int | None = None
    reason: str = ""

    @property
    def failed(self) -> bool:
        return self.status in {"failed", "testbed-broken", "test-failed"}

    # "missing-tool" is the autopkgtest doctor's word for the condition
    # _run_package_tool_check reports as "missing": the tool is not installed on this
    # host. The doctor's status is copied verbatim into this check, and this word was
    # in neither set, so it graded as neither a failure nor a review and a host with
    # no autopkgtest produced a report that said "built" with the package's declared
    # test suite never run. It reviews rather than fails because a missing optional
    # tool is not a broken package -- the same grading lintian's "missing" gets.
    # The doctor's two other blocking words, missing-deb and invalid, are deliberately
    # absent: from this type's one call site the .deb is checked before the doctor is
    # asked, and the null backend always yields a command, so neither can arrive here.
    @property
    def needs_review(self) -> bool:
        return self.status in {"missing", "review required", "skipped", "missing-tool"}

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "status": self.status,
            "command": list(self.command),
            "returncode": self.returncode,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class DebianPackageBuildReport:
    root: Path
    execute: bool
    build: PackageBuildCheck
    checks: tuple[PackageBuildCheck, ...]
    artifacts: tuple[PackageBuildArtifact, ...]
    policy: PackagingPolicyReport

    @property
    def status(self) -> str:
        if not self.execute:
            return "planned"
        if self.build.failed or not any(artifact.kind == "deb" for artifact in self.artifacts):
            return "blocked"
        if self.policy.blocked or any(check.failed for check in self.checks):
            return "blocked"
        if any(check.needs_review for check in self.checks):
            return "review required"
        return "built"

    def to_dict(self) -> dict[str, object]:
        return {
            "root": str(self.root),
            "execute": self.execute,
            "status": self.status,
            "build": self.build.to_dict(),
            "checks": [check.to_dict() for check in self.checks],
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "policy": self.policy.to_dict(),
        }

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def render_text(self) -> str:
        lines = [
            "Debian package build report",
            f"Root: {self.root}",
            f"Status: {self.status}",
            f"Mode: {'execute' if self.execute else 'plan'}",
            "",
            "Build:",
            f"- {self.build.name}: {self.build.status}",
        ]
        if self.build.reason:
            lines.append(f"  {self.build.reason}")
        lines.extend(["", "Checks:"])
        lines.extend(
            f"- {check.name}: {check.status}" + (f" ({check.reason})" if check.reason else "")
            for check in self.checks
        )
        lines.extend(["", "Artifacts:"])
        if self.artifacts:
            lines.extend(
                f"- {artifact.kind}: {artifact.path} ({artifact.size} bytes, SHA256 {artifact.sha256})"
                for artifact in self.artifacts
            )
        else:
            lines.append("- none")
        lines.extend(["", self.policy.render_text()])
        return "\n".join(lines)


@dataclass(frozen=True)
class AutopkgtestDoctorReport:
    root: Path
    deb: Path | None
    backend: str
    testbed: str | None
    execute: bool
    status: str
    classification: str
    command: tuple[str, ...]
    returncode: int | None = None
    detail: str = ""
    remediation: str = ""
    evidence: tuple[str, ...] = ()
    suggested_testbeds: tuple[str, ...] = ()

    @property
    def blocked(self) -> bool:
        return self.status in {"failed", "testbed-broken", "test-failed", "missing-tool", "missing-deb", "invalid"}

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": "distroforge.autopkgtest-doctor.v1",
            "root": str(self.root),
            "deb": str(self.deb) if self.deb else None,
            "backend": self.backend,
            "testbed": self.testbed,
            "execute": self.execute,
            "status": self.status,
            "classification": self.classification,
            "blocked": self.blocked,
            "command": list(self.command),
            "returncode": self.returncode,
            "detail": self.detail,
            "remediation": self.remediation,
            "evidence": list(self.evidence),
            "suggested_testbeds": list(self.suggested_testbeds),
        }

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def render_text(self) -> str:
        lines = [
            "Autopkgtest doctor",
            f"Root: {self.root}",
            f"Deb: {self.deb or '-'}",
            f"Backend: {self.backend}",
            f"Testbed: {self.testbed or '-'}",
            f"Mode: {'execute' if self.execute else 'plan'}",
            f"Status: {self.status}",
            f"Classification: {self.classification}",
            f"Command: {' '.join(self.command) if self.command else '-'}",
        ]
        if self.returncode is not None:
            lines.append(f"Return code: {self.returncode}")
        if self.detail:
            lines.extend(["", "Detail:", self.detail])
        if self.remediation:
            lines.extend(["", "Remediation:", self.remediation])
        if self.evidence:
            lines.extend(["", "Evidence:", *[f"- {line}" for line in self.evidence]])
        if self.suggested_testbeds:
            lines.extend(["", "Suggested testbeds:", *[f"- {name}" for name in self.suggested_testbeds]])
        return "\n".join(lines)


@dataclass(frozen=True)
class HermeticBuildPlan:
    root: Path
    backend: str = "sbuild"
    suite: str = "unstable"
    arch: str = "amd64"

    def commands(self) -> list[tuple[str, ...]]:
        if self.backend == "mmdebstrap":
            return [
                ("mmdebstrap", "--variant=buildd", self.suite, str(self.root / ".build-chroot")),
                ("sbuild", "--chroot", str(self.root / ".build-chroot"), "--arch", self.arch, "--no-run-lintian"),
            ]
        if self.backend == "pbuilder":
            return [
                ("pbuilder", "create", "--distribution", self.suite),
                ("pdebuild", "--buildresult", str(self.root.parent)),
            ]
        return [
            ("sbuild-createchroot", self.suite, str(self.root / ".sbuild-chroot")),
            ("sbuild", "--arch", self.arch, "--dist", self.suite, "--no-run-lintian"),
        ]

    def render_text(self) -> str:
        lines = [
            "Hermetic Debian build plan",
            f"Root: {self.root}",
            f"Backend: {self.backend}",
            f"Suite: {self.suite}",
            f"Architecture: {self.arch}",
            "",
            "Commands:",
        ]
        lines.extend("- " + " ".join(command) for command in self.commands())
        return "\n".join(lines)


@dataclass(frozen=True)
class HermeticReleaseBundleReport:
    root: Path
    output_dir: Path
    version: str
    suite: str
    architecture: str
    artifacts: tuple[PackageBuildArtifact, ...]
    checks: tuple[PackageBuildCheck, ...]

    @property
    def status(self) -> str:
        if any(check.failed for check in self.checks):
            return "blocked"
        if any(check.needs_review for check in self.checks):
            return "review required"
        return "ready"

    def to_dict(self) -> dict[str, object]:
        return {
            "root": str(self.root),
            "output_dir": str(self.output_dir),
            "version": self.version,
            "suite": self.suite,
            "architecture": self.architecture,
            "status": self.status,
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "checks": [check.to_dict() for check in self.checks],
        }

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def render_text(self) -> str:
        lines = [
            "Hermetic local release bundle",
            f"Root: {self.root}",
            f"Output: {self.output_dir}",
            f"Version: {self.version}",
            f"Suite: {self.suite}",
            f"Architecture: {self.architecture}",
            f"Status: {self.status}",
            "",
            "Artifacts:",
        ]
        lines.extend(
            f"- {artifact.kind}: {artifact.path.name} ({artifact.size} bytes, SHA256 {artifact.sha256})"
            for artifact in self.artifacts
        )
        lines.extend(["", "Checks:"])
        lines.extend(
            f"- {check.name}: {check.status}" + (f" ({check.reason})" if check.reason else "")
            for check in self.checks
        )
        lines.extend(["", f"Verify with: cd {self.output_dir} && sha256sum -c SHA256SUMS"])
        return "\n".join(lines)


def create_hermetic_release_bundle(
    root: Path,
    *,
    output_dir: Path,
    artifact_dir: Path | None = None,
    version: str | None = None,
    suite: str = "resolute",
    architecture: str = "all",
    build_timestamp: str | None = None,
    autopkgtest_dir: Path | None = None,
    autopkgtest_report: Path | None = None,
    iso: Path | None = None,
    replace: bool = False,
) -> HermeticReleaseBundleReport:
    root = root.resolve()
    artifact_dir = package_artifact_dir(root, artifact_dir)
    version = version or debian_changelog_version(root)
    output_dir = output_dir.resolve()
    autopkgtest_report = _resolve_autopkgtest_report(root, artifact_dir, autopkgtest_report)
    stashed_autopkgtest: Path | None = None
    stashed_autopkgtest_report: Path | None = None
    # The stashes below outlive the rmtree that empties output_dir, so their removal has to
    # be reached on every exit -- including the FileNotFoundError a few lines down, which a
    # half-built artifact directory raises as a matter of course. Without the finally, that
    # ordinary failure left two directories in /tmp for good.
    try:
        if output_dir.exists() and any(output_dir.iterdir()):
            if not replace:
                raise FileExistsError(f"{output_dir} is not empty; pass --replace to rebuild this bundle")
            if autopkgtest_report and autopkgtest_report.exists():
                try:
                    autopkgtest_report.resolve().relative_to(output_dir)
                except ValueError:
                    pass
                else:
                    stashed_autopkgtest_report = Path(tempfile.mkdtemp(prefix="distroforge-autopkgtest-report-")) / "AUTOPKGTEST-DOCTOR.json"
                    shutil.copy2(autopkgtest_report, stashed_autopkgtest_report)
                    autopkgtest_report = stashed_autopkgtest_report
            if autopkgtest_dir and autopkgtest_dir.exists():
                try:
                    autopkgtest_dir.resolve().relative_to(output_dir)
                except ValueError:
                    pass
                else:
                    stashed_autopkgtest = Path(tempfile.mkdtemp(prefix="distroforge-autopkgtest-")) / "AUTOPKGTEST"
                    shutil.copytree(autopkgtest_dir, stashed_autopkgtest)
                    autopkgtest_dir = stashed_autopkgtest
            shutil.rmtree(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        required = _release_artifacts(artifact_dir, version)
        copied: list[Path] = []
        for path in required:
            if not path.exists():
                raise FileNotFoundError(path)
            target = output_dir / path.name
            shutil.copy2(path, target)
            copied.append(target)
        build_log = _latest_build_log(artifact_dir, version)
        if build_log:
            target = output_dir / build_log.name
            shutil.copy2(build_log, target)
            copied.append(target)
        if autopkgtest_dir and autopkgtest_dir.exists():
            _copy_tree(autopkgtest_dir, output_dir / "AUTOPKGTEST")
        if autopkgtest_report and autopkgtest_report.exists():
            shutil.copy2(autopkgtest_report, output_dir / "AUTOPKGTEST-DOCTOR.json")
    finally:
        if stashed_autopkgtest_report:
            shutil.rmtree(stashed_autopkgtest_report.parent, ignore_errors=True)
        if stashed_autopkgtest:
            shutil.rmtree(stashed_autopkgtest.parent, ignore_errors=True)

    checks = _write_hermetic_bundle_reports(
        root,
        output_dir,
        artifact_dir,
        version,
        suite,
        architecture,
        build_timestamp,
        iso,
    )
    checks = (
        *checks,
        _write_bundle_contract(output_dir, version, suite, architecture, required, copied, checks),
    )
    _write_manifest(output_dir, version, suite, architecture, build_timestamp)
    _write_sha256sums(output_dir)
    checks = (*checks, _verify_sha256sums(output_dir))
    artifacts = tuple(PackageBuildArtifact.from_path(path) for path in sorted(copied))
    return HermeticReleaseBundleReport(root, output_dir, version, suite, architecture, artifacts, checks)


def _release_artifacts(artifact_dir: Path, version: str) -> tuple[Path, ...]:
    upstream = version.split("-", 1)[0]
    return (
        artifact_dir / f"distroforge_{version}_all.deb",
        artifact_dir / f"distroforge_{version}.dsc",
        artifact_dir / f"distroforge_{version}.debian.tar.xz",
        artifact_dir / f"distroforge_{version}_amd64.buildinfo",
        artifact_dir / f"distroforge_{version}_amd64.changes",
        artifact_dir / f"distroforge_{upstream}.orig.tar.xz",
    )


def debian_changelog_version(root: Path) -> str:
    changelog = root / "debian/changelog"
    if not changelog.exists():
        raise ValueError("Package version could not be inferred; pass --version")
    first = changelog.read_text(encoding="utf-8").splitlines()[0]
    match = re.match(r"^\S+ \(([^)]+)\) ", first)
    if not match:
        raise ValueError("Package version could not be inferred from debian/changelog; pass --version")
    return match.group(1)


def debian_changelog_suite(root: Path) -> str:
    """The suite this source targets, or "" when the changelog names none.

    Deliberately not the top stanza's Distribution field. Between releases that field
    is UNRELEASED, which is the normal state of a changelog and which no lintian vendor
    claims -- so reading the top stanza alone sent :func:`lintian_vendor_for_suite` to
    the pinned fallback and brought back, for the whole development cycle, the exact
    regression documented on :data:`LINTIAN_PROFILE`: an Ubuntu-targeted package graded
    against the Debian profile and rated "failed" over a Distribution field that was
    correct. UNRELEASED names no target. The newest stanza that names one does, and it
    is also the suite the entry will carry once it is released.

    Unreadable is not an error here: the only caller feeds this to
    :func:`lintian_vendor_for_suite`, which falls back to the pinned vendor.
    A stanza may list several distributions, and the first one is the target.
    """
    changelog = root / "debian/changelog"
    if not changelog.exists():
        return ""
    for line in changelog.read_text(encoding="utf-8").splitlines():
        # Only a stanza header starts in column zero; bodies are indented and the
        # trailer starts with " -- ".
        match = re.match(r"^\S+ \([^)]+\)\s+([^;]+);", line)
        if match is None:
            continue
        suite = match.group(1).split()[0]
        if suite.upper() != "UNRELEASED":
            return suite
    return ""


def _latest_build_log(artifact_dir: Path, version: str) -> Path | None:
    logs = sorted(artifact_dir.glob(f"distroforge_{version}_amd64-*.build"))
    return logs[-1] if logs else None


def _copy_tree(source: Path, target: Path) -> None:
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(source, target)


def _resolve_autopkgtest_report(root: Path, artifact_dir: Path, explicit: Path | None) -> Path | None:
    candidates = (
        explicit,
        artifact_dir / "AUTOPKGTEST-DOCTOR.json",
        root / "dist/AUTOPKGTEST-DOCTOR.json",
    )
    for path in candidates:
        if path and path.exists():
            return path.resolve()
    return None


def _write_hermetic_bundle_reports(
    root: Path,
    output_dir: Path,
    artifact_dir: Path,
    version: str,
    suite: str,
    architecture: str,
    build_timestamp: str | None,
    iso: Path | None,
) -> tuple[PackageBuildCheck, ...]:
    checks: list[PackageBuildCheck] = []
    deb = artifact_dir / f"distroforge_{version}_all.deb"
    dsc = artifact_dir / f"distroforge_{version}.dsc"
    buildinfo = artifact_dir / f"distroforge_{version}_amd64.buildinfo"
    changes = artifact_dir / f"distroforge_{version}_amd64.changes"
    distroforge = (sys.executable, "-m", "distroforge")
    commands = {
        "LINTIAN.txt": (*lintian_argv(suite), str(deb), str(dsc), str(changes)),
        "BUILDINFO-REPORT.txt": (*distroforge, "buildinfo-report", str(buildinfo), "--changes", str(changes)),
        "PACKAGING-POLICY.txt": (
            *distroforge,
            "packaging-policy",
            str(root),
            "--buildinfo",
            str(buildinfo),
            "--changes",
            str(changes),
        ),
        "HERMETIC-BUILD-PLAN.txt": (*distroforge, "hermetic-build-plan", str(root), "--backend", "sbuild", "--suite", suite),
        "CLI-HELP.txt": (*distroforge, "--help"),
        "HOST-CAPABILITIES.json": (*distroforge, "host", "--json"),
        "CHROOT-BACKENDS.json": (*distroforge, "chroot-backends", "--json"),
        "DESKTOP-VALIDATE.txt": ("desktop-file-validate", "/usr/share/applications/distroforge.desktop"),
        "INSTALLED-PACKAGE.txt": ("dpkg-query", "-W", "-f=${Package} ${Version} ${db:Status-Abbrev} ${Status}\\n", "distroforge"),
        "GNOME-FAVORITES.txt": ("gsettings", "get", "org.gnome.shell", "favorite-apps"),
        "GUI-OFFSCREEN-SMOKE.txt": (
            "python3",
            "-c",
            (
                "from distroforge.ui.qt import QApplication, QIcon; "
                "from distroforge.ui.main_window import MainWindow; "
                "from distroforge.ui.theme import apply_theme; "
                "app = QApplication([]); app.setApplicationName('DistroForge'); "
                "app.setDesktopFileName('distroforge'); app.setWindowIcon(QIcon.fromTheme('distroforge')); "
                "QIcon.setThemeName('Adwaita'); apply_theme(app); "
                "window = MainWindow(); window.resize(900, 640); window.show(); app.processEvents(); "
                "print(window.windowTitle() or app.applicationName())"
            ),
        ),
    }
    for name, command in commands.items():
        env = {"QT_QPA_PLATFORM": "offscreen"} if name == "GUI-OFFSCREEN-SMOKE.txt" else None
        result = _run_capture(command, env=env)
        _write_command_report(output_dir / name, result)
        checks.append(_check_from_result(Path(name).stem.lower(), command, result))
    source_check = _write_source_extract_report(output_dir / "SOURCE-EXTRACT-REPORT.txt", dsc)
    content_check = _write_deb_content_report(output_dir / "DEB-CONTENT-REPORT.txt", deb)
    audit_check = _write_openai_audit(output_dir / "OPENAI-SECRET-AUDIT.txt", root, output_dir)
    _write_iso_validation_plan(output_dir / "ISO-VALIDATION-PLAN.txt", iso)
    _write_local_provenance(output_dir / "LOCAL-PROVENANCE.json", root, version, suite, architecture, build_timestamp)
    _write_release_notes(output_dir / "RELEASE-NOTES.md", version, suite)
    checks.extend((source_check, content_check, audit_check))
    _write_verify_report(output_dir, version, suite, architecture, build_timestamp, checks)
    return tuple(checks)


def _run_capture(command: tuple[str, ...], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    if not shutil.which(command[0]):
        return subprocess.CompletedProcess(command, 127, "", f"{command[0]} is not installed")
    return subprocess.run(command, text=True, capture_output=True, check=False, env=merged_env)


def _write_command_report(path: Path, result: subprocess.CompletedProcess[str]) -> None:
    if path.suffix == ".json" and result.returncode == 0 and result.stdout.strip():
        try:
            parsed = json.loads(result.stdout)
        except json.JSONDecodeError:
            pass
        else:
            path.write_text(json.dumps(parsed, indent=2) + "\n", encoding="utf-8")
            return
    path.write_text(
        "\n".join(
            [
                f"Command: {' '.join(str(part) for part in result.args)}",
                f"Exit code: {result.returncode}",
                "",
                "STDOUT:",
                result.stdout if result.stdout else "(no output)",
                "",
                "STDERR:",
                result.stderr if result.stderr else "(no output)",
                "",
            ]
        ),
        encoding="utf-8",
    )


def _write_bundle_contract(
    output_dir: Path,
    version: str,
    suite: str,
    architecture: str,
    required: tuple[Path, ...],
    copied: list[Path],
    checks: tuple[PackageBuildCheck, ...],
) -> PackageBuildCheck:
    expected_artifacts = [path.name for path in required]
    copied_names = sorted(path.name for path in copied)
    missing_artifacts = [name for name in expected_artifacts if name not in copied_names]
    missing_evidence = [
        name
        for name in HERMETIC_BUNDLE_EVIDENCE
        if not (output_dir / name).exists()
    ]
    payload = {
        "schema": "distroforge.hermetic-release-bundle.contract.v1",
        "package": "distroforge",
        "version": version,
        "suite": suite,
        "architecture": architecture,
        "required_artifacts": expected_artifacts,
        "copied_artifacts": copied_names,
        "required_evidence": list(HERMETIC_BUNDLE_EVIDENCE),
        "optional_evidence": [
            name
            for name in HERMETIC_BUNDLE_OPTIONAL_EVIDENCE
            if (output_dir / name).exists()
        ],
        "missing_artifacts": missing_artifacts,
        "missing_evidence": missing_evidence,
        "checks": [check.to_dict() for check in checks],
    }
    (output_dir / "BUNDLE-CONTRACT.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    missing = [*missing_artifacts, *missing_evidence]
    return PackageBuildCheck(
        "bundle-contract",
        "passed" if not missing else "failed",
        ("write-bundle-contract", str(output_dir)),
        reason=", ".join(missing),
    )


def _check_from_result(name: str, command: tuple[str, ...], result: subprocess.CompletedProcess[str]) -> PackageBuildCheck:
    # lintian exits 0 with warnings, so an exit-code-only verdict declared the
    # shipped 0.3.5-2 package clean while it carried four W: tags. Read the output.
    if command[:1] == ("lintian",) and result.returncode != 127:
        output = f"{result.stdout}\n{result.stderr}"
        status = lintian_status(result.returncode, output)
        reason = lintian_reason(output) if status != "passed" else ""
        return PackageBuildCheck(name, status, command, result.returncode, reason)
    status = "passed" if result.returncode == 0 else "missing" if result.returncode == 127 else "failed"
    return PackageBuildCheck(
        name,
        status,
        command,
        result.returncode,
        _result_reason(result.stdout, result.stderr) if status != "passed" else "",
    )


def _write_source_extract_report(path: Path, dsc: Path) -> PackageBuildCheck:
    with tempfile.TemporaryDirectory(prefix="distroforge-source-") as temp:
        target = Path(temp) / "source"
        result = _run_capture(("dpkg-source", "-x", str(dsc), str(target)))
        patch = target / "debian/patches/ubuntu-resolute-standards-version-test.patch"
        path.write_text(
            "\n".join(
                [
                    f"Source extraction target: {target}",
                    f"Exit code: {result.returncode}",
                    "",
                    "STDOUT:",
                    result.stdout if result.stdout else "(no output)",
                    "",
                    "STDERR:",
                    result.stderr if result.stderr else "(no output)",
                    "",
                    f"Vendor quilt patch present after extraction: {'yes' if patch.exists() else 'no'}",
                    "",
                ]
            ),
            encoding="utf-8",
        )
    status = "passed" if result.returncode == 0 else "failed"
    return PackageBuildCheck("source-extract", status, ("dpkg-source", "-x", str(dsc)), result.returncode)


def _write_deb_content_report(path: Path, deb: Path) -> PackageBuildCheck:
    metadata = _run_capture(("dpkg-deb", "-f", str(deb), "Package", "Version", "Architecture", "Depends", "Recommends"))
    content = _run_capture(("dpkg-deb", "-c", str(deb)))
    # No lintian/overrides/distroforge entry: the package ships none and must not.
    # Requiring the file made deb-content fail on every build for a file the project
    # has decided never to create -- silencing a tag with an override is not the same
    # thing as being clean, so DistroForge fixes tags instead of overriding them.
    required = (
        "distroforge.desktop",
        "distroforge.svg",
        "acceptance-matrix.md",
        "/man1/distroforge",
    )
    selected = [line for line in content.stdout.splitlines() if any(item in line for item in required)]
    path.write_text(
        "\n".join(
            [
                "Debian package metadata",
                "=======================",
                metadata.stdout.strip(),
                "",
                "Selected package content",
                "========================",
                "\n".join(selected),
                "",
            ]
        ),
        encoding="utf-8",
    )
    missing = [item for item in required if item not in "\n".join(selected)]
    status = "passed" if metadata.returncode == 0 and content.returncode == 0 and not missing else "failed"
    return PackageBuildCheck("deb-content", status, ("dpkg-deb", "-c", str(deb)), content.returncode, ", ".join(missing))


def _write_openai_audit(path: Path, root: Path, output_dir: Path) -> PackageBuildCheck:
    pattern = re.compile(rb"(?:sk-proj-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{32,})")
    ignored_dirs = {".venv", ".ruff_cache", ".pytest_cache", "__pycache__"}
    ignored_suffixes = (".egg-info",)
    scanned = 0
    matches: list[str] = []
    for base in (root, output_dir):
        for candidate in base.rglob("*"):
            if not candidate.is_file() or candidate.is_symlink():
                continue
            if set(candidate.parts) & ignored_dirs or any(part.endswith(ignored_suffixes) for part in candidate.parts):
                continue
            try:
                data = candidate.read_bytes()
            except OSError:
                continue
            if b"\0" in data[:8192]:
                continue
            scanned += 1
            if pattern.search(data):
                matches.append(str(candidate))
    path.write_text(
        "\n".join(
            [
                "OpenAI key hygiene audit",
                "=========================",
                "Mode: redacted/no-value scan only",
                f"Paths scanned: {scanned}",
                f"OpenAI-shaped key path hits: {len(matches)}",
                *(matches if matches else ["No OpenAI-shaped key pattern was found."]),
                "",
            ]
        ),
        encoding="utf-8",
    )
    return PackageBuildCheck("openai-secret-audit", "passed" if not matches else "failed", ("redacted-openai-audit", str(root), str(output_dir)), reason=f"{len(matches)} path hits")


def _write_iso_validation_plan(path: Path, iso: Path | None) -> None:
    if iso:
        plan = QemuSmokePlanner().plan(iso)
        path.write_text(plan.render_text() + "\n", encoding="utf-8")
    else:
        path.write_text(
            "ISO validation plan\n===================\nNo ISO path was supplied for this package release bundle.\n",
            encoding="utf-8",
        )


def _write_local_provenance(
    path: Path,
    root: Path,
    version: str,
    suite: str,
    architecture: str,
    build_timestamp: str | None,
) -> None:
    payload = {
        "package": "distroforge",
        "version": version,
        "suite": suite,
        "architecture": architecture,
        "build_timestamp": build_timestamp,
        "bundle_generated_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "root": str(root),
        "source_control": _git_identity(root),
        "local_unsigned": True,
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _git_identity(root: Path) -> dict[str, str]:
    commit = _run_capture(("git", "-C", str(root), "rev-parse", "HEAD"))
    dirty = _run_capture(("git", "-C", str(root), "status", "--short"))
    return {
        "commit": commit.stdout.strip() if commit.returncode == 0 else "",
        "dirty": "yes" if dirty.stdout.strip() else "no",
    }


def _write_release_notes(path: Path, version: str, suite: str) -> None:
    installed = _run_capture(("dpkg-query", "-W", "-f=${Package} ${Version} ${Status}\\n", "distroforge"))
    # The reader must be able to reproduce the verdict in the bundle, so the printed
    # command carries the same profile the bundle was graded with. Spelled bare, it
    # would take the reader's dpkg-vendor default and could disagree with LINTIAN.txt.
    lintian_command = " ".join(lintian_argv(suite))
    path.write_text(
        f"""# DistroForge {version} Hermetic Local Release

This local bundle contains an unsigned Ubuntu {suite} hermetic DistroForge package release.

Installed package check:

```text
{installed.stdout.strip()}
```

Verification commands:

```sh
sha256sum -c SHA256SUMS
{lintian_command} distroforge_{version}_all.deb distroforge_{version}.dsc distroforge_{version}_amd64.changes
dpkg-source -x distroforge_{version}.dsc /tmp/distroforge-verify-source
```

Known local-build caveat:
- This is a local evidence bundle, not a signed archive upload or PPA publication.
""",
        encoding="utf-8",
    )


def _write_verify_report(
    output_dir: Path,
    version: str,
    suite: str,
    architecture: str,
    build_timestamp: str | None,
    checks: list[PackageBuildCheck],
) -> None:
    autopkg_summary = output_dir / "AUTOPKGTEST/summary"
    autopkg_doctor = _autopkgtest_doctor_summary(output_dir / "AUTOPKGTEST-DOCTOR.json")
    lines = [
        f"DistroForge {version} hermetic verification",
        "========================================",
        f"Suite: {suite}",
        f"Architecture: {architecture}",
        f"sbuild: {'successful at ' + build_timestamp if build_timestamp else 'artifact log captured'}",
        f"autopkgtest summary: {autopkg_summary.read_text(encoding='utf-8').strip() if autopkg_summary.exists() else 'not bundled'}",
        f"autopkgtest doctor: {autopkg_doctor}",
        *(f"{check.name}: {check.status}" for check in checks),
        "",
    ]
    (output_dir / "VERIFY-REPORT.txt").write_text("\n".join(lines), encoding="utf-8")


def _autopkgtest_doctor_summary(path: Path) -> str:
    if not path.exists():
        return "not bundled"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return "invalid JSON"
    status = data.get("status", "unknown")
    classification = data.get("classification", "unknown")
    return f"{status}: {classification}"


def _write_manifest(output_dir: Path, version: str, suite: str, architecture: str, build_timestamp: str | None) -> None:
    files = [
        {
            "name": path.relative_to(output_dir).as_posix(),
            "size": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for path in sorted(output_dir.rglob("*"))
        if path.is_file() and path.name not in {"MANIFEST.json", "SHA256SUMS"}
    ]
    payload = {
        "package": "distroforge",
        "version": version,
        "suite": suite,
        "architecture": architecture,
        "build_timestamp": build_timestamp,
        "bundle_generated_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "files": files,
    }
    (output_dir / "MANIFEST.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _write_sha256sums(output_dir: Path) -> None:
    lines = [
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(output_dir).as_posix()}"
        for path in sorted(output_dir.rglob("*"))
        if path.is_file() and path.name != "SHA256SUMS"
    ]
    (output_dir / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _verify_sha256sums(output_dir: Path) -> PackageBuildCheck:
    result = subprocess.run(("sha256sum", "-c", "SHA256SUMS"), cwd=output_dir, text=True, capture_output=True, check=False)
    status = "passed" if result.returncode == 0 else "failed"
    return PackageBuildCheck("sha256sums", status, ("sha256sum", "-c", "SHA256SUMS"), result.returncode, _result_reason(result.stdout, result.stderr))


def packaging_policy_report(
    root: Path,
    buildinfo: Path | None = None,
    changes: Path | None = None,
) -> PackagingPolicyReport:
    declared = _declared_docs(root)
    declared_examples = _declared_examples(root)
    changes_report = read_changes(changes) if changes and changes.exists() else None
    autopkgtest_available = shutil.which("autopkgtest") is not None
    return PackagingPolicyReport(
        root=root,
        buildinfo=read_buildinfo(buildinfo, changes) if buildinfo and buildinfo.exists() else None,
        changes=changes_report if not (buildinfo and buildinfo.exists()) else None,
        data_mode_offenders=_data_mode_offenders(root),
        malformed_toml=_malformed_toml(root),
        malformed_json=_malformed_json(root),
        missing_package_data=_missing_package_data(root),
        malformed_examples=_malformed_examples(root),
        missing_docs=[doc for doc in IMPORTANT_DOCS if doc not in declared],
        missing_examples=[
            str(path.relative_to(root))
            for path in sorted((root / "examples").glob("*.yaml"))
            if str(path.relative_to(root)) not in declared_examples
        ],
        lintian_available=shutil.which("lintian") is not None,
        autopkgtest_available=autopkgtest_available,
        autopkgtest_policy=_autopkgtest_policy(root, autopkgtest_available),
    )


def build_debian_package(
    root: Path,
    *,
    execute: bool = False,
    runner: CommandRunner | None = None,
    artifact_dir: Path | None = None,
) -> DebianPackageBuildReport:
    root = root.resolve()
    artifacts_in = package_artifact_dir(root, artifact_dir)
    runner = runner or CommandRunner(dry_run=not execute)
    effective_execute = execute and not runner.dry_run
    build_spec = CommandSpec(
        argv=("dpkg-buildpackage", "-us", "-uc", "-b"),
        cwd=root,
        description="Build Debian binary package",
    )
    build_result = runner.run(build_spec, check=False)
    build_check = PackageBuildCheck(
        name="dpkg-buildpackage",
        status=_command_status(effective_execute, build_result.returncode),
        command=build_spec.argv,
        returncode=build_result.returncode if effective_execute else None,
        reason=_result_reason(build_result.stdout, build_result.stderr) if effective_execute else "",
    )
    artifacts = tuple(
        PackageBuildArtifact.from_path(path) for path in _package_artifact_paths(artifacts_in)
    )
    deb = _latest_deb(artifacts_in)
    checks = (
        _run_package_tool_check(
            runner,
            root,
            "lintian",
            (*lintian_argv(debian_changelog_suite(root))[1:], str(deb)) if deb else (),
            effective_execute,
            bool(deb),
        ),
        _run_autopkgtest_package_check(runner, root, deb, effective_execute),
    )
    return DebianPackageBuildReport(
        root=root,
        execute=effective_execute,
        build=build_check,
        checks=checks,
        artifacts=artifacts,
        policy=packaging_policy_report(
            root, _latest_buildinfo(artifacts_in), _latest_changes(artifacts_in)
        ),
    )


def run_packaging_ci(
    runner: CommandRunner,
    root: Path,
    *,
    execute: bool = False,
    artifact_dir: Path | None = None,
) -> PackagingPolicyReport:
    return build_debian_package(
        root, execute=execute, runner=runner, artifact_dir=artifact_dir
    ).policy


def diagnose_autopkgtest(
    root: Path,
    *,
    deb: Path | None = None,
    backend: str = "null",
    testbed: str | None = None,
    execute: bool = False,
    runner: CommandRunner | None = None,
) -> AutopkgtestDoctorReport:
    root = root.resolve()
    runner = runner or CommandRunner(dry_run=not execute)
    deb = (deb or _latest_deb(root))
    if execute and not runner.has_binary("autopkgtest"):
        return AutopkgtestDoctorReport(
            root=root,
            deb=deb,
            backend=backend,
            testbed=testbed,
            execute=execute,
            status="missing-tool",
            classification="host-missing-autopkgtest",
            command=(),
            detail="autopkgtest is not installed on this host.",
            remediation="Install autopkgtest or run the package checks in a maintainer test environment.",
        )
    if deb is None or not deb.exists():
        return AutopkgtestDoctorReport(
            root=root,
            deb=deb,
            backend=backend,
            testbed=testbed,
            execute=execute,
            status="missing-deb",
            classification="package-artifact-missing",
            command=(),
            detail="No Debian package artifact was found for autopkgtest.",
            remediation="Run distroforge debian-package ROOT --execute first.",
        )
    suggested_testbeds: tuple[str, ...] = ()
    if backend == "schroot" and not testbed:
        testbed, suggested_testbeds, detail = _select_schroot_testbed(root, runner)
        if testbed is None:
            return AutopkgtestDoctorReport(
                root=root,
                deb=deb,
                backend=backend,
                testbed=None,
                execute=execute,
                status="invalid",
                classification="schroot-testbed-unavailable",
                command=(),
                detail=detail,
                remediation="Create or repair a writable schroot/sbuild testbed, then pass --testbed or rerun --backend schroot.",
                suggested_testbeds=suggested_testbeds,
            )
    command = _autopkgtest_command(deb, backend, testbed)
    if command is None:
        return AutopkgtestDoctorReport(
            root=root,
            deb=deb,
            backend=backend,
            testbed=testbed,
            execute=execute,
            status="invalid",
            classification="testbed-missing",
            command=(),
            detail=f"Backend {backend} requires a testbed name.",
            remediation="Pass --testbed, for example a schroot name such as resolute-amd64-sbuild.",
        )
    if not execute:
        return AutopkgtestDoctorReport(
            root=root,
            deb=deb,
            backend=backend,
            testbed=testbed,
            execute=False,
            status="planned",
            classification="not-run",
            command=command,
            detail="Autopkgtest execution is planned but was not run.",
            remediation="Rerun with --execute to classify the current testbed.",
            suggested_testbeds=suggested_testbeds,
        )
    spec = CommandSpec(argv=command, cwd=root, description="Run autopkgtest doctor")
    result = runner.run(spec, check=False)
    status, classification, detail, remediation, evidence = _classify_autopkgtest_result(result.returncode, result.stdout, result.stderr)
    return AutopkgtestDoctorReport(
        root=root,
        deb=deb,
        backend=backend,
        testbed=testbed,
        execute=True,
        status=status,
        classification=classification,
        command=command,
        returncode=result.returncode,
        detail=detail,
        remediation=remediation,
        evidence=evidence,
        suggested_testbeds=suggested_testbeds,
    )


def _command_status(execute: bool, returncode: int) -> str:
    if not execute:
        return "planned"
    return "passed" if returncode == 0 else "failed"


def _result_reason(stdout: str, stderr: str) -> str:
    lines = [line for line in (stderr or stdout).splitlines() if line.strip()]
    return lines[-1] if lines else ""


def lintian_tags(output: str) -> tuple[str, ...]:
    """Every tag lintian emitted, in order, as ``SEVERITY: package: tag ...``."""
    return tuple(line.strip() for line in output.splitlines() if _LINTIAN_TAG.match(line.strip()))


def lintian_status(returncode: int, output: str) -> str:
    """Grade a lintian run from its tags, not from its exit code.

    lintian exits 0 for a package that emits warnings, so the exit code alone rates
    the shipped 0.3.5-2 .deb -- four W: tags -- as clean. Reading tags is also why
    ``--fail-on warning`` is the wrong lever here: it turns rc into 2 for a healthy
    artifact without blocking anything, so it would paint the bundle red and still
    tell the maintainer nothing about which tag to go and fix.
    """
    tags = lintian_tags(output)
    if any(tag.startswith("E:") for tag in tags):
        return "failed"
    if tags:
        return "review required"
    return "passed" if returncode == 0 else "failed"


def lintian_reason(output: str) -> str:
    """Keep every tag in the reason, not just the last line of output.

    ``_result_reason`` returns one line, so three of the four real warnings were
    dropped before anybody could read them.
    """
    tags = lintian_tags(output)
    if tags:
        return "; ".join(tags)
    lines = [line for line in output.splitlines() if line.strip()]
    return lines[-1] if lines else ""


def _run_package_tool_check(
    runner: CommandRunner,
    root: Path,
    tool: str,
    args: tuple[str, ...],
    execute: bool,
    has_deb: bool,
) -> PackageBuildCheck:
    command = (tool, *args) if args else (tool, "--version")
    if not has_deb:
        return PackageBuildCheck(tool, "skipped", command, reason="no .deb artifact available")
    if not execute:
        spec = CommandSpec(argv=command, cwd=root, description=f"Plan {tool} package check")
        runner.run(spec, check=False)
        return PackageBuildCheck(tool, "planned", command)
    if not runner.has_binary(tool):
        return PackageBuildCheck(tool, "missing", command, reason=f"{tool} is not installed on this host")
    spec = CommandSpec(argv=command, cwd=root, description=f"Run {tool} on Debian package")
    result = runner.run(spec, check=False)
    status = _package_tool_status(tool, result.returncode, result.stdout, result.stderr)
    output = f"{result.stdout}\n{result.stderr}"
    reason = lintian_reason(output) if tool == "lintian" else _result_reason(result.stdout, result.stderr)
    return PackageBuildCheck(
        tool,
        status,
        command,
        returncode=result.returncode,
        reason=reason if status != "passed" else "",
    )


def _run_autopkgtest_package_check(
    runner: CommandRunner,
    root: Path,
    deb: Path | None,
    execute: bool,
) -> PackageBuildCheck:
    if deb is None:
        return PackageBuildCheck(
            "autopkgtest",
            "skipped",
            ("autopkgtest", "--version"),
            reason="no .deb artifact available",
        )
    if not execute:
        command = _autopkgtest_command(deb, "null", None) or ("autopkgtest", str(deb), "--", "null")
        spec = CommandSpec(argv=command, cwd=root, description="Plan autopkgtest package check")
        runner.run(spec, check=False)
        return PackageBuildCheck("autopkgtest", "planned", command)
    report = diagnose_autopkgtest(root, deb=deb, execute=True, runner=runner)
    return PackageBuildCheck(
        "autopkgtest",
        report.status,
        report.command,
        returncode=report.returncode,
        reason=report.detail,
    )


def _package_tool_status(tool: str, returncode: int, stdout: str, stderr: str) -> str:
    output = f"{stdout}\n{stderr}"
    # Grade lintian before looking at rc: it exits 0 with warnings, so the early
    # `if returncode == 0: return "passed"` this replaced never reached its own tag
    # check and the four real warnings on the shipped .deb could not surface.
    if tool == "lintian":
        return lintian_status(returncode, output)
    return "passed" if returncode == 0 else "failed"


def _autopkgtest_command(deb: Path, backend: str, testbed: str | None) -> tuple[str, ...] | None:
    if backend == "null":
        return ("autopkgtest", str(deb), "--", "null")
    if backend == "schroot":
        if not testbed:
            return None
        return ("autopkgtest", str(deb), "--", "schroot", testbed)
    if backend == "qemu":
        if not testbed:
            return None
        return ("autopkgtest", str(deb), "--", "qemu", testbed)
    return None


def _select_schroot_testbed(
    root: Path,
    runner: CommandRunner,
) -> tuple[str | None, tuple[str, ...], str]:
    if not runner.has_binary("schroot"):
        return (None, (), "schroot is not installed, so no writable schroot autopkgtest backend can be selected.")
    result = runner.run(CommandSpec(argv=("schroot", "-l"), cwd=root, description="List schroot autopkgtest testbeds"), check=False)
    if result.returncode != 0:
        detail = _result_reason(result.stdout, result.stderr) or "schroot -l failed while listing testbeds."
        return (None, (), detail)
    candidates = _parse_schroot_testbeds(result.stdout)
    if not candidates:
        return (None, (), "schroot -l did not report any testbeds.")
    return (candidates[0], candidates, f"Selected schroot testbed {candidates[0]}.")


def _parse_schroot_testbeds(output: str) -> tuple[str, ...]:
    values: list[str] = []
    for line in output.splitlines():
        value = line.strip()
        if not value:
            continue
        value = value.split(":", 1)[1] if ":" in value else value
        if value and value not in values:
            values.append(value)
    return tuple(sorted(values, key=_schroot_testbed_score))


def _schroot_testbed_score(name: str) -> tuple[int, str]:
    lowered = name.lower()
    score = 0
    if "sbuild" not in lowered:
        score += 10
    if "amd64" not in lowered:
        score += 2
    if not any(suite in lowered for suite in ("resolute", "unstable", "debian", "ubuntu")):
        score += 1
    return (score, name)


def _classify_autopkgtest_result(
    returncode: int,
    stdout: str,
    stderr: str,
) -> tuple[str, str, str, str, tuple[str, ...]]:
    output = f"{stdout}\n{stderr}"
    evidence = _autopkgtest_evidence_lines(output)
    if returncode == 0:
        return ("passed", "passed", "Autopkgtest passed.", "", evidence)
    if "Read-only file system" in output and "/etc/apt/preferences.d/90autopkgtest" in output:
        return (
            "testbed-broken",
            "testbed-readonly",
            "The testbed cannot write autopkgtest APT preferences, so package tests did not run.",
            "Use a writable autopkgtest backend such as schroot/qemu, or run inside the configured sbuild testbed.",
            evidence,
        )
    if "Unable to lock directory" in output or "Could not open lock file /var/lib/apt/lists/lock" in output:
        return (
            "testbed-broken",
            "testbed-apt-lock",
            "The testbed cannot update APT lists or acquire APT locks.",
            "Fix the testbed privileges/writability or use a dedicated schroot/qemu autopkgtest backend.",
            evidence,
        )
    if "apt-get" in output and "failed with status 100" in output:
        return (
            "testbed-broken",
            "testbed-apt-setup",
            "Autopkgtest failed while preparing the testbed APT configuration.",
            "Inspect the testbed APT sources and rerun with a hermetic schroot/qemu backend.",
            evidence,
        )
    if re.search(r"\b(test|smoke)\b.*\bFAIL\b|\bFAIL\b.*\b(test|smoke)\b", output, re.IGNORECASE):
        return (
            "test-failed",
            "package-test-failed",
            "The autopkgtest test command ran and failed.",
            "Fix debian/tests/* or package dependencies, then rerun autopkgtest.",
            evidence,
        )
    return (
        "failed",
        "unknown-failure",
        _result_reason(stdout, stderr) or f"autopkgtest exited with status {returncode}.",
        "Inspect the full autopkgtest output and rerun with --json for machine-readable triage.",
        evidence,
    )


def _autopkgtest_evidence_lines(output: str) -> tuple[str, ...]:
    patterns = (
        "Read-only file system",
        "Unable to lock directory",
        "Could not open lock file",
        "failed with status 100",
        "test smoke:",
        "summary",
        "FAIL",
        "PASS",
    )
    lines = [
        line.strip()
        for line in output.splitlines()
        if line.strip() and any(pattern in line for pattern in patterns)
    ]
    return tuple(lines[:8])


def _latest_deb(artifact_dir: Path) -> Path | None:
    return _newest_path(artifact_dir.glob("distroforge_*.deb"))


def _latest_buildinfo(artifact_dir: Path) -> Path | None:
    return _newest_path(artifact_dir.glob("distroforge_*_*.buildinfo"))


def _latest_changes(artifact_dir: Path) -> Path | None:
    return _newest_path(artifact_dir.glob("distroforge_*_*.changes"))


def _newest_path(paths) -> Path | None:
    values = list(paths)
    if not values:
        return None
    return max(values, key=lambda path: (path.stat().st_mtime_ns, path.name))


def _package_artifact_paths(artifact_dir: Path) -> list[Path]:
    patterns = ("distroforge_*.deb", "distroforge_*_*.buildinfo", "distroforge_*_*.changes")
    values: list[Path] = []
    for pattern in patterns:
        values.extend(artifact_dir.glob(pattern))
    return sorted(set(values))


def _artifact_kind(path: Path) -> str:
    if path.name.endswith(".buildinfo"):
        return "buildinfo"
    if path.name.endswith(".changes"):
        return "changes"
    if path.name.endswith(".deb"):
        return "deb"
    return path.suffix.lstrip(".") or "artifact"


def _data_files(root: Path) -> list[Path]:
    data_dir = root / "distroforge/data"
    if not data_dir.exists():
        return []
    return [
        path
        for path in sorted(data_dir.iterdir())
        if path.is_file() and path.suffix in {".toml", ".json"}
    ]


def _data_mode_offenders(root: Path) -> list[str]:
    return [
        str(path.relative_to(root))
        for path in _data_files(root)
        if path.stat().st_mode & 0o111
    ]


def _malformed_toml(root: Path) -> list[str]:
    offenders: list[str] = []
    for path in sorted((root / "distroforge/data").glob("*.toml")):
        try:
            tomllib.loads(path.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError:
            offenders.append(str(path.relative_to(root)))
    return offenders


def _malformed_json(root: Path) -> list[str]:
    offenders: list[str] = []
    for path in sorted((root / "distroforge/data").glob("*.json")):
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            offenders.append(str(path.relative_to(root)))
    return offenders


def _missing_package_data(root: Path) -> list[str]:
    patterns = _package_data_patterns(root)
    package_root = root / "distroforge"
    return [
        str(path.relative_to(root))
        for path in _data_files(root)
        if not _package_data_declares(patterns, str(path.relative_to(package_root)))
    ]


def _package_data_patterns(root: Path) -> tuple[str, ...]:
    pyproject = root / "pyproject.toml"
    if not pyproject.exists():
        return ()
    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return ()
    package_data = (
        data.get("tool", {})
        .get("setuptools", {})
        .get("package-data", {})
        .get("distroforge", [])
    )
    if not isinstance(package_data, list):
        return ()
    return tuple(str(pattern) for pattern in package_data)


def _package_data_declares(patterns: tuple[str, ...], relative_path: str) -> bool:
    return any(fnmatch.fnmatchcase(relative_path, pattern) for pattern in patterns)


def _malformed_examples(root: Path) -> list[str]:
    offenders: list[str] = []
    for path in sorted((root / "examples").glob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("example must be a mapping")
            validate_definition_data(data)
        except (OSError, ValueError, yaml.YAMLError):
            offenders.append(str(path.relative_to(root)))
    return offenders


def _declared_docs(root: Path) -> set[str]:
    path = root / "debian/docs"
    if not path.exists():
        return set()
    return {line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()}


def _declared_examples(root: Path) -> set[str]:
    path = root / "debian/examples"
    if not path.exists():
        return set()
    return {line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()}


REQUIRED_AUTOPKGTEST_SMOKE_CHECKS = (
    "distroforge --help",
    "distroforge releases",
    "distroforge doctor --python",
    "distroforge host",
    "distroforge chroot-backends",
    "distroforge packaging-policy",
    "distroforge hermetic-build-plan",
    # The package installs three console scripts and three manpages; the smoke test
    # used to exercise one of them. python3-typer is a hard Depends, so the facade
    # has to answer in the installed package too, not only in the build tree.
    "distroforge-typer --help",
    # autopkgtest hands each test a private scratch directory. Fixed /tmp names are
    # a symlink target for any local user and collide between parallel runs.
    "AUTOPKGTEST_TMP",
    "importlib.resources",
    "distroforge.data",
    "vulndb.json",
    "load_definition",
    "validate_definition_data",
    "/usr/share/doc/distroforge/examples/minimal-bootstrap.yaml",
)


def _autopkgtest_policy(root: Path, host_available: bool) -> AutopkgtestPolicy:
    control = root / "debian/tests/control"
    smoke = root / "debian/tests/smoke"
    declared = control.exists() and smoke.exists()
    control_text = control.read_text(encoding="utf-8") if control.exists() else ""
    smoke_text = smoke.read_text(encoding="utf-8") if smoke.exists() else ""
    missing = tuple(
        check for check in REQUIRED_AUTOPKGTEST_SMOKE_CHECKS if check not in smoke_text
    )
    return AutopkgtestPolicy(
        declared=declared,
        superficial="superficial" in control_text.lower(),
        required_checks=REQUIRED_AUTOPKGTEST_SMOKE_CHECKS,
        missing_checks=missing,
        host_available=host_available,
    )
