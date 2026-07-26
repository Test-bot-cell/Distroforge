from __future__ import annotations

import json
import os
import subprocess

from distroforge.cli import main
from distroforge.core.command import CommandResult, CommandRunner
from distroforge.core.packaging import (
    LINTIAN_ARGV,
    LINTIAN_PROFILE,
    LINTIAN_VENDORS_ROOT,
    HermeticBuildPlan,
    _check_from_result,
    _write_deb_content_report,
    build_debian_package,
    create_hermetic_release_bundle,
    debian_changelog_suite,
    diagnose_autopkgtest,
    lintian_argv,
    lintian_reason,
    lintian_status,
    lintian_tags,
    lintian_vendor_for_suite,
    packaging_policy_report,
)


class FakeAutopkgtestRunner:
    dry_run = False

    def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 20) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.history = []

    def has_binary(self, name: str) -> bool:
        return name == "autopkgtest"

    def run(self, spec, check: bool = True):
        self.history.append(spec)
        return CommandResult(spec, self.returncode, self.stdout, self.stderr)


class FakeSchrootAutopkgtestRunner:
    dry_run = False

    def __init__(self, schroot_output: str, autopkgtest_returncode: int = 0) -> None:
        self.schroot_output = schroot_output
        self.autopkgtest_returncode = autopkgtest_returncode
        self.history = []

    def has_binary(self, name: str) -> bool:
        return name in {"autopkgtest", "schroot"}

    def run(self, spec, check: bool = True):
        self.history.append(spec)
        if spec.argv == ("schroot", "-l"):
            return CommandResult(spec, 0, self.schroot_output, "")
        return CommandResult(spec, self.autopkgtest_returncode, "autopkgtest passed\n", "")


class BrokenSchrootRunner(FakeSchrootAutopkgtestRunner):
    def run(self, spec, check: bool = True):
        self.history.append(spec)
        if spec.argv == ("schroot", "-l"):
            return CommandResult(spec, 1, "", "E: /etc/schroot/schroot.conf: File is not owned by user root\n")
        return CommandResult(spec, self.autopkgtest_returncode, "", "")


class MissingAutopkgtestRunner(FakeAutopkgtestRunner):
    def has_binary(self, name: str) -> bool:
        return False


def test_buildinfo_report_detects_usr_local_taint(tmp_path, capsys) -> None:
    buildinfo = tmp_path / "distroforge.buildinfo"
    changes = tmp_path / "distroforge.changes"
    buildinfo.write_text(
        "Format: 1.0\n"
        "Source: distroforge\n"
        "Build-Tainted-By:\n"
        " usr-local-has-programs\n"
        " usr-local-has-libraries\n",
        encoding="utf-8",
    )
    changes.write_text(
        "Format: 1.8\n"
        "Source: distroforge\n"
        "Distribution: unstable\n",
        encoding="utf-8",
    )

    main(["buildinfo-report", str(buildinfo), "--changes", str(changes)])
    output = capsys.readouterr().out

    assert "Tainted: yes" in output
    assert "usr-local-has-programs" in output
    assert "Changes report" in output
    assert "Publication suite comes from .changes" in output
    assert "Distribution is unstable" in output


def test_packaging_policy_reports_docs_modes_and_tool_availability(tmp_path) -> None:
    root = tmp_path / "root"
    (root / "distroforge/data").mkdir(parents=True)
    (root / "distroforge/data/profiles.toml").write_text("", encoding="utf-8")
    (root / "distroforge/data/vulndb.json").write_text('{"advisories": []}\n', encoding="utf-8")
    (root / "pyproject.toml").write_text(
        '[tool.setuptools.package-data]\ndistroforge = ["data/*.toml", "data/vulndb.json"]\n',
        encoding="utf-8",
    )
    (root / "examples").mkdir()
    (root / "examples/minimal-bootstrap.yaml").write_text("source_mode: bootstrap\n", encoding="utf-8")
    (root / "debian").mkdir()
    (root / "debian/docs").write_text(
        "docs/acceptance-matrix.md\n"
        "docs/definitions.md\n"
        "docs/artifacts-release-readiness.md\n"
        "docs/derivative-profiles.md\n"
        "docs/gui-parity.md\n"
        "docs/maintainer-copilot.md\n"
        "docs/packaging-release.md\n"
        "docs/ux-cognitive-ergonomics.md\n"
        "docs/velocity-responsiveness.md\n"
        "docs/advisory-agent.md\n",
        encoding="utf-8",
    )
    (root / "debian/examples").write_text("examples/minimal-bootstrap.yaml\n", encoding="utf-8")
    (root / "debian/tests").mkdir()
    (root / "debian/tests/control").write_text(
        "Tests: smoke\nDepends:\n @,\n python3-pytest,\nRestrictions: allow-stderr\n",
        encoding="utf-8",
    )
    (root / "debian/tests/smoke").write_text(
        "distroforge --help\n"
        "distroforge releases\n"
        "distroforge doctor --python\n"
        "distroforge host\n"
        "distroforge chroot-backends\n"
        "distroforge packaging-policy\n"
        "distroforge hermetic-build-plan\n"
        "distroforge-typer --help\n"
        "AUTOPKGTEST_TMP\n"
        "importlib.resources\n"
        "distroforge.data\n"
        "vulndb.json\n"
        "load_definition\n"
        "validate_definition_data\n"
        "/usr/share/doc/distroforge/examples/minimal-bootstrap.yaml\n",
        encoding="utf-8",
    )

    report = packaging_policy_report(root)

    assert report.data_mode_offenders == []
    assert report.malformed_toml == []
    assert report.malformed_json == []
    assert report.missing_package_data == []
    assert report.malformed_examples == []
    assert report.missing_docs == []
    assert report.missing_examples == []
    assert report.autopkgtest_policy is not None
    assert report.autopkgtest_policy.status in {"declared and meaningful", "unavailable on host"}
    assert "Packaging policy report" in report.render_text()
    assert "Autopkgtest policy" in report.render_text()


def test_packaging_policy_blocks_malformed_formats_and_undeclared_examples(tmp_path) -> None:
    root = tmp_path / "root"
    (root / "distroforge/data").mkdir(parents=True)
    (root / "distroforge/data/bad.toml").write_text("[broken\n", encoding="utf-8")
    (root / "distroforge/data/bad.json").write_text("{broken\n", encoding="utf-8")
    (root / "pyproject.toml").write_text(
        '[tool.setuptools.package-data]\ndistroforge = ["data/*.toml", "data/*.json"]\n',
        encoding="utf-8",
    )
    (root / "examples").mkdir()
    (root / "examples/bad.yaml").write_text("- not\n- mapping\n", encoding="utf-8")
    (root / "debian").mkdir()
    (root / "debian/docs").write_text("", encoding="utf-8")
    (root / "debian/examples").write_text("", encoding="utf-8")

    report = packaging_policy_report(root)

    assert report.blocked
    assert "distroforge/data/bad.toml" in report.malformed_toml
    assert "distroforge/data/bad.json" in report.malformed_json
    assert "examples/bad.yaml" in report.malformed_examples
    assert "examples/bad.yaml" in report.missing_examples


def test_packaging_policy_blocks_undeclared_package_data(tmp_path) -> None:
    root = tmp_path / "root"
    (root / "distroforge/data").mkdir(parents=True)
    (root / "distroforge/data/profiles.toml").write_text("", encoding="utf-8")
    (root / "distroforge/data/vulndb.json").write_text('{"advisories": []}\n', encoding="utf-8")
    (root / "pyproject.toml").write_text(
        '[tool.setuptools.package-data]\ndistroforge = ["data/*.toml"]\n',
        encoding="utf-8",
    )

    report = packaging_policy_report(root)

    assert report.blocked
    assert report.missing_package_data == ["distroforge/data/vulndb.json"]
    assert "Data files missing from package-data" in report.render_text()


def test_packaging_policy_detects_weak_autopkgtest(tmp_path) -> None:
    root = tmp_path / "root"
    (root / "distroforge/data").mkdir(parents=True)
    (root / "examples").mkdir()
    (root / "debian/tests").mkdir(parents=True)
    (root / "debian/tests/control").write_text(
        "Tests: smoke\nRestrictions: superficial\n",
        encoding="utf-8",
    )
    (root / "debian/tests/smoke").write_text("distroforge releases\n", encoding="utf-8")

    report = packaging_policy_report(root)

    assert report.autopkgtest_policy is not None
    assert report.autopkgtest_policy.status == "declared but weak"
    assert report.blocked
    assert "distroforge --help" in report.autopkgtest_policy.missing_checks
    assert "declared but weak" in report.render_text()


def test_packaging_policy_blocks_missing_autopkgtest_declaration(tmp_path) -> None:
    root = tmp_path / "root"
    (root / "distroforge/data").mkdir(parents=True)
    (root / "examples").mkdir()
    (root / "debian").mkdir()

    report = packaging_policy_report(root)

    assert report.autopkgtest_policy is not None
    assert report.autopkgtest_policy.status == "undeclared"
    assert report.blocked


def test_autopkgtest_doctor_classifies_readonly_testbed(tmp_path) -> None:
    deb = tmp_path / "distroforge_0.1.0-1_all.deb"
    deb.write_bytes(b"package")
    stderr = (
        "cannot create /etc/apt/preferences.d/90autopkgtest: Read-only file system\n"
        "E: Unable to lock directory /var/lib/apt/lists/\n"
    )

    report = diagnose_autopkgtest(
        tmp_path,
        deb=deb,
        execute=True,
        runner=FakeAutopkgtestRunner(stderr=stderr),
    )

    assert report.status == "testbed-broken"
    assert report.classification == "testbed-readonly"
    assert report.blocked
    assert "writable autopkgtest backend" in report.render_text()


def test_autopkgtest_doctor_auto_selects_schroot_testbed(tmp_path) -> None:
    deb = tmp_path / "distroforge_0.1.0-1_all.deb"
    deb.write_bytes(b"package")
    runner = FakeSchrootAutopkgtestRunner(
        "chroot:generic\nchroot:resolute-amd64-sbuild\n",
    )

    report = diagnose_autopkgtest(
        tmp_path,
        deb=deb,
        backend="schroot",
        execute=True,
        runner=runner,
    )

    assert report.status == "passed"
    assert report.classification == "passed"
    assert report.testbed == "resolute-amd64-sbuild"
    assert report.command == ("autopkgtest", str(deb), "--", "schroot", "resolute-amd64-sbuild")
    assert report.suggested_testbeds == ("resolute-amd64-sbuild", "generic")


def test_autopkgtest_doctor_reports_broken_schroot_listing(tmp_path) -> None:
    deb = tmp_path / "distroforge_0.1.0-1_all.deb"
    deb.write_bytes(b"package")

    report = diagnose_autopkgtest(
        tmp_path,
        deb=deb,
        backend="schroot",
        execute=True,
        runner=BrokenSchrootRunner(""),
    )

    assert report.status == "invalid"
    assert report.classification == "schroot-testbed-unavailable"
    assert "schroot.conf" in report.detail


def test_cli_autopkgtest_doctor_writes_json_report(tmp_path, capsys, monkeypatch) -> None:
    deb = tmp_path / "distroforge_0.1.0-1_all.deb"
    output = tmp_path / "AUTOPKGTEST-DOCTOR.json"
    deb.write_bytes(b"package")
    monkeypatch.setattr(CommandRunner, "has_binary", staticmethod(lambda _name: False))

    main(["autopkgtest-doctor", str(tmp_path), "--deb", str(deb), "--output", str(output), "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert payload["schema"] == "distroforge.autopkgtest-doctor.v1"
    assert payload["status"] == "planned"
    assert payload["classification"] == "not-run"
    assert payload["command"] == ["autopkgtest", str(deb), "--", "null"]
    assert output.exists()


def test_autopkgtest_doctor_requires_tool_for_execution(tmp_path) -> None:
    deb = tmp_path / "distroforge_0.1.0-1_all.deb"
    deb.write_bytes(b"package")
    runner = MissingAutopkgtestRunner()

    report = diagnose_autopkgtest(tmp_path, deb=deb, execute=True, runner=runner)

    assert report.status == "missing-tool"
    assert report.classification == "host-missing-autopkgtest"
    assert runner.history == []


def test_hermetic_build_plan_has_backend_commands(tmp_path) -> None:
    plan = HermeticBuildPlan(tmp_path, backend="sbuild", suite="trixie", arch="amd64")

    assert "sbuild-createchroot" in plan.render_text()
    assert "trixie" in plan.render_text()


def test_hermetic_release_bundle_writes_manifest_and_reports(tmp_path, monkeypatch) -> None:
    root = tmp_path / "root"
    artifact_dir = tmp_path / "artifacts"
    output = tmp_path / "bundle"
    root.mkdir()
    artifact_dir.mkdir()
    version = "0.3.4-2"
    (root / "debian").mkdir()
    (root / "debian/changelog").write_text(
        "distroforge (0.3.4-2) resolute; urgency=medium\n\n"
        "  * Test release.\n\n"
        " -- DistroForge maintainers <maintainers@distroforge.invalid>  Wed, 03 Jun 2026 12:00:00 +0200\n",
        encoding="utf-8",
    )
    for name in (
        f"distroforge_{version}_all.deb",
        f"distroforge_{version}.dsc",
        f"distroforge_{version}.debian.tar.xz",
        f"distroforge_{version}_amd64.buildinfo",
        f"distroforge_{version}_amd64.changes",
        "distroforge_0.3.4.orig.tar.xz",
    ):
        (artifact_dir / name).write_bytes(f"{name}\n".encode())
    (artifact_dir / "distroforge_0.3.4-2_amd64-2026-06-03T14:51:10Z.build").write_text("Status: successful\n", encoding="utf-8")
    (artifact_dir / "AUTOPKGTEST-DOCTOR.json").write_text(
        json.dumps(
            {
                "schema": "distroforge.autopkgtest-doctor.v1",
                "status": "passed",
                "classification": "passed",
                "detail": "Autopkgtest passed.",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    def fake_run(command, env=None):
        if command[:2] == ("dpkg-deb", "-c"):
            stdout = "\n".join(
                [
                    "./usr/share/applications/distroforge.desktop",
                    "./usr/share/icons/hicolor/scalable/apps/distroforge.svg",
                    "./usr/share/doc/distroforge/acceptance-matrix.md",
                    "./usr/share/man/man1/distroforge.1.gz",
                ]
            )
        elif command[:2] == ("dpkg-deb", "-f"):
            stdout = "Package: distroforge\nVersion: 0.3.4-2\nArchitecture: all\nDepends: zstd\n"
        elif command[-2:] == ("host", "--json"):
            stdout = '[{"name": "nspawn-terminal", "available": true}]\n'
        elif command[-2:] == ("chroot-backends", "--json"):
            stdout = '[{"name": "auto", "selected": true, "active": false}]\n'
        else:
            stdout = "ok\n"
        return subprocess.CompletedProcess(command, 0, stdout, "")

    monkeypatch.setattr("distroforge.core.packaging._run_capture", fake_run)

    report = create_hermetic_release_bundle(
        root,
        output_dir=output,
        artifact_dir=artifact_dir,
        suite="resolute",
        build_timestamp="2026-06-03T14:51:59Z",
    )

    assert report.status == "ready"
    assert (output / "MANIFEST.json").exists()
    assert (output / "SHA256SUMS").exists()
    assert (output / "BUNDLE-CONTRACT.json").exists()
    assert (output / "AUTOPKGTEST-DOCTOR.json").exists()
    assert (output / "LOCAL-PROVENANCE.json").exists()
    assert (output / "ISO-VALIDATION-PLAN.txt").exists()
    assert "distroforge.hermetic-release-bundle.contract.v1" in (output / "BUNDLE-CONTRACT.json").read_text(encoding="utf-8")
    assert "nspawn-terminal" in (output / "HOST-CAPABILITIES.json").read_text(encoding="utf-8")
    assert "chroot-backends" in (output / "BUNDLE-CONTRACT.json").read_text(encoding="utf-8")
    assert "AUTOPKGTEST-DOCTOR.json" in (output / "BUNDLE-CONTRACT.json").read_text(encoding="utf-8")
    assert "autopkgtest doctor: passed: passed" in (output / "VERIFY-REPORT.txt").read_text(encoding="utf-8")
    assert "OpenAI-shaped key path hits: 0" in (output / "OPENAI-SECRET-AUDIT.txt").read_text(encoding="utf-8")


def test_hermetic_build_plan_is_deterministic_for_supported_backends(tmp_path) -> None:
    assert HermeticBuildPlan(tmp_path).commands() == [
        ("sbuild-createchroot", "unstable", str(tmp_path / ".sbuild-chroot")),
        ("sbuild", "--arch", "amd64", "--dist", "unstable", "--no-run-lintian"),
    ]
    assert HermeticBuildPlan(tmp_path, backend="pbuilder", suite="trixie").commands() == [
        ("pbuilder", "create", "--distribution", "trixie"),
        ("pdebuild", "--buildresult", str(tmp_path.parent)),
    ]
    assert HermeticBuildPlan(tmp_path, backend="mmdebstrap", suite="trixie").commands() == [
        ("mmdebstrap", "--variant=buildd", "trixie", str(tmp_path / ".build-chroot")),
        ("sbuild", "--chroot", str(tmp_path / ".build-chroot"), "--arch", "amd64", "--no-run-lintian"),
    ]


def test_debian_package_build_report_collects_artifacts_and_plans_checks(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    deb = tmp_path / "distroforge_0.1.0-1_all.deb"
    deb.write_bytes(b"package")
    (tmp_path / "distroforge_0.1.0-1_amd64.buildinfo").write_text(
        "Format: 1.0\nSource: distroforge\n",
        encoding="utf-8",
    )
    (tmp_path / "distroforge_0.1.0-1_amd64.changes").write_text(
        "Format: 1.8\nSource: distroforge\nDistribution: unstable\n",
        encoding="utf-8",
    )

    report = build_debian_package(root)

    assert report.status == "planned"
    assert report.build.status == "planned"
    assert {artifact.kind for artifact in report.artifacts} == {"deb", "buildinfo", "changes"}
    assert all(check.status == "planned" for check in report.checks)
    assert "SHA256" in report.render_text()


def test_debian_package_build_report_uses_newest_artifact_metadata(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (tmp_path / "distroforge_0.1.0-1_all.deb").write_bytes(b"old")
    old_buildinfo = tmp_path / "distroforge_0.1.0-1_source.buildinfo"
    old_changes = tmp_path / "distroforge_0.1.0-1_source.changes"
    new_buildinfo = tmp_path / "distroforge_0.1.0-2_amd64.buildinfo"
    new_changes = tmp_path / "distroforge_0.1.0-2_amd64.changes"
    old_buildinfo.write_text("Format: 1.0\nSource: distroforge\n", encoding="utf-8")
    old_changes.write_text("Format: 1.8\nSource: distroforge\nDistribution: old\n", encoding="utf-8")
    new_buildinfo.write_text("Format: 1.0\nSource: distroforge\n", encoding="utf-8")
    new_changes.write_text("Format: 1.8\nSource: distroforge\nDistribution: new\n", encoding="utf-8")
    os.utime(old_buildinfo, (1, 1))
    os.utime(old_changes, (1, 1))
    os.utime(new_buildinfo, (2, 2))
    os.utime(new_changes, (2, 2))

    report = build_debian_package(root)

    assert report.policy.buildinfo is not None
    assert report.policy.buildinfo.path == new_buildinfo
    assert report.policy.buildinfo.changes is not None
    assert report.policy.buildinfo.changes.path == new_changes


def test_cli_packaging_policy_and_hermetic_plan(tmp_path, capsys) -> None:
    root = tmp_path / "root"
    (root / "distroforge/data").mkdir(parents=True)
    (root / "debian").mkdir()
    (root / "debian/docs").write_text("", encoding="utf-8")

    main(["packaging-policy", str(root)])
    assert "Packaging policy report" in capsys.readouterr().out

    main(["debian-package", str(root)])
    assert "Debian package build report" in capsys.readouterr().out

    main(["hermetic-build-plan", str(root), "--backend", "pbuilder", "--suite", "unstable"])
    output = capsys.readouterr().out
    assert "Hermetic Debian build plan" in output
    assert "pbuilder" in output


# The four tags lintian 2.129 really emits on the shipped distroforge_0.3.5-2_all.deb,
# at exit code 0. Verbatim, because the point is that rc alone says "clean".
SHIPPED_LINTIAN_OUTPUT = (
    "W: distroforge: command-with-path-in-maintainer-script /usr/bin/gsettings"
    " (in test syntax) [postinst:11]\n"
    "W: distroforge: debian-changelog-line-too-long"
    " [usr/share/doc/distroforge/changelog.Debian.gz:4]\n"
    "W: distroforge: debian-changelog-line-too-long"
    " [usr/share/doc/distroforge/changelog.Debian.gz:5]\n"
    "W: distroforge: debian-changelog-line-too-long"
    " [usr/share/doc/distroforge/changelog.Debian.gz:6]\n"
)


class FakeLintianRunner:
    """A runner that answers lintian the way lintian answers: warnings at rc 0."""

    dry_run = False

    def __init__(self, output: str = SHIPPED_LINTIAN_OUTPUT, returncode: int = 0) -> None:
        self.output = output
        self.returncode = returncode
        self.history: list = []

    def has_binary(self, name: str) -> bool:
        return name in {"lintian", "dpkg-buildpackage"}

    def run(self, spec, check: bool = True):
        self.history.append(spec)
        if spec.argv[:1] == ("lintian",):
            return CommandResult(spec=spec, returncode=self.returncode, stdout=self.output, stderr="")
        return CommandResult(spec=spec, returncode=0, stdout="", stderr="")


def _package_root(tmp_path):
    root = tmp_path / "root"
    (root / "distroforge/data").mkdir(parents=True)
    (root / "debian").mkdir()
    (root / "debian/docs").write_text("", encoding="utf-8")
    # _latest_deb globs the parent of the source root, where dpkg-buildpackage drops it.
    (root.parent / "distroforge_0.3.5-2_all.deb").write_bytes(b"deb\n")
    return root


def test_lintian_verdict_reads_the_output_instead_of_trusting_exit_zero(tmp_path) -> None:
    """rc 0 with four W: tags is not a pass, and the tags have to reach the report.

    _package_tool_status returned "passed" before it looked at anything, and the reason
    field was cleared for every non-failing status, so the four real warnings on the
    shipped package could not surface through either path.
    """
    runner = FakeLintianRunner()

    report = build_debian_package(_package_root(tmp_path), execute=True, runner=runner)
    lintian = next(check for check in report.checks if check.name == "lintian")

    assert lintian.returncode == 0
    assert lintian.status == "review required"
    assert lintian.reason.count("W: distroforge:") == 4
    assert "command-with-path-in-maintainer-script" in lintian.reason
    assert "debian-changelog-line-too-long" in lintian.reason
    assert lintian.needs_review
    assert not lintian.failed


def test_lintian_falls_back_to_the_pinned_vendor_when_the_suite_is_unreadable(tmp_path) -> None:
    """Left unset, the profile comes from dpkg-vendor on whatever host runs the check.

    lintian profiles are vendors, never suites: `--profile resolute` aborts with
    "Could not find a profile matching: resolute/main". _package_root ships no
    debian/changelog, so this is the fallback path, and the fallback stays pinned.
    """
    runner = FakeLintianRunner()

    build_debian_package(_package_root(tmp_path), execute=True, runner=runner)
    argv = next(spec.argv for spec in runner.history if spec.argv[:1] == ("lintian",))

    assert LINTIAN_PROFILE in {"debian", "ubuntu"}
    assert argv[1:4] == ("--profile", LINTIAN_PROFILE, "--no-tag-display-limit")
    assert argv[:4] == LINTIAN_ARGV


def _vendors_root(tmp_path, mapping: dict[str, tuple[str, ...]]):
    root = tmp_path / "vendors"
    for vendor, dists in mapping.items():
        known = root / vendor / "main/data/changes-file/known-dists"
        known.parent.mkdir(parents=True)
        # A comment and a blank line, because lintian's real files carry both.
        known.write_text(f"# List of {vendor} distributions\n\n" + "\n".join(dists) + "\n", encoding="utf-8")
    return root


def test_the_profile_follows_the_targeted_suite_not_the_build_host(tmp_path) -> None:
    """The vendor decides which Distribution values a .changes may hold.

    Grading an Ubuntu-targeted package against the Debian profile raised
    bad-distribution-in-changes-file for a field that was correct, and since the
    verdict is graded from tags, that rated a compliant package "failed".
    """
    vendors = _vendors_root(tmp_path, {"debian": ("sid", "trixie"), "ubuntu": ("resolute", "questing")})

    assert lintian_vendor_for_suite("resolute", vendors_root=vendors) == "ubuntu"
    assert lintian_vendor_for_suite("sid", vendors_root=vendors) == "debian"
    # A qualified suite resolves through its base name.
    assert lintian_vendor_for_suite("resolute-updates", vendors_root=vendors) == "ubuntu"
    # Anything no installed vendor claims keeps the reproducible pinned verdict.
    assert lintian_vendor_for_suite("UNRELEASED", vendors_root=vendors) == LINTIAN_PROFILE
    assert lintian_vendor_for_suite("", vendors_root=vendors) == LINTIAN_PROFILE
    assert lintian_vendor_for_suite("resolute", vendors_root=tmp_path / "absent") == LINTIAN_PROFILE
    assert lintian_argv("resolute", vendors_root=vendors)[:3] == ("lintian", "--profile", "ubuntu")


def test_this_package_resolves_to_the_vendor_it_actually_targets() -> None:
    """The regression that started this: DistroForge grading its own package failed.

    Read from the shipped changelog rather than a fixture, so the day the target
    suite changes vendor this test is what notices.
    """
    from pathlib import Path

    suite = debian_changelog_suite(Path(__file__).resolve().parents[1])

    assert suite, "the shipped debian/changelog names no suite"
    assert suite not in LINTIAN_VENDORS, f"{suite!r} is a vendor name, not a suite"
    if not LINTIAN_VENDORS_ROOT.is_dir():
        return  # lintian's vendor data is absent, so only the fallback is testable here
    resolved = lintian_vendor_for_suite(suite)
    assert resolved in LINTIAN_VENDORS
    claimed = LINTIAN_VENDORS_ROOT / resolved / "main/data/changes-file/known-dists"
    assert suite in claimed.read_text(encoding="utf-8").split(), (
        f"{resolved!r} was chosen for {suite!r} but does not list it"
    )


def test_the_changelog_suite_reader_takes_the_first_of_several(tmp_path) -> None:
    root = tmp_path / "pkg"
    (root / "debian").mkdir(parents=True)
    assert debian_changelog_suite(root) == ""
    (root / "debian/changelog").write_text("distroforge (0.3.5-3) resolute; urgency=medium\n", encoding="utf-8")
    assert debian_changelog_suite(root) == "resolute"
    (root / "debian/changelog").write_text("distroforge (1-1) resolute questing; urgency=low\n", encoding="utf-8")
    assert debian_changelog_suite(root) == "resolute"
    (root / "debian/changelog").write_text("nonsense\n", encoding="utf-8")
    assert debian_changelog_suite(root) == ""


def test_lintian_errors_block_and_a_silent_run_passes() -> None:
    assert lintian_status(0, "") == "passed"
    assert lintian_status(0, SHIPPED_LINTIAN_OUTPUT) == "review required"
    assert lintian_status(2, "E: distroforge: no-copyright-file\n") == "failed"
    # --fail-on warning is not the mechanism: it turns rc into 2 for a healthy
    # artifact and still blocks nothing, so the tags stay the source of truth.
    assert lintian_status(2, SHIPPED_LINTIAN_OUTPUT) == "review required"
    assert lintian_status(127, "") == "failed"
    assert lintian_tags(SHIPPED_LINTIAN_OUTPUT + "N: 3 hints overridden\n")[-1].startswith("N: ")
    assert lintian_reason(SHIPPED_LINTIAN_OUTPUT).count(";") == 3


def test_hermetic_bundle_lintian_check_keeps_the_tags(tmp_path) -> None:
    """The bundle path grades lintian too, and it graded on rc alone as well."""
    result = subprocess.CompletedProcess(LINTIAN_ARGV, 0, SHIPPED_LINTIAN_OUTPUT, "")

    check = _check_from_result("lintian", LINTIAN_ARGV, result)

    assert check.status == "review required"
    assert "command-with-path-in-maintainer-script" in check.reason
    assert _check_from_result("lintian", LINTIAN_ARGV, subprocess.CompletedProcess(LINTIAN_ARGV, 127, "", "")).status == "missing"


def test_deb_content_does_not_require_a_lintian_override_that_is_never_shipped(tmp_path, monkeypatch) -> None:
    """packaging.py demanded lintian/overrides/distroforge from every built .deb.

    The project ships none and has decided never to: silencing a tag with an override
    is not the same thing as being clean. The requirement made deb-content fail on
    every build for a file that does not and should not exist.
    """
    deb = tmp_path / "distroforge_0.3.5-2_all.deb"
    deb.write_bytes(b"deb\n")

    def fake_run(command, env=None):
        if command[:2] == ("dpkg-deb", "-c"):
            stdout = "\n".join(
                [
                    "./usr/share/applications/distroforge.desktop",
                    "./usr/share/icons/hicolor/scalable/apps/distroforge.svg",
                    "./usr/share/doc/distroforge/acceptance-matrix.md",
                    "./usr/share/man/man1/distroforge.1.gz",
                ]
            )
        else:
            stdout = "Package: distroforge\n"
        return subprocess.CompletedProcess(command, 0, stdout, "")

    monkeypatch.setattr("distroforge.core.packaging._run_capture", fake_run)

    check = _write_deb_content_report(tmp_path / "DEB-CONTENT-REPORT.txt", deb)

    assert check.status == "passed"
    assert check.reason == ""
    assert "lintian/overrides" not in (tmp_path / "DEB-CONTENT-REPORT.txt").read_text(encoding="utf-8")


# lintian ships its profiles as directories under /usr/share/lintian/profiles, one per
# vendor. Passing a suite name instead aborts the run outright, and CI used to guard
# that with a grep for the exact argument pair -- which matched only the comment
# explaining the rule, and missed the form this code actually builds, where the flag
# and its value are two separate argv strings.
LINTIAN_VENDORS = frozenset({"debian", "dpkg", "elxr", "kali", "pardus", "pureos", "ubuntu"})


def test_the_lintian_profile_is_a_vendor_and_not_a_suite() -> None:
    assert LINTIAN_PROFILE in LINTIAN_VENDORS, f"{LINTIAN_PROFILE!r} is not a lintian vendor"
    assert LINTIAN_ARGV[:3] == ("lintian", "--profile", LINTIAN_PROFILE)
    # The suite names DistroForge targets live in debian/changelog and are read from
    # there rather than spelled here, so this test cannot become its own offender.
    suites = _changelog_suites()
    assert suites, "no changelog stanza was parsed, so this assertion proves nothing"
    assert LINTIAN_VENDORS.isdisjoint(suites), f"a suite name collides with a vendor: {suites}"


def _changelog_versions() -> list[str]:
    from pathlib import Path

    changelog = Path(__file__).resolve().parents[1] / "debian/changelog"
    return [line for line in changelog.read_text(encoding="utf-8").splitlines() if line.startswith("distroforge (")]


def _changelog_suites() -> set[str]:
    return {line.split()[2].rstrip(";") for line in _changelog_versions()}


def test_lintian_is_never_invoked_without_the_resolved_profile() -> None:
    from pathlib import Path

    # Every call site must go through lintian_argv(), which is the only place the
    # program name and the --profile pair are spelled. A fourth spelling would
    # silently take the host's dpkg-vendor default, which is the whole bug this
    # module's comment describes.
    source = (Path(__file__).resolve().parents[1] / "distroforge/core/packaging.py").read_text(encoding="utf-8")
    building = [
        line.strip()
        for line in source.splitlines()
        if '"lintian"' in line and "LINTIAN_ARGV" not in line and "==" not in line and "which" not in line
    ]

    assert building == [
        # the one builder ...
        'return ("lintian", "--profile", lintian_vendor_for_suite(suite, vendors_root=vendors_root), "--no-tag-display-limit")',
        # ... and two check *names*, which are labels rather than argv.
        '"LINTIAN.txt": "lintian",',
        '"lintian",',
    ], building
    # No call site may reach past the builder to hand-assemble an invocation.
    assert 'lintian_argv(suite)' in source
    assert 'lintian_argv(debian_changelog_suite(root))' in source
