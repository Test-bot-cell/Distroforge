from __future__ import annotations

import json
import os
import subprocess

from distroforge.cli import main
from distroforge.core.command import CommandResult, CommandRunner
from distroforge.core.packaging import (
    LINTIAN_ARGV,
    LINTIAN_PROFILE,
    HermeticBuildPlan,
    _check_from_result,
    _write_deb_content_report,
    build_debian_package,
    create_hermetic_release_bundle,
    diagnose_autopkgtest,
    lintian_reason,
    lintian_status,
    lintian_tags,
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


def test_lintian_runs_with_a_pinned_vendor_profile(tmp_path) -> None:
    """Left unset, the profile comes from dpkg-vendor on whatever host runs the check.

    lintian profiles are vendors, never suites: `--profile resolute` aborts with
    "Could not find a profile matching: resolute/main".
    """
    runner = FakeLintianRunner()

    build_debian_package(_package_root(tmp_path), execute=True, runner=runner)
    argv = next(spec.argv for spec in runner.history if spec.argv[:1] == ("lintian",))

    assert LINTIAN_PROFILE in {"debian", "ubuntu"}
    assert argv[1:4] == ("--profile", LINTIAN_PROFILE, "--no-tag-display-limit")
    assert argv[:4] == LINTIAN_ARGV


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
