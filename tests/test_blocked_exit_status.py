"""A command that reports "blocked" must not also report success to the shell.

Three commands that perform real, expensive, privileged work printed a verdict of
`blocked` -- the word is in their JSON, under a key called `blocked` -- and exited 0.
`debian-package --execute` did it for a dpkg-buildpackage that returned 2, for a
lintian error tag and for a failed autopkgtest; `iso-build --execute` did it for a
build that produced no ISO at all; `boot-proof` did it for a boot that never
happened. cli.py printed what the renderer returned and returned, and three of the
render_*_command dispatchers hard-coded `False` in the blocked slot next to siblings
that propagated a real verdict (commands/iso.py had three of five propagating,
commands/artifacts.py two of fourteen).

The rule these tests pin is the one the reports already imply: a plan never fails,
an executed action does. A dry run that reports why it cannot proceed has answered
correctly; the same verdict after the work ran means the work did not produce what
it claims to produce.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from distroforge.cli import main
from distroforge.core.command import CommandResult
from distroforge.core.iso_build import IsoBuildReport
from distroforge.core.iso_doctor import IsoDoctorReport
from distroforge.core.packaging import build_debian_package

# rc 0 with a single E: tag. lintian exits 0 with warnings, so this is the shape the
# tag reader exists for, and the gate has to follow the reader rather than rc.
LINTIAN_ERROR_OUTPUT = "E: distroforge: no-copyright-file\n"
LINTIAN_WARNING_OUTPUT = "W: distroforge: debian-changelog-line-too-long [changelog:4]\n"

_REPO_ROOT = Path(__file__).resolve().parents[1]


class FakePackageRunner:
    """Runs nothing. Answers dpkg-buildpackage, lintian and autopkgtest by script."""

    dry_run = False

    def __init__(
        self,
        *,
        build_returncode: int = 0,
        lintian_output: str = "",
        lintian_returncode: int = 0,
        binaries: frozenset[str] = frozenset({"dpkg-buildpackage", "lintian", "autopkgtest"}),
        autopkgtest_returncode: int = 0,
    ) -> None:
        self.build_returncode = build_returncode
        self.lintian_output = lintian_output
        self.lintian_returncode = lintian_returncode
        self.binaries = binaries
        self.autopkgtest_returncode = autopkgtest_returncode
        self.history: list = []

    def has_binary(self, name: str) -> bool:
        return name in self.binaries

    def run(self, spec, check: bool = True):
        self.history.append(spec)
        tool = spec.argv[0] if spec.argv else ""
        if tool == "dpkg-buildpackage":
            return CommandResult(spec=spec, returncode=self.build_returncode, stdout="", stderr="")
        if tool == "lintian":
            return CommandResult(
                spec=spec, returncode=self.lintian_returncode, stdout=self.lintian_output, stderr=""
            )
        if tool == "autopkgtest":
            return CommandResult(spec=spec, returncode=self.autopkgtest_returncode, stdout="", stderr="")
        return CommandResult(spec=spec, returncode=0, stdout="", stderr="")


def _package_root(tmp_path: Path) -> Path:
    """A source tree shaped like this package's, with the .deb where dpkg drops it.

    debian/docs is empty on purpose in some tests below: an empty manifest means every
    important document is missing, which is one of the things the policy report blocks
    on, and it is the cheapest way to reach a blocked policy without a real build.
    """
    root = tmp_path / "root"
    (root / "distroforge/data").mkdir(parents=True)
    (root / "debian").mkdir()
    (root / "debian/docs").write_text("", encoding="utf-8")
    (root.parent / "distroforge_0.3.5-2_all.deb").write_bytes(b"deb\n")
    return root


def _patch_runner(monkeypatch, runner) -> None:
    """Let the CLI reach the real build_debian_package, with a runner that spawns nothing.

    Everything downstream of the process spawn stays real: the status computation, the
    lintian tag reader, the autopkgtest doctor, the renderer and the CLI dispatch.
    """
    monkeypatch.setattr(
        "distroforge.commands.packaging.build_debian_package",
        lambda root, *, execute=False, artifact_dir=None: build_debian_package(
            root, execute=execute, runner=runner, artifact_dir=artifact_dir
        ),
    )


def _doctor(root: Path) -> IsoDoctorReport:
    return IsoDoctorReport(
        project=root,
        output_iso=root / "dist/Ref-26.04.iso",
        status="ready",
        findings=(),
        next_command="distroforge build",
    )


def _iso_report(root: Path, *, status: str, execute: bool) -> IsoBuildReport:
    return IsoBuildReport(
        root,
        root / "dist/Ref-26.04.iso",
        status,
        execute,
        root / "dist/ISO-BUILD.json",
        _doctor(root),
        ("prepare", "bootstrap_rootfs"),
    )


def test_a_build_that_returned_two_fails_the_command(monkeypatch, tmp_path, capsys) -> None:
    _patch_runner(monkeypatch, FakePackageRunner(build_returncode=2))

    with pytest.raises(SystemExit) as exc:
        main(["debian-package", str(_package_root(tmp_path)), "--execute", "--json"])

    assert exc.value.code == 2
    # The report still has to say why, on stdout, or the exit code is all the operator gets.
    assert json.loads(capsys.readouterr().out)["status"] == "blocked"


def test_a_lintian_error_tag_fails_the_command_even_at_exit_zero(monkeypatch, tmp_path, capsys) -> None:
    """The whole reason lintian's verdict is read from its output and not from rc."""
    _patch_runner(
        monkeypatch,
        FakePackageRunner(lintian_output=LINTIAN_ERROR_OUTPUT, lintian_returncode=0),
    )

    with pytest.raises(SystemExit) as exc:
        main(["debian-package", str(_package_root(tmp_path)), "--execute", "--json"])

    assert exc.value.code == 2
    report = json.loads(capsys.readouterr().out)
    lintian = next(check for check in report["checks"] if check["name"] == "lintian")
    assert lintian["returncode"] == 0
    assert lintian["status"] == "failed"


def test_lintian_warnings_are_a_review_and_not_a_failure(monkeypatch, tmp_path, capsys) -> None:
    """A package with warnings and no error tag is the package this project ships.

    This one runs against the real source tree, because the verdict is the whole
    report and a synthetic tree blocks on its own packaging policy -- an empty
    debian/docs means every important document is missing, and no debian/tests means
    the autopkgtest declaration is undeclared. Nothing is written to the tree: the
    runner spawns no process and --artifact-dir keeps the .deb lookup in tmp_path.
    """
    _patch_runner(
        monkeypatch,
        FakePackageRunner(lintian_output=LINTIAN_WARNING_OUTPUT, lintian_returncode=0),
    )
    (tmp_path / "distroforge_0.3.5-2_all.deb").write_bytes(b"deb\n")

    main([
        "debian-package", str(_REPO_ROOT), "--execute", "--artifact-dir", str(tmp_path), "--json",
    ])

    report = json.loads(capsys.readouterr().out)
    assert report["policy"]["blocked"] is False
    assert report["status"] == "review required"


def test_a_plan_never_fails(monkeypatch, tmp_path, capsys) -> None:
    main(["debian-package", str(_package_root(tmp_path)), "--json"])

    assert json.loads(capsys.readouterr().out)["status"] == "planned"


def test_a_host_without_autopkgtest_does_not_report_a_built_package(monkeypatch, tmp_path, capsys) -> None:
    """The second half of the same defect: the doctor's word was graded by nobody.

    PackageBuildCheck.failed and .needs_review knew "missing", the word
    _run_package_tool_check uses, and not "missing-tool", the word the autopkgtest
    doctor uses for the same condition. So a host with no autopkgtest produced a
    report that said "built" with the package's declared test suite never run.

    Against the real tree, for the same reason as the test above.
    """
    _patch_runner(
        monkeypatch,
        FakePackageRunner(binaries=frozenset({"dpkg-buildpackage", "lintian"})),
    )
    (tmp_path / "distroforge_0.3.5-2_all.deb").write_bytes(b"deb\n")

    main([
        "debian-package", str(_REPO_ROOT), "--execute", "--artifact-dir", str(tmp_path), "--json",
    ])

    report = json.loads(capsys.readouterr().out)
    autopkgtest = next(check for check in report["checks"] if check["name"] == "autopkgtest")
    assert autopkgtest["status"] == "missing-tool"
    assert report["status"] == "review required"


def test_a_policy_verdict_is_an_answer_and_never_an_exit_code(tmp_path, capsys) -> None:
    """debian/tests/control declares `distroforge packaging-policy` a required check.

    Making a policy remark exit 2 would turn a remark into a failed autopkgtest of
    the installed package, which is why this command is deliberately not gated even
    though its report has a blocked field like the others.
    """
    main(["packaging-policy", str(_package_root(tmp_path)), "--json"])

    assert json.loads(capsys.readouterr().out)["blocked"] is True


def test_an_executed_iso_build_that_produced_no_iso_fails(monkeypatch, tmp_path, capsys) -> None:
    root = tmp_path / "project"
    monkeypatch.setattr(
        "distroforge.commands.iso_build.Project.load", lambda path: _StubProject(root)
    )
    monkeypatch.setattr(
        "distroforge.commands.iso_build.run_iso_build",
        lambda project, options, **kwargs: _iso_report(root, status="blocked", execute=True),
    )

    with pytest.raises(SystemExit) as exc:
        main(["iso-build", str(root), "--execute", "--json"])

    assert exc.value.code == 2
    assert json.loads(capsys.readouterr().out)["blocked"] is True


def test_a_planned_iso_build_that_the_doctor_refuses_does_not_fail(monkeypatch, tmp_path, capsys) -> None:
    """core/iso_build.py:90 marks a dry run blocked when the doctor refuses the project.

    Reporting that is the plan's job. Only --execute claims an ISO exists.
    """
    root = tmp_path / "project"
    monkeypatch.setattr(
        "distroforge.commands.iso_build.Project.load", lambda path: _StubProject(root)
    )
    monkeypatch.setattr(
        "distroforge.commands.iso_build.run_iso_build",
        lambda project, options, **kwargs: _iso_report(root, status="blocked", execute=False),
    )

    main(["iso-build", str(root), "--json"])

    assert json.loads(capsys.readouterr().out)["blocked"] is True


def test_an_executed_boot_proof_of_a_file_that_is_not_an_iso_fails(tmp_path, capsys) -> None:
    """No monkeypatching: the iso-scan backend is pure Python and needs no privilege.

    So this is the real command, the real backend and the real refusal -- a file with
    no ISO9660 descriptor cannot be proved to boot.
    """
    from distroforge.core.project import Project

    project = Project.create("ProofCli", tmp_path / "proof-cli", "26.04")
    not_an_iso = project.output_dir / "ProofCli-26.04.iso"
    not_an_iso.parent.mkdir(parents=True, exist_ok=True)
    not_an_iso.write_bytes(b"not an iso\n")

    with pytest.raises(SystemExit) as exc:
        main(["boot-proof", str(project.root), "--iso", str(not_an_iso), "--backend", "iso-scan", "--json"])

    assert exc.value.code == 2
    assert json.loads(capsys.readouterr().out)["status"] == "blocked"


def test_a_dry_run_boot_proof_reports_blocked_and_exits_zero(tmp_path, capsys) -> None:
    from distroforge.core.project import Project

    project = Project.create("ProofPlan", tmp_path / "proof-plan", "26.04")

    main(["boot-proof", str(project.root), "--dry-run", "--json"])

    assert json.loads(capsys.readouterr().out)["status"] == "blocked"


def test_the_iso_doctor_answers_instead_of_failing(tmp_path, capsys) -> None:
    """A fresh project is blocked, and naming the next command is the whole answer."""
    from distroforge.core.project import Project

    project = Project.create("DoctorPlan", tmp_path / "doctor-plan", "26.04")

    main(["iso-doctor", str(project.root), "--json"])

    report = json.loads(capsys.readouterr().out)
    assert report["blocked"] is True
    assert report["next_command"].startswith("distroforge build")


class _StubProject:
    """Enough of a Project for render_iso_build, which only loads and passes it on."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.output_dir = root / "dist"
