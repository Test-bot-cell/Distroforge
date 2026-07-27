"""A failure has to arrive as data, not as a traceback or a generic sentence.

Both legs of the first real golden-path run failed, and neither said why.

The ISO leg died inside the chroot -- ``env: 'apt-get': No such file or directory``,
exit 127 -- and the workflow reported ``jq: Could not open file .../ISO-BUILD.json``,
because ``run_iso_build`` let the ``CommandError`` out. Nothing wrote the report the
next step was told to read, so the assertion failed on the absence of the file instead
of on the cause, one step removed from the truth. The traceback did name the failing
command, on stderr, past ``--json``, where no consumer looks.

The package leg built a clean ``.deb`` and then reported ``autopkgtest: test-failed``
with the reason "The autopkgtest test command ran and failed." That sentence is a
classification: it is byte-identical for every failing test in ``debian/tests``. The
doctor had already extracted the lines of output that name which one failed, and put
them in its report's ``evidence`` -- and the one call site that asks the doctor built a
``PackageBuildCheck`` without them.

Same defect twice, so it is tested once, here: whatever decided a failure must survive
into the artifact that gets published.
"""

from __future__ import annotations

import json
from pathlib import Path

from distroforge.commands.iso_build import render_iso_build
from distroforge.core import iso_build as iso_build_module
from distroforge.core.command import CommandError, CommandResult, CommandRunner, CommandSpec
from distroforge.core.packaging import (
    _autopkgtest_evidence_lines,
    _classify_autopkgtest_result,
    _run_autopkgtest_package_check,
)

# What autopkgtest actually prints when a test in debian/tests fails. The summary line
# is the whole point: it names the test, which "The autopkgtest test command ran and
# failed." never does.
AUTOPKGTEST_FAILING_OUTPUT = """\
autopkgtest [22:17:40]: test smoke: [-----------------------
+ distroforge chroot-backends
Traceback (most recent call last):
ModuleNotFoundError: No module named 'pluggy'
autopkgtest [22:17:41]: test smoke: -----------------------]
smoke                FAIL non-zero exit status 1
gui-import           PASS
autopkgtest [22:17:41]: @@@@@@@@@@@@@@@@@@@@ summary
"""


class _RunnerThatFailsOneCommand:
    """Fails the one command the real build failed on, and nothing else."""

    dry_run = False

    def __init__(self) -> None:
        self.history: list[CommandSpec] = []

    def has_binary(self, name: str) -> bool:
        return True

    def run(self, spec: CommandSpec, check: bool = True) -> CommandResult:
        self.history.append(spec)
        result = CommandResult(
            spec=spec,
            returncode=127,
            stdout="",
            stderr="env: 'apt-get': No such file or directory\n",
        )
        raise CommandError(result)


def _project(tmp_path: Path) -> Path:
    from distroforge.cli import main

    root = tmp_path / "derivative"
    main(["new", "derivative", str(root), "--release", "26.04"])
    return root


def test_a_build_that_breaks_writes_a_report_saying_what_broke(tmp_path, monkeypatch) -> None:
    # run_iso_build asks the doctor first and only builds if it does not block, so on a
    # host without xorriso and friends the orchestrator below is never reached and the
    # status is "blocked" -- which is what this test asserts it is not. It passed here
    # and failed on all nine CI runners for exactly that reason: this machine has the
    # ISO toolchain installed and the runners do not. The neighbouring tests in
    # test_core_smoke.py already seal that seam this way; this one did not, so it was
    # measuring the host rather than the code.
    monkeypatch.setattr("distroforge.core.iso_doctor.CommandRunner.has_binary", lambda *args: True)
    root = _project(tmp_path)

    def explode(self):  # type: ignore[no-untyped-def]
        runner = _RunnerThatFailsOneCommand()
        runner.run(
            CommandSpec(
                argv=("sudo", "chroot", str(root / "work/filesystem"), "env", "apt-get", "update"),
                description="Update APT lists inside the chroot",
            )
        )

    monkeypatch.setattr(iso_build_module.BuildOrchestrator, "run", explode)
    rendered, failed = render_iso_build(root, execute=True, json_output=True)

    # Exit status first: the exception used to carry this, and a report that reads
    # nicely while exiting 0 would be a worse bug than the traceback it replaced.
    assert failed, "a build that died inside a command must still exit non-zero"

    report = json.loads(rendered)
    assert report["status"] == "failed"
    assert report["failed"] is True
    assert report["blocked"] is False, "blocked is the doctor's word for a refusal, not a crash"
    failure = report["failure"]
    assert failure["returncode"] == 127
    assert "apt-get" in failure["output"], "the tool's own words, or the report is useless"
    assert failure["description"] == "Update APT lists inside the chroot"
    assert "chroot" in " ".join(failure["command"])

    # And on disk, where the workflow's next step reads it. This is the assertion the
    # golden path failed on: not "status was wrong" but "no such file".
    on_disk = json.loads((root / "dist" / "ISO-BUILD.json").read_text(encoding="utf-8"))
    assert on_disk["failure"]["returncode"] == 127


def test_a_planned_build_still_reports_no_failure(tmp_path) -> None:
    # The negative control. Adding a failure field is only worth anything if it stays
    # empty when nothing failed -- otherwise every dry run would read as a crash.
    root = _project(tmp_path)
    report = json.loads(render_iso_build(root, json_output=True)[0])
    assert report["failure"] is None
    assert report["failed"] is False


def test_the_autopkgtest_check_carries_the_lines_that_named_the_failing_test(tmp_path) -> None:
    status, classification, detail, remediation, evidence = _classify_autopkgtest_result(
        4, AUTOPKGTEST_FAILING_OUTPUT, ""
    )
    assert (status, classification) == ("test-failed", "package-test-failed")
    # The classifier's own view of the output, which the check used to discard.
    assert any("smoke" in line and "FAIL" in line for line in evidence)

    class _Runner(CommandRunner):
        def __init__(self) -> None:
            super().__init__(dry_run=False)

        def has_binary(self, name: str) -> bool:
            return name == "autopkgtest"

        def run(self, spec: CommandSpec, check: bool = True) -> CommandResult:
            self.history.append(spec)
            return CommandResult(spec, 4, AUTOPKGTEST_FAILING_OUTPUT, "")

    # diagnose_autopkgtest checks the artifact exists before it runs anything, so a
    # bare path would grade as missing-deb and never reach the classification at all.
    deb = tmp_path / "distroforge_0.0.0_all.deb"
    deb.write_bytes(b"")
    check = _run_autopkgtest_package_check(_Runner(), tmp_path, deb, execute=True)
    assert check.status == "test-failed"
    assert any("smoke" in line and "FAIL" in line for line in check.evidence), (
        "the doctor extracted the evidence and the check dropped it"
    )
    assert remediation and remediation in check.reason, (
        "the doctor works out what to do about the failure; say it"
    )
    assert "evidence" in check.to_dict(), "and it has to survive serialisation to be read"


def test_the_evidence_extractor_keeps_the_summary_and_bounds_itself() -> None:
    # Without this the assertions above could pass on an extractor that returns
    # everything, which would put an entire autopkgtest log inside a JSON report.
    lines = _autopkgtest_evidence_lines(AUTOPKGTEST_FAILING_OUTPUT)
    assert "smoke                FAIL non-zero exit status 1" in lines
    assert len(lines) <= 8
    assert _autopkgtest_evidence_lines("nothing interesting here\n") == ()
