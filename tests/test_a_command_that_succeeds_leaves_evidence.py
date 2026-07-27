"""A build's log has to be able to explain a command that exited 0 and did nothing.

The first real run of the weekly golden path failed five phases after the bootstrap, in a
chroot, with ``env: 'apt-get': No such file or directory``. The bootstrap itself had
exited 0, in 23 seconds, and mmdebstrap's own output -- the only place that could have said
what it declined to install -- was gone twice over:

* ``CommandRunner._write_event`` recorded ``returncode`` and nothing else, for every event.
  A command's words reach a human only through ``CommandError``, and this command had not
  failed, so there was nothing to raise.
* ``distroforge iso-build`` passed no ``log_path`` at all (commands/iso_build.py), and
  neither did core/demo_iso.py, so ``_write_event`` returned on its first line and the
  golden path produced no command log in the first place. ``distroforge build`` had one;
  the two other entry points that build did not.

So these tests are about evidence, not about the bootstrap: whatever explains that 23
seconds, the next run has to keep enough to be read afterwards.
"""

from __future__ import annotations

import json
from pathlib import Path

from distroforge.core.artifact_paths import default_command_log
from distroforge.core.build import BuildOptions
from distroforge.core.command import CommandRunner, CommandSpec
from distroforge.core.iso_build import run_iso_build
from distroforge.core.project import Project

ROOT = Path(__file__).resolve().parents[1]


def _events(log: Path) -> list[dict]:
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line]


def _finish(log: Path) -> dict:
    finished = [event for event in _events(log) if event["event"] == "finish"]
    assert len(finished) == 1, f"expected one finish event, got {[e['event'] for e in _events(log)]}"
    return finished[0]


def test_the_log_keeps_what_a_command_that_succeeded_said(tmp_path) -> None:
    log = tmp_path / "commands.jsonl"
    runner = CommandRunner(dry_run=False, log_path=log)

    result = runner.run(
        CommandSpec(
            argv=("python3", "-c", "print('declined to install apt')"),
            description="a command that works and explains itself",
        )
    )

    assert result.returncode == 0
    event = _finish(log)
    assert event["returncode"] == 0
    assert "declined to install apt" in event["stdout"]


def test_the_log_keeps_stderr_too_because_tools_disagree_about_which_stream_is_which(tmp_path) -> None:
    log = tmp_path / "commands.jsonl"
    runner = CommandRunner(dry_run=False, log_path=log)

    runner.run(
        CommandSpec(
            argv=("python3", "-c", "import sys; sys.stderr.write('W: apt is not required here\\n')"),
            description="a warning on the other stream",
        )
    )

    assert "apt is not required here" in _finish(log)["stderr"]


def test_a_verbose_command_is_kept_as_a_tail_that_admits_it_is_one(tmp_path) -> None:
    """mksquashfs and apt emit megabytes of progress; the diagnosis is at the end.

    The cap has to be visible in the record, or a reader comparing the log against the
    tool's real output silently concludes the tool never said the missing half.
    """
    log = tmp_path / "commands.jsonl"
    runner = CommandRunner(dry_run=False, log_path=log)

    runner.run(
        CommandSpec(
            argv=("python3", "-c", "print('x' * 12000); print('the last word')"),
            description="a command that talks too much",
        )
    )

    stdout = _finish(log)["stdout"]
    assert stdout.endswith("the last word\n")
    assert "earlier characters dropped" in stdout
    assert len(stdout) < 12000


def test_a_dry_run_records_no_output_rather_than_empty_output(tmp_path) -> None:
    """A negative control: "ran and said nothing" and "never ran" are different facts."""
    log = tmp_path / "commands.jsonl"
    runner = CommandRunner(dry_run=True, log_path=log)

    runner.run(CommandSpec(argv=("mmdebstrap", "--variant=minbase", "resolute"), description="planned"))

    events = _events(log)
    assert [event["event"] for event in events] == ["start", "dry-run"]
    assert all(event["stdout"] is None and event["stderr"] is None for event in events)


def test_the_log_still_refuses_to_record_what_was_fed_in(tmp_path) -> None:
    """stdin stays a bare boolean. It is where a passphrase would be."""
    log = tmp_path / "commands.jsonl"
    runner = CommandRunner(dry_run=False, log_path=log)

    runner.run(
        CommandSpec(
            argv=("python3", "-c", "import sys; sys.stdin.read()"),
            stdin="correct horse battery staple",
            description="something with a secret on stdin",
        )
    )

    body = log.read_text(encoding="utf-8")
    assert "correct horse battery staple" not in body
    assert _finish(log)["has_stdin"] is True


def test_iso_build_writes_a_command_log_without_being_asked(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("distroforge.core.iso_doctor.CommandRunner.has_binary", lambda *args: True)
    project = Project.create("Evidence", tmp_path / "evidence", "26.04")
    project.source_mode = "bootstrap"

    report = run_iso_build(project, BuildOptions(), execute=False)

    assert report.command_log == default_command_log(project, "iso-build")
    assert report.command_log.exists(), "the report named a log nobody wrote"
    assert _events(report.command_log), "the log exists but recorded no command"


def test_the_report_says_where_the_log_went(monkeypatch, tmp_path) -> None:
    """The report is what callers are told to read, so it has to point at the log."""
    monkeypatch.setattr("distroforge.core.iso_doctor.CommandRunner.has_binary", lambda *args: True)
    project = Project.create("Pointer", tmp_path / "pointer", "26.04")
    project.source_mode = "bootstrap"

    report = run_iso_build(project, BuildOptions(), execute=False)

    written = json.loads((project.output_dir / "ISO-BUILD.json").read_text(encoding="utf-8"))
    assert written["command_log"] == str(default_command_log(project, "iso-build"))
    assert f"Command log: {report.command_log}" in report.render_text()


def test_an_explicit_log_file_still_wins(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("distroforge.core.iso_doctor.CommandRunner.has_binary", lambda *args: True)
    project = Project.create("Override", tmp_path / "override", "26.04")
    project.source_mode = "bootstrap"
    chosen = tmp_path / "elsewhere" / "mine.jsonl"

    report = run_iso_build(project, BuildOptions(), execute=False, log_path=chosen)

    assert report.command_log == chosen
    assert chosen.exists()
    assert not default_command_log(project, "iso-build").exists()


def test_a_blocked_project_does_not_advertise_a_log_it_never_opened(tmp_path) -> None:
    """No runner is built for a blocked project, so no log is either -- and it says so."""
    project = Project.create("Blocked", tmp_path / "blocked", "26.04")

    report = run_iso_build(project, BuildOptions(), execute=False)

    assert report.blocked
    assert report.command_log is None
    assert not default_command_log(project, "iso-build").exists()
    assert "Command log: not recorded" in report.render_text()


def test_the_two_entry_points_that_build_keep_separate_logs(tmp_path) -> None:
    """Appending two different runs into one file interleaves them into nothing readable."""
    project = Project.create("Two", tmp_path / "two", "26.04")

    assert default_command_log(project, "build") != default_command_log(project, "iso-build")
    assert default_command_log(project, "build").parent == project.root / "logs"


def test_the_gui_uses_the_same_default_as_the_cli() -> None:
    """A blank field means "where you normally put it", not "nowhere".

    Asserted against the source the way test_ui_responsive.py does, because the branch is
    one line inside a Qt slot and the fact worth pinning is which default it reaches for.
    """
    source = (ROOT / "distroforge/ui/build_controller.py").read_text(encoding="utf-8")

    assert "log_path = Path(text) if text else None" not in source
    assert 'default_command_log(project, "build")' in source
