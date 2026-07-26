from __future__ import annotations

import gc
import sys
import warnings

import pytest

from distroforge.core.apt import AptService, PackagePlan
from distroforge.core.build import BuildOptions, BuildOrchestrator
from distroforge.core.command import CommandError, CommandResult, CommandRunner, CommandSpec
from distroforge.core.iso import IsoService
from distroforge.core.progress_parsers import (
    apt_progress,
    parse_percent,
    parse_ratio,
    squashfs_progress,
    xorriso_progress,
)
from distroforge.core.project import Project
from distroforge.core.squashfs import SquashfsService

# --- parsers (pure, fully verifiable) ---------------------------------------


def test_parse_percent_handles_int_float_and_misses() -> None:
    assert parse_percent("[===] 18%") == pytest.approx(0.18)
    assert parse_percent("xorriso : UPDATE : 12.5% done") == pytest.approx(0.125)
    assert parse_percent("no percentage here") is None
    assert parse_percent("999%") == 1.0  # clamped


def test_parse_ratio_and_zero_total() -> None:
    assert parse_ratio("1234/5678 things") == pytest.approx(1234 / 5678)
    assert parse_ratio("0/0") is None
    assert parse_ratio("no ratio") is None


def test_squashfs_reads_only_the_bracketed_bar() -> None:
    # The done/total ratio inside the bar is authoritative.
    assert squashfs_progress("[=====] 1000/2000  50%") == pytest.approx(0.5)
    assert squashfs_progress("[==] 1/3 33%") == pytest.approx(1 / 3)
    # Stray percentages outside the bar (mksquashfs closing statistics) and bare
    # ratios without the bar are ignored, so the bar cannot jump backwards.
    assert squashfs_progress("\t6.71% of uncompressed inode table size") is None
    assert squashfs_progress("1000/2000") is None
    assert squashfs_progress("warming up") is None


def test_xorriso_and_apt_status_lines() -> None:
    assert xorriso_progress("xorriso : UPDATE :  73.0% done") == pytest.approx(0.73)
    assert apt_progress("pmstatus:vim:42.8571:Unpacking vim") == pytest.approx(0.428571)
    assert apt_progress("dlstatus:1:10.0:Downloading") == pytest.approx(0.10)
    assert apt_progress("Reading package lists...") is None


# --- run_streaming (real subprocess, deterministic) -------------------------


def _py(code: str) -> CommandSpec:
    return CommandSpec(argv=(sys.executable, "-c", code))


def test_run_streaming_splits_on_newline_and_carriage_return() -> None:
    code = (
        "import sys\n"
        "sys.stdout.write('one\\n'); sys.stdout.flush()\n"
        "sys.stdout.write('two\\rthree\\n'); sys.stdout.flush()\n"
    )
    lines: list[str] = []
    result = CommandRunner(dry_run=False).run_streaming(_py(code), lines.append)
    assert lines == ["one", "two", "three"]
    assert result.returncode == 0
    assert "three" in result.stdout


def test_run_streaming_merges_stderr() -> None:
    lines: list[str] = []
    CommandRunner(dry_run=False).run_streaming(
        _py("import sys; sys.stderr.write('err-line\\n'); sys.stderr.flush()"), lines.append
    )
    assert "err-line" in lines


def test_run_streaming_respects_check_and_returncode() -> None:
    failing = _py("import sys; sys.exit(3)")
    result = CommandRunner(dry_run=False).run_streaming(failing, lambda _line: None, check=False)
    assert result.returncode == 3
    with pytest.raises(CommandError):
        CommandRunner(dry_run=False).run_streaming(failing, lambda _line: None)


def test_run_streaming_delivers_a_short_line_before_the_child_writes_again(tmp_path) -> None:
    """A line already sitting in the pipe must reach ``on_line`` at once.

    Text-mode ``read(256)`` blocks until 256 characters or EOF, so a 13-character
    apt ``pmstatus`` line stayed invisible for the whole silence that followed it
    and the progress bar showed a stale state. The child proves delivery without
    a stopwatch: it writes one short line, then waits for the callback to create a
    handshake file before reporting whether it ever appeared.
    """
    handshake = tmp_path / "on-line-fired"
    code = (
        "import sys, time\n"
        "from pathlib import Path\n"
        "flag = Path(sys.argv[1])\n"
        "sys.stdout.write('pmstatus:vim:1.0:Unpacking\\n'); sys.stdout.flush()\n"
        "deadline = time.monotonic() + 5.0\n"
        "while time.monotonic() < deadline and not flag.exists():\n"
        "    time.sleep(0.01)\n"
        "sys.stdout.write('x' * 300 + '\\n'); sys.stdout.flush()\n"
        "sys.stdout.write(f'delivered={flag.exists()}\\n'); sys.stdout.flush()\n"
    )
    spec = CommandSpec(argv=(sys.executable, "-c", code, str(handshake)))
    lines: list[str] = []

    def on_line(line: str) -> None:
        lines.append(line)
        handshake.touch()

    CommandRunner(dry_run=False).run_streaming(spec, on_line)
    assert lines[0] == "pmstatus:vim:1.0:Unpacking"  # the short line came through first
    assert "delivered=True" in lines  # ...while the child was still running


def test_run_streaming_closes_the_output_pipe_itself() -> None:
    """Leaving the merged pipe to the garbage collector raises ResourceWarning and
    keeps the descriptor alive for as long as the wrapper survives."""
    gc.collect()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        CommandRunner(dry_run=False).run_streaming(_py("print('done')"), lambda _line: None)
        gc.collect()
    leaked = [str(entry.message) for entry in caught if issubclass(entry.category, ResourceWarning)]
    assert leaked == []


def test_run_streaming_decodes_utf8_split_across_reads() -> None:
    """Reading available bytes means a multi-byte character can straddle two reads;
    the incremental decoder must join them instead of emitting replacements."""
    code = (
        "import sys, time\n"
        "raw = sys.stdout.buffer\n"
        "raw.write('caf'.encode() + b'\\xc3'); raw.flush()\n"
        "time.sleep(0.05)\n"
        "raw.write(b'\\xa9' + b'\\n'); raw.flush()\n"
    )
    lines: list[str] = []
    result = CommandRunner(dry_run=False).run_streaming(
        CommandSpec(argv=(sys.executable, "-c", code)), lines.append
    )
    assert lines == ["caf\u00e9"]
    assert result.stdout == "caf\u00e9\n"


def test_run_streaming_dry_run_and_virtual_never_stream() -> None:
    dry_calls: list[str] = []
    dry = CommandRunner(dry_run=True).run_streaming(CommandSpec(argv=("unsquashfs", "x")), dry_calls.append)
    assert dry.returncode == 0 and dry_calls == []

    virtual_calls: list[str] = []
    virtual = CommandRunner(dry_run=False).run_streaming(
        CommandSpec(argv=("write-file", "x")), virtual_calls.append
    )
    assert virtual.returncode == 0 and virtual_calls == []


# --- service wiring (fake streaming runner, no real tools) ------------------


class _FakeStreamingRunner(CommandRunner):
    def __init__(self, lines: list[str]) -> None:
        super().__init__(dry_run=False)
        self._lines = lines
        self.streamed: list[CommandSpec] = []

    def run(self, spec: CommandSpec, check: bool = True) -> CommandResult:
        raise AssertionError(f"expected the streaming path, got run(): {spec.display()}")

    def run_streaming(self, spec, on_line, check: bool = True) -> CommandResult:
        self.streamed.append(spec)
        self.history.append(spec)
        for line in self._lines:
            on_line(line)
        return CommandResult(spec=spec, returncode=0, stdout="\n".join(self._lines), stderr="")


def test_squashfs_unpack_streams_parsed_fractions(tmp_path) -> None:
    runner = _FakeStreamingRunner(["[=] 100/1000 10%", "[====] 500/1000 50%", "[========] 1000/1000 100%"])
    got: list[float] = []
    SquashfsService(runner, use_sudo=False).unpack(
        tmp_path / "fs.squashfs", tmp_path / "out" / "root", on_progress=got.append
    )
    assert got == [pytest.approx(0.1), pytest.approx(0.5), pytest.approx(1.0)]


def test_squashfs_pack_streams_parsed_fractions(tmp_path) -> None:
    runner = _FakeStreamingRunner(["[=] 250/1000 25%", "[===] 750/1000 75%"])
    got: list[float] = []
    SquashfsService(runner, use_sudo=False).pack(
        tmp_path / "root", tmp_path / "out" / "fs.squashfs", on_progress=got.append
    )
    assert got == [pytest.approx(0.25), pytest.approx(0.75)]


def test_iso_extract_streams_parsed_fractions(tmp_path) -> None:
    runner = _FakeStreamingRunner(["xorriso : UPDATE : 40.0% done"])
    got: list[float] = []
    IsoService(runner, use_sudo=False).extract(
        tmp_path / "src.iso", tmp_path / "tree", on_progress=got.append
    )
    assert got == [pytest.approx(0.4)]


def test_apt_apply_plan_streams_and_adds_status_fd(tmp_path) -> None:
    project = Project.create("AptStream", tmp_path / "p", "26.04")
    runner = _FakeStreamingRunner(["pmstatus:vim:50.0:Unpacking"])
    got: list[float] = []
    AptService(runner, tmp_path / "root", project.release, use_sudo=False).apply_plan(
        PackagePlan(install=["vim"]), on_progress=got.append
    )
    assert got == [pytest.approx(0.5)]
    assert "APT::Status-Fd=1" in runner.streamed[0].argv


def test_apt_apply_plan_dry_run_omits_status_fd(tmp_path) -> None:
    project = Project.create("AptDry", tmp_path / "p", "26.04")
    runner = CommandRunner(dry_run=True)
    AptService(runner, tmp_path / "root", project.release, use_sudo=False).apply_plan(
        PackagePlan(install=["vim"]), on_progress=lambda _f: None
    )
    install = next(spec for spec in runner.history if "install" in spec.argv)
    assert "APT::Status-Fd=1" not in install.argv


# --- integration: parsed sub-progress fills the orchestrator's current band --


def test_subprogress_flows_through_orchestrator_band(tmp_path) -> None:
    project = Project.create("BandFlow", tmp_path / "p", "26.04")
    project.source_mode = "iso"
    events = []
    orch = BuildOrchestrator(
        project,
        _FakeStreamingRunner(
            ["[=] 100/1000 10%", "[======] 600/1000 60%", "[========] 1000/1000 100%"]
        ),
        BuildOptions(use_sudo=False),
        progress=events.append,
    )
    first = orch.plan()[0]
    orch._step(first.phase, first.title, first.detail)  # open the first weight band
    band_start, band_width = orch._cur_band_start, orch._cur_band_width
    events.clear()

    SquashfsService(orch.runner, use_sudo=False).unpack(
        tmp_path / "fs.squashfs", tmp_path / "out", on_progress=orch._phase_progress
    )
    assert [e.phase_fraction for e in events] == [pytest.approx(p) for p in (0.1, 0.6, 1.0)]
    assert [e.fraction for e in events] == [
        pytest.approx(band_start + p * band_width) for p in (0.1, 0.6, 1.0)
    ]
