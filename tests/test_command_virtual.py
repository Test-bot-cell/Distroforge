from __future__ import annotations

import pytest

from distroforge.core.command import VIRTUAL_COMMANDS, CommandRunner, CommandSpec
from distroforge.core.vulnscan import VulnScanOptions, VulnScanService

# Internal reporting/assertion verbs that are recorded as runner events, never
# executed as real binaries. If one is emitted in a real (non-dry-run) build but
# missing from VIRTUAL_COMMANDS, the runner tries to exec a program of that name
# and the build aborts with FileNotFoundError ([Errno 2] No such file...).
REPORT_MARKERS = (
    ("vuln-report", "ok", "0"),
    ("qemu-user-static-required", "arm64", "amd64"),
    ("bootstrap-bios-skip", "arm64"),
)


@pytest.mark.parametrize("argv", REPORT_MARKERS)
def test_marker_is_registered_virtual(argv: tuple[str, ...]) -> None:
    assert argv[0] in VIRTUAL_COMMANDS


@pytest.mark.parametrize("argv", REPORT_MARKERS)
def test_real_runner_treats_marker_as_virtual(argv: tuple[str, ...]) -> None:
    # dry_run=False is the path a real build takes; the marker must resolve to a
    # virtual event (rc=0, no subprocess) rather than an attempted exec.
    result = CommandRunner(dry_run=False).run(CommandSpec(argv=argv))
    assert result.returncode == 0


def test_unregistered_command_still_execs_and_raises() -> None:
    # Negative control: a verb that is NOT virtual is exec'd for real, so a
    # missing binary raises FileNotFoundError. This is exactly what the markers
    # above were doing before they were registered.
    runner = CommandRunner(dry_run=False)
    with pytest.raises(FileNotFoundError):
        runner.run(CommandSpec(argv=("distroforge-not-a-real-binary",)))


def test_vuln_scan_enforce_does_not_exec_report_marker() -> None:
    # Locks the reported crash: a real-mode CVE scan emits ("vuln-report", ...);
    # before the fix this aborted the build with [Errno 2] ... 'vuln-report'.
    runner = CommandRunner(dry_run=False)
    report = VulnScanService(VulnScanOptions(enabled=True)).enforce([], runner)
    assert report.ok
    assert any(spec.argv[0] == "vuln-report" for spec in runner.history)
