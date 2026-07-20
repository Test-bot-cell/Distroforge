from __future__ import annotations

from distroforge.core.command import CommandRunner
from distroforge.core.size_analysis import SizeAnalysisOptions, SizeAnalysisService


def test_size_analysis_dry_run_records_write_without_touching_disk(tmp_path) -> None:
    output_dir = tmp_path / "out"
    runner = CommandRunner(dry_run=True)
    SizeAnalysisService(
        runner,
        tmp_path / "rootfs",
        output_dir,
        SizeAnalysisOptions(enabled=True, top=10),
    ).run()

    report = output_dir / "size-report.txt"
    write_targets = {spec.argv[1] for spec in runner.history if spec.argv[:1] == ("write-file",)}
    assert str(report) in write_targets
    assert not report.exists()
    assert not output_dir.exists()
