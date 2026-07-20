from __future__ import annotations

from pathlib import Path

from distroforge.core.command import CommandRunner
from distroforge.core.host_artifacts import HostArtifactWriter, write_host_artifact

ROOT = Path(__file__).resolve().parents[1]

RELEASE_FAMILY_WRITERS = (
    "distroforge/core/publish_bundle.py",
    "distroforge/core/publish_drill.py",
    "distroforge/core/publish_drill_baseline.py",
    "distroforge/core/recipe.py",
    "distroforge/core/presets.py",
    "distroforge/core/release_pipeline.py",
    "distroforge/core/release_notes.py",
    "distroforge/core/release_signing.py",
    "distroforge/core/release_verification.py",
)


def test_dry_run_records_write_file_without_touching_disk(tmp_path) -> None:
    runner = CommandRunner(dry_run=True)
    target = tmp_path / "out" / "report.txt"

    HostArtifactWriter(runner).write_text(target, "hello", "Write report")

    assert [spec.argv for spec in runner.history] == [("write-file", str(target))]
    assert runner.history[0].description == "Write report"
    assert not target.exists()
    assert not target.parent.exists()


def test_execute_writes_file_and_records_history(tmp_path) -> None:
    runner = CommandRunner(dry_run=False)
    target = tmp_path / "out" / "report.txt"

    HostArtifactWriter(runner).write_text(target, "hello\n", "Write report")

    assert ("write-file", str(target)) in [spec.argv for spec in runner.history]
    assert target.read_text(encoding="utf-8") == "hello\n"


def test_write_host_artifact_always_writes_and_creates_parents(tmp_path) -> None:
    target = tmp_path / "publish" / "REPORT.json"

    write_host_artifact(target, "{}\n", "Write REPORT.json")

    assert target.read_text(encoding="utf-8") == "{}\n"


def test_release_family_writers_route_through_host_artifact_boundary() -> None:
    for path in RELEASE_FAMILY_WRITERS:
        source = (ROOT / path).read_text(encoding="utf-8")
        assert "write_host_artifact" in source, f"{path} should route writes through the boundary"
        assert ".write_text(" not in source, f"{path} still performs a raw .write_text host write"
