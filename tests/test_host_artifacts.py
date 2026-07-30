from __future__ import annotations

from pathlib import Path

from distroforge.core.command import CommandRunner
from distroforge.core.host_artifacts import HostArtifactWriter, write_host_artifact

ROOT = Path(__file__).resolve().parents[1]

RELEASE_FAMILY_BOUNDARIES = {
    "distroforge/core/publish_bundle.py": ("publish_immutable_tree",),
    "distroforge/core/publish_drill.py": ("publish_regular_text",),
    "distroforge/core/publish_drill_baseline.py": ("publish_regular_text",),
    "distroforge/core/publish_drill_diff.py": ("ArtifactVerificationSession",),
    "distroforge/core/recipe.py": ("write_host_artifact",),
    "distroforge/core/presets.py": ("write_host_artifact",),
    "distroforge/core/release_pipeline.py": ("publish_regular_text",),
    "distroforge/core/release_notes.py": ("publish_regular_text",),
    "distroforge/core/release_signing.py": (
        "copy_immutable_file_descriptor",
        "publish_regular_text",
    ),
    "distroforge/core/release_verification.py": ("publish_regular_text",),
}
PUBLISH_DRILL_BOUNDARIES = (
    "distroforge/core/publish_drill_baseline.py",
    "distroforge/core/publish_drill_diff.py",
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


def test_release_family_modules_route_through_safe_artifact_boundaries() -> None:
    for path, accepted_boundaries in RELEASE_FAMILY_BOUNDARIES.items():
        source = (ROOT / path).read_text(encoding="utf-8")
        assert any(boundary in source for boundary in accepted_boundaries), (
            f"{path} should route artifact I/O through one accepted boundary"
        )
        assert ".write_text(" not in source, f"{path} still performs a raw .write_text host write"


def test_publish_drill_readers_and_writers_keep_path_dangerous_helpers_out() -> None:
    for path in PUBLISH_DRILL_BOUNDARIES:
        source = (ROOT / path).read_text(encoding="utf-8")
        for forbidden in (".mkdir(", "shutil.copy2", "write_host_artifact"):
            assert forbidden not in source, f"{path} still contains {forbidden}"
