from __future__ import annotations

import os
import stat
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from distroforge.core import beginner_iso as beginner_iso_module
from distroforge.core import release_pipeline as release_pipeline_module
from distroforge.core.beginner_iso import repair_beginner_iso_release_artifacts
from distroforge.core.build import BuildOptions
from distroforge.core.project import Project


def _repair_fixture(tmp_path: Path) -> tuple[Project, Path, BuildOptions]:
    project = Project.create("RepairIo", tmp_path / "repair-io", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "RepairIo.iso"
    iso.parent.mkdir(parents=True, exist_ok=True)
    iso.write_bytes(b"bounded-iso")
    options = BuildOptions(output_iso=iso)
    return project, iso, options


def test_beginner_repair_is_byte_idempotent(tmp_path: Path) -> None:
    project, _iso, options = _repair_fixture(tmp_path)

    first = repair_beginner_iso_release_artifacts(project, options)
    names = ("SHA256SUMS", "BUILDINFO", "distroforge-provenance.json", "report.html")
    before = {name: (project.output_dir / name).read_bytes() for name in names}

    second = repair_beginner_iso_release_artifacts(project, options)

    assert before == {name: (project.output_dir / name).read_bytes() for name in names}
    assert {"SHA256SUMS", "BUILDINFO", "report.html"} <= set(second.repaired)
    assert any("reconstructed provenance" in item for item in second.skipped)
    assert not any("refused" in item for item in first.skipped + second.skipped)


@pytest.mark.parametrize("target_name", ["SHA256SUMS", "BUILDINFO", "report.html"])
def test_beginner_repair_refuses_a_different_regular_target(
    tmp_path: Path,
    target_name: str,
) -> None:
    project, _iso, options = _repair_fixture(tmp_path)
    target = project.output_dir / target_name
    target.write_bytes(b"pre-existing-different-bytes")

    report = repair_beginner_iso_release_artifacts(project, options)

    assert target.read_bytes() == b"pre-existing-different-bytes"
    assert target_name not in report.repaired
    assert any(
        target_name in item and "refused" in item
        for item in report.skipped
    )


@pytest.mark.parametrize("target_kind", ["symlink", "fifo"])
def test_beginner_repair_refuses_special_or_linked_targets_without_blocking(
    tmp_path: Path,
    target_kind: str,
) -> None:
    project, _iso, options = _repair_fixture(tmp_path)
    target = project.output_dir / "BUILDINFO"
    victim = tmp_path / "victim"
    victim.write_bytes(b"victim")
    if target_kind == "symlink":
        target.symlink_to(victim)
    else:
        os.mkfifo(target)

    report = repair_beginner_iso_release_artifacts(project, options)

    assert target.is_symlink() if target_kind == "symlink" else stat.S_ISFIFO(target.lstat().st_mode)
    assert victim.read_bytes() == b"victim"
    assert "BUILDINFO" not in report.repaired
    assert any("BUILDINFO" in item and "refused" in item for item in report.skipped)


def test_beginner_repair_refuses_a_linked_provenance_target(tmp_path: Path) -> None:
    project, _iso, options = _repair_fixture(tmp_path)
    victim = tmp_path / "provenance-victim"
    victim.write_text('{"status":"victim"}\n', encoding="utf-8")
    provenance = project.output_dir / "distroforge-provenance.json"
    provenance.symlink_to(victim)

    report = repair_beginner_iso_release_artifacts(project, options)

    assert provenance.is_symlink()
    assert victim.read_text(encoding="utf-8") == '{"status":"victim"}\n'
    assert "distroforge-provenance.json" not in report.repaired
    assert any(
        "distroforge-provenance.json" in item and "refused" in item
        for item in report.skipped
    )


@pytest.mark.parametrize("iso_kind", ["symlink", "fifo"])
def test_beginner_repair_refuses_an_unsafe_iso_without_blocking(
    tmp_path: Path,
    iso_kind: str,
) -> None:
    project = Project.create("UnsafeIso", tmp_path / "unsafe-iso", "26.04")
    iso = project.output_dir / "UnsafeIso.iso"
    iso.parent.mkdir(parents=True, exist_ok=True)
    if iso_kind == "symlink":
        victim = tmp_path / "outside.iso"
        victim.write_bytes(b"outside")
        iso.symlink_to(victim)
    else:
        os.mkfifo(iso)

    report = repair_beginner_iso_release_artifacts(
        project,
        BuildOptions(output_iso=iso),
    )

    assert not report.repaired
    assert any("ISO is missing or unsafe" in item for item in report.skipped)
    assert not (project.output_dir / "SHA256SUMS").exists()


def test_beginner_repair_detects_iso_replacement_during_publication(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    project, iso, options = _repair_fixture(tmp_path)
    real_publish = beginner_iso_module.publish_regular_text
    replaced = False

    def swapping_publish(
        path: Path,
        content: str,
        *,
        max_bytes: int,
        expected_parent_identity: Any,
    ) -> object:
        nonlocal replaced
        if not replaced:
            replaced = True
            original = iso.stat()
            replacement = tmp_path / "replacement.iso"
            replacement.write_bytes(iso.read_bytes())
            os.utime(
                replacement,
                ns=(original.st_atime_ns, original.st_mtime_ns),
            )
            os.replace(replacement, iso)
        return real_publish(
            path,
            content,
            max_bytes=max_bytes,
            expected_parent_identity=expected_parent_identity,
        )

    monkeypatch.setattr(beginner_iso_module, "publish_regular_text", swapping_publish)

    report = repair_beginner_iso_release_artifacts(project, options)

    assert replaced
    assert any(
        "changed while release artifacts were repaired" in item
        for item in report.skipped
    )


def test_beginner_repair_rehashes_iso_after_publication(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    project, iso, options = _repair_fixture(tmp_path)
    real_publish = beginner_iso_module.publish_regular_text
    mutated = False

    def mutating_publish(
        path: Path,
        content: str,
        *,
        max_bytes: int,
        expected_parent_identity: Any,
    ) -> object:
        nonlocal mutated
        if not mutated:
            mutated = True
            original = iso.stat()
            iso.write_bytes(b"tamperd-iso")
            os.utime(
                iso,
                ns=(original.st_atime_ns, original.st_mtime_ns),
            )
        return real_publish(
            path,
            content,
            max_bytes=max_bytes,
            expected_parent_identity=expected_parent_identity,
        )

    monkeypatch.setattr(beginner_iso_module, "publish_regular_text", mutating_publish)

    report = repair_beginner_iso_release_artifacts(project, options)

    assert mutated
    assert report.status == "blocked"
    assert any(
        "changed while release artifacts were repaired" in item
        for item in report.skipped
    )


def test_beginner_repair_blocks_an_output_directory_swap_after_iso_hash(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    project, iso, options = _repair_fixture(tmp_path)
    original_parent = iso.parent
    displaced_parent = tmp_path / "held-output"
    real_seal = beginner_iso_module.ArtifactVerificationSession.seal
    swapped = False

    def seal_then_swap(
        session: beginner_iso_module.ArtifactVerificationSession,
    ) -> object:
        nonlocal swapped
        result = real_seal(session)
        if session.label == "beginner ISO release repair" and not swapped:
            swapped = True
            original_parent.rename(displaced_parent)
            original_parent.mkdir()
            os.link(displaced_parent / iso.name, original_parent / iso.name)
        return result

    monkeypatch.setattr(
        beginner_iso_module.ArtifactVerificationSession,
        "seal",
        seal_then_swap,
    )

    report = repair_beginner_iso_release_artifacts(project, options)

    assert swapped
    assert report.status == "blocked"
    assert not report.repaired
    assert any(
        "output directory changed" in item
        for item in report.skipped
    )
    assert not (original_parent / "SHA256SUMS").exists()


def test_release_pipeline_stops_before_bundle_when_repair_is_blocked(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    project, iso, options = _repair_fixture(tmp_path)

    monkeypatch.setattr(
        release_pipeline_module,
        "repair_beginner_iso_release_artifacts",
        lambda *_args, **_kwargs: SimpleNamespace(
            status="blocked",
            repaired=(),
            skipped=("causal repair refusal",),
        ),
    )

    def unexpected_bundle(*_args: object, **_kwargs: object) -> object:
        pytest.fail("a blocked repair must stop before bundle publication")

    monkeypatch.setattr(
        release_pipeline_module,
        "create_publish_bundle",
        unexpected_bundle,
    )

    report = release_pipeline_module.run_release_pipeline(
        project,
        options,
        iso=iso,
    )

    assert report.status == "blocked"
    assert [(stage.name, stage.status) for stage in report.stages] == [
        ("boot-proof", "review"),
        ("repair-artifacts", "blocked")
    ]
