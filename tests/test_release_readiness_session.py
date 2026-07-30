from __future__ import annotations

import os
from pathlib import Path

from distroforge.core.release_readiness import (
    ReleaseReadinessItem,
    ReleaseReadinessService,
)


def test_release_readiness_refuses_an_output_outside_the_iso_parent(
    tmp_path: Path,
) -> None:
    iso = tmp_path / "product" / "image.iso"
    foreign_output = tmp_path / "foreign-output"
    iso.parent.mkdir()
    foreign_output.mkdir()
    iso.write_bytes(b"iso")
    (foreign_output / "SHA256SUMS").write_text(
        "0" * 64 + "  image.iso\n",
        encoding="utf-8",
    )

    report = ReleaseReadinessService().check(iso, foreign_output)

    assert report.blocked
    assert report.items == [
        ReleaseReadinessItem(
            "product-path",
            "blocked",
            "output_dir must be the canonical parent of the selected ISO",
        )
    ]


def test_status_only_readiness_rejects_a_symlinked_iso_without_hashing(
    tmp_path: Path,
) -> None:
    external = tmp_path / "external.iso"
    external.write_bytes(b"external")
    iso = tmp_path / "linked.iso"
    iso.symlink_to(external)

    report = ReleaseReadinessService().check(
        iso,
        tmp_path,
        verify_checksum=False,
    )

    assert report.blocked
    assert any(
        item.name == "artifact-session" and item.status == "blocked"
        for item in report.items
    )


def test_readiness_never_marks_a_fifo_as_captured_evidence(
    tmp_path: Path,
) -> None:
    iso = tmp_path / "release.iso"
    iso.write_bytes(b"iso")
    os.mkfifo(tmp_path / "BUILDINFO", 0o620)

    report = ReleaseReadinessService().check(
        iso,
        tmp_path,
        verify_checksum=False,
    )

    buildinfo = next(item for item in report.items if item.name == "buildinfo")
    assert buildinfo.status == "blocked"
    assert "regular file" in buildinfo.detail
