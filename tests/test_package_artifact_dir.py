"""Where DistroForge looks for the package it built.

Six call sites across packaging.py and evidence.py hardcoded `root.resolve().parent`,
which is right -- dpkg-buildpackage really does write there -- and unsayable-otherwise.
A maintainer who keeps the archive anywhere else got `debian-package`, `evidence-status`
and the hermetic bundle all reporting cleanly about an empty directory, which is the one
failure mode that reads exactly like success.

`package_artifact_dir` is now the single answer to the question, and `--artifact-dir` (a
field on the Artifacts page, for parity) is how a caller overrides it. Each test below
asserts both halves: that the override is honoured, and that the same call without it does
*not* find the artifact -- an option that is threaded but inert would pass the first half
on its own.
"""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout, suppress
from pathlib import Path

from distroforge import cli
from distroforge.core.artifact_paths import package_artifact_dir
from distroforge.core.evidence import EvidenceStatusService
from distroforge.core.packaging import build_debian_package

DEB = "distroforge_0.3.5-3_all.deb"


def _source_tree(tmp_path: Path) -> Path:
    root = tmp_path / "tree" / "root"
    (root / "distroforge/data").mkdir(parents=True)
    (root / "debian").mkdir()
    (root / "debian/control").write_text(
        "Source: distroforge\nPackage: distroforge\nArchitecture: all\n", encoding="utf-8"
    )
    (root / "debian/docs").write_text("", encoding="utf-8")
    return root


def test_the_default_is_where_dpkg_buildpackage_writes(tmp_path) -> None:
    root = _source_tree(tmp_path)

    assert package_artifact_dir(root) == root.resolve().parent


def test_an_override_wins_and_is_resolved(tmp_path) -> None:
    root = _source_tree(tmp_path)
    archive = tmp_path / "archive"
    archive.mkdir()

    resolved = package_artifact_dir(root, archive)

    assert resolved == archive.resolve()
    assert resolved != root.resolve().parent


def test_build_report_reads_the_override_and_not_the_parent(tmp_path) -> None:
    root = _source_tree(tmp_path)
    archive = tmp_path / "archive"
    archive.mkdir()
    (archive / DEB).write_bytes(b"in the archive\n")

    with_override = build_debian_package(root, artifact_dir=archive)
    without = build_debian_package(root)

    assert [artifact.path for artifact in with_override.artifacts] == [archive / DEB]
    # The other half: the parent holds nothing, so the same call without the override
    # reports an empty set. Without this, a threaded-but-inert option would pass above.
    assert without.artifacts == ()


def test_the_parent_still_works_when_no_override_is_given(tmp_path) -> None:
    root = _source_tree(tmp_path)
    (root.parent / DEB).write_bytes(b"beside the tree\n")

    report = build_debian_package(root)

    assert [artifact.path for artifact in report.artifacts] == [root.parent / DEB]


def test_evidence_status_finds_the_package_through_the_override(tmp_path) -> None:
    root = _source_tree(tmp_path)
    archive = tmp_path / "archive"
    archive.mkdir()
    (archive / DEB).write_bytes(b"in the archive\n")

    def deb_item(report):
        return next(item for item in report.items if item.code == "package:deb")

    service = EvidenceStatusService()
    found = service.check_source_tree(root, profile="package", artifact_dir=archive)
    not_found = service.check_source_tree(root, profile="package")

    assert deb_item(found).status == "ready"
    assert deb_item(not_found).status == "review"


def test_the_cli_flag_reaches_the_report(tmp_path) -> None:
    root = _source_tree(tmp_path)
    archive = tmp_path / "archive"
    archive.mkdir()
    (archive / DEB).write_bytes(b"in the archive\n")

    def run(*extra: str) -> dict:
        out = io.StringIO()
        with redirect_stdout(out), suppress(SystemExit):
            cli.main(["debian-package", str(root), *extra, "--json"])
        return json.loads(out.getvalue())

    with_flag = run("--artifact-dir", str(archive))
    without = run()

    assert [artifact["path"] for artifact in with_flag["artifacts"]] == [str(archive / DEB)]
    assert without["artifacts"] == []


def test_the_gui_field_and_the_cli_flag_describe_the_same_thing(tmp_path) -> None:
    # The parity pillar, checked rather than asserted in a doc: the Artifacts page field
    # exists, and its tooltip names the flag so a GUI user can find the CLI equivalent.
    from distroforge.commands.packaging import ARTIFACT_DIR_HELP

    page = (Path(__file__).resolve().parents[1] / "distroforge/ui/artifacts_page.py").read_text()
    widgets = (
        Path(__file__).resolve().parents[1] / "distroforge/ui/window_widgets.py"
    ).read_text()

    assert "artifacts_package_dir_edit" in page
    assert "artifacts_package_dir_edit" in widgets
    assert "--artifact-dir" in widgets
    assert "dpkg-buildpackage" in ARTIFACT_DIR_HELP
