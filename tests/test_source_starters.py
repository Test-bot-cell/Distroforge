from __future__ import annotations

import json

from distroforge.cli import main
from distroforge.core.project import Project
from distroforge.core.source_starter import apply_source_starter, list_source_starters


def test_source_starter_catalog_covers_ubuntu_and_debian() -> None:
    keys = {starter.key for starter in list_source_starters()}

    assert "ubuntu-26.04-skeleton" in keys
    assert "ubuntu-26.04-official-server" in keys
    assert "debian-13.5-skeleton" in keys
    assert "debian-13.5-netinst" in keys


def test_new_project_defaults_to_skeleton_starter(tmp_path) -> None:
    root = tmp_path / "starter"

    main(["new", "Starter", str(root), "--release", "26.04"])

    project = Project.load(root)
    assert project.source_mode == "bootstrap"
    assert project.source_starter
    assert project.source_starter["key"] == "ubuntu-26.04-skeleton"
    assert project.source_starter["kind"] == "skeleton"


def test_local_iso_starter_tracks_trust_metadata(tmp_path) -> None:
    iso = tmp_path / "seed.iso"
    iso.write_bytes(b"iso")
    root = tmp_path / "local"

    main(
        [
            "new",
            "Local",
            str(root),
            "--starter",
            "local-iso",
            "--source-iso",
            str(iso),
            "--source-iso-sha256",
            "abc123",
        ]
    )

    project = Project.load(root)
    assert project.source_mode == "iso"
    assert project.source_iso == iso
    assert project.source_starter
    assert project.source_starter["key"] == "local-iso"
    assert project.source_starter["trust"]["source_sha256"] == "abc123"


def test_previous_project_starter_copies_source(tmp_path) -> None:
    previous = Project.create("Previous", tmp_path / "previous", "debian-13.5")
    apply_source_starter(previous, "debian-13.5-skeleton")

    current = Project.create("Current", tmp_path / "current", "26.04")
    apply_source_starter(current, "previous-project", previous_project=previous.root)

    loaded = Project.load(current.root)
    assert loaded.release.version == "debian-13.5"
    assert loaded.source_mode == "bootstrap"
    assert loaded.source_starter
    assert loaded.source_starter["key"] == "previous-project"


def test_source_starters_cli_json(capsys) -> None:
    main(["source-starters", "--release", "debian-13.5", "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert {item["key"] for item in payload} == {"debian-13.5-netinst", "debian-13.5-skeleton"}


def test_gui_mentions_source_starter_widgets() -> None:
    from pathlib import Path

    source = Path("distroforge/ui/main_window.py").read_text(encoding="utf-8")
    assert "source_starter_combo" in source
    assert "_apply_source_starter" in source
    assert "_use_previous_project_source" in source
