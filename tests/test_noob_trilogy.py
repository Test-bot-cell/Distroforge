from __future__ import annotations

import json
from pathlib import Path

import pytest

from distroforge.cli import main
from distroforge.core.profile_validation import load_profile_resolver_spec
from distroforge.core.project import Project

ROOT_EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def test_wizard_creates_noob_profile_plan_and_history(capsys, tmp_path) -> None:
    root = tmp_path / "desk"

    main(["wizard", "Desk", str(root), "--profile", "desktop"])

    out = capsys.readouterr().out
    assert "DistroForge beginner-first plan: Bureau" in out
    assert "Smart choices:" in out
    assert "Applications added:" in out
    assert (root / "desktop-wizard.yaml").exists()
    assert (root / ".distroforge" / "history.jsonl").exists()

    project = Project.load(root)
    assert project.customization.desktop == "ubuntu"
    assert "ubuntu-desktop" in project.packages


def test_wizard_plan_only_does_not_create_project(tmp_path, capsys) -> None:
    root = tmp_path / "preview"

    main(["wizard", "Preview", str(root), "--profile", "portable", "--plan-only"])

    out = capsys.readouterr().out
    assert "DistroForge beginner-first plan: Portable" in out
    assert not (root / "project.json").exists()


def test_profile_resolve_json_is_idempotent(capsys, tmp_path) -> None:
    project = Project.create("Resolve", tmp_path / "resolve", "26.04")
    project.packages = ["curl"]
    project.save()

    argv = [
        "profile",
        "resolve",
        str(project.root),
        "--base",
        "desktop",
        "--layer",
        "developer",
        "--json",
    ]
    main(argv)
    first = json.loads(capsys.readouterr().out)
    main(argv)
    second = json.loads(capsys.readouterr().out)

    assert first["resolved"] == second["resolved"]
    assert first["priority"] == second["priority"]
    assert "curl" in first["resolved"]["packages"]
    assert "build-essential" in first["resolved"]["packages"]
    assert first["build_contract"]["replayable"] is True


def test_profile_resolve_reports_package_conflict(capsys, tmp_path) -> None:
    project = Project.create("Conflict", tmp_path / "conflict", "26.04")
    project.packages = ["ubuntu-desktop"]
    project.save()

    main(["profile", "resolve", str(project.root), "--override", "lightweight", "--json"])

    data = json.loads(capsys.readouterr().out)
    assert "ubuntu-desktop" in data["resolved"]["remove_packages"]
    assert any("ubuntu-desktop" in item for item in data["conflicts"])


def test_profile_show_root_renders_resolved_layers(capsys, tmp_path) -> None:
    project = Project.create("ShowResolved", tmp_path / "show", "26.04")
    project.packages = ["curl"]
    project.save()

    main(["profile", "show", "desktop", "--root", str(project.root), "--layer", "developer", "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert payload["schema"] == "distroforge.profile-resolution.v1"
    assert payload["project"] == project.root.as_posix()
    assert "00-project" in payload["priority"]
    assert payload["resolved"]["packages"]
    assert "build-essential" in payload["resolved"]["packages"]


def test_profile_diff_supports_right_side_composable_inputs(capsys, tmp_path) -> None:
    project = Project.create("DiffRight", tmp_path / "diff-right", "26.04")
    main(["profile", "diff", str(project.root), "developer", "--against", "lightweight", "--against-layer", "privacy", "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert payload["right"] is not None
    assert payload["left"]["profile"] == "developer"
    assert payload["right"]["profile"] == "lightweight"
    assert any("20-layer" in name for name in payload["right"]["priority"])
    assert "ufw" in payload["right"]["resolution"]["install"]
    assert "build-essential" in payload["left"]["resolution"]["install"]


def test_history_replay_unknown_entry_has_guidance(capsys, tmp_path) -> None:
    root = tmp_path / "hist"
    main(["wizard", "Hist", str(root), "--profile", "dev"])
    capsys.readouterr()

    with pytest.raises(SystemExit) as exc:
        main(["history", "replay", str(root), "not-a-real-entry"])
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "Unknown history entry 'not-a-real-entry'" in err
    assert "Use 'latest'" in err


def test_history_replay_writes_clean_definition(capsys, tmp_path) -> None:
    root = tmp_path / "hist2"
    main(["wizard", "Hist", str(root), "--profile", "dev"])
    capsys.readouterr()

    main(["history", "list", str(root), "--json"])
    history = json.loads(capsys.readouterr().out)
    entry = history["history"][0]["id"]
    replay = tmp_path / "replay.yaml"

    main(["history", "replay", str(root), entry, "--output", str(replay)])

    out = capsys.readouterr().out
    assert "DistroForge history replay" in out
    assert replay.exists()
    text = replay.read_text(encoding="utf-8")
    assert "packages:" in text
    assert "build-essential" in text


def test_profile_resolution_examples_are_strictly_validated(tmp_path) -> None:
    for name in ("composable-profile.toml", "composable-profile.yaml"):
        spec = load_profile_resolver_spec(ROOT_EXAMPLES / name)
        assert "base" in spec
        assert spec["base"] == "desktop"
        assert "layers" in spec


def test_profile_resolution_rejects_invalid_config_format(tmp_path) -> None:
    bad = tmp_path / "bad-profile.yaml"
    bad.write_text("base: [\n", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid syntax"):
        load_profile_resolver_spec(bad)

    bad.write_text("unknown: true\n", encoding="utf-8")

    with pytest.raises(ValueError, match="unknown keys"):
        load_profile_resolver_spec(bad)
