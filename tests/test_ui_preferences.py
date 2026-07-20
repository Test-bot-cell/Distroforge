from __future__ import annotations

import json

import pytest

from distroforge.ui import preferences


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    return tmp_path / "distroforge" / "ui.json"


def test_default_when_no_file(cfg):
    assert preferences.load_workflow_level() == "beginner"
    assert preferences.has_saved_level() is False


def test_round_trip_persists_under_xdg_config(cfg):
    preferences.save_workflow_level("maintainer")
    assert preferences.load_workflow_level() == "maintainer"
    assert preferences.has_saved_level() is True
    assert json.loads(cfg.read_text())["workflow_level"] == "maintainer"


def test_unknown_level_is_rejected(cfg):
    with pytest.raises(ValueError):
        preferences.save_workflow_level("wizard")
    assert preferences.has_saved_level() is False


def test_corrupt_file_falls_back_to_default(cfg):
    cfg.parent.mkdir(parents=True)
    cfg.write_text("{ not json", encoding="utf-8")
    assert preferences.load_workflow_level() == "beginner"
    assert preferences.has_saved_level() is False


def test_unknown_saved_value_is_ignored(cfg):
    cfg.parent.mkdir(parents=True)
    cfg.write_text(json.dumps({"workflow_level": "bogus"}), encoding="utf-8")
    assert preferences.load_workflow_level("power-user") == "power-user"
    assert preferences.has_saved_level() is False
