from __future__ import annotations

import argparse
import os

import pytest

from distroforge.core import build_journey
from distroforge.core.persona import load_personas
from distroforge.core.workflows import (
    LEVEL_KEYS,
    LEVEL_ORDER,
    WORKFLOW_LEVELS,
    get_workflow_level,
)

EXPECTED_LEVELS = ("beginner", "power-user", "maintainer", "developer")
EXPECTED_PERSONA_LEVELS = {
    "noob": "beginner",
    "friendly": "beginner",
    "intermediate": "power-user",
    "pro": "maintainer",
    "dev_maintainer": "developer",
}


def test_workflow_levels_are_the_canonical_ordered_vocabulary() -> None:
    assert LEVEL_KEYS == EXPECTED_LEVELS
    assert tuple(level.key for level in WORKFLOW_LEVELS) == EXPECTED_LEVELS
    assert LEVEL_ORDER == {key: index for index, key in enumerate(EXPECTED_LEVELS)}


def test_build_journey_reuses_the_one_canonical_level_order() -> None:
    # The journey must derive from workflows, not redefine its own level table.
    assert build_journey.LEVEL_ORDER is LEVEL_ORDER


def test_journey_cli_level_choices_come_from_canonical_levels() -> None:
    from distroforge.commands.journey import register_journey_parser

    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    register_journey_parser(sub)
    journey_parser = sub.choices["journey"]
    level_action = next(action for action in journey_parser._actions if action.dest == "level")
    assert tuple(level_action.choices) == LEVEL_KEYS


def test_every_persona_declares_a_canonical_level() -> None:
    for persona in load_personas().values():
        assert persona.level in LEVEL_KEYS, persona.key


def test_persona_to_level_bridge_is_explicit() -> None:
    assert {key: persona.level for key, persona in load_personas().items()} == EXPECTED_PERSONA_LEVELS


def test_get_workflow_level_resolves_and_rejects() -> None:
    assert get_workflow_level("developer").label == "Developer"
    with pytest.raises(ValueError, match="Unknown workflow level"):
        get_workflow_level("not-a-level")


def test_persona_with_unknown_level_is_rejected(monkeypatch) -> None:
    from distroforge.core import persona as persona_mod

    bad_toml = (
        "[personas.broken]\n"
        'label = "Broken"\n'
        'description = "Declares a level that is not in the canonical vocabulary."\n'
        'level = "not-a-level"\n'
        "sanitize_apt_lists = false\n"
        "sanitize_ssh_host_keys = false\n"
        "drivers_auto = true\n"
        "qemu_matrix = []\n"
        "sbom = true\n"
    )

    class _FakeResource:
        def joinpath(self, _name: str) -> _FakeResource:
            return self

        def read_text(self, encoding: str = "utf-8") -> str:
            return bad_toml

    monkeypatch.setattr(persona_mod, "files", lambda _package: _FakeResource())
    persona_mod.load_personas.cache_clear()
    try:
        with pytest.raises(ValueError, match="unknown workflow level"):
            persona_mod.load_personas()
    finally:
        persona_mod.load_personas.cache_clear()


@pytest.fixture(scope="module")
def qt_app():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from distroforge.ui.qt import QApplication

    return QApplication.instance() or QApplication([])


def test_gui_persona_combo_exposes_the_canonical_level(qt_app) -> None:
    from distroforge.ui.main_window import MainWindow
    from distroforge.ui.qt import Qt

    window = MainWindow()
    combo = window.persona_combo
    tooltips = {}
    for index in range(combo.count()):
        key = combo.itemData(index)
        if key:
            tooltips[key] = combo.itemData(index, Qt.ItemDataRole.ToolTipRole)
    for key, persona in load_personas().items():
        assert key in tooltips, key
        assert get_workflow_level(persona.level).label in tooltips[key]
