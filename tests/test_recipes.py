from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import pytest

from distroforge.commands.guided_recipe import run_guided_recipe
from distroforge.core.education import (
    GUIDED_RECIPES,
    get_guided_recipe,
    guided_recipes_json,
    render_guided_recipes,
)
from distroforge.core.profiles import load_profiles


def test_every_package_profile_has_a_guided_recipe() -> None:
    # The guided recipes are the curated source-to-ISO entry points; each
    # deterministic package profile must be reachable from one of them.
    covered = {recipe.profile for recipe in GUIDED_RECIPES if recipe.profile}
    assert covered == set(load_profiles())


def test_recipe_profiles_are_valid_or_none() -> None:
    profiles = set(load_profiles())
    for recipe in GUIDED_RECIPES:
        assert recipe.profile is None or recipe.profile in profiles, recipe.key


def test_recipe_keys_are_unique() -> None:
    keys = [recipe.key for recipe in GUIDED_RECIPES]
    assert len(keys) == len(set(keys))


def test_to_dict_exposes_profile() -> None:
    for recipe in GUIDED_RECIPES:
        assert recipe.to_dict()["profile"] == recipe.profile


def test_guided_recipes_json_round_trips_every_recipe() -> None:
    payload = json.loads(guided_recipes_json())
    assert {entry["key"] for entry in payload} == {recipe.key for recipe in GUIDED_RECIPES}
    for entry in payload:
        assert entry["profile"] == get_guided_recipe(entry["key"]).profile


def test_render_guided_recipes_lists_every_recipe() -> None:
    listing = render_guided_recipes()
    for recipe in GUIDED_RECIPES:
        assert recipe.key in listing
        assert recipe.label in listing


def test_render_guided_recipes_tags_only_profile_recipes() -> None:
    by_key = {line.split(maxsplit=1)[0]: line for line in render_guided_recipes().splitlines()}
    for recipe in GUIDED_RECIPES:
        line = by_key[recipe.key]
        if recipe.profile:
            assert f"[profile: {recipe.profile}]" in line
        else:
            assert "[profile:" not in line


def test_cli_listing_matches_the_shared_renderer(capsys) -> None:
    run_guided_recipe(argparse.Namespace(name=None, json=False))
    out = capsys.readouterr().out
    assert out == render_guided_recipes() + "\n"
    assert "gaming" in out
    assert "[profile: gaming]" in out


def test_cli_json_listing_exposes_profiles(capsys) -> None:
    run_guided_recipe(argparse.Namespace(name=None, json=True))
    payload = json.loads(capsys.readouterr().out)
    assert any(entry["profile"] == "gaming" for entry in payload)


@pytest.fixture(scope="module")
def qt_app():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from distroforge.ui.qt import QApplication

    return QApplication.instance() or QApplication([])


def test_presets_page_lists_guided_recipes(qt_app) -> None:
    from distroforge.ui.main_window import MainWindow

    window = MainWindow()
    window._show_guided_recipes()
    assert window.recipe_view.toPlainText() == render_guided_recipes()


def test_presets_page_source_wires_guided_recipes() -> None:
    source = Path("distroforge/ui/recipes_page.py").read_text(encoding="utf-8")
    assert "_show_guided_recipes" in source
    assert "Guided recipes" in source
