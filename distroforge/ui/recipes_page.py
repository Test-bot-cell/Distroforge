from __future__ import annotations

from distroforge.ui.qt import QPlainTextEdit, QVBoxLayout, QWidget
from distroforge.ui.widgets import button as _button
from distroforge.ui.widgets import button_group as _button_group
from distroforge.ui.widgets import section as _section


def build_recipes_page(window) -> QWidget:
    page = QWidget()
    layout = QVBoxLayout(page)
    layout.setContentsMargins(18, 18, 18, 18)
    recipe_files = _button_group(
        "Recipe files",
        _button("Guided recipes", window._show_guided_recipes, "help"),
        _button("Export recipe", window._export_recipe, "save"),
        _button("Import recipe", window._import_recipe, "open"),
    )
    presets = _button_group(
        "Build presets",
        _button("Export build preset", window._export_build_preset, "save"),
        _button("Import build preset", window._import_build_preset, "open"),
        _button("Clear preset", window._clear_build_preset, "clear"),
    )
    explain = _button_group(
        "Explain",
        _button("Explain current build", window._explain_build, "explain"),
    )
    window.recipe_view = QPlainTextEdit()
    window.recipe_view.setReadOnly(True)
    layout.addWidget(_section("Recipes", recipe_files, presets, explain, window.recipe_view), 1)
    return page
