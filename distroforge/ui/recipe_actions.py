from __future__ import annotations

import json
from pathlib import Path

from distroforge.core.definition import (
    apply_definition,
    definition_from_project,
    load_definition,
    write_definition,
)
from distroforge.core.education import render_guided_recipes
from distroforge.core.recipe import export_recipe, load_recipe
from distroforge.ui.qt import QFileDialog


def export_recipe_action(window) -> None:
    if not window._require_project():
        return
    window._sync_project_from_ui()
    assert window.project
    path, _ = QFileDialog.getSaveFileName(window, "Export DistroForge recipe", filter="Forge recipes (*.forge.json)")
    if not path:
        return
    export_recipe(window.project, window._build_options()).write(Path(path))
    window._log(f"Wrote recipe {path}")


def export_build_preset_action(window) -> None:
    if not window._require_project():
        return
    window._sync_project_from_ui()
    assert window.project
    path, _ = QFileDialog.getSaveFileName(
        window,
        "Export maintainer build preset",
        filter="Forge presets (*.forge.json *.forge.yaml *.json *.yaml *.yml)",
    )
    if not path:
        return
    data = definition_from_project(
        window.project,
        window._build_options(),
        {"source": "gui"},
    )
    write_definition(data, Path(path))
    window.recipe_view.setPlainText(json.dumps(data, indent=2))
    window._log(f"Wrote build preset {path}")


def import_recipe_action(window) -> None:
    if not window._require_project():
        return
    path, _ = QFileDialog.getOpenFileName(window, "Import DistroForge recipe", filter="Forge recipes (*.json *.forge.json)")
    if not path:
        return
    try:
        data = load_recipe(Path(path))
    except Exception as exc:
        window._error(str(exc))
        return
    assert window.project
    if data.get("source_mode"):
        window.project.source_mode = str(data["source_mode"])
    if data.get("source_iso"):
        window.project.source_iso = Path(str(data["source_iso"]))
    window.project.packages = [str(item) for item in data.get("packages", [])]
    window.project.remove_packages = [str(item) for item in data.get("remove_packages", [])]
    window.project.repositories = [str(item) for item in data.get("repositories", [])]
    customization = data.get("customization")
    if isinstance(customization, dict):
        custom = window.project.customization
        custom.desktop = customization.get("desktop") or None
        custom.display_manager = customization.get("display_manager") or None
        custom.autologin_user = customization.get("autologin_user") or None
        custom.wallpaper = customization.get("wallpaper") or None
        custom.hostname = customization.get("hostname") or None
        custom.locale = customization.get("locale") or None
        custom.timezone = customization.get("timezone") or None
        custom.keyboard_layout = customization.get("keyboard_layout") or None
    window._refresh()
    window._log(f"Imported recipe {path}")


def import_build_preset_action(window) -> None:
    if not window._require_project():
        return
    path, _ = QFileDialog.getOpenFileName(
        window,
        "Import maintainer build preset",
        filter="Forge presets (*.json *.yaml *.yml *.forge.json *.forge.yaml)",
    )
    if not path:
        return
    try:
        data = load_definition(Path(path))
        assert window.project
        window.loaded_preset_options = apply_definition(window.project, data)
        window.loaded_preset_path = Path(path)
    except Exception as exc:
        window._error(str(exc))
        return
    window._refresh()
    window.recipe_view.setPlainText(json.dumps(data, indent=2))
    window._log(f"Imported build preset {path}")


def clear_build_preset_action(window) -> None:
    window.loaded_preset_options = None
    window.loaded_preset_path = None
    if hasattr(window, "recipe_view"):
        window.recipe_view.clear()
    window._log("Cleared imported build preset")


def show_guided_recipes_action(window) -> None:
    window.recipe_view.setPlainText(render_guided_recipes())
    window._log("Listed guided recipes")
