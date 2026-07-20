from __future__ import annotations

from pathlib import Path

from distroforge.core.project import Project
from distroforge.core.source_starter import (
    apply_source_starter,
    default_starter_for_release,
    list_source_starters,
)
from distroforge.ui.qt import QFileDialog, QInputDialog


def new_project_action(window) -> None:
    parent = QFileDialog.getExistingDirectory(window, "Project parent directory")
    if not parent:
        return
    name, ok = QInputDialog.getText(window, "Project name", "Name")
    if not ok or not name.strip():
        return
    release, ok = QInputDialog.getItem(
        window,
        "Base release",
        "Release",
        list(window.releases),
        current=2 if "26.04" in window.releases else 0,
        editable=False,
    )
    if not ok:
        return
    window.project = Project.create(name.strip(), Path(parent) / name.strip(), release)
    starter_items = [
        starter
        for starter in list_source_starters(release)
        if starter.kind in {"skeleton", "official-iso", "netboot"}
    ]
    starter_labels = [starter.label for starter in starter_items]
    starter_label, ok = QInputDialog.getItem(
        window,
        "Source starter",
        "Starter",
        starter_labels,
        current=0,
        editable=False,
    )
    if ok and starter_label:
        starter = starter_items[starter_labels.index(starter_label)]
        apply_source_starter(window.project, starter.key)
    else:
        apply_source_starter(window.project, default_starter_for_release(release))
    window._clear_build_preset()
    window._refresh()
    window._log(f"Created project {window.project.root}")


def open_project_action(window) -> None:
    directory = QFileDialog.getExistingDirectory(window, "Open DistroForge project")
    if not directory:
        return
    try:
        window.project = Project.load(Path(directory))
    except Exception as exc:
        window._error(str(exc))
        return
    sanitize_message = window.project.desktop_sanitization_message()
    window._clear_build_preset()
    window._refresh()
    if sanitize_message:
        window._log(sanitize_message)
    window._log(f"Opened project {window.project.root}")


def save_project_action(window) -> None:
    if not window._require_project():
        return
    window._sync_project_from_ui()
    assert window.project
    window.project.save()
    window._refresh()
    window._log(f"Saved project {window.project.root}")


def apply_source_starter_action(window) -> None:
    if not window._require_project():
        return
    assert window.project
    key = window.source_starter_combo.currentData()
    if not key:
        return
    apply_source_starter(window.project, str(key))
    window._refresh()
    window._log(f"Applied source starter: {window.project.source_starter.get('label')}")


def use_previous_project_source_action(window) -> None:
    if not window._require_project():
        return
    directory = QFileDialog.getExistingDirectory(window, "Select previous DistroForge project")
    if not directory:
        return
    assert window.project
    apply_source_starter(window.project, "previous-project", previous_project=Path(directory))
    window._refresh()
    window._log(f"Copied source starter from {directory}")
