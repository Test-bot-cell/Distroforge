from __future__ import annotations

import ast
import os
from pathlib import Path

import pytest

from distroforge.ui.qt import QApplication

UI_DIR = Path(__file__).resolve().parent.parent / "distroforge" / "ui"


def _window_attr_accesses(source: str) -> tuple[set[str], set[str]]:
    """Return (reads, assignments) of first-level ``window.<attr>`` names."""
    tree = ast.parse(source)
    reads: set[str] = set()
    assigned: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "window":
            if isinstance(node.ctx, ast.Store):
                assigned.add(node.attr)
            else:
                reads.add(node.attr)
    return reads, assigned


@pytest.fixture(scope="module")
def qt_app():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    return QApplication.instance() or QApplication([])


def test_action_modules_only_reference_real_window_attributes(qt_app) -> None:
    from distroforge.ui.main_window import MainWindow

    window = MainWindow()

    reads_by_module: dict[str, set[str]] = {}
    assigned_anywhere: set[str] = set()
    for path in sorted(UI_DIR.glob("*_actions.py")):
        reads, assigned = _window_attr_accesses(path.read_text(encoding="utf-8"))
        reads_by_module[path.name] = reads
        assigned_anywhere |= assigned

    dangling = {
        name: sorted(attr for attr in reads if not hasattr(window, attr) and attr not in assigned_anywhere)
        for name, reads in reads_by_module.items()
    }
    dangling = {name: missing for name, missing in dangling.items() if missing}
    assert dangling == {}, f"Action modules reference window attributes that do not exist: {dangling}"
