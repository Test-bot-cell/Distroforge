"""The Qt import shim and the widget declarations that depend on it.

distroforge/ui/qt.py types the tree against PyQt6 under `if TYPE_CHECKING` while the
runtime still prefers PySide6. That is what makes mypy independent of which binding
happens to be installed, and it costs one thing: mypy reads a branch it does not execute,
so nothing it does would notice a name present in one branch and missing from the other.
The tests below are that missing notice.

The same applies to the widget attributes MainWindow declares. They are attached from the
outside by build_window_widgets() and the page builders, so a declaration is a claim about
another module. mypy checks the reading side -- an attribute read but not declared is an
error -- and these tests check the writing side, where a builder renames a widget and the
declaration keeps pointing at a name nobody assigns any more.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHIM = ROOT / "distroforge" / "ui" / "qt.py"
UI = ROOT / "distroforge" / "ui"
# The binding python3-distroforge depends on, and therefore the one the type checker has
# to agree with. Pinning it here rather than trusting the file to keep pointing at it.
SHIPPED_BINDING = "PyQt6"


def _branches() -> tuple[dict[str, tuple[str, ...]], list[dict[str, tuple[str, ...]]]]:
    """Return (typing branch, [runtime branches]) as {qt submodule: imported names}.

    The typing branch is the body of `if TYPE_CHECKING`; the runtime branches are the try
    and the except inside its `else`. Both are read from the source rather than by
    importing, because importing only ever executes one of them.
    """
    tree = ast.parse(SHIM.read_text())

    def imports(body: list[ast.stmt]) -> dict[str, tuple[str, ...]]:
        found: dict[str, tuple[str, ...]] = {}
        for node in body:
            if isinstance(node, ast.ImportFrom) and node.module:
                _binding, _, submodule = node.module.partition(".")
                found[submodule] = tuple(alias.name for alias in node.names)
        return found

    guards = [
        node
        for node in tree.body
        if isinstance(node, ast.If)
        and isinstance(node.test, ast.Name)
        and node.test.id == "TYPE_CHECKING"
    ]
    assert len(guards) == 1, "the shim is expected to have exactly one TYPE_CHECKING guard"
    guard = guards[0]
    tries = [node for node in guard.orelse if isinstance(node, ast.Try)]
    assert len(tries) == 1, "the runtime branch is expected to be exactly one try/except"
    runtime = [imports(tries[0].body)] + [imports(handler.body) for handler in tries[0].handlers]
    return imports(guard.body), runtime


def _bindings(body: list[ast.stmt]) -> set[str]:
    return {
        node.module.partition(".")[0]
        for node in body
        if isinstance(node, ast.ImportFrom) and node.module
    }


def test_every_branch_of_the_shim_exports_the_same_names_from_the_same_submodules():
    typing_branch, runtime_branches = _branches()
    for runtime_branch in runtime_branches:
        assert runtime_branch.keys() == typing_branch.keys()
        for submodule, names in typing_branch.items():
            assert runtime_branch[submodule] == names, (
                f"{submodule} disagrees between the typing and runtime branches: "
                f"{sorted(set(names) ^ set(runtime_branch[submodule]))}"
            )


def test_the_typing_branch_is_pinned_to_the_binding_the_package_depends_on():
    tree = ast.parse(SHIM.read_text())
    guard = next(
        node
        for node in tree.body
        if isinstance(node, ast.If)
        and isinstance(node.test, ast.Name)
        and node.test.id == "TYPE_CHECKING"
    )
    assert _bindings(guard.body) == {SHIPPED_BINDING}


def test_the_runtime_branch_prefers_pyside6_and_falls_back_to_the_shipped_binding():
    tree = ast.parse(SHIM.read_text())
    guard = next(
        node
        for node in tree.body
        if isinstance(node, ast.If)
        and isinstance(node.test, ast.Name)
        and node.test.id == "TYPE_CHECKING"
    )
    attempt = next(node for node in guard.orelse if isinstance(node, ast.Try))
    assert _bindings(attempt.body) == {"PySide6"}
    assert [_bindings(handler.body) for handler in attempt.handlers] == [{SHIPPED_BINDING}]


def test_the_shim_resolves_to_a_real_binding_at_runtime():
    from distroforge.ui import qt

    binding = qt.QWidget.__module__.partition(".")[0]
    assert binding in {"PySide6", SHIPPED_BINDING}


def _declared_window_attributes() -> dict[str, str]:
    """The class-level annotations on MainWindow: {attribute: annotation}."""
    tree = ast.parse((UI / "main_window.py").read_text())
    cls = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "MainWindow"
    )
    return {
        node.target.id: ast.unparse(node.annotation)
        for node in cls.body
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
    }


def _attributes_attached_to_a_window() -> set[str]:
    """Every name some ui module assigns onto a window object."""
    attached: set[str] = set()
    for module in sorted(UI.glob("*.py")):
        for node in ast.walk(ast.parse(module.read_text())):
            targets: list[ast.expr] = []
            if isinstance(node, ast.Assign):
                targets = list(node.targets)
            elif isinstance(node, ast.AnnAssign):
                targets = [node.target]
            for target in targets:
                if (
                    isinstance(target, ast.Attribute)
                    and isinstance(target.value, ast.Name)
                    and target.value.id in {"window", "self"}
                ):
                    attached.add(target.attr)
    return attached


def test_every_widget_main_window_declares_is_attached_by_some_builder():
    declared = _declared_window_attributes()
    assert declared, "MainWindow is expected to declare the widgets it does not create"
    attached = _attributes_attached_to_a_window()
    orphans = sorted(name for name in declared if name not in attached)
    assert not orphans, (
        "declared on MainWindow but assigned by nobody -- a builder most likely renamed "
        f"the widget: {orphans}"
    )


def test_main_window_declares_widgets_with_their_own_class_not_qwidget():
    # A protocol attribute is invariant, so a loose annotation is not permissive: it is
    # what rejects the precise implementation. QWidget here would put the divergence back
    # exactly where build_page.BuildPageWindow used to have it.
    loose = sorted(
        name for name, annotation in _declared_window_attributes().items()
        if annotation in {"QWidget", "object"}
    )
    assert not loose, f"declared too loosely to be useful: {loose}"
