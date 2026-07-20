"""Runtime proof of the level-independent reachability guarantee shared by the
CLI/GUI-parity pillar and the UX cognitive-ergonomics pillar.

Progressive disclosure prunes only the *guided spine*; it must never prune
*reachability*. Every GUI surface that backs a CLI capability stays reachable at
every workflow level, and the header palette is a complete, level-independent
escape hatch. These are offscreen construction probes (no ``show()``, which
hangs under the offscreen platform), built on a fresh, isolated config home.
"""

from __future__ import annotations

import os
import tempfile

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("XDG_CONFIG_HOME", tempfile.mkdtemp())

from distroforge.core.command_registry import CLI_GUI_COMMANDS  # noqa: E402
from distroforge.ui.qt import QApplication  # noqa: E402


@pytest.fixture(scope="module")
def qt_app():
    return QApplication.instance() or QApplication([])


def _levels(window) -> list[str]:
    return [window.mode_combo.itemData(i) for i in range(window.mode_combo.count())]


def test_palette_is_a_level_independent_escape_hatch(qt_app) -> None:
    from distroforge.core.build_journey import JOURNEY_STEPS
    from distroforge.ui.main_window import MainWindow

    window = MainWindow()
    palette = window._palette_combo
    payloads = [palette.itemData(i) for i in range(palette.count())]
    surface_keys = {p[1] for p in payloads if p and p[0] == "surface"}
    # The escape hatch still enumerates *every* surface, not a level-filtered
    # subset -- the all-actions upgrade only adds entries, it never prunes one.
    assert surface_keys == set(window._surface_labels)
    # It is now a complete, keyboard-first action index: a type-to-filter palette
    # whose entries also cover every guided journey step.
    assert palette.isEditable()
    journey_steps = {p[2] for p in payloads if p and p[0] == "journey"}
    assert {step.step_id for step in JOURNEY_STEPS} <= journey_steps


def test_command_palette_routes_surfaces_and_journey_steps(qt_app) -> None:
    from distroforge.core.build_journey import JOURNEY_STEPS
    from distroforge.ui.main_window import MainWindow

    window = MainWindow()
    palette = window._palette_combo
    payloads = [palette.itemData(i) for i in range(palette.count())]

    # A surface entry opens that surface through the same router as the rail...
    sidx = next(i for i, p in enumerate(payloads) if p and p[0] == "surface" and p[1] == "artifacts")
    palette.setCurrentIndex(sidx)
    window._palette_navigate(palette)
    assert window._pages.currentIndex() == window._surfaces["artifacts"]

    # ...and every guided journey step routes from the palette to a focused panel,
    # including the maintainer steps that retarget a shared surface's banner.
    by_step = {p[2]: i for i, p in enumerate(payloads) if p and p[0] == "journey"}
    for step in JOURNEY_STEPS:
        palette.setCurrentIndex(by_step[step.step_id])
        window._palette_navigate(palette)
        header = window._current_step_focus()
        assert header is not None and header._step.step_id == step.step_id, step.step_id


def test_goal_hub_routes_every_capability_to_its_surface(qt_app) -> None:
    from distroforge.core.workflows import PRODUCT_CAPABILITIES
    from distroforge.ui.goal_hub import GoalHubGrid
    from distroforge.ui.main_window import MainWindow
    from distroforge.ui.qt import QPushButton

    window = MainWindow()
    window._open_surface("command-center")
    grid = window._pages.currentWidget().findChild(GoalHubGrid)
    assert grid is not None
    # One goal card per product capability, each wired to the GUI surface the
    # capability declares in the single-source registry.
    assert len(grid._cards) == len(PRODUCT_CAPABILITIES)
    for index, capability in enumerate(PRODUCT_CAPABILITIES):
        window._open_surface("command-center")
        grid._cards[index].findChild(QPushButton).click()
        assert window._pages.currentIndex() == window._surfaces[capability.gui_surface], capability.key


def test_every_surface_is_reachable_at_every_level(qt_app) -> None:
    from distroforge.ui.main_window import MainWindow

    window = MainWindow()
    levels = _levels(window)
    assert levels, "mode_combo exposes no levels"
    for level in levels:
        window.mode_combo.setCurrentIndex(window.mode_combo.findData(level))
        window._on_level_changed()
        for key in window._surface_labels:
            window._open_surface(key)
            assert window._pages.currentIndex() == window._surfaces[key], (level, key)


def test_full_parity_catalog_is_reachable_at_the_most_restricted_level(qt_app) -> None:
    from distroforge.ui.main_window import MainWindow

    # Every registry capability maps to a real (non-empty) GUI surface.
    assert all(command.gui_surface for command in CLI_GUI_COMMANDS)

    window = MainWindow()
    most_restricted = _levels(window)[0]
    window.mode_combo.setCurrentIndex(window.mode_combo.findData(most_restricted))
    window._on_level_changed()
    # The Command Center renders the full CLI/GUI parity catalog; an advanced user
    # on a beginner install must still reach it.
    window._open_surface("command-center")
    assert window._pages.currentIndex() == window._surfaces["command-center"]


def test_every_journey_step_routes_to_a_focused_panel(qt_app) -> None:
    from distroforge.core.build_journey import JOURNEY_STEPS
    from distroforge.ui.command_center_page import JOURNEY_TARGETS
    from distroforge.ui.main_window import MainWindow

    window = MainWindow()
    # Every guided step lands on a panel whose focused banner reflects that step
    # -- including the maintainer steps that share a heavy surface (rollback on
    # Build & Release, publish-gate on Artifacts). The shared banner retargets
    # rather than stacking a second banner, so the routed step's what/why/status
    # is always the one shown.
    for step in JOURNEY_STEPS:
        window._focus_journey_step(JOURNEY_TARGETS[step.action_id], step.step_id)
        header = window._current_step_focus()
        assert header is not None, step.step_id
        assert header._step.step_id == step.step_id, (step.action_id, step.step_id)


def test_home_button_returns_to_start_from_every_surface(qt_app) -> None:
    from distroforge.ui.main_window import MainWindow

    window = MainWindow()
    # The always-visible counterpart to the recall-leaning Ctrl+K palette: a Start
    # button at the leading edge of the header (GNOME HIG back/home placement),
    # shown on every surface except Start itself, that returns home in one click.
    assert window._home_button.objectName() == "HomeButton"
    for key in window._surface_labels:
        window._open_surface(key)
        # A never-shown widget always reports isVisible() False under the offscreen
        # platform, so assert the explicit hidden flag _open_surface toggles.
        assert window._home_button.isHidden() is (key == "start"), key
    # From any non-start surface a single click routes back to Start and re-hides.
    window._open_surface("artifacts")
    assert window._home_button.isHidden() is False
    window._home_button.click()
    assert window._pages.currentIndex() == window._surfaces["start"]
    assert window._home_button.isHidden() is True


def test_plain_navigation_restores_a_surface_canonical_step(qt_app) -> None:
    from distroforge.ui.main_window import MainWindow

    window = MainWindow()
    # A journey click retargets the shared Artifacts banner to publish-gate...
    window._focus_journey_step("artifacts", "publish-gate")
    assert window._current_step_focus()._step.step_id == "publish-gate"
    # ...but opening the surface plainly (the palette escape hatch) restores its
    # canonical step, so the page keeps a stable identity outside the journey.
    window._open_surface("artifacts")
    assert window._current_step_focus()._step.step_id == "release-evidence"
