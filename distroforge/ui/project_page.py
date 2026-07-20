from __future__ import annotations

from distroforge.ui.journey_cards import build_start_journey_panel
from distroforge.ui.qt import QVBoxLayout, QWidget
from distroforge.ui.widgets import button, responsive_row, section, stat


def build_project_page(window) -> QWidget:
    page = QWidget()
    layout = QVBoxLayout(page)
    layout.setContentsMargins(18, 18, 18, 18)

    actions = responsive_row(
        button("New", window._new_project, "new", primary=True),
        button("Open", window._open_project, "open"),
        button("Save", window._save_project, "save"),
        breakpoint=680,
    )

    stats = responsive_row(
        stat("Release", window.summary_release),
        stat("Source", window.summary_source),
        stat("Packages", window.summary_packages),
        stat("Desktop", window.summary_desktop),
        breakpoint=900,
    )

    layout.addWidget(section("Project", window.project_label, actions))
    layout.addWidget(stats)
    layout.addWidget(section("Build Journey", build_start_journey_panel(window)), 1)
    return page
