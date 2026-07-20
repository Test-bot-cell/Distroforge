from __future__ import annotations

from distroforge.ui.qt import QPlainTextEdit, QVBoxLayout, QWidget
from distroforge.ui.step_focus import StepFocusHeader
from distroforge.ui.widgets import button as _button
from distroforge.ui.widgets import responsive_row as _responsive_row
from distroforge.ui.widgets import section as _section


def build_plugins_page(window) -> QWidget:
    page = QWidget()
    layout = QVBoxLayout(page)
    layout.setContentsMargins(18, 18, 18, 18)
    layout.addWidget(StepFocusHeader(window, "extension-contract"))
    window.plugins_view = QPlainTextEdit()
    window.plugins_view.setReadOnly(True)
    actions = _responsive_row(
        _button("Refresh plugin catalog", window._refresh_plugins, "plan"),
        breakpoint=720,
    )
    layout.addWidget(_section("Plugins", actions, window.plugins_view), 1)
    return page
