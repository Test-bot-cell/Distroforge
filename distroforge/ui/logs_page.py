from __future__ import annotations

from distroforge.ui.qt import QVBoxLayout, QWidget
from distroforge.ui.widgets import button as _button
from distroforge.ui.widgets import responsive_row as _responsive_row
from distroforge.ui.widgets import section as _section


def build_logs_page(window) -> QWidget:
    page = QWidget()
    layout = QVBoxLayout(page)
    layout.setContentsMargins(18, 18, 18, 18)
    actions = _responsive_row(
        window.log_filter_edit,
        _button("Filter", window._filter_logs, "plan"),
        _button("Clear filter", window._clear_log_filter, "clear"),
        breakpoint=820,
    )
    layout.addWidget(_section("Logs", actions, window.logs), 1)
    return page
