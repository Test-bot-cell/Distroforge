"""The guided build journey rendered as the shell's primary surface.

Cognitive-science redesign: instead of a wall of peer pages, the home is a
single ordered spine of the steps the engine already models in
``core.build_journey``. It shows where the user is (progress + current step),
discloses only the steps the chosen level unlocks, and routes a click to that
step's focused panel. The engine's ``title``/``next_action`` are reused verbatim
so the journey has one source of truth.
"""

from __future__ import annotations

from distroforge.core.build_journey import BuildJourneyItem, build_journey
from distroforge.ui.command_center_page import open_journey_target
from distroforge.ui.qt import (
    QHBoxLayout,
    QLabel,
    QSizePolicy,
    Qt,
    QVBoxLayout,
    QWidget,
)
from distroforge.ui.widgets import ElidingLabel

# Engine status -> a compact leading marker. The spine shows the engine's own
# per-item status; the heavier per-step check stays in the step panel so the
# home stays fast and uncluttered.
_STATUS_MARKER = {
    "done": "✓",  # check
    "active": "▶",  # play
    "waiting": "○",  # hollow circle
    "review": "◆",  # diamond
    "info": "◆",
    "warning": "⚠",  # warning
    "error": "✗",  # cross
}


def _progress_bar(done: int, total: int) -> str:
    if total <= 0:
        return ""
    return f"{'●' * done}{'○' * (total - done)}  {done}/{total}"


class _StepRow(QWidget):
    """One clickable spine step: marker + title, plus next action when active."""

    def __init__(self, window, item: BuildJourneyItem, index: int) -> None:
        super().__init__()
        self._window = window
        self._item = item
        self.setObjectName("JourneyStep")
        self.setProperty("journeyStatus", item.status)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(12, 9, 12, 9)
        outer.setSpacing(3)
        head = QHBoxLayout()
        head.setContentsMargins(0, 0, 0, 0)
        head.setSpacing(10)
        marker = QLabel(_STATUS_MARKER.get(item.status, "◆"))
        marker.setObjectName("JourneyStepMarker")
        marker.setFixedWidth(18)
        title = ElidingLabel(f"{index}. {item.step.title}")
        title.setObjectName("JourneyStepTitle")
        title.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        head.addWidget(marker)
        head.addWidget(title, 1)
        outer.addLayout(head)
        if item.status == "active":
            hint = ElidingLabel(item.next_action)
            hint.setObjectName("JourneyStepHint")
            hint.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
            outer.addWidget(hint)

    def mousePressEvent(self, event) -> None:  # noqa: N802
        open_journey_target(self._window, self._item.step.action_id, self._item.step.step_id)
        super().mousePressEvent(event)


class JourneySpine(QWidget):
    """Ordered, level-filtered spine of the build journey."""

    def __init__(self, window) -> None:
        super().__init__()
        self._window = window
        self.setObjectName("JourneySpinePanel")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 14, 12, 14)
        layout.setSpacing(8)
        heading = ElidingLabel("Guided build journey")
        heading.setObjectName("SectionTitle")
        heading.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        self._summary = QLabel("Create or open a project to start the guided build journey.")
        self._summary.setObjectName("JourneySummary")
        self._summary.setWordWrap(True)
        self._rows = QVBoxLayout()
        self._rows.setContentsMargins(0, 0, 0, 0)
        self._rows.setSpacing(6)
        layout.addWidget(heading)
        layout.addWidget(self._summary)
        layout.addLayout(self._rows)
        layout.addStretch(1)

    def refresh(self) -> None:
        while self._rows.count():
            item = self._rows.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
        window = self._window
        if not window.project:
            self._summary.setText("Create or open a project to start the guided build journey.")
            return
        level = window.mode_combo.currentData() or "beginner"
        report = build_journey(window.project, window._build_options(), level)
        done = sum(1 for item in report.items if item.status == "done")
        total = len(report.items)
        if report.current is not None:
            head = f"{report.current.step.title} — {report.current.next_action}"
        elif report.complete:
            head = f"Build journey complete for {level}."
        else:
            head = f"Build journey [{level}]"
        self._summary.setText(f"{_progress_bar(done, total)}\n{head}")
        for index, item in enumerate(report.items, start=1):
            self._rows.addWidget(_StepRow(window, item, index))


def build_journey_spine(window) -> QWidget:
    window.journey_spine = JourneySpine(window)
    return window.journey_spine
