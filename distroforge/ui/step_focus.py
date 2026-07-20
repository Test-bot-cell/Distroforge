"""Focused step header shown at the top of each journey step's surface.

Cognitive-science redesign: a step surface used to drop the user straight into a
dense wall of controls with no statement of *what* the step is or *why* it
matters. This banner restores information scent (title + purpose + live status)
and offers the single primary action -- apply a sensible default -- plus a check,
so the controls below read as that step's details rather than an undifferentiated
menu. Every string and check comes from ``core.build_journey`` so the GUI never
diverges from ``distroforge journey`` / ``distroforge readiness``.
"""

from __future__ import annotations

from distroforge.core.build_journey import JOURNEY_STEPS, check_journey_step
from distroforge.ui.command_center_page import apply_journey_step_id, check_journey_step_id
from distroforge.ui.qt import (
    QFrame,
    QLabel,
    QSizePolicy,
    Qt,
    QVBoxLayout,
    QWidget,
)
from distroforge.ui.widgets import ElidingLabel, button, responsive_row

_STEPS = {step.step_id: step for step in JOURNEY_STEPS}


class StepFocusHeader(QFrame):
    """A focused banner for one journey step: what, why, live status, one action."""

    def __init__(self, window, step_id: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._window = window
        self._step = _STEPS[step_id]
        self._default_step_id = step_id
        self.setObjectName("StepFocus")
        self.setProperty("focusStatus", "neutral")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 13, 16, 14)
        layout.setSpacing(6)

        self._eyebrow = ElidingLabel(self._eyebrow_text())
        self._eyebrow.setObjectName("StepFocusEyebrow")
        self._eyebrow.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        self._title = ElidingLabel(self._step.title)
        self._title.setObjectName("StepFocusTitle")
        self._title.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        self._why = QLabel(self._step.purpose)
        self._why.setObjectName("StepFocusWhy")
        self._why.setWordWrap(True)
        self._status = QLabel(f"Goal: {self._step.done_when}")
        self._status.setObjectName("StepFocusStatus")
        self._status.setWordWrap(True)
        actions = responsive_row(
            button("Apply this step", self._apply, "start", primary=True),
            button("Check", self._check, "audit"),
            breakpoint=420,
        )
        layout.addWidget(self._eyebrow)
        layout.addWidget(self._title)
        layout.addWidget(self._why)
        layout.addWidget(self._status)
        layout.addWidget(actions)

        if hasattr(window, "_step_focus_headers"):
            window._step_focus_headers.append(self)

    def _eyebrow_text(self) -> str:
        return f"Guided step · {self._step.level.replace('-', ' ')}"

    def _apply(self) -> None:
        # apply_journey_step_id already calls window._refresh(), which refreshes
        # this header in turn, so the status line reflects the applied change.
        apply_journey_step_id(self._window, self._step.step_id)

    def _check(self) -> None:
        check_journey_step_id(self._window, self._step.step_id)
        self.refresh()

    def refresh(self) -> None:
        project = getattr(self._window, "project", None)
        if not project:
            self._set_status("neutral", f"Goal: {self._step.done_when}")
            return
        check = check_journey_step(project, self._window._build_options(), self._step.step_id)
        finding = check.findings[0] if check.findings else self._step.done_when
        self._set_status(check.status, f"{check.status.upper()}: {finding}")

    def _set_status(self, status: str, text: str) -> None:
        self._status.setText(text)
        self.setProperty("focusStatus", status)
        self.style().unpolish(self)
        self.style().polish(self)

    def set_step(self, step_id: str) -> None:
        """Retarget this banner to another journey step.

        Several maintainer steps share one heavy backing surface (rollback rides
        on Build & Release, publish-gate on Artifacts). Rather than stack a second
        banner -- an undifferentiated wall -- the surface keeps one focused header
        that reflects whichever step the journey routed to, preserving information
        scent. Plain navigation restores the surface's canonical step.
        """
        if step_id not in _STEPS or step_id == self._step.step_id:
            return
        self._step = _STEPS[step_id]
        self._eyebrow.setText(self._eyebrow_text())
        self._title.setText(self._step.title)
        self._why.setText(self._step.purpose)
        self.refresh()

    def reset_step(self) -> None:
        self.set_step(self._default_step_id)
