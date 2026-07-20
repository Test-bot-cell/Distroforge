from __future__ import annotations

from distroforge.core.build_journey import BuildJourneyItem, build_journey, check_journey_step
from distroforge.ui.command_center_page import (
    apply_journey_step_id,
    check_journey_step_id,
    create_publish_bundle_from_start,
    execute_beginner_iso_from_start,
    open_journey_target,
    prepare_beginner_iso_from_start,
    prepare_poweruser_iso_from_start,
    repair_beginner_release_artifacts_from_start,
    run_beginner_boot_proof_from_start,
)
from distroforge.ui.qt import QFrame, QGridLayout, QLabel, QSizePolicy, QVBoxLayout, QWidget
from distroforge.ui.widgets import button, button_group, responsive_row


def build_start_journey_panel(window) -> QWidget:
    panel = QWidget()
    layout = QVBoxLayout(panel)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(10)
    window.start_journey_status_label = QLabel("Create or open a project to start the guided build journey.")
    window.start_journey_status_label.setWordWrap(True)
    current_step = button_group(
        "Current step",
        button("Open current step", window._open_current_journey_step, "open"),
        button("Apply current step", window._apply_current_journey_step, "start", primary=True),
    )
    prepare = button_group(
        "Prepare ISO",
        button("Prepare beginner ISO path", lambda: prepare_beginner_iso_from_start(window), "disc"),
        button("Prepare power user ISO path", lambda: prepare_poweruser_iso_from_start(window), "disc"),
        button("Build beginner ISO", lambda: execute_beginner_iso_from_start(window), "disc"),
    )
    release = button_group(
        "Release and verify",
        button("Repair release artifacts", lambda: repair_beginner_release_artifacts_from_start(window), "audit"),
        button("Run boot proof", lambda: run_beginner_boot_proof_from_start(window), "audit"),
        button("Publish bundle", lambda: create_publish_bundle_from_start(window), "save"),
        button("Run readiness", window._run_readiness, "audit"),
    )
    window.start_journey_cards = JourneyCardsGrid(window)
    layout.addWidget(window.start_journey_status_label)
    layout.addWidget(current_step)
    layout.addWidget(prepare)
    layout.addWidget(release)
    layout.addWidget(window.start_journey_cards, 1)
    return panel


def refresh_start_journey_cards(window) -> None:
    if not hasattr(window, "start_journey_cards"):
        return
    if not window.project:
        window.start_journey_status_label.setText("Create or open a project to start the guided build journey.")
        window.start_journey_cards.set_items(())
        return
    level = window.mode_combo.currentData() or "beginner"
    report = build_journey(window.project, window._build_options(), level)
    if report.current:
        window.start_journey_status_label.setText(
            f"Current step: {report.current.step.title} - {report.current.next_action}"
        )
    else:
        window.start_journey_status_label.setText(f"Build journey complete for {level}.")
    window.start_journey_cards.set_items(report.items)


class JourneyCardsGrid(QWidget):
    def __init__(self, window, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._window = window
        self._items: tuple[BuildJourneyItem, ...] = ()
        self._cards: list[QWidget] = []
        self._compact: bool | None = None
        self._grid = QGridLayout(self)
        self._grid.setContentsMargins(0, 0, 0, 0)
        self._grid.setSpacing(10)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

    def set_items(self, items: tuple[BuildJourneyItem, ...]) -> None:
        self._items = items
        self._cards = [_journey_card(self._window, item) for item in items]
        self._reflow(force=True)

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self._reflow()

    def _reflow(self, force: bool = False) -> None:
        compact = self.width() < 980
        if not force and compact == self._compact:
            return
        self._compact = compact
        while self._grid.count():
            item = self._grid.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
        columns = 1 if compact else 2
        for index, card in enumerate(self._cards):
            self._grid.addWidget(card, index // columns, index % columns)
        for column in range(2):
            self._grid.setColumnStretch(column, 1 if column < columns else 0)


def _journey_card(window, item: BuildJourneyItem) -> QFrame:
    card = QFrame()
    card.setObjectName("JourneyCard")
    card.setProperty("journeyStatus", item.status)
    card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
    layout = QVBoxLayout(card)
    layout.setContentsMargins(12, 10, 12, 12)
    layout.setSpacing(7)
    title = QLabel(f"{item.step.title} [{item.step.level}]")
    title.setObjectName("JourneyCardTitle")
    title.setWordWrap(True)
    status = QLabel(item.status.upper())
    status.setObjectName("JourneyCardStatus")
    check = check_journey_step(window.project, window._build_options(), item.step.step_id)
    check_label = QLabel(f"{check.status.upper()}: {check.findings[0] if check.findings else 'No findings'}")
    check_label.setObjectName("JourneyCardCheck")
    check_label.setWordWrap(True)
    goal = QLabel(item.step.done_when)
    goal.setWordWrap(True)
    next_action = QLabel(item.next_action)
    next_action.setWordWrap(True)
    meta = QLabel(f"{item.step.gui_surface} | {item.step.command_hint}")
    meta.setObjectName("JourneyCardMeta")
    meta.setWordWrap(True)
    actions = responsive_row(
        button("Open", lambda: open_journey_target(window, item.step.action_id, item.step.step_id), "open"),
        button("Apply", lambda: apply_journey_step_id(window, item.step.step_id), "start"),
        button("Check", lambda: check_journey_step_id(window, item.step.step_id), "audit"),
        breakpoint=520,
    )
    layout.addWidget(status)
    layout.addWidget(title)
    layout.addWidget(goal)
    layout.addWidget(check_label)
    layout.addWidget(next_action)
    layout.addWidget(meta)
    layout.addWidget(actions)
    return card
