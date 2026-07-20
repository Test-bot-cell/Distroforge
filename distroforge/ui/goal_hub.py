"""Goal-oriented entry point: "What do you want to achieve?"

The journey spine answers *what is the next step*; the goal hub answers *I
already know the outcome I want*. Each product capability -- the single source
in ``core.workflows`` -- becomes a card that routes to the GUI surface backing
it, so a user can jump straight to an intent without walking the ordered spine.
Navigation is never level-gated: every goal stays reachable regardless of the
selected level, matching the level-independent escape hatch.
"""

from __future__ import annotations

from distroforge.core.workflows import PRODUCT_CAPABILITIES, WORKFLOW_LEVELS, ProductCapability
from distroforge.ui.qt import QFrame, QGridLayout, QLabel, QSizePolicy, QVBoxLayout, QWidget
from distroforge.ui.widgets import ElidingLabel, button

_LEVEL_LABEL = {level.key: level.label for level in WORKFLOW_LEVELS}


class GoalHubGrid(QWidget):
    """A reflowing 1/2-column grid of static product-capability goal cards."""

    def __init__(self, window, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._window = window
        self._cards = [_goal_card(window, capability) for capability in PRODUCT_CAPABILITIES]
        self._compact: bool | None = None
        self._grid = QGridLayout(self)
        self._grid.setContentsMargins(0, 0, 0, 0)
        self._grid.setSpacing(10)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self._reflow(force=True)

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self._reflow()

    def _reflow(self, force: bool = False) -> None:
        compact = self.width() < 760
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


def _goal_card(window, capability: ProductCapability) -> QFrame:
    card = QFrame()
    card.setObjectName("GoalCard")
    card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
    layout = QVBoxLayout(card)
    layout.setContentsMargins(12, 10, 12, 12)
    layout.setSpacing(6)
    level = QLabel(_LEVEL_LABEL.get(capability.level, capability.level))
    level.setObjectName("GroupLabel")
    title = ElidingLabel(capability.label)
    title.setObjectName("JourneyCardTitle")
    title.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
    workflow = QLabel(capability.workflow)
    workflow.setWordWrap(True)
    when = QLabel(f"Useful when: {capability.when_useful}")
    when.setObjectName("JourneyCardMeta")
    when.setWordWrap(True)
    # CLI equivalents stay visible for parity, but as a muted reference line --
    # never a prompt pushed at a beginner.
    commands = QLabel("CLI: " + " · ".join(capability.commands))
    commands.setObjectName("JourneyCardMeta")
    commands.setWordWrap(True)
    # A zero-arg slot: QPushButton.clicked emits a `checked` bool, and PyQt fills
    # any positional the slot will accept -- so a `surface=...` default would bind
    # to that bool, not the capability. `capability` is this call's own parameter,
    # so the bare closure captures the right surface without a default.
    open_button = button(
        "Open",
        lambda: window._open_surface(capability.gui_surface),
        "open",
    )
    layout.addWidget(level)
    layout.addWidget(title)
    layout.addWidget(workflow)
    layout.addWidget(when)
    layout.addWidget(commands)
    layout.addWidget(open_button)
    return card


def build_goal_hub(window) -> QWidget:
    return GoalHubGrid(window)
