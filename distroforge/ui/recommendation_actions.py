from __future__ import annotations

from typing import Protocol

from distroforge.ui.qt import QWidget
from distroforge.ui.widgets import button, responsive_row


class RecommendationActionWindow(Protocol):
    def _open_surface(self, key: str) -> None: ...

    def _log(self, text: str) -> None: ...


RECOMMENDATION_TARGETS = {
    "open-source": "source",
    "open-packages": "packages",
    "open-virtualization-lab": "virtualization",
    "open-artifacts": "artifacts",
    "open-build-release": "build",
}


def build_recommendation_actions(window: RecommendationActionWindow) -> QWidget:
    return responsive_row(
        button("Open Source", lambda: open_recommendation_target(window, "open-source"), "open"),
        button("Open Packages", lambda: open_recommendation_target(window, "open-packages"), "open"),
        button("Open VM Lab", lambda: open_recommendation_target(window, "open-virtualization-lab"), "audit"),
        button("Open Build", lambda: open_recommendation_target(window, "open-build-release"), "start"),
        button("Open Artifacts", lambda: open_recommendation_target(window, "open-artifacts"), "save"),
        breakpoint=900,
    )


def open_recommendation_target(window: RecommendationActionWindow, action_id: str) -> None:
    target = RECOMMENDATION_TARGETS.get(action_id)
    if target is None:
        window._log(f"ERROR: Unknown recommendation target: {action_id}")
        return
    window._open_surface(target)
    window._log(f"Opened recommendation target: {action_id}")
