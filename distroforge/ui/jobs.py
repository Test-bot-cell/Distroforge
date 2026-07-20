from __future__ import annotations

import queue
import threading
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class JobEvent:
    kind: str
    message: str
    current: int | None = None
    total: int | None = None
    phase: str | None = None
    title: str | None = None
    fraction: float | None = None


class JobEmitter:
    def __init__(self, events: queue.Queue[JobEvent]) -> None:
        self._events = events

    def __call__(self, message: str) -> None:
        self._events.put(JobEvent("log", message))

    def progress(
        self,
        current: int,
        total: int,
        phase: str,
        title: str,
        detail: str,
        fraction: float | None = None,
    ) -> None:
        self._events.put(
            JobEvent(
                "progress",
                detail,
                current=current,
                total=total,
                phase=phase,
                title=title,
                fraction=fraction,
            )
        )

    def journey(self, message: str) -> None:
        self._events.put(JobEvent("journey", message))


class GuiJob:
    def __init__(self, target: Callable[[JobEmitter], None]) -> None:
        self._target = target
        self._events: queue.Queue[JobEvent] = queue.Queue()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._cancel_requested = False

    @property
    def running(self) -> bool:
        return self._thread.is_alive()

    @property
    def cancel_requested(self) -> bool:
        return self._cancel_requested

    def start(self) -> None:
        self._thread.start()

    def cancel(self) -> None:
        self._cancel_requested = True
        self._events.put(JobEvent("cancel", "Cancel requested; current system command may finish first."))

    def poll(self) -> list[JobEvent]:
        events: list[JobEvent] = []
        while True:
            try:
                events.append(self._events.get_nowait())
            except queue.Empty:
                return events

    def _run(self) -> None:
        try:
            self._target(JobEmitter(self._events))
        except Exception as exc:
            self._events.put(JobEvent("error", str(exc)))
            return
        self._events.put(JobEvent("done", "Job finished."))
