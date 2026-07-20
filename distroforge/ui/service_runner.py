from __future__ import annotations

import threading

from distroforge.ui.qt import QTimer


class ServiceRunnerMixin:
    """Non-blocking service call infrastructure for the main window.

    Runs heavy service functions off the Qt main thread and dispatches
    results back via a polling QTimer so the GUI stays responsive.
    """

    def _init_service_runner(self) -> None:
        self._service_workers: list[tuple[threading.Thread, list, list, object, str]] = []
        self._service_timer = QTimer(self)  # type: ignore[arg-type]
        self._service_timer.setInterval(150)
        self._service_timer.timeout.connect(self._poll_service_workers)
        self._service_timer.start()

    def _run_in_worker(self, fn, on_done, label: str = "Working…") -> None:
        if any(
            worker_label == label and thread.is_alive()
            for thread, _, _, _, worker_label in self._service_workers
        ):
            self.statusBar().showMessage(f"{label} (already running)")  # type: ignore[attr-defined]
            return
        result_box: list = []
        error_box: list[Exception] = []

        def _run() -> None:
            try:
                result_box.append(fn())
            except Exception as exc:
                error_box.append(exc)

        t = threading.Thread(target=_run, daemon=True)
        self._service_workers.append((t, result_box, error_box, on_done, label))
        self.statusBar().showMessage(label)  # type: ignore[attr-defined]
        t.start()

    def _poll_service_workers(self) -> None:
        still_running = []
        finished_any = False
        for worker in self._service_workers:
            thread, result_box, error_box, on_done, label = worker
            if thread.is_alive():
                still_running.append(worker)
                continue
            finished_any = True
            try:
                if error_box:
                    self._error(str(error_box[0]))  # type: ignore[attr-defined]
                else:
                    on_done(result_box[0] if result_box else None)
            except Exception as exc:  # a callback must never kill the poll timer
                self._error(f"{label}: {exc}")  # type: ignore[attr-defined]
        self._service_workers = still_running
        if finished_any and not still_running:
            self.statusBar().showMessage("Ready", 2000)  # type: ignore[attr-defined]
