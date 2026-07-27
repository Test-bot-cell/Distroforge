"""Runtime proof of the velocity pillar on the artifact surfaces.

Pillar 4 (``docs/velocity-responsiveness.md``) forbids avoidable freezes: heavy
work runs off the UI thread, and the per-refresh path does no blocking I/O. These
are offscreen construction probes (no ``show()``, which hangs under the offscreen
platform) that watch the real seam -- ``_run_in_worker`` -- carry the work to
another thread, and count how many times a refresh re-reads the finished ISO.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
import threading
import time
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("XDG_CONFIG_HOME", tempfile.mkdtemp())

from distroforge.core.artifact_paths import default_artifact_paths  # noqa: E402
from distroforge.core.project import Project  # noqa: E402
from distroforge.ui.qt import QApplication  # noqa: E402


@pytest.fixture(scope="module")
def qt_app():
    return QApplication.instance() or QApplication([])


def _built_project(root: Path) -> tuple[Project, Path]:
    """A project whose default artifact paths hold a built ISO plus its SHA256SUMS."""
    project = Project.create("OffThread", root, "26.04")
    project.source_mode = "bootstrap"
    iso = default_artifact_paths(project).output_iso
    iso.parent.mkdir(parents=True, exist_ok=True)
    iso.write_bytes(b"iso-payload" * 4096)
    digest = hashlib.sha256(iso.read_bytes()).hexdigest()
    (iso.parent / "SHA256SUMS").write_text(f"{digest}  {iso.name}\n", encoding="utf-8")
    return project, iso


def _count_iso_reads(iso: Path, work) -> int:
    """Run ``work`` and count how many times ``iso`` is opened for reading bytes."""
    reads = []
    real_open = Path.open

    def spy(self, mode="r", *args, **kwargs):
        if "b" in mode and self == iso:
            reads.append(self)
        return real_open(self, mode, *args, **kwargs)

    Path.open = spy
    try:
        work()
    finally:
        Path.open = real_open
    return len(reads)


def _drain_workers(window, timeout: float = 15.0) -> None:
    """Join every service worker and dispatch its result, as the poll timer would."""
    deadline = time.monotonic() + timeout
    while window._service_workers and time.monotonic() < deadline:
        for worker in list(window._service_workers):
            worker[0].join(0.05)
        window._poll_service_workers()
    assert not window._service_workers, "a service worker never finished"


class _Report:
    """Stands in for whichever report the stubbed service would have returned."""

    status = "ready"
    # The boot proof report names the firmware it ran, and the Artifacts controller
    # repeats that word in its log line, so the stub has to carry it too.
    firmware_summary = "bios"

    def render_text(self, verbose: bool = False) -> str:
        return "stub report"

    def render_fix_plan_text(self) -> str:
        return "stub fix plan"

    def render_summary(self) -> str:
        return "stub summary"

    def render_yaml(self) -> str:
        return "stub: yaml\n"

    def counts(self) -> dict[str, int]:
        return {"ready": 1, "review": 0, "blocked": 0, "invalid": 0}


def _thread_recorder(seen: list[int]):
    def _record(*_args, **_kwargs):
        seen.append(threading.get_ident())
        return _Report()

    return _record


def _window(tmp_path) -> tuple[object, Project, Path]:
    from distroforge.ui.main_window import MainWindow

    window = MainWindow()
    project, iso = _built_project(tmp_path / "project")
    window.project = project
    window.artifacts_output_iso_edit.setText(str(iso))
    window.artifacts_reports_dir_edit.setText(str(iso.parent))
    return window, project, iso


@pytest.mark.parametrize(
    ("module", "attribute", "action"),
    [
        # I9: the Artifacts evidence/gate/readiness/bundle family.
        ("distroforge.ui.artifacts_actions", "EvidenceStatusService", "run_evidence_status_action"),
        # I11: the installed-system capture scan (apt-mark, systemctl, config trees).
        ("distroforge.ui.capture_actions", "InstalledSystemCaptureService", "run_capture_scan_action"),
    ],
)
def test_service_backed_actions_leave_the_qt_thread(qt_app, tmp_path, monkeypatch, module, attribute, action) -> None:
    import importlib

    target = importlib.import_module(module)
    window, _project, _iso = _window(tmp_path)
    seen: list[int] = []
    monkeypatch.setattr(target, attribute, lambda: type("S", (), {
        "check": staticmethod(_thread_recorder(seen)),
        "capture": staticmethod(_thread_recorder(seen)),
    })())

    getattr(target, action)(window)
    _drain_workers(window)

    assert seen, f"{action} never reached the service"
    assert threading.get_ident() not in seen  # it ran on a worker, not the Qt thread


@pytest.mark.parametrize(
    ("module", "attribute", "action"),
    [
        # I19: a real QEMU boot, bounded only by the prebuild-vm timeout.
        ("distroforge.core.boot_proof", "run_boot_proof", "boot_proof_from_artifacts"),
        # I19: acceptance hashes the finished ISO end to end.
        ("distroforge.core.iso_acceptance", "accept_iso", "run_iso_accept_from_build"),
    ],
)
def test_long_running_artifact_actions_leave_the_qt_thread(qt_app, tmp_path, monkeypatch, module, attribute, action) -> None:
    import importlib

    from distroforge.ui import artifacts_page, build_page

    core = importlib.import_module(module)
    window, _project, _iso = _window(tmp_path)
    seen: list[int] = []
    monkeypatch.setattr(core, attribute, _thread_recorder(seen))

    slot = getattr(artifacts_page, action, None) or getattr(build_page, action)
    slot(window)
    _drain_workers(window)

    assert seen, f"{action} never reached the service"
    assert threading.get_ident() not in seen


def test_the_gui_boot_proof_runs_the_firmware_the_lab_selected(qt_app, tmp_path, monkeypatch) -> None:
    """The Artifacts button has no firmware control of its own, on purpose.

    The Virtualization Lab combo is the one place that answers "which firmware", for
    the prebuild VM and for this proof alike -- two widgets writing one field is how
    OVMF_CODE.fd came to be hardcoded in nine places. That only holds if the choice
    really travels, so this asserts the travelling rather than the wiring.
    """
    from distroforge.core import boot_proof as core_boot_proof
    from distroforge.ui import artifacts_page

    window, _project, _iso = _window(tmp_path)
    combo = window.prebuild_vm_firmware_combo
    combo.setCurrentIndex(combo.findData("uefi"))
    window.prebuild_vm_secure_boot_check.setChecked(True)
    asked: list[object] = []

    def _capture(_project, options=None, **_kwargs):
        asked.append(options)
        return _Report()

    monkeypatch.setattr(core_boot_proof, "run_boot_proof", _capture)
    artifacts_page.boot_proof_from_artifacts(window)
    _drain_workers(window)

    assert asked, "the Artifacts boot proof never reached the service"
    assert asked[0].prebuild_vm.firmware == "uefi"
    assert asked[0].prebuild_vm.secure_boot is True


def test_refresh_reads_the_finished_iso_at_most_once(qt_app, tmp_path) -> None:
    """B8: the spine, the command center and the Start cards are three views of one
    journey report. Computing it once -- and answering the publish-gate status from
    the SHA256SUMS sidecar -- keeps a maintainer-level refresh off the ISO."""
    window, _project, iso = _window(tmp_path)
    for index in range(window.mode_combo.count()):
        if window.mode_combo.itemData(index) == "maintainer":
            window.mode_combo.setCurrentIndex(index)
            break
    assert window.mode_combo.currentData() == "maintainer"

    # tmp_path is unique per test, so no digest for this ISO can be cached yet.
    first = _count_iso_reads(iso, window._refresh)
    # The per-step card check is still the authoritative hashing one, so a cold
    # refresh may read the ISO once; it must never read it once per view.
    assert first <= 1
    # An unchanged artifact is never re-read on any later refresh.
    assert _count_iso_reads(iso, window._refresh) == 0
