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
import threading
import time
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

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


def _iso_measurements(iso: Path, work) -> tuple[int, set[int]]:
    """Count ISO passes and owning descriptor-backed verdict sessions."""
    from distroforge.core.artifact_verification import ArtifactVerificationSession

    sessions: list[ArtifactVerificationSession] = []
    real_measure = ArtifactVerificationSession._measure

    def spy(self, record, binding, **kwargs):
        if self.anchor_path / binding.relative == iso.absolute():
            # Keep every owner alive until the assertion: otherwise a later
            # verdict may reuse the address of an already-collected session.
            sessions.append(self)
        return real_measure(self, record, binding, **kwargs)

    ArtifactVerificationSession._measure = spy
    try:
        work()
    finally:
        ArtifactVerificationSession._measure = real_measure
    return len(sessions), {id(session) for session in sessions}


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
    verdict = "ready"
    build_run_id = None
    boot_run_id = None
    run_id = None
    pipeline = None
    gate = None
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


@pytest.mark.parametrize(
    ("module", "attribute", "action", "fingerprint_argument"),
    (
        (
            "distroforge.core.release_signing",
            "sign_release_bundle",
            "sign_release_from_artifacts",
            "gpg_key",
        ),
        (
            "distroforge.core.release_verification",
            "verify_release_bundle",
            "verify_release_from_artifacts",
            "expected_signer_fingerprint",
        ),
        (
            "distroforge.core.publish_drill_baseline",
            "promote_publish_drill_baseline",
            "promote_drill_from_artifacts",
            "expected_signer_fingerprint",
        ),
    ),
)
def test_release_contract_gui_actions_propagate_custom_product_and_pin(
    qt_app,
    tmp_path,
    monkeypatch,
    module: str,
    attribute: str,
    action: str,
    fingerprint_argument: str,
) -> None:
    import importlib

    from distroforge.ui import artifacts_page

    core = importlib.import_module(module)
    window, project, _default_iso = _window(tmp_path)
    custom_iso = tmp_path / "custom-output" / "Custom.iso"
    custom_reports = tmp_path / "release-records" / "reports"
    fingerprint = "A" * 40
    window.artifacts_output_iso_edit.setText(str(custom_iso))
    window.artifacts_reports_dir_edit.setText(str(custom_reports))
    window.artifact_gpg_key_edit.setText(fingerprint)
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def capture(*args, **kwargs):
        calls.append((args, kwargs))
        return _Report()

    monkeypatch.setattr(core, attribute, capture)

    getattr(artifacts_page, action)(window)
    _drain_workers(window)

    assert len(calls) == 1
    args, kwargs = calls[0]
    assert args[0] is project
    assert kwargs["bundle_dir"] == custom_reports.parent / "publish"
    assert kwargs["expected_product_iso"] == custom_iso
    assert kwargs["expected_product_output_dir"] == custom_iso.parent
    assert kwargs[fingerprint_argument] == fingerprint


def test_explain_release_gui_propagates_custom_product_bundle_and_pin(
    qt_app,
    tmp_path,
    monkeypatch,
) -> None:
    from distroforge.core import release_explain
    from distroforge.ui import artifacts_page

    window, project, _default_iso = _window(tmp_path)
    custom_iso = tmp_path / "custom-output" / "Custom.iso"
    custom_reports = tmp_path / "release-records" / "reports"
    fingerprint = "B" * 40
    window.artifacts_output_iso_edit.setText(str(custom_iso))
    window.artifacts_reports_dir_edit.setText(str(custom_reports))
    window.artifact_gpg_key_edit.setText(fingerprint)
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def capture(*args, **kwargs):
        calls.append((args, kwargs))
        return _Report()

    monkeypatch.setattr(release_explain, "explain_release", capture)

    artifacts_page.explain_release_from_artifacts(window)
    _drain_workers(window)

    assert calls == [
        (
            (project,),
            {
                "iso": custom_iso,
                "bundle_dir": custom_reports.parent / "publish",
                "expected_signer_fingerprint": fingerprint,
            },
        )
    ]


@pytest.mark.parametrize(
    ("module", "attribute", "action", "contract"),
    (
        (
            "distroforge.core.release_signing",
            "sign_release_bundle",
            "sign_release_from_artifacts",
            "sign",
        ),
        (
            "distroforge.core.release_verification",
            "verify_release_bundle",
            "verify_release_from_artifacts",
            "verify",
        ),
        (
            "distroforge.core.release_explain",
            "explain_release",
            "explain_release_from_artifacts",
            "explain",
        ),
        (
            "distroforge.core.publish_drill",
            "run_publish_drill",
            "publish_drill_from_artifacts",
            "drill",
        ),
        (
            "distroforge.core.publish_drill_diff",
            "diff_publish_drills",
            "compare_drill_from_artifacts",
            "diff",
        ),
        (
            "distroforge.core.publish_drill_baseline",
            "promote_publish_drill_baseline",
            "promote_drill_from_artifacts",
            "baseline",
        ),
    ),
)
def test_release_gui_actions_run_offthread_with_frozen_contract(
    qt_app,
    tmp_path,
    monkeypatch,
    module: str,
    attribute: str,
    action: str,
    contract: str,
) -> None:
    import importlib

    from distroforge.ui import artifacts_page

    core = importlib.import_module(module)
    window, project, _default_iso = _window(tmp_path)
    custom_iso = tmp_path / "custom-output" / "Custom.iso"
    custom_reports = tmp_path / "release-records" / "reports"
    bundle_dir = custom_reports.parent / "publish"
    fingerprint = "C" * 40
    options = object()
    backend = str(window.boot_proof_backend_combo.currentData() or "auto")
    window.artifacts_output_iso_edit.setText(str(custom_iso))
    window.artifacts_reports_dir_edit.setText(str(custom_reports))
    window.artifact_gpg_key_edit.setText(fingerprint)
    monkeypatch.setattr(window, "_build_options", lambda: options)
    calls: list[
        tuple[int, tuple[object, ...], dict[str, object]]
    ] = []

    def capture(*args, **kwargs):
        calls.append((threading.get_ident(), args, kwargs))
        return _Report()

    monkeypatch.setattr(core, attribute, capture)

    getattr(artifacts_page, action)(window)
    _drain_workers(window)

    assert len(calls) == 1
    thread_id, args, kwargs = calls[0]
    assert thread_id != threading.get_ident()
    if contract == "sign":
        assert args == (project,)
        assert kwargs == {
            "bundle_dir": bundle_dir,
            "execute": False,
            "gpg_key": fingerprint,
            "expected_product_iso": custom_iso,
            "expected_product_output_dir": custom_iso.parent,
        }
    elif contract == "verify":
        assert args == (project,)
        assert kwargs == {
            "bundle_dir": bundle_dir,
            "expected_signer_fingerprint": fingerprint,
            "expected_product_iso": custom_iso,
            "expected_product_output_dir": custom_iso.parent,
        }
    elif contract == "explain":
        assert args == (project,)
        assert kwargs == {
            "iso": custom_iso,
            "bundle_dir": bundle_dir,
            "expected_signer_fingerprint": fingerprint,
        }
    elif contract == "drill":
        assert args == (project, options)
        assert kwargs == {
            "iso": custom_iso,
            "bundle_dir": bundle_dir,
            "gpg_key": fingerprint,
            "boot_backend": backend,
            "build_run_id": None,
            "boot_run_id": None,
        }
    elif contract == "diff":
        assert args == (
            bundle_dir / "PUBLISH-DRILL.previous.json",
            bundle_dir / "PUBLISH-DRILL.json",
        )
        assert kwargs == {}
    else:
        assert contract == "baseline"
        assert args == (project,)
        assert kwargs == {
            "bundle_dir": bundle_dir,
            "expected_signer_fingerprint": fingerprint,
            "expected_product_iso": custom_iso,
            "expected_product_output_dir": custom_iso.parent,
        }


def test_create_publish_bundle_gui_uses_one_release_path_contract(
    qt_app,
    tmp_path,
    monkeypatch,
) -> None:
    from distroforge.core import publish_bundle
    from distroforge.ui import artifacts_actions

    window, project, _default_iso = _window(tmp_path)
    custom_iso = tmp_path / "custom-output" / "Custom.iso"
    custom_reports = tmp_path / "release-records" / "reports"
    window.artifacts_output_iso_edit.setText(str(custom_iso))
    window.artifacts_reports_dir_edit.setText(str(custom_reports))
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def capture(*args, **kwargs):
        calls.append((args, kwargs))
        return _Report()

    monkeypatch.setattr(publish_bundle, "create_publish_bundle", capture)

    artifacts_actions.create_publish_bundle_action(window)
    _drain_workers(window)

    assert len(calls) == 1
    args, kwargs = calls[0]
    assert args[0] is project
    assert kwargs == {
        "iso": custom_iso,
        "output_dir": custom_iso.parent,
        "bundle_dir": custom_reports.parent / "publish",
        "build_run_id": None,
        "boot_run_id": None,
    }


def test_release_gate_gui_uses_the_selected_bundle(
    qt_app,
    tmp_path,
    monkeypatch,
) -> None:
    from distroforge.core import release_gate
    from distroforge.ui import artifacts_actions

    window, project, _default_iso = _window(tmp_path)
    custom_iso = tmp_path / "custom-output" / "Custom.iso"
    custom_reports = tmp_path / "release-records" / "reports"
    window.artifacts_output_iso_edit.setText(str(custom_iso))
    window.artifacts_reports_dir_edit.setText(str(custom_reports))
    calls: list[tuple[object, object, dict[str, object]]] = []

    def capture(_self, called_project, called_options, **kwargs):
        calls.append((called_project, called_options, kwargs))
        return _Report()

    monkeypatch.setattr(release_gate.ReleaseGateService, "check", capture)

    artifacts_actions.run_release_gate_action(window)
    _drain_workers(window)

    assert len(calls) == 1
    called_project, _called_options, kwargs = calls[0]
    assert called_project is project
    assert kwargs == {
        "iso": custom_iso,
        "output_dir": custom_iso.parent,
        "bundle_dir": custom_reports.parent / "publish",
        "build_run_id": None,
        "boot_run_id": None,
    }


@pytest.mark.parametrize(
    ("action", "method"),
    (
        ("forgeadvisor_explain_evidence_action", "explain_evidence"),
        ("forgeadvisor_fix_plan_action", "narrate_fix_plan"),
        ("forgeadvisor_copilot_action", "maintainer_copilot"),
    ),
)
def test_publish_advisor_uses_product_parent_not_reports_dir(
    qt_app,
    tmp_path,
    monkeypatch,
    action: str,
    method: str,
) -> None:
    from distroforge.ai import backend as backend_module
    from distroforge.ai import forgeadvisor as forgeadvisor_module
    from distroforge.core import build_memory as build_memory_module
    from distroforge.ui import advisor_actions

    window, _project, _default_iso = _window(tmp_path)
    custom_iso = tmp_path / "custom-output" / "Custom.iso"
    custom_reports = tmp_path / "release-records" / "reports"
    window.artifacts_output_iso_edit.setText(str(custom_iso))
    window.artifacts_reports_dir_edit.setText(str(custom_reports))
    calls: list[tuple[str, dict[str, object]]] = []

    class _Advisor:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def explain_evidence(self, *_args, **kwargs):
            calls.append(("explain_evidence", kwargs))
            return _Report()

        def narrate_fix_plan(self, *_args, **kwargs):
            calls.append(("narrate_fix_plan", kwargs))
            return _Report()

        def maintainer_copilot(self, *_args, **kwargs):
            calls.append(("maintainer_copilot", kwargs))
            return _Report()

    monkeypatch.setattr(backend_module, "select_backend", lambda *_args: object())
    monkeypatch.setattr(forgeadvisor_module, "ForgeAdvisor", _Advisor)
    monkeypatch.setattr(build_memory_module, "BuildMemory", lambda *_args: object())
    monkeypatch.setattr(
        build_memory_module,
        "default_corpus_path",
        lambda: tmp_path / "unused-corpus.json",
    )

    getattr(advisor_actions, action)(window)
    _drain_workers(window)

    assert len(calls) == 1
    called_method, kwargs = calls[0]
    assert called_method == method
    assert kwargs["iso"] == custom_iso
    assert kwargs["output_dir"] == custom_iso.parent
    assert kwargs["profile"] == "publish"


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


def test_refresh_rehashes_each_verdict_until_scoped_reuse_exists(qt_app, tmp_path) -> None:
    """Each refresh owns one session: one measurement plus one closing recheck."""
    window, _project, iso = _window(tmp_path)
    for index in range(window.mode_combo.count()):
        if window.mode_combo.itemData(index) == "maintainer":
            window.mode_combo.setCurrentIndex(index)
            break
    assert window.mode_combo.currentData() == "maintainer"

    first_passes, first_sessions = _iso_measurements(iso, window._refresh)
    assert first_passes == 2
    assert len(first_sessions) == 1
    # No digest survives into the next independently computed verdict.
    second_passes, second_sessions = _iso_measurements(iso, window._refresh)
    assert second_passes == 2
    assert len(second_sessions) == 1
