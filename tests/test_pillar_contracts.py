"""Phrase-lock and structural guards for the two newest founding pillar
contracts: UX cognitive-ergonomics and velocity/responsiveness.

These contracts are inviolable `.md` documents. The tests below keep them from
being silently deleted or watered down (phrase locks), keep them shipped with
the Debian package (lockstep with the CLI/GUI-parity and Debian-policy pillars),
and back the velocity pillar with structural teeth that prove heavy work runs
off the UI thread and that the per-frame refresh paths do no blocking I/O.
"""

from __future__ import annotations

import ast
import hashlib
import os
import threading
import time
from pathlib import Path

from distroforge.core.packaging import IMPORTANT_DOCS

ROOT = Path(__file__).resolve().parents[1]

UX_DOC = "docs/ux-cognitive-ergonomics.md"
VELOCITY_DOC = "docs/velocity-responsiveness.md"


def _normalized(path: str) -> str:
    """Lower-cased, whitespace-collapsed text so phrase asserts survive wrapping."""
    return " ".join((ROOT / path).read_text(encoding="utf-8").lower().split())


# --- Pillar 2: UX cognitive-ergonomics -------------------------------------


def test_ux_cognitive_ergonomics_contract_is_inviolable_and_grounded() -> None:
    text = _normalized(UX_DOC)
    # The pillar declares itself non-negotiable in the contract's own voice.
    assert "ux cognitive-ergonomics is non-negotiable" in text
    # The cognitive-science invariants must be named verbatim so they are testable.
    for phrase in (
        "progressive disclosure",
        "recognition over recall",
        "level-independent escape hatch",
        "no control is ever clipped",
        "one guided journey",
        "teach by showing state",
        "never forced on a beginner",
    ):
        assert phrase in text, phrase
    # The invariants must be argued from recognized works, not taste.
    for work in ("hick", "nielsen", "miller", "norman", "cognitive load"):
        assert work in text, work


# --- Pillar 4: velocity / responsiveness -----------------------------------


def test_velocity_contract_is_inviolable_and_structural() -> None:
    text = _normalized(VELOCITY_DOC)
    assert "velocity and responsiveness are non-negotiable" in text
    for phrase in (
        "no avoidable latency, lag, or freeze",
        "modulo the inherent",
        "responsiveness during long work, not making long work instant",
        "heavy work runs off the ui thread",
        "no blocking i/o on the per-frame path",
        "guijob",
        "cooperative cancel",
        "weighted progress",
        "generous",
    ):
        assert phrase in text, phrase


def test_guijob_runs_heavy_work_off_the_calling_thread() -> None:
    """Pillar 4 teeth: GuiJob must execute its target on a thread other than the
    caller (the UI thread) and report completion back through its event queue."""
    from distroforge.ui.jobs import GuiJob

    caller_thread = threading.get_ident()
    worker: dict[str, int] = {}
    ran = threading.Event()

    def target(emit) -> None:
        worker["thread"] = threading.get_ident()
        emit("heavy step")
        emit.progress(1, 1, "phase", "Title", "detail", fraction=1.0)
        ran.set()

    job = GuiJob(target)
    assert not job.running  # nothing runs until start()
    job.start()
    assert ran.wait(timeout=5.0), "GuiJob target never ran"

    kinds: list[str] = []
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        kinds.extend(event.kind for event in job.poll())
        if "done" in kinds:
            break
        time.sleep(0.005)

    assert worker["thread"] != caller_thread  # off the UI/calling thread
    assert "done" in kinds  # completion reported back for the UI thread to drain
    assert "log" in kinds and "progress" in kinds


def test_heavy_gui_controllers_dispatch_through_guijob() -> None:
    """The interactive controllers that launch long work must route it through
    GuiJob rather than blocking the event loop inline."""
    for module in (
        "distroforge/ui/command_center_page.py",
        "distroforge/ui/build_controller.py",
    ):
        source = (ROOT / module).read_text(encoding="utf-8")
        assert "GuiJob" in source, module


def test_per_frame_refresh_paths_have_no_blocking_io() -> None:
    """The hot paths drawn on every frame/refresh must not perform synchronous
    subprocess or blocking-build work; heavy work belongs on a GuiJob thread."""
    forbidden = ("subprocess", "check_call", "check_output", "Popen", "os.system")
    for module in (
        "distroforge/ui/journey_shell.py",
        "distroforge/ui/step_focus.py",
    ):
        source = (ROOT / module).read_text(encoding="utf-8")
        present = [token for token in forbidden if token in source]
        assert present == [], (module, present)


_HEAVY_OFF_THREAD_ACTIONS = {
    "distroforge/ui/artifacts_actions.py": (
        "run_release_readiness_action",
        "run_release_gate_action",
        "run_evidence_status_action",
        "create_publish_bundle_action",
    ),
    "distroforge/ui/capture_actions.py": (
        "run_capture_scan_action",
        "export_capture_profile_action",
    ),
    "distroforge/ui/artifacts_page.py": (
        "release_pipeline_from_artifacts",
        "boot_proof_from_artifacts",
    ),
    "distroforge/ui/build_page.py": ("run_iso_accept_from_build",),
}


def test_heavy_artifact_actions_dispatch_through_the_worker_seam() -> None:
    """Every slot that hashes, copies or boots an ISO must hand the work to the one
    concurrency seam the neighbouring modules already use, not run it in the click
    handler. Counting the offenders keeps a new heavy action from slipping back."""
    blocking = []
    for module, names in _HEAVY_OFF_THREAD_ACTIONS.items():
        tree = ast.parse((ROOT / module).read_text(encoding="utf-8"))
        functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
        for name in names:
            called = {
                node.func.attr
                for node in ast.walk(functions[name])
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            }
            if "_run_in_worker" not in called:
                blocking.append(f"{module}:{name}")
    assert blocking == []


def _iso_with_sidecar(root: Path) -> tuple[object, Path]:
    """A project whose default artifact paths hold a built ISO plus its SHA256SUMS."""
    from distroforge.core.artifact_paths import default_artifact_paths
    from distroforge.core.project import Project

    project = Project.create("PillarIso", root, "26.04")
    project.source_mode = "bootstrap"
    iso = default_artifact_paths(project).output_iso
    iso.parent.mkdir(parents=True, exist_ok=True)
    iso.write_bytes(b"iso-payload" * 4096)
    digest = hashlib.sha256(iso.read_bytes()).hexdigest()
    (iso.parent / "SHA256SUMS").write_text(f"{digest}  {iso.name}\n", encoding="utf-8")
    return project, iso


def count_iso_reads(iso: Path, work) -> int:
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


def test_journey_status_never_hashes_the_iso(tmp_path) -> None:
    """Pillar 4 teeth: the guided journey is recomputed on every refresh, so its
    publish-gate status answers from the SHA256SUMS sidecar. The full gate -- which
    reads the ISO twice -- belongs to the on-demand per-step check."""
    from distroforge.core.build import BuildOptions
    from distroforge.core.build_journey import build_journey

    project, iso = _iso_with_sidecar(tmp_path / "journey")
    options = BuildOptions()
    assert count_iso_reads(iso, lambda: build_journey(project, options, "maintainer")) == 0
    # The step panel's check is still the authoritative, hashing one.
    from distroforge.core.build_journey import check_journey_step

    assert count_iso_reads(iso, lambda: check_journey_step(project, options, "publish-gate")) >= 1


def test_evidence_status_never_reuses_a_digest_across_verdicts(tmp_path) -> None:
    """The security interlock recomputes every digest until a gate-scoped file
    descriptor can provide safe reuse without trusting mutable path metadata."""
    from distroforge.core.build import BuildOptions
    from distroforge.core.evidence import EvidenceStatusService

    project, iso = _iso_with_sidecar(tmp_path / "evidence")
    reads = count_iso_reads(
        iso,
        lambda: EvidenceStatusService().check(
            project, BuildOptions(), iso=iso, output_dir=iso.parent
        ),
    )
    assert reads == 3


def test_same_size_same_mtime_replacement_cannot_reuse_a_digest(tmp_path) -> None:
    """A path cache must not hide an atomic inode replacement whose cheap stat
    metadata has deliberately been restored."""
    from distroforge.core.hashing import sha256_file

    iso = tmp_path / "artifact.iso"
    iso.write_bytes(b"first-bytes")
    original = iso.stat()
    first = sha256_file(iso)

    replacement = tmp_path / "replacement.iso"
    replacement.write_bytes(b"other-bytes")
    os.utime(replacement, ns=(original.st_atime_ns, original.st_mtime_ns))
    os.replace(replacement, iso)

    current = iso.stat()
    assert current.st_size == original.st_size
    assert current.st_mtime_ns == original.st_mtime_ns
    assert current.st_ino != original.st_ino
    assert sha256_file(iso) == hashlib.sha256(b"other-bytes").hexdigest() != first


# --- Pillar 3 lockstep: the contract docs ship -----------------------------


def test_new_pillar_docs_ship_with_the_package() -> None:
    declared = {
        line.strip()
        for line in (ROOT / "debian/docs").read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    for doc in (UX_DOC, VELOCITY_DOC):
        assert (ROOT / doc).exists(), doc
        assert doc in declared, doc  # listed in the Debian install manifest
        assert doc in IMPORTANT_DOCS, doc  # guarded by the packaging policy report


def test_each_pillar_doc_cross_references_the_other_three() -> None:
    """A pillar doc that forgets the others lets the four-pillar contract drift."""
    ux = _normalized(UX_DOC)
    velocity = _normalized(VELOCITY_DOC)
    architecture = "docs/distroforge-platform-architecture.md"
    assert all(ref in ux for ref in ("gui-parity.md", "debian-canonical-compliance.md", VELOCITY_DOC, architecture))
    assert all(ref in velocity for ref in ("gui-parity.md", "debian-canonical-compliance.md", UX_DOC, architecture))
