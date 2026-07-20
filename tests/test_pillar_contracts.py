"""Phrase-lock and structural guards for the two newest founding pillar
contracts: UX cognitive-ergonomics and velocity/responsiveness.

These contracts are inviolable `.md` documents. The tests below keep them from
being silently deleted or watered down (phrase locks), keep them shipped with
the Debian package (lockstep with the CLI/GUI-parity and Debian-policy pillars),
and back the velocity pillar with structural teeth that prove heavy work runs
off the UI thread and that the per-frame refresh paths do no blocking I/O.
"""

from __future__ import annotations

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
