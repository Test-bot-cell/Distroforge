"""Inviolable teeth for the advisory-agent governance contract.

`docs/advisory-agent.md` elevates the platform invariant "AI is advisory" into a
tested, inviolable contract. These tests are that contract's teeth: they keep the
document shipped and un-watered-down (ship lockstep + phrase locks) and back its
four named guarantees with executable guards:

- **No silent mutation** — no agent code path reaches an engine mutation.
- **Offline degrade** — with no backend the agent still answers from the corpus.
- **Parity** — every agent capability has both a CLI verb and a GUI surface.
- **Single-source register** — registers derive only from the canonical levels.

The agent is *governed by the four founding pillars, not added as a fifth*; these
guards live alongside the pillar-contract guards in `test_pillar_contracts.py`.
"""

from __future__ import annotations

import argparse
import os
import tempfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("XDG_CONFIG_HOME", tempfile.mkdtemp())

from distroforge.ai.backend import AdvisorContext, OfflineBackend, select_backend  # noqa: E402
from distroforge.ai.proposals import PREVIEW_ONLY_STATUS  # noqa: E402
from distroforge.ai.registers import register_keys  # noqa: E402
from distroforge.cli import build_parser  # noqa: E402
from distroforge.core.packaging import IMPORTANT_DOCS  # noqa: E402
from distroforge.core.workflows import LEVEL_KEYS  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
AGENT_DOC = "docs/advisory-agent.md"
COPILOT_DOC = "docs/maintainer-copilot.md"

# Engine-mutation entry points: BuildOrchestrator (core/build.py) drives the
# build, FileSystemOps (core/fsops.py) mutates the filesystem, and iso.rebuild
# rewrites the ISO. Any execute/dry-run gate that flips work from preview to real
# is equally forbidden in advisory code.
ENGINE_MUTATION_TOKENS = (
    "BuildOrchestrator",
    "FileSystemOps",
    ".rebuild(",
    "dry_run=False",
    "execute=True",
    "run_orchestrator=True",
)

# Each agent capability has a CLI verb and a GUI surface (handler wired on the
# maintainer page). Parity is a founding pillar, not optional for the agent.
AGENT_CLI_TO_GUI = {
    "explain-log": "_forgeadvisor_explain_log",
    "triage-log": "_forgeadvisor_triage_log",
    "explain-evidence": "_forgeadvisor_explain_evidence",
    "fix-plan": "_forgeadvisor_fix_plan",
    "review-definition": "_forgeadvisor_review_definition",
    "search-local": "_forgeadvisor_search_local",
    "copilot": "_forgeadvisor_copilot",
    "review-build": "_run_forgeadvisor",
    "propose-fixes": "_forgeadvisor_propose_fixes",
    "doctor-ai": "_forgeadvisor_doctor_ai",
}


def _normalized(path: str) -> str:
    """Lower-cased, whitespace-collapsed text so phrase asserts survive wrapping."""
    return " ".join((ROOT / path).read_text(encoding="utf-8").lower().split())


def _forgeadvisor_verbs(parser: argparse.ArgumentParser) -> set[str]:
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    forge_sub = next(
        a for a in sub.choices["forgeadvisor"]._actions if isinstance(a, argparse._SubParsersAction)
    )
    return set(forge_sub.choices)


def _dirty_bootstrap_project(tmp_path: Path, name: str):
    from distroforge.core.project import Project

    project = Project.create(name, tmp_path / name, "26.04")
    project.source_mode = "bootstrap"
    project.output_dir.mkdir(parents=True, exist_ok=True)
    (project.output_dir / "old.iso").write_text("old", encoding="utf-8")
    return project


def _tree_snapshot(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): path.read_text(encoding="utf-8")
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


# --- Ship lockstep + phrase locks ------------------------------------------


def test_advisory_agent_contract_ships_with_the_package() -> None:
    declared = {
        line.strip()
        for line in (ROOT / "debian/docs").read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    assert (ROOT / AGENT_DOC).exists()
    assert AGENT_DOC in declared  # listed in the Debian install manifest
    assert AGENT_DOC in IMPORTANT_DOCS  # guarded by the packaging policy report
    assert (ROOT / COPILOT_DOC).exists()
    assert COPILOT_DOC in declared
    assert COPILOT_DOC in IMPORTANT_DOCS


def test_advisory_agent_contract_is_phrase_locked() -> None:
    text = _normalized(AGENT_DOC)
    # The contract declares itself ratified and bound by the four pillars.
    assert "ratified and enforced" in text
    assert "governed by the four founding pillars, not added as a fifth" in text
    # Prime directive — the hard wall, verbatim so it cannot be softened.
    for phrase in (
        "the advisory agent is advisory, never autonomous",
        "never mutates the build, the recipe or the iso without an explicit",
        "it may never take the click",
    ):
        assert phrase in text, phrase
    # The four rings, named so the perimeter stays testable.
    for ring in (
        "perception (always on, silent)",
        "explanation (free, no approval)",
        "proposal (drafts, never commits)",
        "execution (only via the explicit-action wall)",
    ):
        assert ring in text, ring
    # Single-source vocabulary and the no-embedded-weights guarantee.
    assert "single source of truth" in text
    assert "no parallel taxonomy" in text
    assert "no model weights ship in the core" in text
    # The enforcement teeth and non-goals name themselves.
    assert "no agent code path reaches an engine mutation" in text
    assert "no silent or autonomous mutation of the build, recipe or iso" in text


def test_advisory_agent_contract_cross_references_the_pillars() -> None:
    """A contract that forgets the pillars governing it lets the wall drift."""
    text = _normalized(AGENT_DOC)
    for ref in (
        "gui-parity.md",
        "ux-cognitive-ergonomics.md",
        "debian-canonical-compliance.md",
        "velocity-responsiveness.md",
        "docs/distroforge-platform-architecture.md",
    ):
        assert ref in text, ref


# --- Tooth 1: no silent mutation -------------------------------------------


def test_no_agent_code_path_names_an_engine_mutation() -> None:
    """The advisory package must never reach the deterministic engine's mutating
    entry points; advisory code perceives, explains and proposes only."""
    offenders: dict[str, list[str]] = {}
    for module in sorted(Path(ROOT / "distroforge/ai").glob("*.py")):
        source = module.read_text(encoding="utf-8")
        present = [token for token in ENGINE_MUTATION_TOKENS if token in source]
        if present:
            offenders[module.name] = present
    assert offenders == {}, offenders


def test_agent_run_mutates_neither_options_nor_the_project_tree(tmp_path) -> None:
    """The hard wall, behaviourally: running explanation (Ring 1) and proposal
    (Ring 2) leaves the build options and the project tree byte-identical."""
    from distroforge.ai.forgeadvisor import ForgeAdvisor
    from distroforge.core.build import BuildOptions

    project = _dirty_bootstrap_project(tmp_path, "HardWall")
    options = BuildOptions(use_sudo=False)
    before = _tree_snapshot(project.root)

    ForgeAdvisor().review_build(project, options)
    proposal = ForgeAdvisor().propose_fixes(project, options)

    assert options.use_sudo is False  # the proposed flip was never applied
    assert proposal.to_dict()["status"] == PREVIEW_ONLY_STATUS
    assert _tree_snapshot(project.root) == before  # nothing on disk changed


# --- Tooth 2: offline degrade ----------------------------------------------


def test_agent_answers_with_no_backend_available() -> None:
    """With no model backend selected the agent still perceives and answers from
    the deterministic offline path — it never blocks or requires the network."""
    assert select_backend(None).name == "offline"
    offline = OfflineBackend()
    assert offline.available() is True
    context = AdvisorContext(
        title="t", verdict="review", findings=("squashfs: failed",), corpus_citation=""
    )
    narrated = offline.narrate(context)
    assert narrated is not None and "review" in narrated


# --- Tooth 3: parity (CLI verb + GUI surface) ------------------------------


def test_every_agent_capability_has_cli_and_gui() -> None:
    verbs = _forgeadvisor_verbs(build_parser())
    page = (ROOT / "distroforge/ui/maintainer_page.py").read_text(encoding="utf-8")
    shell = (ROOT / "distroforge/ui/main_window.py").read_text(encoding="utf-8")
    for verb, handler in AGENT_CLI_TO_GUI.items():
        assert verb in verbs, verb  # CLI verb exists
        assert handler in page or handler in shell, handler  # GUI surface wired


# --- Tooth 4: single-source register ---------------------------------------


def test_agent_registers_derive_only_from_canonical_levels() -> None:
    """Registers are a projection of the canonical workflow levels, in order, with
    no private level table."""
    assert register_keys() == LEVEL_KEYS
    registers_source = (ROOT / "distroforge/ai/registers.py").read_text(encoding="utf-8")
    assert "from distroforge.core.workflows import" in registers_source
