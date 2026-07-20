from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("XDG_CONFIG_HOME", tempfile.mkdtemp())

from distroforge.ai.forgeadvisor import ForgeAdvisor  # noqa: E402
from distroforge.ai.proposals import (  # noqa: E402
    PREVIEW_ONLY_STATUS,
    ProposalReport,
    build_proposal,
)
from distroforge.ai.registers import register_keys  # noqa: E402
from distroforge.cli import build_parser, main  # noqa: E402
from distroforge.core.build import BuildOptions  # noqa: E402
from distroforge.core.project import Project  # noqa: E402


def _dirty_bootstrap_project(tmp_path: Path, name: str) -> Project:
    # A bootstrap project with a non-empty output dir reliably raises advisory
    # findings (output-dir-not-empty, plus privilege-disabled when sudo is off)
    # without depending on which host tools happen to be installed.
    project = Project.create(name, tmp_path / name, "26.04")
    project.source_mode = "bootstrap"
    project.output_dir.mkdir(parents=True, exist_ok=True)
    (project.output_dir / "old.iso").write_text("old", encoding="utf-8")
    return project


def test_proposal_is_preview_only_and_never_mutates_options(tmp_path) -> None:
    project = _dirty_bootstrap_project(tmp_path, "PreviewOnly")
    options = BuildOptions(use_sudo=False)

    proposal = ForgeAdvisor(level="maintainer").propose_fixes(project, options)

    # The hard wall: a proposal records the would-be change, it never applies it.
    assert options.use_sudo is False
    assert proposal.to_dict()["status"] == PREVIEW_ONLY_STATUS
    assert PREVIEW_ONLY_STATUS in proposal.render_text()
    assert any(
        change.option == "use_sudo" and change.current == "False" and change.proposed == "True"
        for change in proposal.option_changes
    )


def test_option_diff_is_grounded_and_skips_no_ops(tmp_path) -> None:
    enabled = ForgeAdvisor().propose_fixes(
        _dirty_bootstrap_project(tmp_path, "SudoOn"), BuildOptions(use_sudo=True)
    )
    disabled = ForgeAdvisor().propose_fixes(
        _dirty_bootstrap_project(tmp_path, "SudoOff"), BuildOptions(use_sudo=False)
    )

    # use_sudo is already True -> no no-op diff is proposed.
    assert not any(change.option == "use_sudo" for change in enabled.option_changes)
    # use_sudo is False and the privilege finding implies enabling it -> exactly one flip.
    sudo_changes = [c for c in disabled.option_changes if c.option == "use_sudo"]
    assert len(sudo_changes) == 1
    assert sudo_changes[0].rationale


def test_steps_are_grounded_ordered_and_deduplicated(tmp_path) -> None:
    project = _dirty_bootstrap_project(tmp_path, "Steps")
    options = BuildOptions(use_sudo=False)

    proposal = ForgeAdvisor().propose_fixes(project, options)
    codes = [step.code for step in proposal.steps]

    assert proposal.steps
    # Grounded in the same findings review_build explains.
    assert "privilege-disabled" in codes
    assert "output-dir-not-empty" in codes
    # Deduplicated: readiness and the dry-run can both raise output-dir-not-empty.
    assert len(codes) == len(set(codes))
    # Errors are planned before warnings.
    levels = [step.level for step in proposal.steps]
    assert levels == sorted(levels, key=lambda level: 0 if level == "error" else 1)
    # Each step carries an actionable remediation.
    assert all(step.action for step in proposal.steps)


def test_beginner_register_frames_proposal_in_plain_language(tmp_path) -> None:
    project = _dirty_bootstrap_project(tmp_path, "BeginnerProposal")
    options = BuildOptions(use_sudo=False)

    proposal = ForgeAdvisor(level="beginner").propose_fixes(project, options)

    assert proposal.register == "Beginner"
    assert "Register: Beginner" in proposal.render_text()
    # privilege-disabled's detail mentions rootfs/chroot/ISO -> beginner expands them.
    assert any(note.startswith("Plain language - ") for note in proposal.notes)
    assert any("you do not need the command line" in note for note in proposal.notes)


def test_developer_register_applies_debian_lens_without_jargon_expansion(tmp_path) -> None:
    project = _dirty_bootstrap_project(tmp_path, "DeveloperProposal")
    options = BuildOptions(use_sudo=False)

    proposal = ForgeAdvisor(level="developer").propose_fixes(project, options)

    assert proposal.register == "Senior Debian/Canonical"
    assert any("Debian/Canonical lens" in note for note in proposal.notes)
    assert not any(note.startswith("Plain language - ") for note in proposal.notes)


def test_proposal_json_serializes_register_status_and_sections(tmp_path) -> None:
    project = _dirty_bootstrap_project(tmp_path, "JsonProposal")
    proposal = ForgeAdvisor(level="maintainer").propose_fixes(project, BuildOptions(use_sudo=False))

    payload = json.loads(proposal.render_json())

    assert payload["register"] == "Maintainer"
    assert payload["status"] == PREVIEW_ONLY_STATUS
    assert payload["steps"]
    assert any(change["option"] == "use_sudo" for change in payload["option_changes"])


def test_build_proposal_does_not_invent_changes_without_findings() -> None:
    # No findings -> an honest empty preview, never a fabricated diff.
    proposal = build_proposal("empty", [], BuildOptions(use_sudo=False), "Beginner")

    assert isinstance(proposal, ProposalReport)
    assert proposal.steps == []
    assert proposal.option_changes == []
    assert proposal.verdict == "informational"
    assert "no remediation steps" in proposal.render_text()


def test_cli_propose_fixes_choices_match_registry() -> None:
    parser = build_parser()
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    forge_sub = next(
        a for a in sub.choices["forgeadvisor"]._actions if isinstance(a, argparse._SubParsersAction)
    )
    register_action = next(
        a for a in forge_sub.choices["propose-fixes"]._actions if a.dest == "register"
    )
    assert list(register_action.choices) == list(register_keys())
    assert register_action.default is None


def test_cli_propose_fixes_is_preview_only_json(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "distroforge.core.build_memory.default_corpus_path", lambda: tmp_path / "corpus.jsonl"
    )
    project = _dirty_bootstrap_project(tmp_path, "CliProposal")
    project.save()

    main(["forgeadvisor", "propose-fixes", str(project.root), "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert payload["status"] == PREVIEW_ONLY_STATUS
    assert "steps" in payload
    assert "option_changes" in payload


def test_cli_no_sudo_surfaces_the_grounded_option_diff(tmp_path, monkeypatch, capsys) -> None:
    # Parity with the GUI sudo toggle: --no-sudo lets the CLI preview a build that
    # runs without the privilege helper, so the use_sudo diff becomes reachable.
    monkeypatch.setattr(
        "distroforge.core.build_memory.default_corpus_path", lambda: tmp_path / "corpus.jsonl"
    )
    project = _dirty_bootstrap_project(tmp_path, "CliNoSudo")
    project.save()

    main(["forgeadvisor", "propose-fixes", str(project.root), "--no-sudo", "--json"])
    payload = json.loads(capsys.readouterr().out)

    sudo_changes = [c for c in payload["option_changes"] if c["option"] == "use_sudo"]
    assert len(sudo_changes) == 1
    assert sudo_changes[0]["current"] == "False" and sudo_changes[0]["proposed"] == "True"
    assert payload["status"] == PREVIEW_ONLY_STATUS  # still never applied


def test_cli_forgeadvisor_evidence_and_fix_plan_are_preview_only(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "distroforge.core.build_memory.default_corpus_path", lambda: tmp_path / "corpus.jsonl"
    )
    project = Project.create("AiEvidence", tmp_path / "ai-evidence", "26.04")

    main(["forgeadvisor", "explain-evidence", str(project.root), "--profile", "iso", "--json"])
    evidence = json.loads(capsys.readouterr().out)
    assert evidence["verdict"] == "blocked"
    assert any(finding["code"].startswith("evidence-") for finding in evidence["findings"])
    assert any(note.startswith("next action:") for note in evidence["notes"])

    main(["forgeadvisor", "fix-plan", str(project.root), "--profile", "iso", "--json"])
    fix_plan = json.loads(capsys.readouterr().out)
    assert any("distroforge iso-build" in note for note in fix_plan["notes"])
    assert any("Preview only" in note for note in fix_plan["notes"])

    main(["forgeadvisor", "copilot", str(project.root), "--profile", "iso", "--query", "evidence", "--json"])
    copilot = json.loads(capsys.readouterr().out)
    assert copilot["title"].startswith("maintainer copilot")
    assert any("Workflow: explain-evidence -> fix-plan -> search-local." in note for note in copilot["notes"])
    assert any("Preview only" in note for note in copilot["notes"])

    main(["forgeadvisor", "copilot", str(project.root), "--profile", "package", "--query", "evidence", "--json"])
    package_copilot = json.loads(capsys.readouterr().out)
    assert any(note.startswith("Maintainer toolchain:") for note in package_copilot["notes"])


def test_cli_forgeadvisor_triage_definition_and_local_search(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "distroforge.core.build_memory.default_corpus_path", lambda: tmp_path / "corpus.jsonl"
    )
    log = tmp_path / "build.log"
    log.write_text("E: Unable to locate package missing-demo\n", encoding="utf-8")
    main(["forgeadvisor", "triage-log", str(log), "--json"])
    triage = json.loads(capsys.readouterr().out)
    assert triage["title"].startswith("build log triage")
    assert triage["findings"]

    definition = tmp_path / "definition.yaml"
    definition.write_text("source_iso: demo.iso\n", encoding="utf-8")
    main(["forgeadvisor", "review-definition", str(definition), "--json"])
    review = json.loads(capsys.readouterr().out)
    assert review["verdict"] in {"review", "blocked"}
    assert any("recommended evidence profile" in note for note in review["notes"])

    root = tmp_path / "repo"
    (root / "docs").mkdir(parents=True)
    (root / "docs" / "evidence.md").write_text("Evidence profiles guide maintainer review.\n", encoding="utf-8")
    main(["forgeadvisor", "search-local", str(root), "evidence profiles", "--json"])
    search = json.loads(capsys.readouterr().out)
    assert search["findings"][0]["citations"][0]["line"] == 1
    assert "evidence.md" in search["findings"][0]["title"]


@pytest.fixture(scope="module")
def qt_app():
    from distroforge.ui.qt import QApplication

    return QApplication.instance() or QApplication([])


def test_gui_propose_fixes_button_is_wired(qt_app) -> None:
    from distroforge.ui.main_window import MainWindow
    from distroforge.ui.qt import QPushButton

    window = MainWindow()

    assert callable(window._run_debian_dev_doctor)
    assert callable(window._forgeadvisor_propose_fixes)
    labels = {button.text() for button in window.findChildren(QPushButton)}
    assert "Debian Dev Doctor" in labels
    assert "FA: propose fixes" in labels
    assert "Maintainer Copilot" in labels
    assert "FA: triage log" in labels
