from __future__ import annotations

import argparse
import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from distroforge.cli import build_parser
from distroforge.commands.build_contracts import build_option_contracts
from distroforge.core.build_journey import JOURNEY_STEPS
from distroforge.core.workflows import PRODUCT_CAPABILITIES, WORKFLOW_LEVELS

ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _build_subparser() -> argparse.ArgumentParser:
    parser = build_parser()
    subparsers = next(action for action in parser._actions if isinstance(action, argparse._SubParsersAction))
    return subparsers.choices["build"]


def _ruff_argv() -> list[str] | None:
    # Prefer a ruff binary on PATH; fall back to `-m ruff`; None lets the gate skip.
    binary = shutil.which("ruff")
    if binary:
        return [binary]
    if importlib.util.find_spec("ruff") is not None:
        return [sys.executable, "-m", "ruff"]
    return None


def test_no_statement_packing_in_python_sources() -> None:
    # Replaces the old monolith line-count ratchet: capping lines only encouraged packing
    # many statements onto one line, so we forbid the packing (E701/E702) directly instead.
    ruff_argv = _ruff_argv()
    if ruff_argv is None:
        pytest.skip("ruff is unavailable to enforce the E701/E702 statement-packing gate")
    result = subprocess.run(
        [
            *ruff_argv,
            "check",
            "--select",
            "E701,E702",
            "--no-cache",
            "--output-format",
            "concise",
            str(ROOT / "distroforge"),
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )

    assert result.returncode == 0, (
        "Statement-packing is not allowed; put each statement on its own line.\n"
        + (result.stdout or result.stderr)
    )


def test_cli_delegates_build_argument_registration() -> None:
    cli = _read("distroforge/cli.py")
    build_options = _read("distroforge/commands/build_options.py")

    assert "register_build_arguments(build_parser)" in cli
    assert 'build_parser.add_argument("--brand-name")' not in cli
    assert 'parser.add_argument("--brand-name")' in build_options
    assert 'parser.add_argument("--prebuild-vm"' in build_options


def test_main_window_delegates_build_page() -> None:
    main = _read("distroforge/ui/main_window.py")
    build_page = _read("distroforge/ui/build_page.py")

    assert "return build_build_page(self)" in main
    assert "def build_build_page" in build_page
    assert "Build Controls" in build_page
    assert "Release and Cache" in build_page
    assert "Plan Detail" in build_page


def test_main_window_delegates_build_execution() -> None:
    main = _read("distroforge/ui/main_window.py")
    controller = _read("distroforge/ui/build_controller.py")

    assert "BuildController(self).show_plan()" in main
    assert "BuildController(self).run_build(execute)" in main
    assert "class BuildController" in controller
    assert "BuildOrchestrator" in controller
    assert "SnapshotService" in controller
    assert "run_doctor" in controller


def test_main_window_delegates_build_options_mapping() -> None:
    main = _read("distroforge/ui/main_window.py")
    mapper = _read("distroforge/ui/build_options_mapper.py")

    assert "return build_options_from_window(self)" in main
    assert "def build_options_from_window" in mapper
    assert "BuildOptions(" in mapper
    assert "get_persona" in mapper


def test_main_window_delegates_cli_equivalent_mapping() -> None:
    main = _read("distroforge/ui/main_window.py")
    cli_equivalent = _read("distroforge/ui/cli_equivalent.py")

    assert "return build_cli_equivalent(self)" in main
    assert "def build_cli_equivalent" in cli_equivalent
    assert "distroforge new NAME PATH" in cli_equivalent
    assert "--source-iso-sha256" in cli_equivalent


def test_product_workflows_are_executable_contracts() -> None:
    window_widgets = _read("distroforge/ui/window_widgets.py")
    guidance = _read("distroforge/ui/build_guidance.py")
    recommendation_actions = _read("distroforge/ui/recommendation_actions.py")
    command_center = _read("distroforge/ui/command_center_page.py")
    journey_cards = _read("distroforge/ui/journey_cards.py")
    quality_page = _read("distroforge/ui/quality_page.py")

    assert [level.key for level in WORKFLOW_LEVELS] == [
        "beginner",
        "power-user",
        "maintainer",
        "developer",
    ]
    assert {capability.level for capability in PRODUCT_CAPABILITIES} <= {
        level.key for level in WORKFLOW_LEVELS
    }
    # Every product capability declares the GUI surface that backs it, so the goal
    # hub routes intent -> surface from the same single source as the CLI map.
    assert all(capability.gui_surface for capability in PRODUCT_CAPABILITIES)
    assert "WORKFLOW_LEVELS" in window_widgets
    assert "product_capability_text()" in command_center
    assert "build_recommendation_actions(window)" in quality_page
    assert "open_recommendation_target" in recommendation_actions
    assert "build_journey" in command_center
    assert "apply_journey_step" in command_center
    assert "prepare_beginner_iso_path" in command_center
    assert "prepare_poweruser_iso_path" in command_center
    assert "explain_beginner_iso_failure" in command_center
    assert "repair_beginner_iso_release_artifacts" in command_center
    assert "run_beginner_iso_boot_proof" in command_center
    assert "create_publish_bundle" in command_center
    assert "GuiJob" in command_center
    assert "run_doctor" in command_center
    assert "install_missing" in command_center
    assert "emit.progress" in command_center
    assert "Open current step" in command_center
    assert "Apply current step" in command_center
    assert "open_journey_target" in journey_cards
    assert "apply_journey_step_id" in journey_cards
    assert "check_journey_step_id" in journey_cards
    assert "check_journey_step(" in journey_cards
    assert "item.next_action" in journey_cards
    assert {step.level for step in JOURNEY_STEPS} == {"beginner", "power-user", "maintainer", "developer"}
    assert "workflow_level_status_text()" in guidance


def test_journey_and_recommendation_targets_are_explicit() -> None:
    command_center = _read("distroforge/ui/command_center_page.py")
    recommendation_actions = _read("distroforge/ui/recommendation_actions.py")

    for action_id in {step.action_id for step in JOURNEY_STEPS}:
        assert f'"{action_id}"' in command_center
    assert "JOURNEY_TARGETS.get(action_id, " not in command_center
    assert "RECOMMENDATION_TARGETS.get(action_id, " not in recommendation_actions
    assert "Unknown journey target" in command_center
    assert "Unknown recommendation target" in recommendation_actions


def test_build_option_contract_covers_cli_and_gui_surfaces() -> None:
    parser = _build_subparser()
    contracts = build_option_contracts(parser)
    contract_options = {contract.option for contract in contracts}
    parser_options = {
        option
        for action in parser._actions
        for option in action.option_strings
        if option.startswith("--")
    }
    gui_source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (ROOT / "distroforge/ui").glob("*.py")
    )

    assert contract_options == parser_options
    assert {contract.level for contract in contracts} == {
        "beginner",
        "power-user",
        "maintainer",
        "developer",
    }
    missing_gui = [
        contract.option
        for contract in contracts
        if contract.requires_gui_token and contract.gui_token not in gui_source
    ]

    assert missing_gui == []


def test_platform_architecture_uses_product_contract_language() -> None:
    text = _read("docs/distroforge-platform-architecture.md")

    assert "operating-system forge" in text
    assert "Reference Source-To-ISO Path" in text
    assert "Beginner" in text
    assert "Power user" in text
    assert "Maintainer" in text
    assert "Developer" in text
    assert "CLI/GUI parity is non-negotiable" in text
    assert "AI is advisory" in text


def test_refactor_audit_names_debt_and_extraction_tracks() -> None:
    text = _read("docs/platform-refactor-audit.md")

    assert "not a claim that the platform is already clean" in text
    assert "CLI entrypoint" in text
    assert "GUI shell" in text
    assert "Build core" in text
    assert "Source-To-ISO Kernel" in text
    assert "CLI Command Adapters" in text
    assert "GUI Page Architecture" in text
    assert "Definition Of Done" in text


def test_platform_docs_are_packaged_and_referenced() -> None:
    architecture = _read("docs/architecture.md")
    declared_docs = _read("debian/docs")

    for path in (
        "docs/distroforge-platform-architecture.md",
        "docs/platform-refactor-audit.md",
    ):
        assert path in architecture or path in declared_docs
        assert path in declared_docs
        assert (ROOT / path).exists()


def test_platform_docs_use_product_framing() -> None:
    for path in (
        "docs/distroforge-platform-architecture.md",
        "docs/platform-refactor-audit.md",
        "docs/architecture.md",
    ):
        text = _read(path)
        assert "forge" in text


def test_rootfs_iso_mutators_depend_on_filesystem_boundary() -> None:
    modules = (
        "distroforge/core/apt.py",
        "distroforge/core/apt_cache.py",
        "distroforge/core/autoinstall.py",
        "distroforge/core/bootstrap.py",
        "distroforge/core/branding.py",
        "distroforge/core/casper.py",
        "distroforge/core/chroot.py",
        "distroforge/core/customize.py",
        "distroforge/core/debrand.py",
        "distroforge/core/kiosk.py",
        "distroforge/core/mirrors.py",
        "distroforge/core/network.py",
        "distroforge/core/oem.py",
        "distroforge/core/ppa.py",
        "distroforge/core/release_track.py",
        "distroforge/core/reproducible.py",
        "distroforge/core/seeds.py",
        "distroforge/core/system_sync.py",
    )

    offenders = [path for path in modules if "FileSystemOps" not in _read(path)]

    assert offenders == []


def test_snapshot_service_keeps_transactional_privileged_contract() -> None:
    source = _read("distroforge/core/snapshots.py")

    assert "temp_target" in source
    assert '".part"' in source
    assert "self.snapshots_dir.mkdir(parents=True, exist_ok=True)" in source
    assert '"tar"' in source
    assert '"--zstd"' in source
    assert '"-cpf"' in source
    assert '"-xpf"' in source
    assert 'argv=sudo(("tar", "--zstd", "-xpf"' in source
    assert "needs_root=self.use_sudo" in source
