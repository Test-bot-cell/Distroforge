from __future__ import annotations

import argparse
import ast
import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

from distroforge.cli import build_parser
from distroforge.commands.build_contracts import build_option_contracts
from distroforge.core.build_journey import JOURNEY_STEPS
from distroforge.core.workflows import PRODUCT_CAPABILITIES, WORKFLOW_LEVELS

ROOT = Path(__file__).resolve().parents[1]
GATED_SOURCE_DIRS = ("distroforge", "tools")
# Hard and soft keywords that open a block. `\b` keeps `else_` and `match_case`
# out: they are ordinary names that merely start with the same letters.
_CLAUSE_KEYWORD = re.compile(
    r"^(if|elif|else|for|while|with|try|except|finally|def|class|async|match|case)\b"
)
# Split like DISALLOWED_PUBLIC_NAMES in test_policy_compliance, for the same reason:
# the test that forbids the token must not contain the token.
_SELECT_OVERRIDE = '"--' + 'select"'


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _build_subparser() -> argparse.ArgumentParser:
    parser = build_parser()
    subparsers = next(action for action in parser._actions if isinstance(action, argparse._SubParsersAction))
    return subparsers.choices["build"]


def packed_statements(path: Path) -> list[str]:
    """Report E701/E702 statement packing using nothing but the standard library.

    This gate used to shell out to ruff and ``pytest.skip`` when ruff was missing.
    ruff has no binary package in the archive, so it is absent from the sbuild
    chroot that produces the .deb: the gate reported "1 skipped", exit 0, and never
    ran once during a package build. Nothing here can be missing, so nothing here
    can be skipped.

    E702 is two statements sharing one line inside the same block. E701 is a
    statement that starts on a line which opens a clause -- ``if x: y``, ``else: y``
    -- detected from the physical line plus the column, which also covers ``else``
    and ``finally``, clauses the AST gives no position of their own. An inline ``...``
    body is exempt, matching ruff: it is how a Protocol declares a method.
    """
    source = path.read_text(encoding="utf-8")
    lines = source.splitlines()
    findings: list[str] = []
    for block in _statement_blocks(ast.parse(source, filename=str(path))):
        for previous, statement in zip(block, block[1:], strict=False):
            if previous.lineno == statement.lineno:
                findings.append(f"{path}:{statement.lineno}: E702 two statements on one line")
        if len(block) == 1 and _is_ellipsis(block[0]):
            continue
        for statement in block:
            line = lines[statement.lineno - 1]
            indent = len(line) - len(line.lstrip())
            if statement.col_offset > indent and _CLAUSE_KEYWORD.match(line.lstrip()):
                findings.append(f"{path}:{statement.lineno}: E701 statement on a clause line")
    return findings


def _is_ellipsis(statement: ast.stmt) -> bool:
    return (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and statement.value.value is Ellipsis
    )


def _statement_blocks(tree: ast.AST) -> list[list[ast.stmt]]:
    blocks: list[list[ast.stmt]] = []
    for node in ast.walk(tree):
        for field in ("body", "orelse", "finalbody"):
            block = getattr(node, field, None)
            if isinstance(block, list) and block and all(isinstance(item, ast.stmt) for item in block):
                blocks.append(block)
    return blocks


def test_no_statement_packing_in_python_sources() -> None:
    # Replaces the old monolith line-count ratchet: capping lines only encouraged packing
    # many statements onto one line, so we forbid the packing (E701/E702) directly instead.
    sources = [
        path
        for directory in GATED_SOURCE_DIRS
        for path in sorted((ROOT / directory).rglob("*.py"))
        if "__pycache__" not in path.parts
    ]
    findings = [finding for path in sources for finding in packed_statements(path)]

    # Anti-vacuity: a gate that inspected nothing is not a gate.
    assert len(sources) >= 200, f"only {len(sources)} sources inspected"
    assert findings == [], "Statement-packing is not allowed; put each statement on its own line.\n" + "\n".join(
        findings
    )


def test_statement_packing_detector_flags_both_spellings(tmp_path: Path) -> None:
    # The detector has to be shown catching what it claims to catch, or the green
    # result above only proves that it looks at nothing.
    sample = tmp_path / "packed.py"
    sample.write_text(
        "def f(x):\n"
        "    a = 1; b = 2\n"
        "    if x: return a\n"
        "    else: return b\n",
        encoding="utf-8",
    )

    findings = packed_statements(sample)

    assert any("E702" in finding for finding in findings)
    assert sum("E701" in finding for finding in findings) == 2
    assert packed_statements(Path(__file__)) == []


def test_ruff_gate_runs_the_project_configuration_not_a_command_line_override() -> None:
    """The lint gate must exercise the config the project actually ships.

    Passing ``--select E701,E702`` replaced ``select`` *and* ``extend-select`` from
    pyproject, so the run that was supposed to guard the tree checked four rules out
    of the six families the project declares -- S202, the archive-extraction filter
    guard, among the ones it silently dropped.
    """
    lint = tomllib.loads(_read("pyproject.toml"))["tool"]["ruff"]["lint"]

    assert "E" in lint["select"]
    assert "S202" in lint["extend-select"]
    # The argv spelling, not the prose: this file explains the defect it removed.
    assert _SELECT_OVERRIDE not in _read("tests/test_platform_contracts.py")

    ruff = shutil.which("ruff")
    if ruff is None:
        pytest.skip("ruff is not installed here; the stdlib gate above covers the packing rules")
    result = subprocess.run(
        [ruff, "check", "--no-cache", "--output-format", "concise", "."],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )

    assert result.returncode == 0, result.stdout or result.stderr


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
