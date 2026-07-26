from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("typer", reason="the Typer facade is an optional extra")

ROOT = Path(__file__).resolve().parents[1]

# Every command of the facade forwards to the legacy CLI except plugins and
# export-recipe, which call a helper that really does take a Path. explain used
# to call render_explain(root) although render_explain takes an argparse
# Namespace, so `distroforge-typer explain` raised TypeError on every
# invocation: a shipped console script with a shipped manpage and no test.
FORWARDING_COMMANDS = ("explain", "readiness", "explain-risk", "dry-run-report")


@pytest.fixture(scope="module")
def project(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("project") / "demo"
    _run("-m", "distroforge", "new", "demo", str(root), "--release", "26.04")
    return root


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        (sys.executable, *args),
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )


@pytest.mark.parametrize("command", FORWARDING_COMMANDS)
def test_facade_command_runs_against_a_real_project(project: Path, command: str) -> None:
    result = _run("-m", "distroforge.typer_cli", command, str(project))

    assert result.stdout.strip()


def test_facade_explain_honours_json(project: Path) -> None:
    result = _run("-m", "distroforge.typer_cli", "explain", str(project), "--json")

    assert json.loads(result.stdout)


def test_facade_matches_the_legacy_cli_output(project: Path) -> None:
    facade = _run("-m", "distroforge.typer_cli", "explain", str(project))
    legacy = _run("-m", "distroforge", "explain", str(project))

    assert facade.stdout == legacy.stdout
