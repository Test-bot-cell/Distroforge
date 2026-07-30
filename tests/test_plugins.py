"""Unit tests for :mod:`distroforge.core.plugins`.

The plugin service runs both filesystem script plugins (``<dir>/<phase>.*``) and, when
pluggy is present, Python ``plugin.py`` modules through a Pluggy hook. Both routes are
exercised here against a temporary plugins directory.
"""

from __future__ import annotations

from pathlib import Path

from distroforge.core.command import CommandRunner
from distroforge.core.plugins import PluginOptions, PluginService, pluggy_status


def test_pluggy_status_reports_installed() -> None:
    # pluggy is a declared runtime dependency, so it is always importable in the suite.
    enabled, message = pluggy_status()
    assert enabled is True
    assert "enabled" in message


def test_run_phase_without_plugins_dir_runs_nothing() -> None:
    runner = CommandRunner(dry_run=True)
    service = PluginService(runner, PluginOptions(plugins_dir=None))

    service.run_phase("customize")

    assert runner.history == []


def test_run_phase_executes_matching_scripts(tmp_path: Path) -> None:
    plugins_dir = tmp_path / "plugins"
    (plugins_dir / "alpha").mkdir(parents=True)
    (plugins_dir / "beta").mkdir(parents=True)
    script = plugins_dir / "alpha" / "customize.sh"
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    # A script for a different phase must not run.
    (plugins_dir / "beta" / "finalize.sh").write_text("#!/bin/sh\n", encoding="utf-8")

    runner = CommandRunner(dry_run=True)
    PluginService(runner, PluginOptions(plugins_dir=plugins_dir)).run_phase("customize")

    script_runs = [spec for spec in runner.history if spec.argv == (str(script),)]
    assert len(script_runs) == 1
    assert script_runs[0].description == "Run plugin alpha:customize"


def test_run_phase_invokes_python_plugin_hook(tmp_path: Path) -> None:
    plugins_dir = tmp_path / "plugins"
    (plugins_dir / "gamma").mkdir(parents=True)
    (plugins_dir / "gamma" / "plugin.py").write_text(
        "from distroforge.core.command import CommandSpec\n"
        "def run_phase(phase, runner):\n"
        "    runner.run(CommandSpec(argv=('plugin-hook', phase), description='python plugin'))\n",
        encoding="utf-8",
    )

    runner = CommandRunner(dry_run=True)
    PluginService(runner, PluginOptions(plugins_dir=plugins_dir)).run_phase("customize")

    hook_calls = [spec for spec in runner.history if spec.argv == ("plugin-hook", "customize")]
    assert len(hook_calls) == 1


def test_python_plugin_with_native_hook_is_registered(tmp_path: Path) -> None:
    plugins_dir = tmp_path / "plugins"
    (plugins_dir / "delta").mkdir(parents=True)
    (plugins_dir / "delta" / "plugin.py").write_text(
        "import pluggy\n"
        "from distroforge.core.command import CommandSpec\n"
        "hookimpl = pluggy.HookimplMarker('distroforge')\n"
        "@hookimpl\n"
        "def distroforge_phase(phase, runner):\n"
        "    runner.run(CommandSpec(argv=('native-hook', phase), description='native'))\n",
        encoding="utf-8",
    )

    runner = CommandRunner(dry_run=True)
    PluginService(runner, PluginOptions(plugins_dir=plugins_dir)).run_phase("finalize")

    assert any(spec.argv == ("native-hook", "finalize") for spec in runner.history)


def test_service_tolerates_missing_plugins_dir_for_manager(tmp_path: Path) -> None:
    # A configured-but-absent directory yields no manager and no runs.
    service = PluginService(CommandRunner(dry_run=True), PluginOptions(plugins_dir=tmp_path / "absent"))
    assert service.manager is None
    service.run_phase("customize")
    assert service.runner.history == []
