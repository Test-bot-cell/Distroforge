from __future__ import annotations

from pathlib import Path

import pytest

from distroforge.core.command import CommandRunner
from distroforge.core.plugins import PluginOptions, PluginService


def test_python_plugin_is_not_imported_outside_command_provenance(
    tmp_path: Path,
) -> None:
    plugins = tmp_path / "plugins"
    plugin = plugins / "hostile" / "plugin.py"
    marker = tmp_path / "imported"
    plugin.parent.mkdir(parents=True)
    plugin.write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran')\n",
        encoding="utf-8",
    )
    runner = CommandRunner(dry_run=False)
    service = PluginService(runner, PluginOptions(plugins))

    assert not marker.exists()
    with pytest.raises(ValueError, match="cannot participate in a sealed ISO"):
        service.run_phase("pre-host")

    assert not marker.exists()
    assert runner.history[-1].argv[:2] == (
        "python-plugin-refused",
        "pre-host",
    )


def test_executable_phase_script_stays_inside_command_runner(
    tmp_path: Path,
) -> None:
    plugins = tmp_path / "plugins"
    script = plugins / "proved" / "pre-host.sh"
    marker = tmp_path / "script-ran"
    script.parent.mkdir(parents=True)
    script.write_text(
        f"#!/bin/sh\nprintf proved > {str(marker)!r}\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    runner = CommandRunner(dry_run=False)

    PluginService(runner, PluginOptions(plugins)).run_phase("pre-host")

    assert marker.read_text(encoding="utf-8") == "proved"
    assert runner.execution_identities[-1]["dispatch_bound"] is True
