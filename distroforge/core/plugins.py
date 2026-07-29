from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .command import CommandRunner, CommandSpec

try:
    import pluggy
except ImportError:  # pragma: no cover - minimal runtime fallback.
    pluggy = None  # type: ignore[assignment]


@dataclass
class PluginOptions:
    plugins_dir: Path | None = None


class PluginService:
    def __init__(self, runner: CommandRunner, options: PluginOptions) -> None:
        self.runner = runner
        self.options = options

    def run_phase(self, phase: str) -> None:
        if not self.options.plugins_dir or not self.options.plugins_dir.exists():
            return
        python_plugins = sorted(self.options.plugins_dir.glob("*/plugin.py"))
        if python_plugins:
            names = ", ".join(path.parent.name for path in python_plugins)
            self.runner.run(
                CommandSpec(
                    argv=("python-plugin-refused", phase, *names.split(", ")),
                    description=(
                        "Refuse in-process Python plugins outside the sealed "
                        "command/provenance boundary"
                    ),
                )
            )
            raise ValueError(
                "In-process Python plugins cannot participate in a sealed ISO "
                f"build ({names}). Convert them to executable <phase> scripts so "
                "CommandRunner can bind and record their executable bytes."
            )
        for script in sorted(self.options.plugins_dir.glob(f"*/{phase}.*")):
            if script.is_file() and script.name != "plugin.py":
                self.runner.run(
                    CommandSpec(
                        argv=(str(script),),
                        description=f"Run plugin {script.parent.name}:{phase}",
                    )
                )

def pluggy_status() -> tuple[bool, str]:
    if pluggy is None:
        return False, "Pluggy is not installed; script plugins still work"
    return (
        True,
        "Pluggy is installed; sealed builds accept only executable phase scripts",
    )
