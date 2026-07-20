from __future__ import annotations

import importlib.util
from dataclasses import dataclass
from pathlib import Path

from .command import CommandRunner, CommandSpec

try:
    import pluggy
except ImportError:  # pragma: no cover - minimal runtime fallback.
    pluggy = None  # type: ignore[assignment]


HOOK_NAMESPACE = "distroforge"


@dataclass
class PluginOptions:
    plugins_dir: Path | None = None


class PluginService:
    def __init__(self, runner: CommandRunner, options: PluginOptions) -> None:
        self.runner = runner
        self.options = options
        self.manager = self._manager()

    def run_phase(self, phase: str) -> None:
        if self.manager:
            self.manager.hook.distroforge_phase(phase=phase, runner=self.runner)
        if not self.options.plugins_dir or not self.options.plugins_dir.exists():
            return
        for script in sorted(self.options.plugins_dir.glob(f"*/{phase}.*")):
            if script.is_file():
                self.runner.run(
                    CommandSpec(
                        argv=(str(script),),
                        description=f"Run plugin {script.parent.name}:{phase}",
                    )
                )

    def _manager(self):
        if pluggy is None or not self.options.plugins_dir or not self.options.plugins_dir.exists():
            return None
        manager = pluggy.PluginManager(HOOK_NAMESPACE)

        hookspec = pluggy.HookspecMarker(HOOK_NAMESPACE)

        class Specs:
            @hookspec
            def distroforge_phase(self, phase: str, runner: CommandRunner) -> None:
                """Run a DistroForge plugin phase."""

        manager.add_hookspecs(Specs)
        hookimpl = pluggy.HookimplMarker(HOOK_NAMESPACE)
        for path in sorted(self.options.plugins_dir.glob("*/plugin.py")):
            module = self._load_python_plugin(path)
            if module and not hasattr(module, "distroforge_phase") and hasattr(module, "run_phase"):

                @hookimpl
                def distroforge_phase(phase: str, runner: CommandRunner, _module=module) -> None:
                    _module.run_phase(phase, runner)

                module.distroforge_phase = distroforge_phase
            if module:
                manager.register(module, name=path.parent.name)
        return manager

    @staticmethod
    def _load_python_plugin(path: Path):
        spec = importlib.util.spec_from_file_location(f"distroforge_plugin_{path.parent.name}", path)
        if not spec or not spec.loader:
            return None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module


def pluggy_status() -> tuple[bool, str]:
    if pluggy is None:
        return False, "Pluggy is not installed; script plugins still work"
    return True, "Pluggy plugin hooks enabled"
