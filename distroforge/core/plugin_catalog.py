from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class PluginManifest:
    name: str
    path: Path
    version: str = "0"
    phases: tuple[str, ...] = ()
    enabled: bool = True
    description: str = ""
    compatibility: str = "unknown"


def discover_plugins(root: Path) -> list[PluginManifest]:
    plugins_dir = root / "plugins"
    if not plugins_dir.exists():
        return []
    manifests: list[PluginManifest] = []
    for manifest in sorted(plugins_dir.glob("*/plugin.json")):
        data = json.loads(manifest.read_text(encoding="utf-8"))
        manifests.append(
            PluginManifest(
                name=str(data.get("name", manifest.parent.name)),
                path=manifest.parent,
                version=str(data.get("version", "0")),
                phases=tuple(str(phase) for phase in data.get("phases", [])),
                enabled=bool(data.get("enabled", True)),
                description=str(data.get("description", "")),
                compatibility=str(data.get("compatibility", "unknown")),
            )
        )
    return manifests


def render_catalog(root: Path) -> str:
    plugins = discover_plugins(root)
    if not plugins:
        return "No local plugins found."
    lines = ["Local DistroForge plugins:"]
    for plugin in plugins:
        state = "enabled" if plugin.enabled else "disabled"
        phases = ",".join(plugin.phases) or "-"
        lines.append(
            f"- {plugin.name} {plugin.version} [{state}] compat={plugin.compatibility} phases={phases}"
        )
        if plugin.description:
            lines.append(f"  {plugin.description}")
    return "\n".join(lines)
