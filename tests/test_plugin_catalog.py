"""Unit tests for :mod:`distroforge.core.plugin_catalog`.

Discovery reads ``<root>/plugins/*/plugin.json`` and the catalog renders a stable,
sorted, human-readable listing. Both the empty case and the defaults applied to a
sparse manifest are pinned here.
"""

from __future__ import annotations

import json
from pathlib import Path

from distroforge.core.plugin_catalog import PluginManifest, discover_plugins, render_catalog


def _write_plugin(root: Path, name: str, data: dict[str, object]) -> None:
    plugin_dir = root / "plugins" / name
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "plugin.json").write_text(json.dumps(data), encoding="utf-8")


def test_discover_returns_empty_without_plugins_dir(tmp_path: Path) -> None:
    assert discover_plugins(tmp_path) == []


def test_discover_reads_full_manifest(tmp_path: Path) -> None:
    _write_plugin(
        tmp_path,
        "alpha",
        {
            "name": "Alpha",
            "version": "1.2",
            "phases": ["customize", "finalize"],
            "enabled": False,
            "description": "does things",
            "compatibility": "verified",
        },
    )

    (manifest,) = discover_plugins(tmp_path)

    assert manifest == PluginManifest(
        name="Alpha",
        path=tmp_path / "plugins" / "alpha",
        version="1.2",
        phases=("customize", "finalize"),
        enabled=False,
        description="does things",
        compatibility="verified",
    )


def test_discover_applies_defaults_and_sorts(tmp_path: Path) -> None:
    _write_plugin(tmp_path, "zeta", {})
    _write_plugin(tmp_path, "beta", {"name": "Beta"})

    manifests = discover_plugins(tmp_path)

    # Sorted by the glob over plugin directories: beta before zeta.
    assert [m.path.name for m in manifests] == ["beta", "zeta"]
    fallback = manifests[1]
    # A manifest with no name falls back to the directory name.
    assert fallback.name == "zeta"
    assert fallback.version == "0"
    assert fallback.phases == ()
    assert fallback.enabled is True
    assert fallback.compatibility == "unknown"


def test_render_catalog_reports_no_plugins(tmp_path: Path) -> None:
    assert render_catalog(tmp_path) == "No local plugins found."


def test_render_catalog_lists_state_and_description(tmp_path: Path) -> None:
    _write_plugin(
        tmp_path,
        "alpha",
        {
            "name": "Alpha",
            "version": "2.0",
            "phases": ["customize"],
            "enabled": False,
            "description": "explains itself",
            "compatibility": "verified",
        },
    )

    rendered = render_catalog(tmp_path)

    assert rendered.splitlines() == [
        "Local DistroForge plugins:",
        "- Alpha 2.0 [disabled] compat=verified phases=customize",
        "  explains itself",
    ]


def test_render_catalog_shows_dash_for_missing_phases(tmp_path: Path) -> None:
    _write_plugin(tmp_path, "alpha", {"name": "Alpha"})

    rendered = render_catalog(tmp_path)

    assert rendered.splitlines() == [
        "Local DistroForge plugins:",
        "- Alpha 0 [enabled] compat=unknown phases=-",
    ]
