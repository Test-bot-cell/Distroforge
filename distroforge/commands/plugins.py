from __future__ import annotations

from pathlib import Path

from distroforge.core.plugin_catalog import render_catalog


def render_plugins(root: Path) -> str:
    return render_catalog(root)
