from __future__ import annotations

from pathlib import Path

from distroforge.core.build import BuildOptions
from distroforge.core.explain import explain_build
from distroforge.core.project import Project


def render_explain(root: Path) -> str:
    project = Project.load(root)
    return explain_build(project, BuildOptions()).render_text()
