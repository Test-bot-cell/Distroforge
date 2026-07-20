from __future__ import annotations

from pathlib import Path

from distroforge.core.build import BuildOptions
from distroforge.core.project import Project
from distroforge.core.recipe import export_recipe


def export_project_recipe(root: Path, target: Path) -> None:
    project = Project.load(root)
    export_recipe(project, BuildOptions()).write(target)
