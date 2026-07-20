from __future__ import annotations

import pytest

from distroforge.core.definition import load_definition
from distroforge.core.project import Project
from distroforge.core.schema import validate_definition_data


def test_load_yaml_definition(tmp_path) -> None:
    path = tmp_path / "image.yaml"
    path.write_text(
        """
source_mode: bootstrap
packages:
  - git
customization:
  desktop: ubuntu_minimal
""".strip(),
        encoding="utf-8",
    )

    data = load_definition(path)

    assert data["source_mode"] == "bootstrap"
    assert data["packages"] == ["git"]


def test_load_definition_requires_mapping(tmp_path) -> None:
    path = tmp_path / "image.yaml"
    path.write_text("- git\n- curl\n", encoding="utf-8")

    with pytest.raises(ValueError, match="mapping/object"):
        load_definition(path)


def test_schema_rejects_invalid_known_nested_field() -> None:
    with pytest.raises(ValueError, match="unknown"):
        validate_definition_data({"kernel": {"unknown": True}})


def test_project_definition_example_loads(tmp_path) -> None:
    project = Project.create("DocSmoke", tmp_path / "doc-smoke", "26.04")
    project.source_mode = "bootstrap"
    project.save()

    loaded = Project.load(project.root)

    assert loaded.source_mode == "bootstrap"
    assert loaded.release.version == "26.04"
