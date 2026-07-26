from __future__ import annotations

from dataclasses import dataclass

import pytest

from distroforge.core.definition import apply_definition, load_definition
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


# Every option group apply_definition builds by keyword unpacking. schema.py models
# only eight of them, so the other 23 used to raise a bare TypeError -- which
# cli.py does not catch -- and a typo in a YAML definition printed a Python
# traceback instead of "distroforge: error: ...". ValueError is the friendly path.
DEFINITION_GROUPS = (
    "sanitize",
    "bootstrap",
    "drivers",
    "autoinstall",
    "branding",
    "secure_boot",
    "provenance",
    "seeds",
    "release_track",
    "system_sync",
    "apt_cache",
    "snapshots",
    "oem",
    "systemd",
    "network",
    "mirrors",
    "kiosk",
    "bootcheck",
    "prebuild_vm",
    "qemu_screenshot",
    "policy",
    "size_analysis",
    "reproducible",
    "kernel",
    "release_artifacts",
    "html_report",
    "vuln_scan",
)


@pytest.mark.parametrize("group", DEFINITION_GROUPS)
def test_unknown_key_in_any_option_group_is_a_friendly_error(tmp_path, group: str) -> None:
    project = Project.create("GroupGuard", tmp_path / f"group-{group}", "26.04")

    with pytest.raises(ValueError):
        apply_definition(project, {group: {"__not_an_option__": True}})


def _interpreter_suggests_keyword_arguments() -> bool:
    """Whether this CPython appends "Did you mean" to an unexpected-keyword TypeError.

    It does from 3.13 on, and not before. Probed rather than version-compared: the
    assertion is about the interpreter's behaviour, so let the interpreter answer.
    """

    @dataclass
    class Probe:
        logs: bool = False

    try:
        Probe(logz=True)  # type: ignore[call-arg]
    except TypeError as error:
        return "Did you mean" in str(error)
    return False


def test_group_error_keeps_whatever_the_interpreter_says(tmp_path) -> None:
    # The whole value of routing through ValueError instead of pre-validating each
    # group is that the interpreter's own message survives to the user -- including
    # its "Did you mean" hint where the interpreter offers one. What is guaranteed on
    # every supported interpreter is the group name and the offending key, so that is
    # asserted unconditionally and the hint only where it exists. Asserting the hint
    # everywhere failed on 3.11 and 3.12, which is the matrix earning its keep.
    project = Project.create("GroupHint", tmp_path / "group-hint", "26.04")

    with pytest.raises(ValueError) as raised:
        apply_definition(project, {"sanitize": {"logz": True}})

    message = str(raised.value)
    assert "'sanitize'" in message
    assert "logz" in message
    if _interpreter_suggests_keyword_arguments():
        assert "Did you mean 'logs'" in message


def test_definition_typo_exits_two_with_a_friendly_message(tmp_path, capsys) -> None:
    from distroforge.cli import main

    project = Project.create("GroupCli", tmp_path / "group-cli", "26.04")
    project.source_mode = "bootstrap"
    project.save()
    definition = tmp_path / "image.yaml"
    definition.write_text("kiosk:\n  urlz: about:blank\n", encoding="utf-8")

    with pytest.raises(SystemExit) as excinfo:
        main(["build", str(project.root), "--definition", str(definition)])

    assert excinfo.value.code == 2
    assert "distroforge: error:" in capsys.readouterr().err


def test_project_definition_example_loads(tmp_path) -> None:
    project = Project.create("DocSmoke", tmp_path / "doc-smoke", "26.04")
    project.source_mode = "bootstrap"
    project.save()

    loaded = Project.load(project.root)

    assert loaded.source_mode == "bootstrap"
    assert loaded.release.version == "26.04"
