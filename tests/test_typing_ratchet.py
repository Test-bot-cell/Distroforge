from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "distroforge"

# mypy is configured as a ratchet, not a suggestion: every module is checked
# except an explicit debt list. The list is what makes the rest enforceable, so
# it has to stay honest -- an entry naming a module that no longer exists, or a
# module that has since been cleaned, would quietly widen the hole.
#
# It found real defects the moment it was switched on: distroforge-typer explain
# passing a Path where an argparse.Namespace was declared, and six report sections
# whose `extend(...) or append(...)` fired unconditionally because list.extend
# returns None. No ruff rule catches either one.


def _mypy_config() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["mypy"]


def _debt_modules() -> list[str]:
    overrides = _mypy_config()["overrides"]
    ignored = [
        module
        for override in overrides
        if override.get("ignore_errors")
        for module in override["module"]
    ]
    return ignored


def test_mypy_is_pinned_to_the_supported_floor() -> None:
    config = _mypy_config()

    # Not the interpreter that happens to be installed: tarfile extraction
    # defaults and other behaviour differ between 3.11 and 3.14.
    assert config["python_version"] == "3.11"
    assert config["ignore_missing_imports"] is True


def test_every_module_on_the_debt_list_still_exists() -> None:
    missing = [
        module
        for module in _debt_modules()
        if not (ROOT / (module.replace(".", "/") + ".py")).exists()
    ]

    assert missing == [], f"stale entries in the mypy debt list: {missing}"


def test_the_debt_list_only_shrinks() -> None:
    # Raise nothing here. Lowering this number is the only allowed edit, and it
    # must come with the matching removal from pyproject.
    assert len(_debt_modules()) <= 41


def test_the_debt_list_covers_a_minority_of_the_tree() -> None:
    total = len(list(SOURCE_ROOT.rglob("*.py")))

    assert total >= 200
    assert len(_debt_modules()) * 4 < total, "the debt list has grown into the majority"


def test_the_modules_repaired_by_this_campaign_are_not_exempt() -> None:
    # These carried the defects mypy surfaced. Exempting them would have frozen
    # the bugs instead of revealing them, which is the trap this list invites.
    debt = set(_debt_modules())

    assert "distroforge.typer_cli" not in debt
    assert "distroforge.core.artifact_paths" not in debt
    assert "distroforge.core.gpg" not in debt
    assert "distroforge.core.hashing" not in debt
