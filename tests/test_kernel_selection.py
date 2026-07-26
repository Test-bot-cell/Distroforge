from __future__ import annotations

from pathlib import Path

import pytest

from distroforge.core.command import CommandRunner
from distroforge.core.kernel import KernelModuleOptions, KernelModuleService, _version_key

# The body of _version_key was covered by no test at all. It mixed bare ints and
# strs in the sort key, so ordering /lib/modules raised TypeError as soon as one
# entry did not start with a digit -- and lost+found is present on any ext4 root.
NON_NUMERIC_ENTRIES = ("lost+found", "extramodules", ".keep")


def _service(root: Path) -> KernelModuleService:
    return KernelModuleService(CommandRunner(dry_run=True), root, Path("work"), KernelModuleOptions())


def test_version_key_orders_real_kernels() -> None:
    versions = ["6.8.0-51-generic", "6.11.0-9-generic", "6.11.0-10-generic"]

    assert sorted(versions, key=_version_key) == [
        "6.8.0-51-generic",
        "6.11.0-9-generic",
        "6.11.0-10-generic",
    ]


@pytest.mark.parametrize("stray", NON_NUMERIC_ENTRIES)
def test_version_key_sorts_alongside_a_non_numeric_entry(stray: str) -> None:
    entries = ["6.11.0-9-generic", stray, "6.8.0-51-generic"]

    # The point of the test: this used to raise TypeError, not return a list.
    ordered = sorted(entries, key=_version_key)

    assert ordered[-1] == "6.11.0-9-generic"
    assert ordered[0] == stray


def test_latest_kernel_ignores_lost_and_found(tmp_path: Path) -> None:
    modules = tmp_path / "lib" / "modules"
    for name in ("6.8.0-51-generic", "6.11.0-9-generic", "lost+found"):
        (modules / name).mkdir(parents=True)

    assert _service(tmp_path)._latest_kernel() == "6.11.0-9-generic"


def test_latest_kernel_reports_an_empty_modules_tree(tmp_path: Path) -> None:
    (tmp_path / "lib" / "modules").mkdir(parents=True)

    with pytest.raises(ValueError, match="No installed kernels"):
        _service(tmp_path)._latest_kernel()


def test_latest_kernel_reports_a_missing_modules_tree(tmp_path: Path) -> None:
    service = KernelModuleService(
        CommandRunner(dry_run=False), tmp_path, Path("work"), KernelModuleOptions()
    )

    with pytest.raises(ValueError, match="No /lib/modules directory"):
        service._latest_kernel()
