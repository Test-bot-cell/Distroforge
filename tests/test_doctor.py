from __future__ import annotations

from distroforge.core.doctor import (
    install_packages_for_debian_dev,
    manual_install_packages_for_debian_dev,
    python_package_versions,
    run_debian_dev_doctor,
    run_python_doctor,
)


class FakeRunner:
    def __init__(self, available: set[str]) -> None:
        self.available = available

    def has_binary(self, name: str) -> bool:
        return name in self.available


def test_python_doctor_reports_required_packages() -> None:
    report = {item.binary: item for item in run_python_doctor()}

    assert report["pydantic"].available
    assert report["yaml"].available
    assert report["rich"].available
    assert report["pluggy"].available


def test_python_package_versions_have_entries() -> None:
    versions = python_package_versions()

    assert versions["pydantic"] != "-"
    assert "PyQt6" in versions
    assert "PySide6" in versions


def test_debian_dev_doctor_reports_maintainer_tool_groups() -> None:
    report = run_debian_dev_doctor(FakeRunner({"debuild", "lintian", "qemu-system-x86_64"}))  # type: ignore[arg-type]
    items = {item.binary: item for item in report}

    assert items["debuild"].available
    assert items["debuild"].apt_package == "devscripts"
    assert items["lintian"].group == "qa"
    assert items["qemu-system-x86_64"].group == "iso"
    assert not items["lb"].available
    assert items["lb"].manual_install


def test_debian_dev_install_packages_exclude_manual_live_stack_by_default() -> None:
    report = run_debian_dev_doctor(FakeRunner(set()))  # type: ignore[arg-type]

    packages = install_packages_for_debian_dev(report)
    manual_packages = manual_install_packages_for_debian_dev(report)

    assert "devscripts" in packages
    assert "live-build" not in packages
    assert manual_packages == ["live-build"]
    assert "live-build" in install_packages_for_debian_dev(report, include_manual=True)
