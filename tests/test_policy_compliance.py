from __future__ import annotations

import fnmatch
import json
import os
import tomllib
from pathlib import Path

import pytest

from distroforge.cli import build_parser
from distroforge.core.definition import load_definition
from distroforge.core.schema import validate_definition_data
from distroforge.core.vulnscan import VulnScanOptions, VulnScanService

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {".venv", ".git", ".pytest_cache", ".ruff_cache", "__pycache__"}
GENERATED_PACKAGE_PATHS = (
    ".pybuild",
    "build",
    "dist",
    "debian/.debhelper",
    "debian/debhelper-build-stamp",
    "debian/files",
    "debian/distroforge",
    "debian/distroforge.substvars",
    "debian/distroforge.postinst.debhelper",
    "debian/distroforge.prerm.debhelper",
)
DISALLOWED_PUBLIC_NAMES = (
    "Ubuntu" + " Forge",
    "UBUNTU" + "_FORGE",
    "ubuntu" + "-forge",
    "ubuntu" + "forge",
    "u" + "forge",
    "Distro" + " Forge",
    "distro" + "-forge",
)


def _package_data_patterns() -> tuple[str, ...]:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    package_data = pyproject["tool"]["setuptools"]["package-data"]["distroforge"]
    return tuple(str(pattern) for pattern in package_data)


def _package_data_declares(patterns: tuple[str, ...], relative_path: str) -> bool:
    return any(fnmatch.fnmatchcase(relative_path, pattern) for pattern in patterns)


def test_public_name_is_distroforge_everywhere() -> None:
    offenders: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or SKIP_DIRS & set(path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for value in DISALLOWED_PUBLIC_NAMES:
            if value in text:
                offenders.append(f"{path.relative_to(ROOT)}: {value}")

    assert offenders == []


def test_cli_prog_and_debian_package_are_distroforge() -> None:
    assert build_parser().prog == "distroforge"
    control = (ROOT / "debian/control").read_text(encoding="utf-8")

    assert "Source: distroforge\n" in control
    assert "\nPackage: distroforge\n" in control
    assert "Rules-Requires-Root: no\n" in control
    assert "Standards-Version: 4.7.3\n" in control


def test_debian_source_format_and_declared_manpages_exist() -> None:
    assert (ROOT / "debian/source/format").read_text(encoding="utf-8").strip() == "3.0 (quilt)"

    manpages = [
        line.strip()
        for line in (ROOT / "debian/manpages").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert manpages
    assert all((ROOT / item).exists() for item in manpages)
    assert all(Path(item).name.startswith("distroforge") for item in manpages)


def test_canonical_trademark_disclaimer_is_documented() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    compliance = (ROOT / "docs/debian-canonical-compliance.md").read_text(encoding="utf-8")

    assert "not affiliated with or endorsed by Canonical" in readme
    assert "Ubuntu may be mentioned only as a supported target platform" in compliance


def test_alpha_tree_has_no_generated_package_artifacts() -> None:
    if os.environ.get("DISTROFORGE_DEBIAN_BUILD") == "1":
        pytest.skip("Debian package builds create these artifacts while dh is running.")
    assert [path for path in GENERATED_PACKAGE_PATHS if (ROOT / path).exists()] == []


def test_gitignore_blocks_generated_package_artifacts() -> None:
    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8")

    for pattern in (
        ".pybuild/",
        "*.deb",
        "*.buildinfo",
        "*.changes",
        "debian/.debhelper/",
        "debian/debhelper-build-stamp",
        "debian/files",
        "debian/*.substvars",
        "debian/*.debhelper",
        "debian/distroforge/",
    ):
        assert pattern in ignored


def test_debian_clean_removes_generated_package_artifacts() -> None:
    clean = (ROOT / "debian/clean").read_text(encoding="utf-8")

    for pattern in (
        ".pybuild/",
        "*.egg-info/",
        "build/",
        "dist/",
        "debian/.debhelper/",
        "debian/debhelper-build-stamp",
        "debian/files",
        "debian/*.substvars",
        "debian/*.debhelper",
        "debian/distroforge/",
    ):
        assert pattern in clean


def test_packaged_toml_and_json_data_files_are_not_executable() -> None:
    offenders = [
        path.relative_to(ROOT)
        for path in sorted(
            list((ROOT / "distroforge/data").glob("*.toml"))
            + list((ROOT / "distroforge/data").glob("*.json"))
        )
        if path.stat().st_mode & 0o111
    ]

    assert offenders == []


def test_packaged_toml_data_files_parse_and_are_declared_as_package_data() -> None:
    package_data = _package_data_patterns()
    offenders: list[str] = []
    for path in sorted((ROOT / "distroforge/data").glob("*.toml")):
        try:
            tomllib.loads(path.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError:
            offenders.append(str(path.relative_to(ROOT)))
        assert _package_data_declares(package_data, f"data/{path.name}")

    assert offenders == []


def test_packaged_json_data_files_parse_and_vulndb_is_declared_as_package_data() -> None:
    package_data = _package_data_patterns()
    offenders: list[str] = []
    for path in sorted((ROOT / "distroforge/data").glob("*.json")):
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            offenders.append(str(path.relative_to(ROOT)))

    assert _package_data_declares(package_data, "data/vulndb.json")
    assert offenders == []


def test_bundled_vuln_database_is_available_to_vuln_scan() -> None:
    report = VulnScanService(VulnScanOptions(enabled=True)).scan(["curl", "libwebp"])
    cves = {finding.cve for finding in report.findings}

    assert "DB-UNAVAILABLE" not in cves
    assert {"CVE-2023-38545", "CVE-2023-4863"}.issubset(cves)


def test_yaml_examples_are_schema_valid_and_declared_for_debian_install() -> None:
    declared = {
        line.strip()
        for line in (ROOT / "debian/examples").read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    examples = sorted((ROOT / "examples").glob("*.yaml"))

    assert examples
    assert {str(path.relative_to(ROOT)) for path in examples} <= declared
    for path in examples:
        validate_definition_data(load_definition(path))


def test_debian_docs_include_all_referenced_project_docs() -> None:
    declared = {
        line.strip()
        for line in (ROOT / "debian/docs").read_text(encoding="utf-8").splitlines()
        if line.strip()
    }

    for path in (
        "docs/acceptance-matrix.md",
        "docs/definitions.md",
        "docs/artifacts-release-readiness.md",
        "docs/derivative-profiles.md",
        "docs/gui-parity.md",
        "docs/maintainer-copilot.md",
        "docs/packaging-release.md",
        "docs/ux-cognitive-ergonomics.md",
        "docs/velocity-responsiveness.md",
    ):
        assert path in declared
        assert (ROOT / path).exists()


def test_autopkgtest_smoke_is_meaningful_not_superficial() -> None:
    control = (ROOT / "debian/tests/control").read_text(encoding="utf-8")
    smoke = (ROOT / "debian/tests/smoke").read_text(encoding="utf-8")

    assert "superficial" not in control.lower()
    for token in (
        "distroforge --help",
        "distroforge releases",
        "distroforge doctor --python",
        "distroforge host",
        "distroforge chroot-backends",
        "distroforge packaging-policy",
        "distroforge hermetic-build-plan",
        "importlib.resources",
        "distroforge.data",
        "vulndb.json",
        "load_definition",
        "validate_definition_data",
        "/usr/share/doc/distroforge/examples/minimal-bootstrap.yaml",
    ):
        assert token in smoke
