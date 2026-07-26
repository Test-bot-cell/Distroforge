from __future__ import annotations

import fnmatch
import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from distroforge.cli import build_parser
from distroforge.core.definition import load_definition
from distroforge.core.packaging import REQUIRED_AUTOPKGTEST_SMOKE_CHECKS
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
    for token in REQUIRED_AUTOPKGTEST_SMOKE_CHECKS:
        assert token in smoke
    for token in (
        "distroforge.data",
        "vulndb.json",
        "load_definition",
        "validate_definition_data",
    ):
        assert token in smoke


def test_autopkgtest_declares_only_dependencies_it_uses() -> None:
    """Policy 4.9 / autopkgtest: a test dependency is a claim that the test needs it.

    debian/tests/control declared python3-pytest while the only pytest invocation in
    the tree was debian/rules at build time. The dependency pulled a package into
    every testbed for a command that was never run.
    """
    control = (ROOT / "debian/tests/control").read_text(encoding="utf-8")
    scripts = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / "debian/tests").iterdir())
        if path.is_file() and path.name != "control"
    )

    assert "python3-pytest" not in control
    assert "pytest" not in scripts
    # The Qt bindings are a Recommends, so a test that imports the GUI has to say so.
    assert "Tests: gui-import" in control
    assert "python3-pyqt6" in control
    assert "distroforge.ui.app" in scripts


def test_autopkgtest_uses_private_scratch_paths_not_fixed_tmp_names() -> None:
    for path in sorted((ROOT / "debian/tests").iterdir()):
        if not path.is_file() or path.name == "control":
            continue
        text = path.read_text(encoding="utf-8")
        # Comment lines are excluded: each script explains the fixed-path defect it fixed.
        code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))

        assert "AUTOPKGTEST_TMP" in code, path.name
        assert "/tmp/" not in code, path.name


def test_autopkgtest_installed_path_assertion_can_fail() -> None:
    """The packaged example is the only acceptable answer for an installed-package test.

    smoke used to fall back to examples/minimal-bootstrap.yaml when the packaged copy
    was absent, so debian/examples could stop shipping the file and the source tree
    sitting next to the test would keep the check green: an assertion that cannot fail.
    """
    smoke = (ROOT / "debian/tests/smoke").read_text(encoding="utf-8")

    assert "/usr/share/doc/distroforge/examples/minimal-bootstrap.yaml" in smoke
    assert 'Path("examples/minimal-bootstrap.yaml")' not in smoke
    assert "assert example.is_file()" in smoke


def test_build_depends_nocheck_names_only_tools_the_suite_runs() -> None:
    """Policy 7.7: <!nocheck> declares a package the test suite needs.

    Measured with a PATH shim that logged every invocation across a full run: xorriso
    is called 9 times and zstd once (via `tar --zstd` in the snapshot service, whose
    test fails without it). debootstrap, qemu-system-x86 and squashfs-tools were never
    invoked and never even looked up, so every arch:all build installed them for
    nothing. They stay in Depends, which is where the runtime need actually is.
    """
    control = (ROOT / "debian/control").read_text(encoding="utf-8")
    build_depends, _, binary = control.partition("\nPackage: distroforge\n")

    for package in ("xorriso", "zstd"):
        assert f" {package} <!nocheck>,\n" in build_depends
    for package in ("debootstrap", "qemu-system-x86", "squashfs-tools"):
        assert f" {package} <!nocheck>,\n" not in build_depends
        assert f" {package},\n" in binary
    # ruff has no binary package in the archive, so declaring it would make the
    # source unbuildable. The E701/E702 gate is stdlib-only for exactly that reason.
    assert "ruff" not in build_depends


def test_recommends_names_no_virtual_package_already_pulled_by_depends() -> None:
    """qemu-kvm has no candidate of its own; qemu-system-x86 provides it and is a Depends.

    A Recommends that is always already satisfied installs nothing and suggests an
    acceleration the package does not actually pull.
    """
    control = (ROOT / "debian/control").read_text(encoding="utf-8")

    assert " qemu-system-x86,\n" in control
    assert "qemu-kvm" not in control
    # The apt-package mapping, not the comment that records why it changed.
    doctor = (ROOT / "distroforge/core/doctor.py").read_text(encoding="utf-8")

    assert '"kvm": "qemu-kvm"' not in doctor
    assert '"kvm": "qemu-system-x86"' in doctor


def test_debian_rules_verifies_the_staged_package_not_the_checkout() -> None:
    """Policy 4.9 build target: the tests that gate a package must test that package.

    `python3 -m pytest -q` from the source root imported the checkout -- pyproject sets
    pythonpath = ["."] -- so a file dropped from package-data shipped a broken .deb with
    a green build log. Going through dh_auto_test also restores the pybuild loop over
    python3-all instead of testing the default interpreter only.
    """
    rules = (ROOT / "debian/rules").read_text(encoding="utf-8")

    assert "dh $@ --buildsystem=pybuild" in rules
    assert "DISTROFORGE_DEBIAN_BUILD=1 dh_auto_test" in rules
    assert "python3 -m pytest" not in rules
    assert "-o pythonpath={build_dir}" in rules
    assert "{dir}/tests" in rules
    # Rules-Requires-Root: no stays, so the suite has to remain rootless and offline.
    assert "Rules-Requires-Root: no\n" in (ROOT / "debian/control").read_text(encoding="utf-8")


def test_no_maintainer_script_pins_the_launcher_behind_the_user() -> None:
    """The GNOME favorites hook left the postinst and became a GUI question.

    Policy gives a maintainer script no way to obtain consent and dpkg no way to undo
    a dconf write, and org.gnome.shell favorite-apps lives in the user's own /home.
    The postinst had nothing else to do, so it is gone entirely -- which also restores
    dh_python3's py3compile snippet: the file carried no #DEBHELPER# token, so the
    snippet was dropped and the shipped package never byte-compiled its modules.
    """
    assert not (ROOT / "debian/distroforge.postinst").exists()
    assert not (ROOT / "debian/distroforge.preinst").exists()
    for name in ("gnome_favorites.py", "first_run.py"):
        assert any(path.name == name for path in (ROOT / "distroforge").rglob("*.py"))
    favorites = (ROOT / "distroforge/core/gnome_favorites.py").read_text(encoding="utf-8")
    first_run = (ROOT / "distroforge/ui/first_run.py").read_text(encoding="utf-8")

    assert "org.gnome.shell" in favorites
    assert "distroforge.desktop" in favorites
    assert "sudo" not in favorites
    assert "pkexec" not in favorites
    assert "save_dock_pin_choice" in first_run
    assert "unpin_launcher" in first_run


def test_latest_changelog_entry_stays_within_the_policy_line_length() -> None:
    """lintian debian-changelog-line-too-long fired on three lines of 0.3.5-2.

    Only the newest entry is reflowed: published stanzas are history and the wording
    is unchanged, only where the lines break.
    """
    lines = (ROOT / "debian/changelog").read_text(encoding="utf-8").splitlines()
    entry = lines[: next(index for index, line in enumerate(lines) if line.startswith(" -- "))]
    long_lines = [line for line in entry if len(line) > 80]

    assert long_lines == []
    assert lines[0].startswith("distroforge (")


def _stage_wheel_layout(destination: Path) -> Path:
    """Copy exactly what the wheel carries: pyproject's packages plus package-data.

    This is pybuild's {build_dir} without dpkg-buildpackage -- an emulation of the
    staged tree, not a real build, and nothing here builds a package.
    """
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    setuptools_config = pyproject["tool"]["setuptools"]
    patterns = setuptools_config["package-data"]["distroforge"]
    for package in setuptools_config["packages"]:
        source = ROOT / package.replace(".", "/")
        target = destination / package.replace(".", "/")
        target.mkdir(parents=True, exist_ok=True)
        for path in source.glob("*.py"):
            (target / path.name).write_bytes(path.read_bytes())
    for pattern in patterns:
        for path in (ROOT / "distroforge").glob(pattern):
            (destination / "distroforge" / path.relative_to(ROOT / "distroforge")).write_bytes(path.read_bytes())
    return destination


def _rules_pytest_argv(build_dir: Path, nodeid: str) -> tuple[str, ...]:
    """The arguments debian/rules hands pybuild, with the placeholders substituted.

    The trailing {dir}/tests directory is narrowed to one node id so the check costs a
    single test rather than a nested run of the whole suite.
    """
    rules = (ROOT / "debian/rules").read_text(encoding="utf-8")
    line = next(item for item in rules.splitlines() if item.startswith("export PYBUILD_TEST_ARGS="))
    args = line.partition("=")[2].replace("{build_dir}", str(build_dir)).replace("{dir}", str(ROOT))
    argv = args.split()

    assert argv[-1] == str(ROOT / "tests")
    return (sys.executable, "-m", "pytest", *argv[:-1], f"{ROOT / 'tests'}/{nodeid}")


def test_the_rules_test_arguments_import_the_staged_package_not_the_checkout(tmp_path) -> None:
    """I6, verified by reproducing pybuild's test phase rather than trusting the string.

    With `python3 -m pytest -q` from the source root, pyproject's pythonpath = ["."]
    put the checkout first: a data file dropped from package-data shipped a broken
    .deb behind a green build log. The same run against the staged tree fails.
    """
    build_dir = _stage_wheel_layout(tmp_path / "build")
    origin = subprocess.run(
        (sys.executable, "-c", "import distroforge; print(distroforge.__file__)"),
        cwd=build_dir,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": str(build_dir)},
    )

    assert origin.stdout.strip().startswith(str(build_dir))

    argv = _rules_pytest_argv(
        build_dir,
        "test_policy_compliance.py::test_bundled_vuln_database_is_available_to_vuln_scan",
    )
    environment = {**os.environ, "DISTROFORGE_DEBIAN_BUILD": "1", "QT_QPA_PLATFORM": "offscreen"}
    staged = subprocess.run(argv, cwd=build_dir, capture_output=True, text=True, env=environment)

    assert staged.returncode == 0, staged.stdout + staged.stderr

    # Drop a declared data file from the staged tree only. The checkout still has it,
    # so this fails only if the run really reads what the package would ship.
    (build_dir / "distroforge/data/vulndb.json").unlink()
    regressed = subprocess.run(argv, cwd=build_dir, capture_output=True, text=True, env=environment)

    assert regressed.returncode != 0
    assert (ROOT / "distroforge/data/vulndb.json").is_file()
