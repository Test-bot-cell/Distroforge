from __future__ import annotations

import ast
import configparser
import datetime
import fnmatch
import json
import os
import re
import subprocess
import sys
import tomllib
from email.utils import parsedate_to_datetime
from pathlib import Path

import pytest

from distroforge.cli import build_parser
from distroforge.core.definition import load_definition
from distroforge.core.packaging import REQUIRED_AUTOPKGTEST_SMOKE_CHECKS
from distroforge.core.schema import validate_definition_data
from distroforge.core.vulnscan import VulnScanOptions, VulnScanService

ROOT = Path(__file__).resolve().parents[1]
# .mypy_cache was the omission of the set: `make typecheck` creates it on every dev
# machine, its JSON holds dotted symbol names that read as addresses, and no test had
# looked inside it before the mailbox check below did.
SKIP_DIRS = {".venv", ".git", ".pytest_cache", ".ruff_cache", "__pycache__", ".mypy_cache"}
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


def test_no_test_module_makes_a_temporary_directory_at_import_time() -> None:
    """Nothing removes a directory created while a module is being imported.

    Six modules used to redirect the config home for themselves, at import, with
    `os.environ.setdefault("XDG_CONFIG_HOME", tempfile.mkdtemp())`. `setdefault`
    evaluates its second argument before it decides whether to keep it, so all six
    created a directory and five were discarded unused -- and nothing removed the
    sixth either. Measured 2026-07-27, before the fix: 1425 had accumulated under
    /tmp, 241 of them holding a `ui.json`, and a full run added six more.

    The redirection now lives once in tests/conftest.py, on `tmp_path_factory`,
    whose base directory pytest rotates. This guard is about import time only:
    inside a test or a fixture, `tmp_path` and `tmp_path_factory` are available and
    `mkdtemp` is a choice rather than the only reachable option.
    """
    offenders: list[str] = []
    for path in sorted((ROOT / "tests").glob("*.py")):
        module = ast.parse(path.read_text(encoding="utf-8"))
        for statement in module.body:
            # A def or a class body runs when it is called, not when it is imported.
            if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                continue
            for node in ast.walk(statement):
                if not isinstance(node, ast.Call):
                    continue
                name = node.func.attr if isinstance(node.func, ast.Attribute) else None
                if name in {"mkdtemp", "mkstemp"}:
                    offenders.append(f"{path.name}:{node.lineno}: {name}()")

    assert offenders == [], (
        "temporary paths created at import time are never cleaned up; "
        f"use a fixture on tmp_path/tmp_path_factory instead: {offenders}"
    )


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


def test_the_maintainer_address_is_one_that_can_receive_mail() -> None:
    """Policy 3.3, not 5.6.2: the Maintainer field is a mailbox, not a signature.

    5.6.2 governs only the field's syntax. The substantive rule is 3.3, "The maintainer
    of a package", and it asks for more than not bouncing: the address "must accept mail
    from those role accounts in Debian used to send automated mails regarding the
    package", naming the bug-tracking system and the archive maintenance software. An
    over-eager spam filter violates it as surely as a dead domain does -- see #1063752,
    filed at serious severity against a package whose maintainer address rejected
    ftpmaster's mail over DMARC, and reassigned to lists.debian.org once the cause was
    found in the list's own configuration.

    This tree carried maintainers@distroforge.invalid for its whole history, and the
    obvious next mistake is a GitHub noreply -- correct as a commit author identity,
    which is what the repository already uses, and inbound-blocked by design.

    Nothing upstream of this test catches either. lintian's bogus-mail-host fires only
    `unless is_domain($host)`, and Net::Domain::TLD counts invalid, test, example and
    localhost as existing TLDs because RFC 2606 reserves them, so is_domain() returns
    true for all four; mail-address-loops-or-bounces holds exactly one address, and it
    is ubuntu-devel-discuss. Measured 2026-07-27: the package linted clean, built
    clean, and was not uploadable.

    A negative check on purpose. Proving an address really delivers needs mail sent to
    it, which no offline suite can do -- see debian/README.source for the manual step.
    This rules out the classes that provably cannot.
    """
    control = (ROOT / "debian/control").read_text(encoding="utf-8")
    field = next(line for line in control.splitlines() if line.startswith("Maintainer:"))
    _, _, address = field.partition("<")
    address = address.rstrip(">").strip()
    host = address.rpartition("@")[2].lower()

    assert host, f"no host in Maintainer address: {field}"
    # RFC 2606 reserves these so they can never resolve. Right for test fixtures --
    # tests/test_gpg_signer_pinning.py and tests/test_packaging_reports.py keep using
    # them, deliberately -- and disqualifying here.
    assert host.rpartition(".")[2] not in {"invalid", "test", "example", "localhost"}
    assert not host.endswith("noreply.github.com"), (
        "GitHub noreply addresses reject all inbound mail by design"
    )


PUBLISHED_MAILBOXES = frozenset(
    {
        # debian/control, debian/copyright and every changelog trailer from 0.3.5-10 on.
        "github@distroforge.anonaddy.com",
        # The changelog entries up to 0.3.5-9, README.source quoting them, and the two
        # fixtures that deliberately want an address RFC 2606 guarantees cannot receive.
        "maintainers@distroforge.invalid",
        "probe@distroforge.invalid",
    }
)
_MAILBOX = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def test_no_file_in_the_tree_names_a_mailbox_that_is_not_a_published_identity() -> None:
    """An allowlist, deliberately, and not a list of addresses to keep out.

    What is being protected is a personal mailbox, and this repository is public: a
    denylist would have to spell that address out here in order to check for it, which
    publishes the very thing it is meant to withhold. So the check inverts. Three
    addresses may appear anywhere in the tree; a fourth fails, whoever it belongs to.

    Measured 2026-07-27 over every tracked file: exactly those three, 56 occurrences, and
    nothing else. The maintainer's signing key does carry a personal user id, which no
    code path in this tool exports -- signing produces detached signatures, which carry a
    key id and no user ids, and the only keyring written into an image is a third party's,
    fetched from a keyserver by fingerprint. The address has never appeared in this tree
    nor anywhere in its history, and every commit is authored by the GitHub noreply. This
    check is what keeps that true the day someone commits a keyring, a signature, a
    changelog trailer or a copyright stanza. docs/packaging-release.md carries the rest:
    the filtered export for the one moment a public key does get published.
    """
    offenders: list[str] = []
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or SKIP_DIRS & set(path.parts):
            continue
        relative = path.relative_to(ROOT).as_posix()
        # Build output belongs to whatever dh last ran here, not to this tree.
        if any(relative.startswith(generated) for generated in GENERATED_PACKAGE_PATHS):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for mailbox in _MAILBOX.findall(text):
            if mailbox.lower() not in PUBLISHED_MAILBOXES:
                offenders.append(f"{relative}: {mailbox}")

    assert offenders == []


def test_a_documented_key_export_cannot_publish_an_unfiltered_key() -> None:
    """The export lives in a procedure, so the procedure is what gets guarded.

    Nothing in this tool exports a public key, so there is no function to check. The only
    place the maintainer's key is ever exported is the command written down in
    docs/packaging-release.md, for the day an apt repository needs a `signed-by=` keyring
    that anyone can verify against. `gpg --export` without `--export-filter` writes every
    user id on the key into that keyring, which for this key means a personal mailbox
    handed to everyone who installs from the archive.

    Verified 2026-07-27 that the documented form does what it claims: the whole key
    exports as 3579 bytes with three user ids, the filtered form as 2930 with the two
    published ones, and the filtered export imported into an empty GNUPGHOME verifies a
    real signature made by that key while an empty keyring rejects it. Also asserts the
    procedure still exists -- deleting it would leave nothing for this test to check and
    no filter for the next person to copy.
    """
    documented = 0
    for path in sorted((ROOT / "docs").glob("*.md")):
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(r"gpg --export\b", text):
            documented += 1
            # The command wraps, so the flag sits on a later line of the same invocation.
            window = text[match.start() : match.start() + 200]
            assert "--export-filter" in window, (
                f"{path.name}: an unfiltered key export publishes every user id"
            )

    assert documented, "the filtered export procedure is no longer documented anywhere"


def test_the_maintainer_stamped_into_generated_debs_tracks_debian_control() -> None:
    """The address DistroForge writes into other people's packages, not just its own.

    `_DEB_MAINTAINER` is printed straight into the `DEBIAN/control` of every desktop
    component .deb the tool assembles (distroforge/core/desktop_source.py, the
    `dpkg-deb --build` command), so it reaches end users rather than staying inside
    this source tree. It carried a comment promising it was "kept in step with the
    Maintainer field of debian/control" and nothing enforced that promise, which is
    the shape that goes stale silently: correcting one of the two leaves the other
    behind, and the divergence surfaces in a stranger's package.

    Deliberately a coupling assertion and not a spelling one -- it states that the two
    agree, not what they say, so it survives the address changing and fails only if
    the change misses a site. Debian Policy 3.3 requires the maintainer address to be a
    working one -- 5.6.2 governs only the field's syntax, as the test 130 lines above this
    one says -- and neither lintian check reaches this constant: `bogus-mail-host`
    fires only when the host is not a domain, and `.invalid` is a domain as far as
    Net::Domain::TLD is concerned (it is an RFC 2606 reserved TLD, present in that
    list), while `mail-address-loops-or-bounces` knows exactly one address.
    """
    from distroforge.core.desktop_source import _DEB_MAINTAINER

    control = (ROOT / "debian/control").read_text(encoding="utf-8")
    declared = [
        line.partition(":")[2].strip()
        for line in control.splitlines()
        if line.startswith("Maintainer:")
    ]

    assert len(declared) == 1, f"expected exactly one Maintainer field, found {len(declared)}"
    assert _DEB_MAINTAINER == declared[0]


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


# Fixed on purpose rather than strftime("%a"): Python leaves LC_TIME at C, but this
# suite is run on a French machine and a single locale.setlocale anywhere in a future
# test would turn Mon into lun. and make the weekday assertion below fail on a correct
# changelog. RFC 5322 names the days in English regardless.
_WEEKDAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")


def test_every_changelog_trailer_date_is_one_that_had_already_happened() -> None:
    """Four consecutive entries named a time that had not arrived yet.

    Measured 2026-07-27 by comparing every trailer against the author date of the commit
    that introduced its line: 0.3.5-7 was 3 minutes ahead of its own commit, 0.3.5-8 was
    13, 0.3.5-9 was 146 and 0.3.5-10 was 160 -- the last two still in the future two
    hours later. Nothing said so. lintian's changelog check reads the newest entry's
    weekday, a short list of textually invalid dates, and whether the newest entry is
    newer than the one directly below it; there is no future-date tag at all, and nothing
    under the top two entries is looked at. So the package linted clean while claiming to
    have been released two and a half hours after it was built.

    The date is not decoration: dpkg-parsechangelog hands it to the archive as the
    release date of that version, and it is what an upload and a bug report are dated
    against. The defect is writing it by estimating the clock instead of reading it, so
    the check has to sit at the moment of writing -- which it does, through the
    changelog-policy pre-commit hook, whose `-k changelog` selection picks this up on any
    change to the file.

    Weaker than it looks, deliberately: once real time passes a fabricated date the date
    is no longer in the future and this stops catching it. It catches every such entry at
    the commit that introduces it, which is when it can still be corrected for free. The
    two checks either side of it hold permanently -- the weekday, and strict ordering
    across the whole file rather than lintian's top pair. Entries at 0.3.5-2 and below
    predate this git repository; their dates are the original packaging record, not a
    reading of this repository's clock, and are left alone.
    """
    lines = (ROOT / "debian/changelog").read_text(encoding="utf-8").splitlines()
    trailers: list[tuple[str, str, datetime.datetime]] = []
    version = ""
    for line in lines:
        if line.startswith("distroforge ("):
            version = line.partition("(")[2].partition(")")[0]
        elif line.startswith(" -- "):
            declared = line.partition(">")[2].strip()
            # Raises on anything RFC 5322 cannot read, which is the check dpkg makes.
            trailers.append((version, declared, parsedate_to_datetime(declared)))

    assert len(trailers) == sum(1 for line in lines if line.startswith("distroforge (")), (
        "every changelog entry carries exactly one trailer"
    )
    # Two minutes of grace for the clock difference between the machine that writes an
    # entry and the runner that checks it. The smallest fabrication measured here was
    # three minutes ahead of its own commit, so the grace does not swallow the defect.
    latest_allowed = datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=2)
    for version, declared, stamp in trailers:
        assert stamp <= latest_allowed, f"{version} is dated in the future: {declared}"
        actual = _WEEKDAYS[stamp.weekday()]
        assert declared.partition(",")[0] == actual, (
            f"{version} says {declared.partition(',')[0]}, but {stamp.date()} was a {actual}"
        )

    for (newer, shown, newer_stamp), (older, _, older_stamp) in zip(
        trailers, trailers[1:], strict=False
    ):
        assert newer_stamp > older_stamp, f"{newer} ({shown}) is not newer than {older}"


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


def _git(*args: str) -> subprocess.CompletedProcess[str]:
    """Shell out to git, making an absent git look the way a failed git call looks.

    The distro-dependencies job installs distribution packages only and git is not one of
    them, so actions/checkout there falls back to the REST tarball: that leg runs with no
    git binary and no .git directory at all. Without this, the first call raised
    FileNotFoundError and turned "there is no history here to check" into a failing suite,
    which is what it did on the commit that introduced these tests.
    """
    try:
        return subprocess.run(
            ["git", "-C", str(ROOT), *args], capture_output=True, text=True, check=False
        )
    except OSError as error:
        return subprocess.CompletedProcess(
            args=("git", *args), returncode=127, stdout="", stderr=str(error)
        )


def _git_history_available() -> bool:
    return _git("rev-parse", "--git-dir").returncode == 0


def test_gbp_conf_names_only_things_this_repository_actually_has() -> None:
    """The release configuration named a branch that has never existed here.

    `debian/gbp.conf` carried `upstream-branch = upstream` from the 0.3.5-1 baseline
    import onward, while `distroforge doctor` lists gbp as this package's release
    workflow. There is no `upstream` branch and there never was -- upstream and the
    packaging are one tree -- so the first gbp command to resolve it would have failed.
    Nothing caught that because nothing had ever run the workflow: 46 changelog versions
    and not one tag.

    The tag format and `sign-tags` are asserted by value and not merely for presence.
    Both match gbp 0.9.42's own defaults, which makes this look redundant and is exactly
    why it is not: gbp/git/repository.py passes `--no-sign` when `sign-tags` is unset,
    overriding `tag.gpgsign = true` in the repository config, so an unpinned file yields
    an unsigned release tag over commits that are all signed. And what a release tag is
    called is a contract, which must not change because a different gbp ran the command
    -- the same reasoning that keeps Rules-Requires-Root written out in debian/control.

    interpolation=None is required rather than stylistic: the value holds `%(version)s`
    and a default ConfigParser raises InterpolationMissingOptionError reading it.
    """
    parser = configparser.ConfigParser(interpolation=None)
    read = parser.read(ROOT / "debian/gbp.conf", encoding="utf-8")
    assert read, "debian/gbp.conf is unreadable or gone"

    maintained = {"main", "develop"}
    defaults = parser["DEFAULT"]
    for option in ("debian-branch", "upstream-branch"):
        assert defaults[option] in maintained, (
            f"gbp.conf {option} = {defaults[option]!r}, which is not a branch this project keeps"
        )
    assert defaults["debian-tag"] == "debian/%(version)s", "DEP-14 names the packaging tag"
    assert defaults["sign-tags"] == "True", "gbp writes --no-sign unless this says True"
    assert parser["buildpackage"]["upstream-tree"] == "BRANCH", (
        "gbp's default is TAG, which hunts for an upstream/<version> tag this workflow never cuts"
    )

    # The value check above cannot see a branch that was renamed away, so resolve them for
    # real where the refs are there to resolve. A shallow checkout has only the branch it
    # was made from, which is what actions/checkout produces by default, so asking there
    # would fail over the fetch depth rather than over the configuration.
    if (
        not _git_history_available()
        or _git("rev-parse", "--is-shallow-repository").stdout.strip() != "false"
    ):
        return
    for option in ("debian-branch", "upstream-branch"):
        name = defaults[option]
        resolved = any(
            _git("rev-parse", "--verify", "--quiet", ref).returncode == 0
            for ref in (f"refs/heads/{name}", f"refs/remotes/origin/{name}")
        )
        assert resolved, f"gbp.conf {option} names {name!r}, which no ref in this repository resolves"


def test_every_packaging_tag_names_the_version_its_own_commit_declares() -> None:
    """A tag is a claim about which commit a version is, so the claim gets checked.

    Nothing anchored a released version to a commit: 46 versions in debian/changelog and
    zero tags, local or on the remote. The risk once tags exist is the mislabelled one --
    `debian/0.3.5-15` sitting on a commit whose changelog says something else -- because
    that misdirects anyone bisecting a regression or reproducing an upload, and no
    amount of signing catches it.

    Read from the tagged commit's own changelog rather than from the working tree, so it
    answers "does this tag name what its commit claimed to be" and not "does it match
    whatever is checked out now". The mangling is deliberately restated here from DEP-14
    rather than imported from gbp: gbp is not installed on the CI runners, and a test that
    recomputes the invariant independently disagrees loudly if the implementation drifts.
    """
    if not _git_history_available():
        pytest.skip("no git binary or no .git here, so there is no history to check")

    listed = _git("tag", "--list", "debian/*")
    assert listed.returncode == 0, listed.stderr
    tags = [line.strip() for line in listed.stdout.splitlines() if line.strip()]
    if not tags:
        pytest.skip(
            "no packaging tags here: actions/checkout fetches none by default, so this "
            "gate is real in packaging-static, which sets fetch-depth: 0, and in any "
            "full clone, and vacuous in the matrix jobs"
        )

    changelog = (ROOT / "debian/changelog").read_text(encoding="utf-8")
    known_versions = set(re.findall(r"^distroforge \(([^)]+)\)", changelog, re.MULTILINE))

    for tag in tags:
        assert _git("cat-file", "-t", tag).stdout.strip() == "tag", (
            f"{tag} is a lightweight tag, so it carries neither a tagger nor a signature"
        )
        assert "-----BEGIN PGP SIGNATURE-----" in _git("cat-file", "tag", tag).stdout, (
            f"{tag} is unsigned, over commits that are all signed"
        )

        shown = _git("show", f"{tag}:debian/changelog")
        assert shown.returncode == 0, f"{tag} has no debian/changelog: {shown.stderr.strip()}"
        declared = re.match(r"^distroforge \(([^)]+)\)", shown.stdout.splitlines()[0])
        assert declared, f"{tag} points at a commit whose changelog has no version line"

        version = declared.group(1)
        expected = "debian/" + version.replace(":", "%").replace("~", "_").replace("..", ".#.")
        assert tag == expected, f"{tag} sits on a commit whose changelog declares {version}"
        assert version in known_versions, (
            f"{tag} names {version}, which the current changelog no longer records"
        )


def test_the_release_tag_procedure_is_wired_to_something() -> None:
    """Same shape as the key-export guard: the procedure is what there is to check.

    A convention pinned in debian/gbp.conf and a script nobody calls would be the defect
    this whole change was about -- configuration that reads correctly and runs never. So
    this asserts the three ends are joined: the Makefile has a `tag` target, the target
    runs the script, the script is executable, and a document explains it. Deleting any
    one of them fails here instead of quietly leaving the next version unanchored.
    """
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert re.search(r"^tag:\n\ttools/release-tag\.sh$", makefile, re.MULTILINE), (
        "the Makefile tag target no longer runs tools/release-tag.sh"
    )
    assert re.search(r"^\.PHONY:.*\btag\b", makefile, re.MULTILINE), (
        "tag is not phony, so a file named tag would silence the target"
    )

    script = ROOT / "tools/release-tag.sh"
    assert script.is_file(), "tools/release-tag.sh is gone"
    assert os.access(script, os.X_OK), "tools/release-tag.sh is not executable"

    documented = [
        path.name
        for path in sorted((ROOT / "docs").glob("*.md"))
        if "tools/release-tag.sh" in path.read_text(encoding="utf-8")
    ]
    assert documented, "no document explains how a release version gets anchored to a commit"


def test_no_finalized_changelog_revision_is_left_without_a_release_tag() -> None:
    """The revision number was a commit counter. Measured, and it is not a Policy breach.

    Debian Policy says less here than it is usually quoted as saying: 4.4 carries no
    one-revision-per-upload requirement, 3.2.2 states outright that the Debian revision
    "doesn't need to start at 1 or be consecutive", and the only hard rule in the area --
    never reuse a version number -- is scoped to "once the package has been accepted into
    the archive", which this package never has been. dpkg goes further and contradicts the
    strict reading: `dpkg-parsechangelog -v<older>` folds every newer stanza into one
    upload's Changes field, measured on this tree as one Version with four stanza headers
    inside it. So this gate is not enforcing Policy. It is enforcing that a version number
    means something here.

    What it was worth, measured 2026-07-27 at 0.3.5-17: 16 finalized revisions, of which
    exactly one carries a tag and one more is installed on the maintainer's machine, 0
    GitHub releases -- 14 revisions naming a package that exists nowhere. Fifteen of the
    seventeen were written inside 23.7 hours and fourteen inside 11.6.

    The cadence that replaces it is what devscripts and gbp already assume rather than an
    invention: one UNRELEASED stanza collects bullets for a whole cycle, `dch -r`
    finalizes it at release, and `make tag` anchors it. UNRELEASED is a devscripts idea,
    not a dpkg or Policy one -- the string appears nowhere in either manual -- and the
    strongest machine-readable opinion about it is a lintian tag at severity *info*.

    Positional, not by version comparison: stanzas are newest-first and the trailer test
    above already asserts strict date ordering across the whole file, so "above the newest
    tagged stanza" is a checked property and needs no dpkg. A ratchet, like the typing
    one: the 15 untagged revisions below the tag are grandfathered history that cannot be
    anchored after the fact, while finalizing the next one without tagging it fails here.
    """
    lines = (ROOT / "debian/changelog").read_text(encoding="utf-8").splitlines()
    stanzas = [
        (match.group(1), match.group(2).split()[0])
        for line in lines
        if (match := re.match(r"^distroforge \(([^)]+)\)\s+([^;]+);", line))
    ]
    assert stanzas, "debian/changelog has no version line"

    # The cumulative half of the cadence, and the half that needs no git: a second open
    # stanza is the old habit returning under a new name.
    open_entries = [version for version, suite in stanzas if suite.upper() == "UNRELEASED"]
    assert len(open_entries) <= 1, (
        f"{len(open_entries)} entries are open at once ({', '.join(open_entries)}); a cycle "
        "collects its bullets in one UNRELEASED entry"
    )
    if open_entries:
        assert stanzas[0][0] == open_entries[0], (
            f"{open_entries[0]} is UNRELEASED but sits below {stanzas[0][0]}, so a finalized "
            "entry was written on top of an unreleased one"
        )

    if not _git_history_available():
        pytest.skip("no git binary or no .git here, so there is no history to check")
    listed = _git("tag", "--list", "debian/*")
    assert listed.returncode == 0, listed.stderr
    anchored = {line.strip() for line in listed.stdout.splitlines() if line.strip()}
    if not anchored:
        pytest.skip(
            "no packaging tags here: actions/checkout fetches none by default, so this "
            "gate is real in packaging-static, which sets fetch-depth: 0, and in any "
            "full clone, and vacuous in the matrix jobs"
        )

    for version, suite in stanzas:
        # DEP-14 mangling restated as it is above, and for the same reason: gbp is not
        # installed on the runners, and an independent recomputation disagrees loudly.
        tag = "debian/" + version.replace(":", "%").replace("~", "_").replace("..", ".#.")
        if tag in anchored:
            return
        assert suite.upper() == "UNRELEASED", (
            f"{version} is finalized as {suite!r} and carries no {tag}, so it names a "
            "release that exists nowhere -- either tag it with `make tag` or fold its "
            "bullets back into the open entry"
        )
    pytest.skip("no entry in this changelog is tagged, so there is no anchor to measure from")



_COMMIT_TYPES = (
    "build",
    "chore",
    "ci",
    "docs",
    "feat",
    "fix",
    "perf",
    "refactor",
    "revert",
    "style",
    "test",
)
_SUBJECT = re.compile(rf"^({'|'.join(_COMMIT_TYPES)})(\([a-z0-9][a-z0-9./_-]*\))?!?: \S")


def test_every_commit_subject_carries_a_type_the_log_can_be_filtered_by() -> None:
    """A convention followed by 58 commits out of 58 and written down nowhere.

    Measured 2026-07-27: every subject in this repository's history carries a Conventional
    Commits type prefix -- 38 `fix:`, 6 `docs:`, 5 `feat:`, 3 `ci:`, 2 `test:`, and one
    each of refactor, perf, chore and build -- and no file in the tree documented it, no
    hook checked it and no test asserted it. That is the shape of thing this project
    treats as a defect on its own: a rule everyone follows and nothing protects.

    The optional scope field is deliberately not required. Requiring it would split the
    history into two regimes, because the 58 existing commits are signed and cannot be
    rewritten to add one. The argument for scopes is that `git log --oneline | grep <zone>`
    should find a zone's commits, and that argument does not survive measurement: grepping
    subjects for a zone word recovers 10-36% of the commits that actually touched that
    zone, while `git log -- <path>` recovers all of them. The pathspec is the zone filter.
    The type prefix is what a subject cannot supply any other way, so that is what is
    gated.

    The negative cases run first and are not decoration. The failure mode of a
    pattern-matching gate is a pattern that accepts everything, which passes silently
    forever; these four shapes are the ones a `grep`-flavoured rewrite would start letting
    through.
    """
    for rejected in ("Fix the vendor lookup", "wip", "fix the vendor lookup", "fix:no space"):
        assert not _SUBJECT.match(rejected), f"the subject gate accepts {rejected!r}"

    if not _git_history_available():
        pytest.skip("no git binary or no .git here, so there is no history to check")
    log = _git("log", "--format=%s")
    assert log.returncode == 0, log.stderr
    subjects = [line for line in log.stdout.splitlines() if line.strip()]
    if not subjects:
        pytest.skip("no commits reachable from here")

    offenders = [subject for subject in subjects if not _SUBJECT.match(subject)]
    assert offenders == [], (
        "these subjects carry no Conventional Commits type, so `git log` cannot be "
        f"filtered by kind of change: {offenders}"
    )
