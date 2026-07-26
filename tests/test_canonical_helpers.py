from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "distroforge"

# Four helpers had been copy-pasted across the release chain, and copies drift:
# the six _read_json bodies had grown three different answers to the same
# question, and the GUI's private shell-quoting helper had diverged into a version
# that let anything without a space through raw.
#
# One source of truth each, guarded here so the copies cannot come back quietly.


def _sources() -> dict[str, str]:
    return {
        path.relative_to(ROOT).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(SOURCE_ROOT.rglob("*.py"))
    }


def test_only_hashing_defines_a_file_digest_helper() -> None:
    offenders = {
        rel: text.count("def _sha256(")
        for rel, text in _sources().items()
        if "def _sha256(" in text
    }

    assert offenders == {}, f"use core.hashing.sha256_file instead: {offenders}"


def test_only_jsonio_defines_a_plain_json_object_reader() -> None:
    # release_verification keeps its own: it appends a verdict to a report rather
    # than answering what is in the file, which is a different contract.
    allowed = {"distroforge/core/release_verification.py"}
    offenders = {
        rel: text.count("def _read_json(")
        for rel, text in _sources().items()
        if "def _read_json(" in text and rel not in allowed
    }

    assert offenders == {}, f"use core.jsonio instead: {offenders}"


def test_no_module_hand_rolls_shell_quoting() -> None:
    # The hand-rolled versions were "'" + value.replace(...) + "'" and, worse, a
    # variant that returned anything whitespace-free unquoted.
    hand_rolled = re.compile(r"def _shell_quote\(|\"'\" \+ \w+\.replace")
    offenders = [rel for rel, text in _sources().items() if hand_rolled.search(text)]

    assert offenders == [], f"use shlex.quote instead: {offenders}"


def test_the_options_dataclass_has_no_dead_duplicate_of_the_cache_flag() -> None:
    # BuildOptions.clean_apt_cache was never read anywhere in the tree and shadowed
    # SanitizeOptions.apt_cache, which is the one the pipeline honours.
    build = (SOURCE_ROOT / "core" / "build.py").read_text(encoding="utf-8")
    sanitize = (SOURCE_ROOT / "core" / "sanitize.py").read_text(encoding="utf-8")

    assert "clean_apt_cache" not in build
    assert "apt_cache: bool" in sanitize


def test_no_test_reads_a_source_path_relative_to_the_working_directory() -> None:
    # pybuild runs the test phase from the staged build tree, so a bare relative path
    # to a source file reads the installed copy, and one under debian/ does not resolve
    # at all -- which is exactly how tests/test_app_icon.py failed the packaged build.
    # Anchor at ROOT = Path(__file__).resolve().parents[1] instead. The needle is
    # assembled from two pieces so this guard is not its own first offender.
    needle = 'Path("' + "distroforge/"
    offenders = {
        path.name: [
            number
            for number, line in enumerate(path.read_text(encoding="utf-8").split("\n"), start=1)
            if needle in line
        ]
        for path in sorted((ROOT / "tests").glob("*.py"))
        if needle in path.read_text(encoding="utf-8")
    }

    assert offenders == {}, f"anchor these at the source root: {offenders}"


def test_command_display_quotes_every_part() -> None:
    from distroforge.core.command import CommandSpec

    # The printed plan is read and re-run by operators, so a part carrying shell
    # meaning without whitespace must not come out bare. It used to: the helper
    # only quoted values containing whitespace.
    rendered = CommandSpec(argv=("echo", "$(id)", "*", "~root")).display()

    assert rendered == "echo '$(id)' '*' '~root'"
    # A plain word still reads naturally, so ordinary plans are unchanged.
    assert CommandSpec(argv=("tar", "-xf", "a.tar")).display() == "tar -xf a.tar"
