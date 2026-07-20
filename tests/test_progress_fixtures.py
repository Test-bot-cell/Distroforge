from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from distroforge.core.progress_parsers import apt_progress, squashfs_progress, xorriso_progress

# These tests pin the parsers against progress output captured from the real tools
# (see the header of each fixture). They run fully offline -- no tool is executed --
# so they stay deterministic under CI, buildd, and autopkgtest restrictions, and
# never write an artifact (Rules-Requires-Root: no). When the toolchain is upgraded,
# re-capture the fixtures by hand (the capture method is recorded in each fixture's
# header) rather than executing a tool from the suite.

_FIXTURES = Path(__file__).parent / "fixtures" / "progress"


def _lines(name: str) -> list[str]:
    text = (_FIXTURES / name).read_text(encoding="utf-8")
    return [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]


@pytest.mark.parametrize("name", ["mksquashfs.txt", "unsquashfs.txt"])
def test_squashfs_fixture_yields_only_the_terminal_frame(name: str) -> None:
    observed = [f for f in (squashfs_progress(line) for line in _lines(name)) if f is not None]
    # Over a pipe the real tools emit a single bar frame at 100%; the closing
    # statistics carry stray percentages that must NOT be read as progress.
    assert observed == [pytest.approx(1.0)]


@pytest.mark.parametrize("name", ["xorriso-build.txt", "xorriso-extract.txt"])
def test_xorriso_fixture_yields_no_fraction(name: str) -> None:
    # Real xorriso reports file/node counts, never "% done": no fraction is available.
    assert all(xorriso_progress(line) is None for line in _lines(name))


def test_apt_fixture_streams_expected_fractions() -> None:
    observed = [f for f in (apt_progress(line) for line in _lines("apt-status-fd.txt")) if f is not None]
    # Download reports 10% then install restarts at 0%, so the stream is not globally
    # monotonic, but every value is a real in-range fraction.
    assert observed == [pytest.approx(p) for p in (0.10, 0.0, 0.428571, 1.0)]
    assert all(0.0 <= f <= 1.0 for f in observed)


@pytest.mark.parametrize(
    "name,parser",
    [
        ("mksquashfs.txt", squashfs_progress),
        ("unsquashfs.txt", squashfs_progress),
        ("xorriso-build.txt", xorriso_progress),
        ("xorriso-extract.txt", xorriso_progress),
        ("apt-status-fd.txt", apt_progress),
    ],
)
def test_no_parser_raises_on_real_lines(name: str, parser: Callable[[str], float | None]) -> None:
    for line in _lines(name):
        result = parser(line)
        assert result is None or 0.0 <= result <= 1.0
