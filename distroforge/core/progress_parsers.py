from __future__ import annotations

import re

# Line -> completion-fraction parsers for the heavy build commands.
#
# These shapes were captured from the real tools (squashfs-tools 4.7.5, xorriso
# 1.5.6) over a pipe -- the production path -- and pinned as fixtures under
# tests/fixtures/progress/. The capture showed:
#   * mksquashfs/unsquashfs print only the final "[===] N/M 100%" bar frame over a
#     pipe (the live redraw is tty-gated) and then emit statistics lines that carry
#     unrelated percentages ("6.71% of uncompressed inode table size"); squashfs_progress
#     reads only the bracketed bar so those stats cannot drive the bar backwards.
#   * xorriso reports file/node COUNTS ("64 files restored"), never "% done", so
#     xorriso_progress yields no fraction for the ISO build/extract path on this
#     toolchain; the band simply completes at the step boundary.
#   * apt with APT::Status-Fd=1 emits an explicit per-item percentage -- the one
#     heavy command that streams a real fraction.
# Every parser returns None for anything it does not recognize, so a format drift
# degrades the live bar to step-level granularity rather than raising.

_PERCENT = re.compile(r"(\d+(?:\.\d+)?)\s*%")
_RATIO = re.compile(r"(\d+)\s*/\s*(\d+)")
_SQUASHFS_BAR = re.compile(r"\[[^\]]*\]\s*(\d+)\s*/\s*(\d+)\s+(\d+)\s*%")
_APT_STATUS = re.compile(r"^(?:pmstatus|dlstatus):[^:]*:(\d+(?:\.\d+)?):")


def _clamp(value: float) -> float:
    return 0.0 if value < 0.0 else 1.0 if value > 1.0 else value


def parse_percent(line: str) -> float | None:
    match = _PERCENT.search(line)
    if not match:
        return None
    return _clamp(float(match.group(1)) / 100.0)


def parse_ratio(line: str) -> float | None:
    match = _RATIO.search(line)
    if not match:
        return None
    done, total = int(match.group(1)), int(match.group(2))
    if total <= 0:
        return None
    return _clamp(done / total)


def squashfs_progress(line: str) -> float | None:
    """Read mksquashfs/unsquashfs's progress bar ``[===] 1234/65432  18%``.

    Only the bracketed bar is read, and the ``done/total`` ratio is authoritative
    (the trailing integer percent is a rounded fallback when ``total`` is 0). Stray
    percentages in mksquashfs's closing statistics, such as
    ``6.71% of uncompressed inode table size``, are deliberately ignored so the bar
    cannot jump backwards at the end of a pack.
    """
    match = _SQUASHFS_BAR.search(line)
    if not match:
        return None
    done, total, percent = int(match.group(1)), int(match.group(2)), int(match.group(3))
    if total > 0:
        return _clamp(done / total)
    return _clamp(percent / 100.0)


def xorriso_progress(line: str) -> float | None:
    """xorriso pacifier lines look like ``xorriso : UPDATE : 12.3% done``."""
    return parse_percent(line)


def apt_progress(line: str) -> float | None:
    """apt-get with ``-o APT::Status-Fd`` emits ``pmstatus:pkg:42.85:Unpacking``."""
    match = _APT_STATUS.match(line.strip())
    if not match:
        return None
    return _clamp(float(match.group(1)) / 100.0)
