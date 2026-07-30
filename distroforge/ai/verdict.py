"""The severity ladder shared by every advisory report.

``AdvisorReport`` and ``ProposalReport`` both summarise a list of findings into
a single verdict with the same rule; defining it once here keeps the two reports
from drifting and gives the ladder a single home to change. The helper is
duck-typed on ``.level`` so it can live below both report modules without
importing either, which would reintroduce the forgeadvisor/proposals import
cycle.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

    from distroforge.ai.forgeadvisor import AdvisorFinding


def verdict_for_findings(findings: Iterable[AdvisorFinding]) -> str:
    """``blocked`` on any error, ``review`` on any warning, else ``informational``."""
    if any(finding.level == "error" for finding in findings):
        return "blocked"
    if any(finding.level == "warning" for finding in findings):
        return "review"
    return "informational"
