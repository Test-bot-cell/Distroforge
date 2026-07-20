"""Ring 2 of the advisory agent: previewable fix proposals that are never applied.

The advisory-agent contract (``docs/advisory-agent.md``) lets Ring 2 "produce
multi-step plans, previewable option diffs and recipes -- all as inspectable
previews. Nothing is applied." This module is the data structure for that ring.

Two guarantees keep the prime directive intact:

* **Grounded, never invented.** Steps are the remediations the deterministic
  layers already emit (``core.build_diagnosis`` / ``core.readiness`` /
  ``core.dry_run_report``); an option diff is only proposed when a *present*
  finding's own remediation unambiguously implies a single, safe build-option
  change, and only when the current value actually differs (never a no-op).
* **Preview only.** Nothing here mutates a ``Project``, ``BuildOptions`` or the
  runner. A proposed change is recorded as a before/after string the user must
  apply themselves through the existing explicit-action wall (Ring 3).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

    from distroforge.ai.forgeadvisor import AdvisorFinding
    from distroforge.core.build import BuildOptions

# Rendered verbatim wherever a proposal is shown; it is the visible promise of the
# hard wall, and a test asserts the agent never reaches an engine mutation.
PREVIEW_ONLY_STATUS = "preview only - nothing is applied"


@dataclass(frozen=True)
class ProposalStep:
    """One ordered, previewable remediation drawn from a real finding."""

    order: int
    level: str
    code: str
    action: str

    def to_dict(self) -> dict[str, object]:
        return {"order": self.order, "level": self.level, "code": self.code, "action": self.action}


@dataclass(frozen=True)
class OptionChange:
    """A single build-option change a finding implies, recorded but not applied."""

    option: str
    current: str
    proposed: str
    rationale: str

    def to_dict(self) -> dict[str, object]:
        return {
            "option": self.option,
            "current": self.current,
            "proposed": self.proposed,
            "rationale": self.rationale,
        }


@dataclass
class ProposalReport:
    """A previewable plan: ordered steps plus any grounded option diff."""

    title: str
    backend: str = "offline"
    register: str = "Beginner"
    findings: list[AdvisorFinding] = field(default_factory=list)
    steps: list[ProposalStep] = field(default_factory=list)
    option_changes: list[OptionChange] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        if any(finding.level == "error" for finding in self.findings):
            return "blocked"
        if any(finding.level == "warning" for finding in self.findings):
            return "review"
        return "informational"

    def to_dict(self) -> dict[str, object]:
        return {
            "title": self.title,
            "backend": self.backend,
            "register": self.register,
            "verdict": self.verdict,
            "status": PREVIEW_ONLY_STATUS,
            "option_changes": [change.to_dict() for change in self.option_changes],
            "steps": [step.to_dict() for step in self.steps],
            "notes": self.notes,
        }

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def render_text(self) -> str:
        lines = [
            f"ForgeAdvisor: {self.title}",
            f"Backend: {self.backend}",
            f"Register: {self.register}",
            f"Verdict: {self.verdict}",
            f"Status: {PREVIEW_ONLY_STATUS}",
        ]
        if self.notes:
            lines.extend(["", "Notes:"])
            lines.extend(f"- {note}" for note in self.notes)
        lines.extend(["", "Proposed option changes (preview - not applied):"])
        if not self.option_changes:
            lines.append(
                "- none: no build option change is safe to propose automatically; follow the plan below."
            )
        for change in self.option_changes:
            lines.append(f"- {change.option}: {change.current} -> {change.proposed}")
            lines.append(f"      why: {change.rationale}")
        lines.extend(["", "Remediation plan (preview - not applied):"])
        if not self.steps:
            lines.append("- no remediation steps: the reviewed build raised nothing to act on.")
        for step in self.steps:
            lines.append(f"{step.order}. [{step.level}] {step.code}: {step.action}")
        return "\n".join(lines)


def _ordered_unique_findings(findings: Sequence[AdvisorFinding]) -> list[AdvisorFinding]:
    """Errors before warnings, deduplicated by canonical code (the finding title).

    Readiness and the dry-run can surface the same canonical issue under
    different source prefixes; the plan shows each issue once, keeping the most
    severe instance.
    """
    ordered = sorted(findings, key=lambda finding: 0 if finding.level == "error" else 1)
    seen: set[str] = set()
    unique: list[AdvisorFinding] = []
    for finding in ordered:
        if finding.title in seen:
            continue
        seen.add(finding.title)
        unique.append(finding)
    return unique


def _option_changes(findings: Sequence[AdvisorFinding], options: BuildOptions) -> list[OptionChange]:
    """Build-option diffs implied unambiguously by a present finding.

    Only mappings grounded in a real remediation belong here. ``privilege-disabled``
    (from ``core.dry_run_report``) literally asks to enable the privilege helper, so
    when it is present and ``use_sudo`` is off we preview that one flip -- never a
    no-op, never anything the remediation does not call for.
    """
    changes: list[OptionChange] = []
    privilege_disabled = next((finding for finding in findings if finding.title == "privilege-disabled"), None)
    if privilege_disabled is not None and options.use_sudo is False:
        changes.append(
            OptionChange(
                "use_sudo",
                "False",
                "True",
                privilege_disabled.remediation or "Enable the privilege helper for full builds.",
            )
        )
    return changes


def build_proposal(
    title: str,
    findings: Sequence[AdvisorFinding],
    options: BuildOptions,
    register: str,
) -> ProposalReport:
    """Assemble a preview-only proposal from already-computed advisory findings.

    ``options`` is read to ground the option diff and to skip no-ops; it is never
    mutated.
    """
    unique = _ordered_unique_findings(findings)
    steps = [
        ProposalStep(index, finding.level, finding.title, finding.remediation or finding.detail)
        for index, finding in enumerate(unique, start=1)
    ]
    return ProposalReport(
        title=title,
        register=register,
        findings=unique,
        steps=steps,
        option_changes=_option_changes(unique, options),
    )
