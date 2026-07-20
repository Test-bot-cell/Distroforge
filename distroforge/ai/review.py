from __future__ import annotations

import json
from dataclasses import dataclass, field

from distroforge.core.dry_run_report import DryRunReport
from distroforge.core.readiness import ReadinessReport
from distroforge.core.recipe_ai import RecipeAdvisor, RecipeRequest
from distroforge.core.schema import validate_definition_data


@dataclass(frozen=True)
class ReviewFinding:
    level: str
    title: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return self.__dict__


@dataclass
class PlanReview:
    verdict: str
    findings: list[ReviewFinding] = field(default_factory=list)

    def render_text(self) -> str:
        lines = [f"AI-assisted review: {self.verdict}"]
        if not self.findings:
            lines.append("- No advisory findings.")
        for finding in self.findings:
            lines.append(f"- {finding.level.upper()} {finding.title}: {finding.detail}")
        return "\n".join(lines)

    def render_json(self) -> str:
        return json.dumps(
            {
                "verdict": self.verdict,
                "findings": [finding.to_dict() for finding in self.findings],
            },
            indent=2,
        )


class PlanReviewer:
    """Local, schema-bound reviewer. It advises; it never executes."""

    def review(self, readiness: ReadinessReport, dry_run: DryRunReport) -> PlanReview:
        findings: list[ReviewFinding] = []
        if readiness.status == "blocked":
            findings.append(
                ReviewFinding(
                    "error",
                    "Readiness blockers",
                    "Resolve readiness errors before executing any build command.",
                )
            )
        dry_run_errors = [item for item in dry_run.findings if item.level == "error"]
        dry_run_warnings = [item for item in dry_run.findings if item.level == "warning"]
        if dry_run_errors:
            findings.append(
                ReviewFinding(
                    "error",
                    "Dry-run blockers",
                    "Resolve dry-run errors: " + ", ".join(item.code for item in dry_run_errors),
                )
            )
        if dry_run_warnings:
            findings.append(
                ReviewFinding(
                    "warning",
                    "Dry-run warnings",
                    "Review dry-run warnings: " + ", ".join(item.code for item in dry_run_warnings),
                )
            )
        if dry_run.remove:
            findings.append(
                ReviewFinding(
                    "warning",
                    "Package removals",
                    f"Review removals before publishing: {', '.join(dry_run.remove)}.",
                )
            )
        if any("release-track" in flag for flag in dry_run.flags):
            findings.append(
                ReviewFinding(
                    "warning",
                    "Experimental release track",
                    "Run prebuild VM and QA matrix before sharing this image.",
                )
            )
        if not dry_run.trust.ok:
            findings.append(
                ReviewFinding(
                    "warning",
                    "Trust chain incomplete",
                    "Pin SHA256 and GPG signer metadata for redistributable builds.",
                )
            )
        verdict = "blocked" if any(item.level == "error" for item in findings) else "review"
        if not findings:
            verdict = "ready-for-human-maintainer-review"
        return PlanReview(verdict, findings)


class ConstrainedRecipeAssistant:
    """Heuristic recipe generation constrained by the DistroForge definition schema."""

    def suggest_definition(self, prompt: str) -> dict[str, object]:
        data = RecipeAdvisor().suggest_definition(RecipeRequest(prompt))
        return validate_definition_data(data)
