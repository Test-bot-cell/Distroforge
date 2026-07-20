from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .command import CommandRunner
from .diff_preview import DiffPreviewService
from .doctor import REQUIRED_TOOLS, run_doctor
from .dry_run_report import DryRunReport, generate_dry_run_report
from .policy import PolicyFinding, PolicyService
from .transaction import BuildTransaction, plan_transaction
from .trust import TrustReport, TrustService
from .validate import validate_for_build
from .vulnscan import VulnScanService
from .workflows import (
    WorkflowFinding,
    WorkflowRecommendation,
    evaluate_workflow_fit,
    recommend_workflow_actions,
)

if TYPE_CHECKING:
    from .build import BuildOptions
    from .project import Project


@dataclass(frozen=True)
class ReadinessCheck:
    level: str
    code: str
    message: str
    remediation: str = ""

    def to_dict(self) -> dict[str, str]:
        return self.__dict__


@dataclass
class ReadinessReport:
    status: str
    score: int
    transaction: BuildTransaction
    checks: list[ReadinessCheck] = field(default_factory=list)
    policy: list[PolicyFinding] = field(default_factory=list)
    workflow: list[WorkflowFinding] = field(default_factory=list)
    recommendations: list[WorkflowRecommendation] = field(default_factory=list)
    trust: TrustReport = field(default_factory=TrustReport)
    dry_run: DryRunReport | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "score": self.score,
            "transaction": self.transaction.to_dict(),
            "checks": [check.to_dict() for check in self.checks],
            "policy": [finding.to_dict() for finding in self.policy],
            "workflow": [finding.to_dict() for finding in self.workflow],
            "recommendations": [recommendation.to_dict() for recommendation in self.recommendations],
            "trust": self.trust.to_dict(),
            "dry_run": self.dry_run.to_dict() if self.dry_run else None,
        }

    def render_text(self) -> str:
        lines = [
            f"Readiness: {self.status.upper()} ({self.score}/100)",
            f"Build id: {self.transaction.build_id}",
            f"Run dir: {self.transaction.run_dir}",
            "",
            "Checks:",
        ]
        if not self.checks:
            lines.append("- no findings")
        for check in self.checks:
            lines.append(f"- {check.level.upper():7} {check.code:24} {check.message}")
            if check.remediation:
                lines.append(f"          fix: {check.remediation}")
        if self.policy:
            lines.extend(["", "Policy:"])
            for finding in self.policy:
                lines.append(f"- {finding.severity.upper():7} {finding.code:24} {finding.message}")
                if finding.remediation:
                    lines.append(f"          fix: {finding.remediation}")
        if self.workflow:
            lines.extend(["", "Workflow fit:"])
            for finding in self.workflow:
                lines.append(f"- {finding.level.upper():7} {finding.code:36} {finding.message}")
                if finding.remediation:
                    lines.append(f"          fix: {finding.remediation}")
        if self.recommendations:
            lines.extend(["", "Next recommended actions:"])
            for recommendation in self.recommendations[:5]:
                lines.append(
                    f"- P{recommendation.priority:02d} {recommendation.code:34} "
                    f"{recommendation.action}"
                )
                lines.append(f"          why: {recommendation.reason}")
                lines.append(f"          where: {recommendation.gui_surface}")
                if recommendation.command_hint:
                    lines.append(f"          cli: {recommendation.command_hint}")
        if self.trust.checks:
            lines.extend(["", self.trust.render_text()])
        if self.dry_run:
            lines.extend(["", "Timeline:"])
            for index, step in enumerate(self.dry_run.steps, start=1):
                lines.append(f"{index:02d}. {step.phase.value:18} {step.title}")
        return "\n".join(lines)

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class ReadinessService:
    def check(self, project: Project, options: BuildOptions, include_dry_run: bool = True) -> ReadinessReport:
        checks: list[ReadinessCheck] = []
        validation = validate_for_build(project, CommandRunner(dry_run=True), execute=False)
        for issue in validation:
            checks.append(
                ReadinessCheck(
                    issue.level,
                    f"validation-{issue.code}",
                    issue.message,
                )
            )

        for item in run_doctor(CommandRunner(dry_run=True)):
            if item.binary in REQUIRED_TOOLS and not item.available:
                checks.append(
                    ReadinessCheck(
                        "error",
                        f"host-{item.binary}",
                        f"{item.binary} is missing: {item.reason}",
                        "Install the missing host tool before executing a build.",
                    )
                )

        if project.output_dir.exists() and any(project.output_dir.iterdir()):
            checks.append(
                ReadinessCheck(
                    "warning",
                    "output-dir-not-empty",
                    f"Output directory is not empty: {project.output_dir}",
                    "Use a fresh project, clean old artifacts, or inspect before execution.",
                )
            )

        trust = (
            TrustService().check_source_iso(project.source_iso, options.trust, strict=options.policy.strict)
            if project.source_mode == "iso"
            else TrustReport()
        )
        checks.extend(
            ReadinessCheck(check.level, f"trust-{check.code}", check.message, check.remediation)
            for check in trust.checks
            if check.level in {"error", "warning"}
        )

        if options.vuln_scan.enabled:
            packages = DiffPreviewService().preview(project, options).install
            vuln = VulnScanService(options.vuln_scan).scan(packages)
            checks.extend(
                ReadinessCheck(
                    finding.level,
                    f"vuln-{finding.cve.lower()}",
                    f"{finding.severity.upper()} {finding.cve} in {finding.package}: {finding.message}",
                    finding.remediation,
                )
                for finding in vuln.findings
                if finding.level in {"error", "warning"}
            )

        policy = PolicyService().check(project, options, options.policy)
        workflow = list(evaluate_workflow_fit(project, options))
        recommendations = list(recommend_workflow_actions(project, options, tuple(workflow)))
        dry_run = generate_dry_run_report(project, options, run_orchestrator=False) if include_dry_run else None
        transaction = dry_run.transaction if dry_run else plan_transaction(project, options)
        score = _score(checks, policy, workflow)
        status = "blocked" if _has_blockers(checks, policy, workflow) else "ready" if score >= 85 else "review"
        return ReadinessReport(
            status,
            score,
            transaction,
            checks,
            policy,
            workflow,
            recommendations,
            trust,
            dry_run,
        )


def _has_blockers(
    checks: list[ReadinessCheck], policy: list[PolicyFinding], workflow: list[WorkflowFinding]
) -> bool:
    return any(check.level == "error" for check in checks) or any(
        finding.severity == "error" for finding in policy
    ) or any(finding.level == "error" for finding in workflow)


def _score(
    checks: list[ReadinessCheck], policy: list[PolicyFinding], workflow: list[WorkflowFinding]
) -> int:
    score = 100
    for check in checks:
        score -= 25 if check.level == "error" else 10 if check.level == "warning" else 0
    for finding in policy:
        score -= 25 if finding.severity == "error" else 10 if finding.severity == "warning" else 0
    for finding in workflow:
        score -= 25 if finding.level == "error" else 10 if finding.level == "warning" else 0
    return max(score, 0)
