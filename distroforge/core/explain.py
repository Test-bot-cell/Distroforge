from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .build import BuildOrchestrator
from .command import CommandRunner
from .project import Project
from .validate import ValidationIssue, collect_option_issues, validate_for_build


def _issue_payload(issue: ValidationIssue) -> dict[str, str]:
    return {
        "severity": issue.level,
        "code": issue.code,
        "message": issue.message,
    }


@dataclass(frozen=True)
class BuildExplainReport:
    project: Path
    steps: tuple[str, ...]
    phase_plan: tuple[dict[str, object], ...]
    rollback_possible: bool
    rollback_points: tuple[str, ...]
    prerequisites: tuple[dict[str, str], ...]
    next_commands: tuple[str, ...]
    blocked: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": "distroforge.build-explain.v1",
            "project": str(self.project),
            "blocked": self.blocked,
            "rollback_possible": self.rollback_possible,
            "rollback_points": list(self.rollback_points),
            "steps": list(self.steps),
            "plan": list(self.phase_plan),
            "prerequisites": [
                {
                    "severity": item["severity"],
                    "code": item["code"],
                    "message": item["message"],
                }
                for item in self.prerequisites
            ],
            "next_commands": list(self.next_commands),
            "next_contract": {
                "build_command": f"distroforge build {self.project}",
                "validate_command": f"distroforge validate {self.project}",
            },
        }

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2) + "\n"

    def render_text(self) -> str:
        lines = [
            "Build explanation",
            f"Project: {self.project}",
            f"Blocked: {'yes' if self.blocked else 'no'}",
            f"Rollback possible: {'yes' if self.rollback_possible else 'no'}",
            "",
            "What will happen:",
        ]
        for phase in self.phase_plan:
            lines.append(f"[{phase['phase']}]")
            for step in phase.get("steps", ()):  # type: ignore[union-attr]
                lines.append(f"- {step}")
            if not phase.get("steps", ()):  # type: ignore[union-attr]
                lines.append("- no steps")
        lines.append("")
        lines.append("Prerequisites before retry:")
        if self.prerequisites:
            for item in self.prerequisites:
                lines.append(f"- [{item['severity'].upper()}] {item['code']}: {item['message']}")
        else:
            lines.append("- none")
        lines.extend(["", "Next commands:"])  # noqa: RET503
        for command in self.next_commands:
            lines.append(f"- {command}")
        if self.rollback_points:
            lines.append("")
            lines.append("Rollback points:")
            for point in self.rollback_points:
                lines.append(f"- {point}")
        return "\n".join(lines) + "\n"


def _to_phase_plan(steps: list[tuple[str, str]]) -> tuple[dict[str, object], ...]:
    phase_map: dict[str, list[str]] = {}
    order: list[str] = []
    for phase, step in steps:
        if phase not in phase_map:
            order.append(phase)
            phase_map[phase] = []
        phase_map[phase].append(step)
    return tuple({"phase": phase, "steps": tuple(phase_map[phase])} for phase in order)


def _prerequisites_from_issues(issues: list[ValidationIssue]) -> tuple[dict[str, str], ...]:
    payload: list[dict[str, str]] = []
    for issue in issues:
        payload.append(_issue_payload(issue))
    return tuple(payload)


def _retry_commands(issues: list[ValidationIssue], blocked: bool, project: Path) -> tuple[str, ...]:
    commands = [
        f"distroforge validate {project}",
    ]
    if blocked:
        commands.append("distroforge doctor")
    commands.append(f"distroforge build {project}")
    return tuple(dict.fromkeys(commands))


def explain_build(project: Project, options, *, strict: bool = False) -> BuildExplainReport:
    runner = CommandRunner(dry_run=True)
    plan_steps = BuildOrchestrator(project, runner, options).plan()
    step_rows: list[tuple[str, str]] = [(step.phase.value, step.title) for step in plan_steps]
    phase_plan = _to_phase_plan(step_rows)
    rollback_points = tuple(
        point for point in ("before-install", "after-packages", "after-configuration", "after-scripts")
    )
    rollback_possible = bool(options.snapshots.enabled)
    issues = validate_for_build(project, runner, execute=False)
    issues.extend(collect_option_issues(options, strict=strict or options.policy.strict))
    blocked = any(issue.level == "error" for issue in issues)
    prerequisites = _prerequisites_from_issues(issues)
    next_commands = _retry_commands(issues, blocked, project.root)
    return BuildExplainReport(
        project=project.root,
        steps=tuple(f"{step.phase.value}: {step.title}" for step in plan_steps),
        phase_plan=phase_plan,
        rollback_possible=rollback_possible,
        rollback_points=rollback_points if rollback_possible else tuple(),
        prerequisites=prerequisites,
        next_commands=next_commands,
        blocked=blocked,
    )
