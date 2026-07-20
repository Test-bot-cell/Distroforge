from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .consistency import ConsistencyService
from .project import Project

if TYPE_CHECKING:
    from .build import BuildOptions


@dataclass
class HealthReport:
    score: int
    status: str
    messages: list[str]


class HealthService:
    def score(self, project: Project, options: BuildOptions) -> HealthReport:
        issues = ConsistencyService().check(project, options)
        score = 100
        for issue in issues:
            score -= 25 if issue.level == "error" else 10
        score = max(0, score)
        status = "green" if score >= 85 else "orange" if score >= 60 else "red"
        return HealthReport(score, status, [f"{i.level}:{i.code}:{i.message}" for i in issues])
