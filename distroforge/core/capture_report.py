from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass(frozen=True)
class CaptureFinding:
    category: str
    path: str
    status: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "category": self.category,
            "path": self.path,
            "status": self.status,
            "message": self.message,
        }


@dataclass
class CaptureReport:
    findings: list[CaptureFinding] = field(default_factory=list)

    def add(self, category: str, path: str, status: str, message: str) -> None:
        self.findings.append(CaptureFinding(category, path, status, message))

    def extend(self, findings: list[CaptureFinding]) -> None:
        self.findings.extend(findings)

    def counts(self) -> dict[str, int]:
        values: dict[str, int] = {}
        for finding in self.findings:
            values[finding.status] = values.get(finding.status, 0) + 1
        return values

    def to_dict(self) -> dict[str, object]:
        return {
            "counts": self.counts(),
            "findings": [finding.to_dict() for finding in self.findings],
        }

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def render_text(self) -> str:
        counts = self.counts()
        lines = [
            "Installed system capture report",
            "Counts: "
            + ", ".join(f"{key}={counts[key]}" for key in sorted(counts))
            if counts
            else "Counts: none",
            "",
        ]
        for finding in self.findings:
            lines.append(
                f"[{finding.status}] {finding.category}: {finding.path} - {finding.message}"
            )
        return "\n".join(lines)
