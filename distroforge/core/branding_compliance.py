from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, fields
from pathlib import Path

from .branding import BrandingOptions
from .project import Project

STRICT_MODES = {"redistributable", "approved", "certified"}
DESCRIPTIVE_FIELDS = {"id_like", "home_url", "support_url", "bug_report_url", "privacy_policy_url"}
CANONICAL_MARKS = (
    "ubuntu",
    "canonical",
    "kubuntu",
    "lubuntu",
    "xubuntu",
    "edubuntu",
    "ubuntu studio",
    "ubuntukylin",
    "ubuntu budgie",
    "ubuntu cinnamon",
    "ubuntu mate",
    "ubuntu unity",
)
MARK_RE = re.compile(
    r"\b("
    + "|".join(re.escape(mark).replace(r"\ ", r"\s+") for mark in sorted(CANONICAL_MARKS, key=len, reverse=True))
    + r")\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class BrandingComplianceFinding:
    code: str
    field: str
    value: str
    mark: str
    severity: str
    message: str
    remediation: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class BrandingComplianceReport:
    project: str
    mode: str
    status: str
    findings: list[BrandingComplianceFinding]

    def to_dict(self) -> dict[str, object]:
        return {
            "project": self.project,
            "mode": self.mode,
            "status": self.status,
            "findings": [finding.to_dict() for finding in self.findings],
        }

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def render_text(self) -> str:
        lines = [f"Branding compliance: {self.status}", f"Mode: {self.mode}"]
        if not self.findings:
            lines.append("No Canonical trademark exposure detected in branding options.")
            return "\n".join(lines)
        for finding in self.findings:
            lines.append(
                f"- {finding.severity} {finding.code} {finding.field}: "
                f"{finding.message} Remediation: {finding.remediation}"
            )
        return "\n".join(lines)


class BrandingComplianceService:
    def audit(
        self,
        project: Project,
        options: BrandingOptions,
        mode: str = "internal",
    ) -> BrandingComplianceReport:
        normalized_mode = _normalize_mode(mode)
        findings: list[BrandingComplianceFinding] = []
        for field_name, value in _iter_branding_values(options):
            findings.extend(self._find_field_issues(field_name, value, normalized_mode))
        status = "blocked" if any(finding.severity == "error" for finding in findings) else "review"
        if not findings:
            status = "clear"
        return BrandingComplianceReport(project.name, normalized_mode, status, findings)

    def write_clearance(
        self,
        project: Project,
        options: BrandingOptions,
        target: Path | None = None,
        mode: str = "internal",
    ) -> BrandingComplianceReport:
        report = self.audit(project, options, mode)
        output = target or project.output_dir / "TRADEMARK-CLEARANCE.json"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(report.render_json() + "\n", encoding="utf-8")
        return report

    def _find_field_issues(
        self,
        field_name: str,
        value: str,
        mode: str,
    ) -> list[BrandingComplianceFinding]:
        findings: list[BrandingComplianceFinding] = []
        for match in MARK_RE.finditer(value):
            mark = match.group(0)
            if field_name in DESCRIPTIVE_FIELDS and mode == "internal":
                severity = "warning"
                code = "canonical-trademark-descriptive-reference"
                message = f"{field_name} mentions {mark}; keep this descriptive and non-endorsement only."
                remediation = "For redistributable builds, move platform references into controlled docs or support text."
            elif field_name in DESCRIPTIVE_FIELDS:
                severity = "warning"
                code = "canonical-trademark-visible-reference"
                message = f"{field_name} contains {mark} in a visible metadata field."
                remediation = "Use project-owned URLs and keep upstream compatibility notes outside product identity."
            else:
                severity = "error" if mode in STRICT_MODES else "warning"
                code = "canonical-trademark-branding"
                message = f"{field_name} presents {mark} inside the distro identity."
                remediation = "Replace Canonical/Ubuntu marks with a distinct distro-owned identity."
            findings.append(
                BrandingComplianceFinding(
                    code=code,
                    field=field_name,
                    value=value,
                    mark=mark,
                    severity=severity,
                    message=message,
                    remediation=remediation,
                )
            )
        return findings


def _normalize_mode(mode: str) -> str:
    value = mode.strip().lower()
    if value == "certified":
        return "approved"
    if value in {"internal", "redistributable", "approved"}:
        return value
    raise ValueError("Branding compliance mode must be internal, redistributable or approved")


def _iter_branding_values(options: BrandingOptions) -> list[tuple[str, str]]:
    values: list[tuple[str, str]] = []
    for field in fields(BrandingOptions):
        value = getattr(options, field.name)
        if isinstance(value, str) and value.strip():
            values.append((field.name, value.strip()))
        elif isinstance(value, tuple):
            for item in value:
                if isinstance(item, str) and item.strip():
                    values.append((field.name, item.strip()))
    return values
