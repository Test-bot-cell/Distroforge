from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path

from .command import CommandRunner, CommandSpec

VULN_POLICIES: tuple[str, ...] = ("off", "warn", "block-high", "block-critical")
_SEVERITY_ORDER = {"unknown": 0, "negligible": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_SEVERITY_LABELS = ("critical", "high", "medium", "low", "unknown")


@dataclass
class VulnScanOptions:
    enabled: bool = False
    policy: str = "warn"
    db_path: Path | None = None


@dataclass(frozen=True)
class VulnFinding:
    level: str
    cve: str
    package: str
    severity: str
    message: str
    remediation: str = ""

    def to_dict(self) -> dict[str, str]:
        return self.__dict__


@dataclass
class VulnScanReport:
    findings: list[VulnFinding] = field(default_factory=list)
    scanned: int = 0
    policy: str = "warn"
    database: str = "bundled"
    enabled: bool = False

    @property
    def ok(self) -> bool:
        return not any(finding.level == "error" for finding in self.findings)

    @property
    def counts(self) -> dict[str, int]:
        out = {label: 0 for label in _SEVERITY_LABELS}
        for finding in self.findings:
            out[finding.severity] = out.get(finding.severity, 0) + 1
        return out

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "enabled": self.enabled,
            "policy": self.policy,
            "database": self.database,
            "scanned": self.scanned,
            "counts": self.counts,
            "findings": [finding.to_dict() for finding in self.findings],
        }

    def render_text(self) -> str:
        if not self.enabled:
            return "CVE scan: disabled (enable with --vuln-scan)."
        header = f"CVE scan (policy={self.policy}, db={self.database}) — {self.scanned} package(s)"
        lines = [header]
        if not self.findings:
            lines.append("- no known advisories matched the planned package set")
            return "\n".join(lines)
        counts = self.counts
        summary = ", ".join(f"{label}={counts[label]}" for label in _SEVERITY_LABELS if counts[label])
        lines.append(f"summary: {summary}")
        for finding in self.findings:
            lines.append(
                f"{finding.level.upper():7} {finding.severity:8} {finding.cve:18} "
                f"{finding.package}: {finding.message}"
            )
            if finding.remediation:
                lines.append(f"        fix: {finding.remediation}")
        return "\n".join(lines)


class VulnScanService:
    """Match a planned package set against a local CVE advisory database.

    The scan is intentionally offline and planning-level: it never builds or
    downloads packages, so it stays usable in dry-run, air-gapped and CI
    contexts. Matching is by source/binary package name, which is the only
    identity available before any .deb is fetched.
    """

    def __init__(self, options: VulnScanOptions | None = None) -> None:
        self.options = options or VulnScanOptions()

    def scan(self, packages: Iterable[str]) -> VulnScanReport:
        policy = self.options.policy if self.options.policy in VULN_POLICIES else "warn"
        pkgset = sorted({str(pkg).strip() for pkg in packages if str(pkg).strip()})
        report = VulnScanReport(scanned=len(pkgset), policy=policy, enabled=self.options.enabled)
        if not self.options.enabled:
            return report
        advisories, source, db_error = self._load_database()
        report.database = source
        if db_error:
            report.findings.append(
                VulnFinding(
                    level="warning",
                    cve="DB-UNAVAILABLE",
                    package="(database)",
                    severity="unknown",
                    message=db_error,
                    remediation="Point --vuln-db at a readable advisory JSON or use the bundled database.",
                )
            )
            return report
        index: dict[str, list[dict]] = {}
        for advisory in advisories:
            index.setdefault(str(advisory["package"]), []).append(advisory)
        for pkg in pkgset:
            for advisory in index.get(pkg, []):
                report.findings.append(self._finding(pkg, advisory, policy))
        report.findings.sort(
            key=lambda finding: (-_SEVERITY_ORDER.get(finding.severity, 0), finding.package, finding.cve)
        )
        return report

    def enforce(self, packages: Iterable[str], runner: CommandRunner) -> VulnScanReport:
        report = self.scan(packages)
        counts = report.counts
        runner.run(
            CommandSpec(
                argv=("vuln-report", "ok" if report.ok else "blocked", str(len(report.findings))),
                description=(
                    f"CVE scan policy={report.policy} db={report.database} scanned={report.scanned} "
                    f"critical={counts['critical']} high={counts['high']} "
                    f"medium={counts['medium']} low={counts['low']}"
                ),
            )
        )
        errors = [finding for finding in report.findings if finding.level == "error"]
        if errors:
            raise ValueError(
                "Blocked by CVE policy "
                f"({report.policy}): "
                + "; ".join(f"{finding.cve} [{finding.severity}] in {finding.package}" for finding in errors)
            )
        return report

    def _finding(self, package: str, advisory: dict, policy: str) -> VulnFinding:
        severity = str(advisory.get("severity", "unknown")).lower()
        if severity not in _SEVERITY_ORDER:
            severity = "unknown"
        fixed = str(advisory.get("fixed_version", "")).strip()
        cve = str(advisory.get("id", "UNKNOWN"))
        remediation = (
            f"Upgrade {package} to {fixed} or later, then rebuild."
            if fixed
            else f"Track {cve} and rebuild once a fixed {package} is published."
        )
        return VulnFinding(
            level=self._level_for(severity, policy),
            cve=cve,
            package=package,
            severity=severity,
            message=str(advisory.get("summary", "Known vulnerability")),
            remediation=remediation,
        )

    def _level_for(self, severity: str, policy: str) -> str:
        rank = _SEVERITY_ORDER.get(severity, 0)
        if policy == "block-critical" and rank >= _SEVERITY_ORDER["critical"]:
            return "error"
        if policy == "block-high" and rank >= _SEVERITY_ORDER["high"]:
            return "error"
        if policy == "off":
            return "info"
        return "warning"

    def _load_database(self) -> tuple[list[dict], str, str]:
        if self.options.db_path:
            path = Path(self.options.db_path)
            if not path.exists():
                return [], f"missing:{path}", f"CVE database not found: {path}"
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                return [], f"invalid:{path}", f"CVE database could not be parsed: {exc}"
            source = str(path)
        else:
            try:
                resource = files("distroforge.data").joinpath("vulndb.json")
                raw = json.loads(resource.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:  # pragma: no cover - bundled data is shipped
                return [], "bundled", f"Bundled CVE database could not be parsed: {exc}"
            source = "bundled"
        advisories = raw.get("advisories", []) if isinstance(raw, dict) else []
        cleaned = [item for item in advisories if isinstance(item, dict) and item.get("package")]
        return cleaned, source, ""
