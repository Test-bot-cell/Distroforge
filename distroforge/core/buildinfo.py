from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class ChangesReport:
    path: Path
    distribution: str | None = None
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "distribution": self.distribution,
            "warnings": list(self.warnings),
        }

    def render_text(self) -> str:
        lines = [
            "Changes report",
            f"Path: {self.path}",
            f"Distribution: {self.distribution or '-'}",
        ]
        if self.warnings:
            lines.extend(["", "Warnings:", *[f"- {item}" for item in self.warnings]])
        return "\n".join(lines)


@dataclass(frozen=True)
class BuildInfoReport:
    path: Path
    distribution: str | None = None
    changes: ChangesReport | None = None
    tainted_by: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def tainted(self) -> bool:
        return bool(self.tainted_by)

    def to_dict(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "distribution": self.distribution,
            "changes": self.changes.to_dict() if self.changes else None,
            "tainted": self.tainted,
            "tainted_by": list(self.tainted_by),
            "warnings": list(self.warnings),
        }

    def render_text(self) -> str:
        lines = [
            "Buildinfo report",
            f"Path: {self.path}",
            f"Distribution: {self.distribution or '-'}",
            f"Tainted: {'yes' if self.tainted else 'no'}",
        ]
        if self.changes:
            lines.extend(["", self.changes.render_text()])
        if self.tainted_by:
            lines.extend(["", "Tainted by:", *[f"- {item}" for item in self.tainted_by]])
        if self.warnings:
            lines.extend(["", "Warnings:", *[f"- {item}" for item in self.warnings]])
        return "\n".join(lines)

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def read_buildinfo(path: Path, changes: Path | None = None) -> BuildInfoReport:
    fields = _parse_fields(path)
    changes_report = read_changes(changes) if changes and changes.exists() else None
    tainted = tuple(fields.get("Build-Tainted-By", "").split())
    distribution = fields.get("Distribution")
    warnings: list[str] = []
    if any(item.startswith("usr-local-has-") for item in tainted):
        warnings.append("Build host contains /usr/local programs or libraries; use sbuild/pbuilder/mmdebstrap for release builds.")
    if distribution == "unstable":
        warnings.append("Distribution is unstable; align changelog suite before publishing to a target archive.")
    if changes_report and not distribution and changes_report.distribution:
        warnings.append("Publication suite comes from .changes; .buildinfo does not always carry Distribution.")
    return BuildInfoReport(
        path=path,
        distribution=distribution,
        changes=changes_report,
        tainted_by=tainted,
        warnings=tuple(warnings),
    )


def read_changes(path: Path) -> ChangesReport:
    fields = _parse_fields(path)
    distribution = fields.get("Distribution")
    warnings: list[str] = []
    if distribution == "unstable":
        warnings.append("Distribution is unstable; align changelog suite before publishing to a target archive.")
    return ChangesReport(path=path, distribution=distribution, warnings=tuple(warnings))


def _parse_fields(path: Path) -> dict[str, str]:
    fields: dict[str, str] = {}
    current: str | None = None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line:
            current = None
            continue
        if line.startswith(" ") and current:
            fields[current] += "\n" + line.strip()
            continue
        if ":" in line:
            key, value = line.split(":", 1)
            current = key
            fields[key] = value.strip()
    return fields


@dataclass(frozen=True)
class AutopkgtestPolicy:
    declared: bool
    superficial: bool
    required_checks: tuple[str, ...]
    missing_checks: tuple[str, ...]
    host_available: bool

    @property
    def status(self) -> str:
        if not self.declared:
            return "undeclared"
        if self.superficial or self.missing_checks:
            return "declared but weak"
        if not self.host_available:
            return "unavailable on host"
        return "declared and meaningful"

    def to_dict(self) -> dict[str, object]:
        return {
            "declared": self.declared,
            "superficial": self.superficial,
            "required_checks": list(self.required_checks),
            "missing_checks": list(self.missing_checks),
            "host_available": self.host_available,
            "status": self.status,
        }

    def render_text(self) -> str:
        lines = [
            "Autopkgtest policy",
            f"Status: {self.status}",
            f"Declared: {'yes' if self.declared else 'no'}",
            f"Host tool: {'available' if self.host_available else 'missing'}",
            f"Superficial: {'yes' if self.superficial else 'no'}",
        ]
        if self.missing_checks:
            lines.extend(["Missing smoke checks:", *[f"- {item}" for item in self.missing_checks]])
        return "\n".join(lines)


@dataclass
class PackagingPolicyReport:
    root: Path
    buildinfo: BuildInfoReport | None = None
    changes: ChangesReport | None = None
    data_mode_offenders: list[str] = field(default_factory=list)
    malformed_toml: list[str] = field(default_factory=list)
    malformed_json: list[str] = field(default_factory=list)
    missing_package_data: list[str] = field(default_factory=list)
    malformed_examples: list[str] = field(default_factory=list)
    missing_docs: list[str] = field(default_factory=list)
    missing_examples: list[str] = field(default_factory=list)
    lintian_available: bool = False
    autopkgtest_available: bool = False
    autopkgtest_policy: AutopkgtestPolicy | None = None

    @property
    def blocked(self) -> bool:
        return bool(
            self.data_mode_offenders
            or self.malformed_toml
            or self.malformed_json
            or self.missing_package_data
            or self.malformed_examples
            or self.missing_docs
            or self.missing_examples
            or (
                self.autopkgtest_policy is not None
                and self.autopkgtest_policy.status in {"undeclared", "declared but weak"}
            )
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "root": str(self.root),
            "blocked": self.blocked,
            "buildinfo": self.buildinfo.to_dict() if self.buildinfo else None,
            "changes": self.changes.to_dict() if self.changes else None,
            "data_mode_offenders": self.data_mode_offenders,
            "malformed_toml": self.malformed_toml,
            "malformed_json": self.malformed_json,
            "missing_package_data": self.missing_package_data,
            "malformed_examples": self.malformed_examples,
            "missing_docs": self.missing_docs,
            "missing_examples": self.missing_examples,
            "lintian_available": self.lintian_available,
            "autopkgtest_available": self.autopkgtest_available,
            "autopkgtest_policy": self.autopkgtest_policy.to_dict()
            if self.autopkgtest_policy
            else None,
        }

    def render_text(self) -> str:
        lines = [
            "Packaging policy report",
            f"Root: {self.root}",
            f"Status: {'blocked' if self.blocked else 'review required'}",
            f"Lintian: {'available' if self.lintian_available else 'missing'}",
            f"Autopkgtest: {'available' if self.autopkgtest_available else 'missing'}",
        ]
        if self.autopkgtest_policy:
            lines.extend(["", self.autopkgtest_policy.render_text()])
        if self.buildinfo:
            lines.extend(["", self.buildinfo.render_text()])
        elif self.changes:
            lines.extend(["", self.changes.render_text()])
        if self.data_mode_offenders:
            lines.extend(["", "Executable bundled data files:", *[f"- {item}" for item in self.data_mode_offenders]])
        if self.malformed_toml:
            lines.extend(["", "Malformed TOML data files:", *[f"- {item}" for item in self.malformed_toml]])
        if self.malformed_json:
            lines.extend(["", "Malformed JSON data files:", *[f"- {item}" for item in self.malformed_json]])
        if self.missing_package_data:
            lines.extend(["", "Data files missing from package-data:", *[f"- {item}" for item in self.missing_package_data]])
        if self.malformed_examples:
            lines.extend(["", "Malformed YAML examples:", *[f"- {item}" for item in self.malformed_examples]])
        if self.missing_docs:
            lines.extend(["", "Docs missing from debian/docs:", *[f"- {item}" for item in self.missing_docs]])
        if self.missing_examples:
            lines.extend(["", "Examples missing from debian/examples:", *[f"- {item}" for item in self.missing_examples]])
        return "\n".join(lines)

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)
