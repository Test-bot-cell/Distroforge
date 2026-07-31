from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass, field
from importlib.resources import as_file, files
from pathlib import Path

from .artifact_verification import (
    ArtifactLimits,
    ArtifactVerificationError,
    ArtifactVerificationSession,
)
from .command import CommandRunner, CommandSpec

VULN_POLICIES: tuple[str, ...] = ("off", "warn", "block-high", "block-critical")
VULN_DB_SCHEMA = "distroforge-vulndb/1"
MAX_VULN_DB_BYTES = 16 * 1024 * 1024
MAX_VULN_DB_JSON_NODES = 250_000
MAX_VULN_SCAN_PACKAGE_INPUTS = 65_536
MAX_VULN_PACKAGE_NAME_BYTES = 255
MAX_VULN_META_SOURCE_BYTES = 2_048
MAX_VULN_META_UPDATED_BYTES = 128
MAX_VULN_META_DESCRIPTION_BYTES = 8_192
MAX_VULN_ADVISORY_ID_BYTES = 256
MAX_VULN_ADVISORY_SUMMARY_BYTES = 4_096
MAX_VULN_SEVERITY_BYTES = 16
MAX_VULN_FIXED_VERSION_BYTES = 512
_BLOCKING_POLICIES = frozenset({"block-high", "block-critical"})
_VULN_DB_LIMITS = ArtifactLimits(
    max_open_files=1,
    max_file_bytes=MAX_VULN_DB_BYTES,
    max_buffered_bytes=MAX_VULN_DB_BYTES,
    max_hashed_bytes=MAX_VULN_DB_BYTES * 2,
    max_json_depth=64,
    max_json_nodes=MAX_VULN_DB_JSON_NODES,
    max_path_components=256,
    max_closing_fds=512,
    max_inventory_entries=1,
)
_SEVERITY_ORDER = {"unknown": 0, "negligible": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_SEVERITY_LABELS = ("critical", "high", "medium", "low", "unknown")
_DATABASE_ROOT_KEYS = frozenset({"meta", "advisories"})
_DATABASE_META_KEYS = frozenset({"schema", "description", "source", "updated"})
_ADVISORY_KEYS = frozenset({"id", "package", "severity", "fixed_version", "summary"})
_PACKAGE_NAME = re.compile(r"[a-z0-9][a-z0-9+.-]+")


class _VulnDatabaseError(ValueError):
    """A database is readable JSON but cannot support a scan verdict."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class _NormalizedPackageInput:
    packages: tuple[str, ...] = ()
    error_code: str = ""
    finding_code: str = ""
    message: str = ""


@dataclass(frozen=True)
class _ValidatedVulnDatabase:
    advisories: tuple[dict[str, object], ...]
    schema: str
    source: str
    updated: str


@dataclass(frozen=True)
class _VulnDatabaseLoad:
    database: _ValidatedVulnDatabase | None
    location: str
    sha256: str = ""
    finding_code: str = ""
    error_code: str = ""
    message: str = ""


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
    database_status: str = "disabled"
    database_error: str = ""
    advisory_count: int = 0
    database_sha256: str = ""
    database_schema: str = ""
    database_source: str = ""
    database_updated: str = ""
    enabled: bool = False

    @property
    def ok(self) -> bool:
        return not any(finding.level == "error" for finding in self.findings)

    @property
    def verdict(self) -> str:
        if not self.enabled:
            return "disabled"
        if not self.ok:
            return "blocked"
        if self.database_status != "valid":
            return "degraded"
        if self.findings:
            return "findings"
        return "clean"

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
            "database_status": self.database_status,
            "database_error": self.database_error,
            "advisory_count": self.advisory_count,
            "database_sha256": self.database_sha256,
            "database_schema": self.database_schema,
            "database_source": self.database_source,
            "database_updated": self.database_updated,
            "verdict": self.verdict,
            "scanned": self.scanned,
            "counts": self.counts,
            "findings": [finding.to_dict() for finding in self.findings],
        }

    def render_text(self) -> str:
        if not self.enabled:
            return "CVE scan: disabled (enable with --vuln-scan)."
        header = (
            f"CVE scan (policy={self.policy}, db={self.database}, "
            f"database_status={self.database_status}, verdict={self.verdict}, "
            f"db_sha256={self.database_sha256 or 'unavailable'}) "
            f"— {self.scanned} package(s)"
        )
        lines = [header]
        if not self.findings:
            lines.append("- no known advisories matched the planned package set")
            return "\n".join(lines)
        counts = self.counts
        summary = ", ".join(
            f"{label}={counts[label]}" for label in _SEVERITY_LABELS if counts[label]
        )
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
        policy = self.options.policy
        report = VulnScanReport(policy=policy, enabled=self.options.enabled)
        if not self.options.enabled:
            return report
        if policy not in VULN_POLICIES:
            report.database_status = "not-checked"
            report.database_error = "invalid-policy"
            report.findings.append(
                VulnFinding(
                    level="error",
                    cve="POLICY-INVALID",
                    package="(policy)",
                    severity="unknown",
                    message=f"Unsupported CVE policy: {policy!r}",
                    remediation="Select one of: " + ", ".join(VULN_POLICIES) + ".",
                )
            )
            return report
        normalized = _normalize_package_input(packages)
        if normalized.error_code:
            report.database_status = "not-checked"
            report.database_error = normalized.error_code
            report.findings.append(
                VulnFinding(
                    level="error" if policy in _BLOCKING_POLICIES else "warning",
                    cve=normalized.finding_code,
                    package="(input)",
                    severity="unknown",
                    message=normalized.message,
                    remediation=(
                        "Supply between 1 and "
                        f"{MAX_VULN_SCAN_PACKAGE_INPUTS} canonical Debian package "
                        f"names of at most {MAX_VULN_PACKAGE_NAME_BYTES} bytes each."
                    ),
                )
            )
            return report
        pkgset = normalized.packages
        report.scanned = len(pkgset)

        loaded = self._load_database()
        report.database = loaded.location
        if loaded.error_code:
            report.database_status = "invalid"
            report.database_error = loaded.error_code
            report.findings.append(
                VulnFinding(
                    level="error" if policy in _BLOCKING_POLICIES else "warning",
                    cve=loaded.finding_code,
                    package="(database)",
                    severity="unknown",
                    message=loaded.message,
                    remediation=(
                        "Point --vuln-db at a stable, readable regular file using "
                        f"schema {VULN_DB_SCHEMA}, or use the bundled database."
                    ),
                )
            )
            return report
        database = loaded.database
        if database is None:
            report.database_status = "invalid"
            report.database_error = "internal"
            report.findings.append(
                VulnFinding(
                    level="error" if policy in _BLOCKING_POLICIES else "warning",
                    cve="DB-UNAVAILABLE",
                    package="(database)",
                    severity="unknown",
                    message="CVE database loader returned no verified snapshot",
                    remediation="Retry with a verified CVE database and report this internal error.",
                )
            )
            return report
        report.database_status = "valid"
        report.advisory_count = len(database.advisories)
        report.database_sha256 = loaded.sha256
        report.database_schema = database.schema
        report.database_source = database.source
        report.database_updated = database.updated
        index: dict[str, list[dict[str, object]]] = {}
        for advisory in database.advisories:
            index.setdefault(str(advisory["package"]), []).append(advisory)
        for pkg in pkgset:
            for advisory in index.get(pkg, []):
                report.findings.append(self._finding(pkg, advisory, policy))
        report.findings.sort(
            key=lambda finding: (
                -_SEVERITY_ORDER.get(finding.severity, 0),
                finding.package,
                finding.cve,
            )
        )
        return report

    def enforce(
        self,
        packages: Iterable[str],
        runner: CommandRunner,
    ) -> VulnScanReport:
        report = self.scan(packages)
        counts = report.counts
        runner.run(
            CommandSpec(
                argv=(
                    "vuln-report",
                    (
                        "blocked"
                        if not report.ok
                        else "degraded"
                        if report.verdict == "degraded"
                        else "ok"
                    ),
                    str(len(report.findings)),
                ),
                description=(
                    f"CVE scan policy={report.policy} db={report.database} "
                    f"database_status={report.database_status} "
                    f"database_error={report.database_error or 'none'} "
                    f"verdict={report.verdict} "
                    f"db_sha256={report.database_sha256 or 'unavailable'} "
                    f"advisories={report.advisory_count} scanned={report.scanned} "
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
                + "; ".join(
                    f"{finding.cve} [{finding.severity}] in {finding.package}" for finding in errors
                )
            )
        return report

    def _finding(self, package: str, advisory: dict[str, object], policy: str) -> VulnFinding:
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

    def _load_database(self) -> _VulnDatabaseLoad:
        location = "bundled"
        try:
            if self.options.db_path:
                database_path = Path(self.options.db_path)
                location = str(database_path)
                return self._load_database_path(database_path, location)
            resource = files("distroforge.data").joinpath("vulndb.json")
            with as_file(resource) as resource_path:
                database_path = Path(resource_path)
                return self._load_database_path(database_path, location)
        except Exception as exc:
            return _VulnDatabaseLoad(
                None,
                location,
                finding_code="DB-UNAVAILABLE",
                error_code=_database_unavailable_code(exc),
                message=(f"CVE database resource is unusable: {type(exc).__name__}: {exc}"),
            )

    def _load_database_path(
        self,
        path: Path,
        location: str,
    ) -> _VulnDatabaseLoad:
        def load(
            active_session: ArtifactVerificationSession,
            absolute: Path,
        ) -> tuple[_ValidatedVulnDatabase, str]:
            raw = active_session.file_path(
                absolute,
                label="CVE advisory database",
                max_bytes=MAX_VULN_DB_BYTES,
            ).json_object()
            database = _validate_database(raw)
            digest = active_session.file_path(
                absolute,
                label="CVE advisory database",
                max_bytes=MAX_VULN_DB_BYTES,
            ).digest()
            return database, digest

        try:
            absolute = path.absolute()
            with ArtifactVerificationSession(
                Path("/"),
                label="CVE database verification",
                limits=_VULN_DB_LIMITS,
            ) as owned_session:
                database, digest = load(owned_session, absolute)
        except _VulnDatabaseError as exc:
            return _VulnDatabaseLoad(
                None,
                location,
                finding_code="DB-INVALID",
                error_code=exc.code,
                message=str(exc),
            )
        except Exception as exc:
            return _VulnDatabaseLoad(
                None,
                location,
                finding_code="DB-UNAVAILABLE",
                error_code=_database_unavailable_code(exc),
                message=f"CVE database is unusable: {type(exc).__name__}: {exc}",
            )
        return _VulnDatabaseLoad(database, location, sha256=digest)


def _validate_database(raw: dict[str, object]) -> _ValidatedVulnDatabase:
    unexpected_root = set(raw) - _DATABASE_ROOT_KEYS
    if unexpected_root:
        raise _VulnDatabaseError(
            "unexpected-root-fields",
            "CVE database contains "
            f"{len(unexpected_root)} unsupported top-level field(s)",
        )
    meta = raw.get("meta")
    if not isinstance(meta, dict):
        raise _VulnDatabaseError(
            "missing-meta",
            "CVE database meta must be an object",
        )
    unexpected_meta = set(meta) - _DATABASE_META_KEYS
    if unexpected_meta:
        raise _VulnDatabaseError(
            "unexpected-meta-fields",
            "CVE database meta contains "
            f"{len(unexpected_meta)} unsupported field(s)",
        )
    schema = meta.get("schema")
    if schema != VULN_DB_SCHEMA:
        raise _VulnDatabaseError(
            "schema-mismatch",
            f"CVE database meta.schema must equal {VULN_DB_SCHEMA}",
        )
    metadata: dict[str, str] = {}
    for field_name in ("source", "updated"):
        metadata[field_name] = _canonical_database_text(
            meta.get(field_name),
            label=f"CVE database meta.{field_name}",
            code=f"invalid-meta-{field_name}",
            max_bytes=(
                MAX_VULN_META_SOURCE_BYTES
                if field_name == "source"
                else MAX_VULN_META_UPDATED_BYTES
            ),
        )
    description = meta.get("description")
    if description is not None:
        _canonical_database_text(
            description,
            label="CVE database meta.description",
            code="invalid-meta-description",
            max_bytes=MAX_VULN_META_DESCRIPTION_BYTES,
        )

    advisory_values = raw.get("advisories")
    if not isinstance(advisory_values, list):
        raise _VulnDatabaseError(
            "invalid-advisories",
            "CVE database advisories must be a non-empty array",
        )
    if not advisory_values:
        raise _VulnDatabaseError(
            "empty-advisories",
            "CVE database advisories must not be empty",
        )

    advisories: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for position, value in enumerate(advisory_values):
        label = f"CVE database advisory #{position + 1}"
        if not isinstance(value, dict):
            raise _VulnDatabaseError(
                "invalid-advisory",
                f"{label} must be an object",
            )
        unexpected = set(value) - _ADVISORY_KEYS
        if unexpected:
            raise _VulnDatabaseError(
                "unexpected-advisory-fields",
                f"{label} contains {len(unexpected)} unsupported field(s)",
            )
        normalized: dict[str, object] = {}
        for field_name in ("id", "package", "severity", "summary"):
            normalized[field_name] = _canonical_database_text(
                value.get(field_name),
                label=f"{label}.{field_name}",
                code=f"invalid-advisory-{field_name}",
                max_bytes=(
                    MAX_VULN_ADVISORY_ID_BYTES
                    if field_name == "id"
                    else MAX_VULN_PACKAGE_NAME_BYTES
                    if field_name == "package"
                    else MAX_VULN_SEVERITY_BYTES
                    if field_name == "severity"
                    else MAX_VULN_ADVISORY_SUMMARY_BYTES
                ),
            )
        package = str(normalized["package"])
        if _PACKAGE_NAME.fullmatch(package) is None:
            raise _VulnDatabaseError(
                "invalid-advisory-package",
                f"{label}.package is not a canonical Debian package name: {package!r}",
            )
        severity = str(normalized["severity"])
        if severity not in _SEVERITY_ORDER:
            raise _VulnDatabaseError(
                "invalid-advisory-severity",
                f"{label}.severity is unsupported: {severity!r}",
            )
        normalized["severity"] = severity
        fixed_version = value.get("fixed_version", "")
        normalized["fixed_version"] = _canonical_database_text(
            fixed_version,
            label=f"{label}.fixed_version",
            code="invalid-advisory-fixed-version",
            max_bytes=MAX_VULN_FIXED_VERSION_BYTES,
            allow_empty=True,
        )
        identity = (str(normalized["package"]), str(normalized["id"]))
        if identity in seen:
            raise _VulnDatabaseError(
                "duplicate-advisory",
                f"{label} duplicates package/id {identity[0]}/{identity[1]}",
            )
        seen.add(identity)
        advisories.append(normalized)
    return _ValidatedVulnDatabase(
        tuple(advisories),
        str(schema),
        metadata["source"],
        metadata["updated"],
    )


def _normalize_package_input(packages: Iterable[str]) -> _NormalizedPackageInput:
    unique: set[str] = set()
    try:
        for position, package in enumerate(packages, start=1):
            if position > MAX_VULN_SCAN_PACKAGE_INPUTS:
                return _NormalizedPackageInput(
                    error_code="package-input-bounds",
                    finding_code="INPUT-BOUNDS",
                    message=(
                        "CVE scan package input exceeds "
                        f"{MAX_VULN_SCAN_PACKAGE_INPUTS} entries"
                    ),
                )
            if type(package) is not str:
                return _NormalizedPackageInput(
                    error_code="invalid-package-input",
                    finding_code="INPUT-INVALID",
                    message=(
                        f"CVE scan package input #{position} is not a string"
                    ),
                )
            if len(package) > MAX_VULN_PACKAGE_NAME_BYTES:
                return _NormalizedPackageInput(
                    error_code="package-input-bounds",
                    finding_code="INPUT-BOUNDS",
                    message=(
                        f"CVE scan package input #{position} exceeds "
                        f"{MAX_VULN_PACKAGE_NAME_BYTES} bytes"
                    ),
                )
            if _PACKAGE_NAME.fullmatch(package) is None:
                return _NormalizedPackageInput(
                    error_code="invalid-package-input",
                    finding_code="INPUT-INVALID",
                    message=(
                        f"CVE scan package input #{position} is not a canonical "
                        "Debian package name"
                    ),
                )
            unique.add(package)
    except Exception as exc:
        return _NormalizedPackageInput(
            error_code="package-input-error",
            finding_code="INPUT-INVALID",
            message=(
                "CVE scan package input could not be consumed safely: "
                f"{type(exc).__name__}: {exc}"
            ),
        )
    if not unique:
        return _NormalizedPackageInput(
            error_code="empty-package-set",
            finding_code="SCAN-EMPTY",
            message="CVE scan package input is empty",
        )
    return _NormalizedPackageInput(packages=tuple(sorted(unique)))


def _canonical_database_text(
    value: object,
    *,
    label: str,
    code: str,
    max_bytes: int,
    allow_empty: bool = False,
) -> str:
    if not isinstance(value, str):
        raise _VulnDatabaseError(code, f"{label} must be a string")
    if not value:
        if allow_empty:
            return ""
        raise _VulnDatabaseError(code, f"{label} must not be empty")
    if value != value.strip():
        raise _VulnDatabaseError(
            code,
            f"{label} must not contain leading or trailing whitespace",
        )
    if unicodedata.normalize("NFC", value) != value:
        raise _VulnDatabaseError(
            code,
            f"{label} must use NFC-normalized Unicode",
        )
    if any(
        unicodedata.category(character).startswith("C")
        or unicodedata.category(character) in {"Zl", "Zp"}
        for character in value
    ):
        raise _VulnDatabaseError(
            code,
            f"{label} must not contain control, format, surrogate, or private-use characters",
        )
    encoded_size = len(value.encode("utf-8"))
    if encoded_size > max_bytes:
        raise _VulnDatabaseError(
            code,
            f"{label} exceeds its {max_bytes}-byte limit",
        )
    return value


def _database_unavailable_code(error: Exception) -> str:
    chain: list[BaseException] = []
    current: BaseException | None = error
    while current is not None and current not in chain:
        chain.append(current)
        current = current.__cause__ or current.__context__
    if any(isinstance(item, FileNotFoundError) for item in chain):
        return "missing"
    if any(isinstance(item, PermissionError) for item in chain):
        return "permission"
    if any(isinstance(item, UnicodeError) for item in chain):
        return "encoding"
    message = " ".join(str(item).lower() for item in chain)
    if "bounded canonical json" in message or "must contain one json object" in message:
        return "json"
    if "byte limit" in message or "budget" in message:
        return "bounds"
    if "not a regular file" in message:
        return "non-regular"
    if (
        "symlink, non-directory, or unreadable component" in message
        or "leaf is a symlink" in message
        or "unreadable ancestor" in message
    ):
        return "unsafe-path"
    if "changed" in message or "identity" in message:
        return "unstable"
    if any(isinstance(item, OSError) for item in chain):
        return "io"
    if any(isinstance(item, ArtifactVerificationError) for item in chain):
        return "artifact-boundary"
    return "internal"
