from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from .command import CommandRunner, CommandSpec


@dataclass
class TrustOptions:
    source_sha256: str | None = None
    source_signature: Path | None = None
    source_gpg_fingerprint: str | None = None
    require_source_checksum: bool = False
    require_source_signature: bool = False


@dataclass(frozen=True)
class TrustCheck:
    level: str
    code: str
    message: str
    subject: str = "source"
    remediation: str = ""


@dataclass
class TrustReport:
    checks: list[TrustCheck] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not any(check.level == "error" for check in self.checks)

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "checks": [check.__dict__ for check in self.checks],
        }

    def render_text(self) -> str:
        if not self.checks:
            return "Trust checks: no source artifact configured."
        lines = ["Trust checks"]
        for check in self.checks:
            lines.append(f"{check.level.upper():7} {check.code:24} {check.message}")
            if check.remediation:
                lines.append(f"        fix: {check.remediation}")
        return "\n".join(lines)


class TrustService:
    def check_source_iso(
        self, source_iso: Path | None, options: TrustOptions, strict: bool = False
    ) -> TrustReport:
        checks: list[TrustCheck] = []
        if not source_iso:
            checks.append(
                TrustCheck(
                    "error",
                    "source-iso-missing",
                    "No source ISO is configured.",
                    remediation="Set a source ISO, choose a local ISO starter, or switch to a skeleton starter.",
                )
            )
            return TrustReport(checks)

        require_checksum = options.require_source_checksum or strict
        require_signature = options.require_source_signature or strict

        if not source_iso.exists():
            checks.append(
                TrustCheck(
                    "warning",
                    "source-iso-not-local",
                    f"Source ISO is configured but not present locally: {source_iso}",
                    remediation="Download the ISO before executing, then verify SHA/GPG.",
                )
            )
        if options.source_sha256:
            checks.extend(self._check_sha256(source_iso, options.source_sha256))
        elif require_checksum:
            checks.append(
                TrustCheck(
                    "error",
                    "source-sha256-required",
                    "Strict source integrity requires an expected SHA256 checksum.",
                    remediation="Pass --source-iso-sha256 or add trust.source_sha256 to the definition.",
                )
            )
        else:
            checks.append(
                TrustCheck(
                    "warning",
                    "source-sha256-missing",
                    "No expected SHA256 checksum is configured for the source ISO.",
                    remediation="Record the official SHA256 before executing a build.",
                )
            )

        if options.source_signature:
            checks.extend(self._check_signature_metadata(options, strict))
        elif require_signature:
            checks.append(
                TrustCheck(
                    "error",
                    "source-signature-required",
                    "Strict source authentication requires a detached signature.",
                    remediation="Pass --source-iso-signature and --source-iso-gpg-fingerprint.",
                )
            )
        else:
            checks.append(
                TrustCheck(
                    "info",
                    "source-signature-not-required",
                    "Detached GPG signature verification is not required for this run.",
                    remediation="Enable it for redistributable or maintainer builds.",
                )
            )
        return TrustReport(checks)

    def enforce_source_iso(
        self,
        source_iso: Path | None,
        options: TrustOptions,
        runner: CommandRunner,
        strict: bool = False,
    ) -> TrustReport:
        report = self.check_source_iso(source_iso, options, strict)
        runner.run(
            CommandSpec(
                argv=("trust-report", "ok" if report.ok else "blocked", str(len(report.checks))),
                description="; ".join(f"{check.code}: {check.message}" for check in report.checks)
                or "No source trust checks configured",
            )
        )
        errors = [check for check in report.checks if check.level == "error"]
        if errors:
            raise ValueError("; ".join(f"{check.code}: {check.message}" for check in errors))
        if source_iso and options.source_signature:
            runner.run(
                CommandSpec(
                    argv=("gpg", "--verify", str(options.source_signature), str(source_iso)),
                    description="Verify detached source ISO signature",
                ),
                check=not runner.dry_run,
            )
            if options.source_gpg_fingerprint:
                runner.run(
                    CommandSpec(
                        argv=("gpg-fingerprint-check", options.source_gpg_fingerprint),
                        description="Require expected source ISO signer fingerprint",
                    )
                )
        return report

    def _check_sha256(self, path: Path, expected: str) -> list[TrustCheck]:
        normalized = expected.strip().lower()
        if len(normalized) != 64 or any(char not in "0123456789abcdef" for char in normalized):
            return [
                TrustCheck(
                    "error",
                    "source-sha256-invalid",
                    "Expected SHA256 must be a 64-character hexadecimal digest.",
                    remediation="Use the official SHA256 digest for the exact ISO file.",
                )
            ]
        if not path.exists():
            return [
                TrustCheck(
                    "warning",
                    "source-sha256-deferred",
                    "SHA256 is configured and will be checked once the ISO exists locally.",
                )
            ]
        actual = _sha256(path)
        if actual != normalized:
            return [
                TrustCheck(
                    "error",
                    "source-sha256-mismatch",
                    f"Source ISO SHA256 mismatch: expected {normalized}, got {actual}.",
                    remediation="Discard the ISO and download it again from an official source.",
                )
            ]
        return [TrustCheck("info", "source-sha256-ok", f"Source ISO SHA256 matches {normalized}.")]

    def _check_signature_metadata(
        self, options: TrustOptions, strict: bool = False
    ) -> list[TrustCheck]:
        signature = options.source_signature
        assert signature is not None
        checks: list[TrustCheck] = []
        if not signature.exists():
            checks.append(
                TrustCheck(
                    "warning",
                    "source-signature-not-local",
                    f"Detached signature is configured but not present locally: {signature}",
                    remediation="Download the official detached signature before executing.",
                )
            )
        if not options.source_gpg_fingerprint:
            level = "error" if (options.require_source_signature or strict) else "warning"
            checks.append(
                TrustCheck(
                    level,
                    "source-gpg-fingerprint-missing",
                    "Detached signature is configured without an expected signer fingerprint.",
                    remediation="Pin the official signing key fingerprint.",
                )
            )
        else:
            checks.append(
                TrustCheck(
                    "info",
                    "source-gpg-fingerprint-pinned",
                    f"Detached signature will be checked against {options.source_gpg_fingerprint}.",
                )
            )
        return checks


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
