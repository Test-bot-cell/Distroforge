from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from .command import CommandError, CommandRunner, CommandSpec
from .gpg import normalize_fingerprint, verify_argv

_FULL_FINGERPRINT_LENGTHS = frozenset({40, 64})
_HEX = frozenset("0123456789abcdef")
_VALIDSIG = "[GNUPG:] VALIDSIG "


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
        source_path_problem = _regular_file_problem(
            source_iso,
            code_prefix="source-iso",
            description="Source ISO",
            required=strict,
        )
        if source_path_problem:
            checks.append(source_path_problem)
        if options.source_sha256:
            checks.extend(
                self._check_sha256(
                    source_iso,
                    options.source_sha256,
                    path_is_regular=source_path_problem is None,
                )
            )
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
            checks.extend(self._check_signature_metadata(options, require_signature))
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
        # Every real build is a sealed build.  ``policy.strict`` controls
        # redistribution policy, not whether an executing remaster may consume an
        # unauthenticated ISO, so execution must not inherit the advisory dry-run
        # defaults.
        sealed = not runner.dry_run
        report = self.check_source_iso(source_iso, options, strict or sealed)
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
            source_before: tuple[object, ...] | None = None
            signature_before: tuple[object, ...] | None = None
            directory_guards: dict[Path, tuple[int, ...]] = {}
            if sealed:
                source_before = _stable_regular_identity(source_iso, include_digest=False)
                signature_before = _stable_regular_identity(
                    options.source_signature,
                    include_digest=True,
                )
                directory_guards = _directory_guards(
                    (source_iso, options.source_signature)
                )
            result = runner.run(
                CommandSpec(
                    argv=verify_argv(options.source_signature, source_iso),
                    description="Verify detached source ISO signature",
                ),
                check=False,
            )
            if sealed:
                assert source_before is not None
                assert signature_before is not None
                source_after = _stable_regular_identity(source_iso, include_digest=False)
                signature_after = _stable_regular_identity(
                    options.source_signature,
                    include_digest=True,
                )
                directory_guards_after = _directory_guards(
                    (source_iso, options.source_signature)
                )
                if (
                    source_after != source_before
                    or signature_after != signature_before
                    or directory_guards_after != directory_guards
                ):
                    raise ValueError(
                        "Source ISO or detached signature changed during GPG verification"
                    )
                if result.returncode != 0:
                    raise CommandError(result)
                assert options.source_gpg_fingerprint is not None
                _assert_unique_full_signer(
                    result.stdout,
                    options.source_gpg_fingerprint,
                )
            if options.source_gpg_fingerprint:
                runner.run(
                    CommandSpec(
                        argv=("gpg-fingerprint-check", options.source_gpg_fingerprint),
                        description="Require expected source ISO signer fingerprint",
                    )
                )
        return report

    def _check_sha256(
        self,
        path: Path,
        expected: str,
        *,
        path_is_regular: bool,
    ) -> list[TrustCheck]:
        normalized = expected.strip().lower()
        if len(normalized) != 64 or any(char not in _HEX for char in normalized):
            return [
                TrustCheck(
                    "error",
                    "source-sha256-invalid",
                    "Expected SHA256 must be a 64-character hexadecimal digest.",
                    remediation="Use the official SHA256 digest for the exact ISO file.",
                )
            ]
        if not path_is_regular:
            return []
        try:
            identity = _stable_regular_identity(path, include_digest=True)
        except (OSError, ValueError) as exc:
            return [
                TrustCheck(
                    "error",
                    "source-iso-unstable",
                    f"Source ISO could not be stably hashed: {exc}",
                    remediation="Use an immutable local regular file and retry.",
                )
            ]
        actual = identity[-1]
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
        self, options: TrustOptions, required: bool = False
    ) -> list[TrustCheck]:
        signature = options.source_signature
        assert signature is not None
        checks: list[TrustCheck] = []
        path_problem = _regular_file_problem(
            signature,
            code_prefix="source-signature",
            description="Detached signature",
            required=required,
        )
        if path_problem:
            checks.append(path_problem)
        if not options.source_gpg_fingerprint:
            level = "error" if required else "warning"
            checks.append(
                TrustCheck(
                    level,
                    "source-gpg-fingerprint-missing",
                    "Detached signature is configured without an expected signer fingerprint.",
                    remediation="Pin the official signing key fingerprint.",
                )
            )
        else:
            fingerprint = normalize_fingerprint(options.source_gpg_fingerprint)
            if not _is_full_fingerprint(fingerprint):
                checks.append(
                    TrustCheck(
                        "error" if required else "warning",
                        "source-gpg-fingerprint-invalid",
                        "Source signer pin must be one unique full 40- or 64-hex fingerprint.",
                        remediation="Pin the complete fingerprint published by the ISO vendor.",
                    )
                )
            else:
                checks.append(
                    TrustCheck(
                        "info",
                        "source-gpg-fingerprint-pinned",
                        f"Detached signature will be checked against {fingerprint}.",
                    )
                )
        return checks


def _regular_file_problem(
    path: Path,
    *,
    code_prefix: str,
    description: str,
    required: bool,
) -> TrustCheck | None:
    level = "error" if required else "warning"
    remediation = f"Provide {description.lower()} as a non-empty local regular file."
    symlink = _first_symlink_component(path)
    if symlink is not None:
        return TrustCheck(
            level,
            f"{code_prefix}-symlink",
            f"{description} path contains a symlink at {symlink}: {path}",
            remediation=remediation,
        )
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return TrustCheck(
            level,
            f"{code_prefix}-not-local",
            f"{description} is configured but not present locally: {path}",
            remediation=remediation,
        )
    except OSError as exc:
        return TrustCheck(
            level,
            f"{code_prefix}-unreadable",
            f"{description} metadata cannot be read safely: {path}: {exc}",
            remediation=remediation,
        )
    if stat.S_ISLNK(metadata.st_mode):
        return TrustCheck(
            level,
            f"{code_prefix}-symlink",
            f"{description} must not be a symlink: {path}",
            remediation=remediation,
        )
    if not stat.S_ISREG(metadata.st_mode):
        return TrustCheck(
            level,
            f"{code_prefix}-not-regular",
            f"{description} is not a regular file: {path}",
            remediation=remediation,
        )
    if required and metadata.st_size <= 0:
        return TrustCheck(
            "error",
            f"{code_prefix}-empty",
            f"{description} is empty: {path}",
            remediation=remediation,
        )
    return None


def _is_full_fingerprint(value: str) -> bool:
    return len(value) in _FULL_FINGERPRINT_LENGTHS and all(
        character.lower() in _HEX for character in value
    )


def _stat_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _stable_regular_identity(
    path: Path,
    *,
    include_digest: bool,
) -> tuple[object, ...]:
    """Read a regular file without following a final symlink and close its path.

    ``O_NONBLOCK`` prevents a regular-file-to-FIFO race from hanging the trust
    check before ``fstat`` can reject the replacement.  The descriptor, path and
    metadata must still identify the same stable inode after the optional hash.
    """
    symlink = _first_symlink_component(path)
    if symlink is not None:
        raise ValueError(f"path contains a symlink at {symlink}: {path}")
    opening_path = path.lstat()
    if stat.S_ISLNK(opening_path.st_mode) or not stat.S_ISREG(opening_path.st_mode):
        raise ValueError(f"not a non-symlink regular file: {path}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"not a regular file after open: {path}")
        if (
            before.st_dev != opening_path.st_dev
            or before.st_ino != opening_path.st_ino
        ):
            raise ValueError(f"path changed while opening: {path}")
        digest: str | None = None
        if include_digest:
            hasher = hashlib.sha256()
            while chunk := os.read(descriptor, 1024 * 1024):
                hasher.update(chunk)
            digest = hasher.hexdigest()
        after = os.fstat(descriptor)
        closing_symlink = _first_symlink_component(path)
        if closing_symlink is not None:
            raise ValueError(
                f"path gained a symlink at {closing_symlink}: {path}"
            )
        closing_path = path.lstat()
    finally:
        os.close(descriptor)
    before_identity = _stat_identity(before)
    if (
        _stat_identity(after) != before_identity
        or _stat_identity(closing_path) != before_identity
    ):
        raise ValueError(f"changed while being witnessed: {path}")
    if digest is None:
        return before_identity
    return (*before_identity, digest)


def _first_symlink_component(path: Path) -> Path | None:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            return None
        if stat.S_ISLNK(metadata.st_mode):
            return current
    return None


def _directory_identity(path: Path) -> tuple[int, ...]:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(
            f"Trust input parent is not a non-symlink directory: {path}"
        )
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _directory_guards(paths: tuple[Path, ...]) -> dict[Path, tuple[int, ...]]:
    directories: set[Path] = set()
    for path in paths:
        parent = Path(os.path.abspath(path)).parent
        directories.add(parent)
        directories.update(parent.parents)
    return {
        directory: _directory_identity(directory)
        for directory in sorted(directories, key=str)
    }


def _assert_unique_full_signer(status_output: str, expected: str) -> None:
    """Accept only VALIDSIG records linked to the one configured full pin."""
    wanted = normalize_fingerprint(expected)
    if not _is_full_fingerprint(wanted):
        raise ValueError("Source signer pin is not a full OpenPGP fingerprint")
    signatures: list[set[str]] = []
    for line in status_output.splitlines():
        if not line.startswith(_VALIDSIG):
            continue
        fields = line[len(_VALIDSIG) :].split()
        if not fields:
            continue
        identities = {normalize_fingerprint(fields[0])}
        # GnuPG appends the primary-key fingerprint for a signature made by a
        # signing subkey.  A vendor normally publishes that primary fingerprint,
        # so either exact identity may close the one allowed signer.
        if len(fields) >= 10:
            primary = normalize_fingerprint(fields[-1])
            if _is_full_fingerprint(primary):
                identities.add(primary)
        signatures.append(identities)
    if not signatures:
        raise ValueError(
            "GPG reported no valid signature for the source ISO; "
            f"cannot honour the pinned fingerprint {wanted}"
        )
    if any(wanted not in identities for identities in signatures):
        seen = sorted({identity for identities in signatures for identity in identities})
        raise ValueError(
            "Source ISO signature is not exclusively from the pinned fingerprint "
            f"{wanted}; GPG reported {', '.join(seen)}"
        )
