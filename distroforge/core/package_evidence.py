from __future__ import annotations

import bz2
import errno
import gzip
import hashlib
import json
import lzma
import os
import re
import shlex
import stat
import tempfile
from collections import defaultdict
from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit, urlunsplit

from .chroot import ChrootService
from .command import CommandError, CommandRunner, CommandSpec
from .evidence_run import evidence_run_path, write_immutable_text
from .fsops import FileSystemOps
from .gpg import normalize_fingerprint

if TYPE_CHECKING:
    from .project import Project


PACKAGE_INPUTS_SCHEMA = "distroforge.package-inputs.v1"
PACKAGE_TRANSACTION_SCHEMA = "distroforge.package-input-transaction.v1"
_COPY_CHUNK = 1024 * 1024
_JOURNAL_COLUMNS = 8
_INSECURE_APT_PATTERNS = (
    re.compile(r"\btrusted\s*=\s*yes\b", re.IGNORECASE),
    re.compile(r"\ballow-insecure\s*=\s*yes\b", re.IGNORECASE),
    re.compile(r"\ballow-weak\s*=\s*yes\b", re.IGNORECASE),
    re.compile(r"\ballow-downgrade-to-insecure\s*=\s*yes\b", re.IGNORECASE),
    re.compile(r"\bcheck-valid-until\s*=\s*(?:no|false)\b", re.IGNORECASE),
    re.compile(r"\bcheck-date\s*=\s*(?:no|false)\b", re.IGNORECASE),
    re.compile(r"AllowInsecureRepositories\s+\"?true", re.IGNORECASE),
    re.compile(r"AllowWeakRepositories\s+\"?true", re.IGNORECASE),
    re.compile(r"AllowUnauthenticated\s+\"?true", re.IGNORECASE),
    re.compile(r"Check-Valid-Until\s+\"?false", re.IGNORECASE),
    re.compile(r"Check-Date\s+\"?false", re.IGNORECASE),
)
_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FULL_FINGERPRINT = re.compile(r"^(?:[0-9A-F]{40}|[0-9A-F]{64})$")
_PACKAGES_MEMBER = re.compile(
    r"(?:^|/)Packages(?:\.(?:bz2|gz|lz4|xz|zst))?$"
)
_POLICY_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]*$")
_UNSAFE_APT_FLAGS = {
    "--allow-unauthenticated",
    "--allow-insecure-repositories",
    "--allow-weak-repositories",
    "--force-yes",
    "--no-check-gpg",
}
_UNSAFE_APT_TRUE_KEYS = {
    "acquireallowdowngradetoinsecurerepositories",
    "acquireallowinsecurerepositories",
    "acquireallowweakrepositories",
    "aptgetallowunauthenticated",
}
_UNSAFE_APT_FALSE_KEYS = {
    "acquirecheckdate",
    "acquirecheckvaliduntil",
}
_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}


@dataclass(frozen=True)
class PackageEvidenceValidation:
    ok: bool
    detail: str
    filesystem_causality: str = "unverified"

    @property
    def release_ready(self) -> bool:
        """Whether this result closes both inputs and installed filesystem bytes.

        The package-input proof currently closes signed repository metadata to exact
        ``.deb`` bytes and an installed dpkg identity.  It does not yet prove which
        payload bytes produced every final rootfs path, so callers must not silently
        promote ``ok`` into release readiness.
        """

        return self.ok and self.filesystem_causality == "verified"


@dataclass(frozen=True)
class PackageSourcePolicy:
    """External trust and freshness policy for one repository namespace.

    The policy is intentionally not learned from PACKAGE-INPUTS.json.  A caller must
    construct it from the sealed build definition (and pass the same policy back to
    the release gate), otherwise repository URI, suite and key ownership would be
    self-authorising evidence.
    """

    policy_id: str
    base_uri: str
    suites: tuple[str, ...]
    codenames: tuple[str, ...]
    components: tuple[str, ...]
    architectures: tuple[str, ...]
    signer_fingerprints: tuple[str, ...]
    keyring_sha256: tuple[str, ...]
    snapshot_at: str | None = None
    max_release_age_seconds: int = 31 * 24 * 60 * 60
    max_future_skew_seconds: int = 5 * 60
    require_valid_until: bool = False


@dataclass(frozen=True)
class _IndexPolicyBinding:
    policy: PackageSourcePolicy
    uri: str
    suite: str
    component: str
    architecture: str
    release_member: str


def normalise_package_source_policies(
    policies: Iterable[PackageSourcePolicy | Mapping[str, object]],
) -> tuple[PackageSourcePolicy, ...]:
    """Validate and canonicalise external repository policies for wiring."""

    return _normalise_source_policies(policies)


def package_source_policy_sha256(
    policies: Iterable[PackageSourcePolicy | Mapping[str, object]],
) -> str:
    """Return the canonical digest recorded by package-input evidence."""

    normalised = _normalise_source_policies(policies)
    document = [_source_policy_document(policy) for policy in normalised]
    encoded = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def package_apt_command_argv_sha256(
    commands: Iterable[Sequence[str]],
) -> str:
    """Bind the APT-affecting argv supplied by an external command ledger."""

    relevant = _normalise_apt_command_argv(commands)
    encoded = json.dumps(
        relevant,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _normalise_source_policies(
    policies: Iterable[PackageSourcePolicy | Mapping[str, object]],
) -> tuple[PackageSourcePolicy, ...]:
    result: list[PackageSourcePolicy] = []
    for raw in policies:
        if isinstance(raw, PackageSourcePolicy):
            values: Mapping[str, object] = {
                "policy_id": raw.policy_id,
                "base_uri": raw.base_uri,
                "suites": raw.suites,
                "codenames": raw.codenames,
                "components": raw.components,
                "architectures": raw.architectures,
                "signer_fingerprints": raw.signer_fingerprints,
                "keyring_sha256": raw.keyring_sha256,
                "snapshot_at": raw.snapshot_at,
                "max_release_age_seconds": raw.max_release_age_seconds,
                "max_future_skew_seconds": raw.max_future_skew_seconds,
                "require_valid_until": raw.require_valid_until,
            }
        elif isinstance(raw, Mapping):
            values = raw
        else:
            raise ValueError("package source policy is not an object")

        policy_id = values.get("policy_id")
        if not isinstance(policy_id, str) or not _POLICY_TOKEN.fullmatch(policy_id):
            raise ValueError("package source policy has an unsafe policy_id")
        base_uri = values.get("base_uri")
        if not isinstance(base_uri, str):
            raise ValueError(f"package source policy {policy_id} has no base URI")
        canonical_uri = _canonical_repository_uri(base_uri, base=True)
        suites = _policy_tokens(values.get("suites"), policy_id, "suites")
        codenames = _policy_tokens(
            values.get("codenames"),
            policy_id,
            "codenames",
        )
        components = _policy_tokens(
            values.get("components"),
            policy_id,
            "components",
        )
        architectures = _policy_tokens(
            values.get("architectures"),
            policy_id,
            "architectures",
        )
        fingerprints = _policy_string_values(
            values.get("signer_fingerprints"),
            policy_id,
            "signer fingerprints",
        )
        normalised_fingerprints = tuple(
            sorted(normalize_fingerprint(value) for value in fingerprints)
        )
        if any(
            not _FULL_FINGERPRINT.fullmatch(value)
            for value in normalised_fingerprints
        ):
            raise ValueError(
                f"package source policy {policy_id} has a non-full signer fingerprint"
            )
        if len(set(normalised_fingerprints)) != len(normalised_fingerprints):
            raise ValueError(
                f"package source policy {policy_id} duplicates a signer fingerprint"
            )
        keyring_digests = tuple(
            sorted(
                value.lower()
                for value in _policy_string_values(
                    values.get("keyring_sha256"),
                    policy_id,
                    "keyring SHA256",
                )
            )
        )
        if any(not _HEX_SHA256.fullmatch(value) for value in keyring_digests):
            raise ValueError(
                f"package source policy {policy_id} has a malformed keyring SHA256"
            )
        if len(set(keyring_digests)) != len(keyring_digests):
            raise ValueError(
                f"package source policy {policy_id} duplicates a keyring SHA256"
            )

        snapshot = values.get("snapshot_at")
        if snapshot is not None and not isinstance(snapshot, (str, datetime)):
            raise ValueError(
                f"package source policy {policy_id} has an invalid snapshot instant"
            )
        canonical_snapshot = (
            _canonical_instant(snapshot, f"policy {policy_id} snapshot")
            if snapshot is not None
            else None
        )
        max_age = values.get("max_release_age_seconds", 31 * 24 * 60 * 60)
        future_skew = values.get("max_future_skew_seconds", 5 * 60)
        if (
            isinstance(max_age, bool)
            or not isinstance(max_age, int)
            or max_age <= 0
        ):
            raise ValueError(
                f"package source policy {policy_id} has an invalid maximum Release age"
            )
        if (
            isinstance(future_skew, bool)
            or not isinstance(future_skew, int)
            or future_skew < 0
            or future_skew > 24 * 60 * 60
        ):
            raise ValueError(
                f"package source policy {policy_id} has an invalid future skew"
            )
        require_valid_until = values.get("require_valid_until", False)
        if not isinstance(require_valid_until, bool):
            raise ValueError(
                f"package source policy {policy_id} has invalid Valid-Until policy"
            )
        result.append(
            PackageSourcePolicy(
                policy_id=policy_id,
                base_uri=canonical_uri,
                suites=suites,
                codenames=codenames,
                components=components,
                architectures=architectures,
                signer_fingerprints=normalised_fingerprints,
                keyring_sha256=keyring_digests,
                snapshot_at=canonical_snapshot,
                max_release_age_seconds=max_age,
                max_future_skew_seconds=future_skew,
                require_valid_until=require_valid_until,
            )
        )

    if not result:
        raise ValueError("no external package source policy was supplied")
    result.sort(key=lambda policy: policy.policy_id)
    if len({policy.policy_id for policy in result}) != len(result):
        raise ValueError("package source policy ids are duplicated")
    namespaces: set[tuple[str, str]] = set()
    for policy in result:
        for suite in policy.suites:
            namespace = (policy.base_uri, suite)
            if namespace in namespaces:
                raise ValueError(
                    "package source policies overlap the same repository suite: "
                    f"{policy.base_uri} {suite}"
                )
            namespaces.add(namespace)
    return tuple(result)


def _source_policy_document(policy: PackageSourcePolicy) -> dict[str, object]:
    return {
        "policy_id": policy.policy_id,
        "base_uri": policy.base_uri,
        "suites": list(policy.suites),
        "codenames": list(policy.codenames),
        "components": list(policy.components),
        "architectures": list(policy.architectures),
        "signer_fingerprints": list(policy.signer_fingerprints),
        "keyring_sha256": list(policy.keyring_sha256),
        "snapshot_at": policy.snapshot_at,
        "max_release_age_seconds": policy.max_release_age_seconds,
        "max_future_skew_seconds": policy.max_future_skew_seconds,
        "require_valid_until": policy.require_valid_until,
    }


def _policy_tokens(value: object, policy_id: str, label: str) -> tuple[str, ...]:
    values = _policy_string_values(value, policy_id, label)
    if any(not _POLICY_TOKEN.fullmatch(item) for item in values):
        raise ValueError(
            f"package source policy {policy_id} has an unsafe {label} value"
        )
    normalised = tuple(sorted(values))
    if len(set(normalised)) != len(normalised):
        raise ValueError(f"package source policy {policy_id} duplicates {label}")
    return normalised


def _policy_string_values(
    value: object,
    policy_id: str,
    label: str,
) -> tuple[str, ...]:
    if isinstance(value, str):
        values = (value,)
    elif isinstance(value, Sequence):
        values = tuple(value)
    else:
        raise ValueError(f"package source policy {policy_id} has no {label}")
    if not values or not all(isinstance(item, str) and item for item in values):
        raise ValueError(f"package source policy {policy_id} has invalid {label}")
    return tuple(str(item) for item in values)


def _canonical_repository_uri(value: str, *, base: bool) -> str:
    if any(character.isspace() for character in value):
        raise ValueError("repository URI contains whitespace")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"repository URI is malformed: {value}") from exc
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError("repository URI must use HTTP or HTTPS")
    if (
        not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("repository URI has unsupported authority or suffix")
    try:
        host = parsed.hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("repository URI hostname is invalid") from exc
    if ":" in host:
        host = f"[{host}]"
    if port is not None and not (
        (scheme == "http" and port == 80)
        or (scheme == "https" and port == 443)
    ):
        host = f"{host}:{port}"
    path = parsed.path or "/"
    if "%" in path or "//" in path or any(
        part in {".", ".."} for part in path.split("/")
    ):
        raise ValueError("repository URI path is not canonical")
    if base:
        path = path.rstrip("/") or "/"
    elif path.endswith("/"):
        raise ValueError("repository index URI has a trailing slash")
    return urlunsplit((scheme, host, path, "", ""))


def _canonical_instant(value: str | datetime, label: str) -> str:
    parsed = _parse_iso_instant(value, label)
    return parsed.isoformat()


def _parse_iso_instant(value: str | datetime, label: str) -> datetime:
    try:
        parsed = (
            value
            if isinstance(value, datetime)
            else datetime.fromisoformat(value.replace("Z", "+00:00"))
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} is not a valid ISO-8601 instant") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} must include a UTC offset")
    return parsed.astimezone(UTC)


def _normalise_apt_command_argv(
    commands: Iterable[Sequence[str]],
) -> list[list[str]]:
    relevant: list[list[str]] = []
    for command in commands:
        if isinstance(command, (str, bytes)) or not isinstance(command, Sequence):
            raise ValueError("APT command ledger contains malformed argv")
        argv = list(command)
        if not argv or not all(isinstance(token, str) and token for token in argv):
            raise ValueError("APT command ledger contains malformed argv")
        if _is_apt_command(argv):
            relevant.append(argv)
    return relevant


def _is_apt_command(argv: Sequence[str]) -> bool:
    tools = {"apt", "apt-get", "aptitude", "debootstrap", "mmdebstrap"}
    for token in argv:
        if Path(token).name.lower() in tools:
            return True
        if not any(character.isspace() for character in token):
            continue
        lowered = token.lower()
        if any(
            re.search(
                rf"(?:^|[\s;&|])(?:/[^\s;&|]+/)?{re.escape(tool)}"
                r"(?:[\s;&|]|$)",
                lowered,
            )
            for tool in tools
        ):
            return True
    return False


def default_archive_keyring(family: str) -> Path:
    leaf = (
        "debian-archive-keyring.gpg"
        if family.lower() == "debian"
        else "ubuntu-archive-keyring.gpg"
    )
    return Path("/usr/share/keyrings") / leaf


class PackageEvidenceService:
    """Seal the package bytes consumed by APT before image hygiene deletes them.

    APT verifies a repository while downloading, but that fact is not independently
    replayable once ``apt-get clean`` and list cleanup have removed the bytes.  This
    service installs a DPkg pre-install hook which copies the exact Release, Packages,
    keyring and .deb bytes into a content-addressed staging area.  The staging area is
    copied into the immutable build run after autoremove and before cleanup.

    mmdebstrap/debootstrap run before that hook can exist.  Their transaction is
    therefore captured synchronously by :meth:`capture_bootstrap`.
    """

    _HOOK = "usr/lib/distroforge/capture-package-inputs"
    _CONF = "etc/apt/apt.conf.d/99distroforge-evidence"
    _STAGING = "var/lib/distroforge/package-evidence"

    def __init__(
        self,
        runner: CommandRunner,
        project: Project,
        root: Path,
        evidence_context: dict[str, object] | None,
        *,
        use_sudo: bool = True,
        archive_keyring: Path | None = None,
        archive_keyring_sha256: str | None = None,
        allowed_signer_fingerprints: Iterable[str] = (),
        source_policies: Iterable[
            PackageSourcePolicy | Mapping[str, object]
        ] = (),
        verification_time: str | datetime | None = None,
        fresh_rootfs: bool = False,
    ) -> None:
        self.runner = runner
        self.project = project
        self.root = root
        self.evidence_context = evidence_context or {}
        self.use_sudo = use_sudo
        selected_keyring = archive_keyring or default_archive_keyring(
            project.release.family
        )
        self.archive_keyring = (
            selected_keyring.resolve()
            if selected_keyring.exists()
            else selected_keyring
        )
        self._source_archive_keyring = self.archive_keyring
        self.archive_keyring_sha256 = (
            archive_keyring_sha256.strip().lower()
            if archive_keyring_sha256
            else None
        )
        self.allowed_signer_fingerprints = tuple(
            sorted(
                {
                    normalized
                    for value in allowed_signer_fingerprints
                    if (normalized := normalize_fingerprint(value))
                }
            )
        )
        source_policy_values = tuple(source_policies)
        self.source_policies = (
            _normalise_source_policies(source_policy_values)
            if source_policy_values
            else ()
        )
        selected_verification_time = (
            verification_time
            if verification_time is not None
            else self.evidence_context.get("created_at")
        )
        self.verification_time = (
            _canonical_instant(
                selected_verification_time,
                "package verification time",
            )
            if isinstance(selected_verification_time, (str, datetime))
            else None
        )
        self.fresh_rootfs = fresh_rootfs
        self._transaction_paths: list[Path] = []
        self._baseline_inventory: list[dict[str, str]] | None = None
        self._capture_installed = False

    @property
    def _run_id(self) -> str:
        value = self.evidence_context.get("run_id")
        if not isinstance(value, str) or not value or Path(value).name != value:
            raise ValueError("Package evidence requires a safe build run_id")
        return value

    @property
    def _executed(self) -> bool:
        return (
            self.evidence_context.get("mode") == "execute"
            and not self.runner.dry_run
        )

    @property
    def _run_dir(self) -> Path:
        return evidence_run_path(
            self.project.output_dir,
            self._run_id,
            "PACKAGE-INPUTS.json",
            executed=self._executed,
        ).parent

    def capture_source_baseline(self) -> None:
        """Remember packages supplied by a trusted source ISO before any mutation."""
        self.runner.run(
            CommandSpec(
                argv=("write-file", str(self._transaction_path("source-baseline"))),
                description="Plan source ISO package baseline evidence",
            )
        )
        if self.runner.dry_run:
            return
        inventory = self._installed_inventory()
        # The source ISO is authenticated separately, so only this exact package
        # inventory may be exempted from post-unpack APT byte capture.  The aggregate
        # validator binds this list back to this transaction instead of trusting a
        # free-standing baseline claim.
        self._baseline_inventory = inventory
        transaction = {
            "schema": PACKAGE_TRANSACTION_SCHEMA,
            "run_id": self._run_id,
            "id": "source-baseline",
            "kind": "source-iso-baseline",
            "fresh_rootfs": False,
            "records": [],
            "inventory": inventory,
            "complete": True,
            "issues": [],
        }
        self._write_transaction("source-baseline", transaction)

    def seal_bootstrap_keyring(self) -> Path:
        """Copy and rehash the pinned trust anchor before the bootstrap process.

        Hashing a host path in preflight and handing that mutable path to
        mmdebstrap/debootstrap leaves a change/restore window.  The bootstrap consumes
        this content-addressed run copy instead; capture_bootstrap later records the
        same bytes as the transaction's host-bootstrap keyring.
        """
        expected = self.archive_keyring_sha256
        planned_digest = expected or "UNPINNED"
        target = self._run_dir / "apt" / "blobs" / "keyring" / planned_digest
        self.runner.run(
            CommandSpec(
                argv=(
                    "copy-file",
                    str(self._source_archive_keyring),
                    str(target),
                ),
                description="Seal bootstrap archive keyring before dispatch",
            )
        )
        if self.runner.dry_run:
            return target
        if expected is None or not _HEX_SHA256.fullmatch(expected):
            raise ValueError("Bootstrap archive keyring SHA256 is not pinned")
        actual, size = _stable_digest(self._source_archive_keyring)
        if actual != expected:
            raise ValueError(
                "Bootstrap archive keyring bytes differ from the configured SHA256"
            )
        target = self._run_dir / "apt" / "blobs" / "keyring" / actual
        _stable_copy(
            self._source_archive_keyring,
            target,
            expected_sha256=actual,
            expected_size=size,
        )
        self.archive_keyring = target
        return target

    def capture_bootstrap(self) -> None:
        """Capture transaction zero before live-base rewrites lists and sources."""
        self.runner.run(
            CommandSpec(
                argv=("write-file", str(self._transaction_path("bootstrap"))),
                description="Plan bootstrap package-input evidence",
            )
        )
        if self.runner.dry_run:
            return
        records = self._current_apt_records(include_host_keyring=True)
        inventory = self._installed_inventory()
        # A fresh bootstrap has no earlier authenticated filesystem.  Every package
        # that survives into the final target must therefore trace to captured .deb
        # bytes, including the packages installed by mmdebstrap/debootstrap itself.
        self._baseline_inventory = []
        transaction = self._close_transaction(
            "bootstrap",
            "bootstrap",
            records,
            inventory=inventory,
            require_debs=True,
        )
        self._write_transaction("bootstrap", transaction)

    def install_capture_hook(self) -> None:
        """Install a transaction hook before any post-bootstrap package install."""
        # An extracted ISO tree can carry files left by an interrupted earlier run:
        # unsquashfs overwrite mode does not prune them.  Remove that stale journal,
        # CAS and hook before this run starts recording.
        self._remove_capture_hook(force=True)
        self._capture_installed = True
        fs = FileSystemOps(self.runner, self.use_sudo)
        fs.write_text(
            self.root / self._HOOK,
            _capture_hook_script(),
            "Install package-input pre-install capture hook",
            mode="0755",
        )
        fs.write_text(
            self.root / self._CONF,
            _capture_hook_config(),
            "Configure package-input capture and retained APT downloads",
            mode="0644",
        )

    def cleanup_target_capture(self) -> None:
        """Remove a partially installed hook after an aborted build."""
        self._remove_capture_hook()

    def seal_before_cleanup(self) -> Path | None:
        """Copy hook captures into the run and write the offline-verifiable closure."""
        target = evidence_run_path(
            self.project.output_dir,
            self._run_id,
            "PACKAGE-INPUTS.json",
            executed=self._executed,
        )
        self.runner.run(
            CommandSpec(
                argv=("write-file", str(target)),
                description="Write sealed package-input closure",
            )
        )
        if self.runner.dry_run:
            self._remove_capture_hook()
            return None

        try:
            self._collect_hook_transactions()
            # Captures the final active repository state as evidence even when an
            # update downloaded no packages and therefore invoked no DPkg hook.
            current = self._current_apt_records(include_host_keyring=False)
            self._write_transaction(
                "final-apt-state",
                self._close_transaction(
                    "final-apt-state",
                    "apt-state",
                    current,
                    inventory=[],
                    require_debs=False,
                ),
            )
            local_transaction = self._capture_local_debs()
            if local_transaction is not None:
                self._write_transaction("local-builds", local_transaction)

            final_inventory = self._installed_inventory()
            transaction_refs = [
                _identity_for_run(path, self._run_dir)
                for path in self._transaction_paths
            ]
            command_argv = [spec.argv for spec in self.runner.history]
            aggregate = {
                "schema": PACKAGE_INPUTS_SCHEMA,
                "run_id": self._run_id,
                "scope": "target-root",
                "source_mode": self.project.source_mode,
                "capture_mode": "dpkg-pre-install-sealed-copy",
                "fresh_rootfs": self.fresh_rootfs,
                "archive_keyring": {
                    "source": str(self.archive_keyring),
                    "expected_sha256": self.archive_keyring_sha256,
                },
                "allowed_signer_fingerprints": list(
                    self.allowed_signer_fingerprints
                ),
                "source_policy_sha256": (
                    package_source_policy_sha256(self.source_policies)
                    if self.source_policies
                    else None
                ),
                "verification_time": self.verification_time,
                "apt_command_argv_sha256": package_apt_command_argv_sha256(
                    command_argv
                ),
                "transactions": transaction_refs,
                "baseline_inventory": self._baseline_inventory or [],
                "final_inventory": final_inventory,
            }
            validation = validate_package_evidence_payload(
                aggregate,
                self._run_dir,
                run_gpg=True,
                expected_source_mode=self.project.source_mode,
                expected_signer_fingerprints=self.allowed_signer_fingerprints,
                expected_keyring_sha256=self.archive_keyring_sha256,
                expected_source_policies=self.source_policies,
                expected_verification_time=self.verification_time,
                apt_command_argv=command_argv,
            )
            aggregate["validation"] = {
                "ok": validation.ok,
                "detail": validation.detail,
                "filesystem_causality": validation.filesystem_causality,
                "release_ready": validation.release_ready,
            }
            write_immutable_text(target, json.dumps(aggregate, indent=2) + "\n")
            if not validation.ok:
                raise ValueError(
                    f"Package-input closure failed: {validation.detail}"
                )
            return target
        finally:
            self._remove_capture_hook()

    def _transaction_path(self, name: str) -> Path:
        return evidence_run_path(
            self.project.output_dir,
            self._run_id,
            f"apt/transactions/{name}.json",
            executed=self._executed,
        )

    def _write_transaction(
        self,
        name: str,
        transaction: dict[str, object],
    ) -> None:
        target = self._transaction_path(name)
        write_immutable_text(target, json.dumps(transaction, indent=2) + "\n")
        self._transaction_paths.append(target)

    def _current_apt_records(
        self,
        *,
        include_host_keyring: bool,
    ) -> list[dict[str, object]]:
        lists_dir, archives_dir = self._apt_directories()
        records: list[dict[str, object]] = []
        for kind, path, extra in self._apt_configuration_files(
            include_host_keyring=include_host_keyring
        ):
            records.append(self._seal_source(kind, path, extra=extra))

        index_targets = self._index_targets()
        for path, uri in index_targets:
            records.append(self._seal_source("index", path, extra=uri))

        for path in _confined_regular_files_by_suffix(
            self.root,
            lists_dir,
            ("InRelease", "Release", "Release.gpg"),
        ):
            records.append(self._seal_source("release", path))

        for path in _confined_regular_files_by_suffix(
            self.root,
            archives_dir,
            (".deb",),
        ):
            records.append(self._seal_source("deb", path))
        return records

    def _apt_directories(self) -> tuple[Path, Path]:
        result = self.runner.run(
            CommandSpec(
                argv=ChrootService(
                    self.runner, self.root, self.use_sudo
                ).command(
                    "apt-config",
                    "shell",
                    "lists",
                    "Dir::State::lists/f",
                    "archives",
                    "Dir::Cache::archives/f",
                ).argv,
                needs_root=self.use_sudo,
                description="Resolve effective APT lists and archive directories",
            )
        )
        values: dict[str, str] = {}
        for line in result.stdout.splitlines():
            key, separator, raw = line.partition("=")
            if separator and key in {"lists", "archives"}:
                try:
                    parsed = shlex.split(raw)
                except ValueError as exc:
                    raise ValueError(f"APT returned an invalid {key} path") from exc
                if len(parsed) == 1:
                    values[key] = parsed[0]
        missing = {"lists", "archives"} - values.keys()
        if missing:
            raise ValueError(
                "APT did not disclose its effective directories: "
                + ", ".join(sorted(missing))
            )
        return (
            _inside_root(
                self.root,
                values["lists"],
                expected="directory",
            ),
            _inside_root(
                self.root,
                values["archives"],
                expected="directory",
            ),
        )

    def _index_targets(self) -> list[tuple[Path, str]]:
        result = self.runner.run(
            CommandSpec(
                argv=ChrootService(
                    self.runner, self.root, self.use_sudo
                ).command(
                    "apt-get",
                    "indextargets",
                    "--format",
                    "$(IDENTIFIER)\t$(FILENAME)\t$(URI)",
                ).argv,
                needs_root=self.use_sudo,
                description="Enumerate active APT package indexes",
            )
        )
        targets: list[tuple[Path, str]] = []
        for line in result.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) != 3 or parts[0] != "Packages":
                continue
            targets.append(
                (
                    _inside_root(
                        self.root,
                        parts[1],
                        expected="regular",
                    ),
                    parts[2],
                )
            )
        return sorted(set(targets), key=lambda item: (str(item[0]), item[1]))

    def _apt_configuration_files(
        self,
        *,
        include_host_keyring: bool,
    ) -> list[tuple[str, Path, str]]:
        candidates: list[tuple[str, Path, str]] = []
        fixed = (
            ("source", self.root / "etc/apt/sources.list", ""),
            ("config", self.root / "etc/apt/apt.conf", ""),
            ("keyring", self.root / "etc/apt/trusted.gpg", ""),
        )
        candidates.extend(
            item
            for item in fixed
            if _confined_optional_regular_file(self.root, item[1])
        )
        for kind, relative in (
            ("source", "etc/apt/sources.list.d"),
            ("config", "etc/apt/apt.conf.d"),
            ("keyring", "etc/apt/trusted.gpg.d"),
            ("keyring", "etc/apt/keyrings"),
            ("keyring", "usr/share/keyrings"),
        ):
            directory = self.root / relative
            candidates.extend(
                (kind, path, "")
                for path in _confined_tree_files(self.root, directory)
            )
        if include_host_keyring:
            candidates.append(("keyring", self.archive_keyring, "host-bootstrap"))
        return candidates

    def _seal_source(
        self,
        kind: str,
        source: Path,
        *,
        extra: str = "",
    ) -> dict[str, object]:
        confinement_root = self.root
        if extra == "host-bootstrap":
            if kind != "keyring":
                raise ValueError(
                    "host-bootstrap exception is restricted to a keyring"
                )
            expected = self.archive_keyring_sha256
            if expected is None or not _HEX_SHA256.fullmatch(expected):
                raise ValueError("host-bootstrap keyring has no external SHA256 pin")
            expected_source = (
                self._run_dir / "apt" / "blobs" / "keyring" / expected
            )
            if (
                Path(os.path.abspath(source))
                != Path(os.path.abspath(expected_source))
                or source != self.archive_keyring
            ):
                raise ValueError(
                    "host-bootstrap keyring was not consumed from its sealed run copy"
                )
            confinement_root = self._run_dir
        with _open_confined_path(
            confinement_root,
            source,
            expected="regular",
        ) as descriptor:
            digest, size = _stable_digest_fd(descriptor)
            if extra == "host-bootstrap" and digest != self.archive_keyring_sha256:
                raise ValueError(
                    "host-bootstrap sealed keyring differs from its external pin"
                )
            suffix = ".deb" if kind in {"deb", "local-deb"} else ""
            target = self._run_dir / "apt" / "blobs" / kind / f"{digest}{suffix}"
            self.runner.run(
                CommandSpec(
                    argv=("copy-file", str(source), str(target)),
                    description=f"Seal package-input {kind} bytes",
                )
            )
            if Path(os.path.abspath(source)) != Path(os.path.abspath(target)):
                _stable_copy_fd(
                    descriptor,
                    source,
                    target,
                    expected_sha256=digest,
                    expected_size=size,
                )
        return {
            "kind": kind,
            "source_path": str(source),
            "path": str(target.relative_to(self._run_dir)),
            "size": size,
            "sha256": digest,
            "extra": extra,
        }

    def _close_transaction(
        self,
        transaction_id: str,
        kind: str,
        records: list[dict[str, object]],
        *,
        inventory: list[dict[str, str]],
        require_debs: bool,
    ) -> dict[str, object]:
        command_argv = [spec.argv for spec in self.runner.history]
        issues = _insecure_configuration_issues(records, self._run_dir)
        issues.extend(_insecure_apt_argv_issues(command_argv))
        closure = _repository_closure(
            records,
            self._run_dir,
            runner=self.runner,
            allowed_fingerprints=self.allowed_signer_fingerprints,
            source_policies=self.source_policies,
            verification_time=self.verification_time,
        )
        closure_issues = closure.get("issues")
        if isinstance(closure_issues, list):
            issues.extend(str(issue) for issue in closure_issues)
        deb_count = sum(record.get("kind") == "deb" for record in records)
        if require_debs and deb_count == 0:
            issues.append("transaction captured no .deb bytes")
        if kind == "bootstrap":
            host_keyrings = [
                record
                for record in records
                if record.get("kind") == "keyring"
                and record.get("extra") == "host-bootstrap"
            ]
            if not host_keyrings:
                issues.append("bootstrap trust anchor was not captured")
            elif self.archive_keyring_sha256 is None:
                issues.append("bootstrap trust-anchor SHA256 is not pinned")
            elif not any(
                record.get("sha256") == self.archive_keyring_sha256
                for record in host_keyrings
            ):
                issues.append("bootstrap trust-anchor SHA256 differs from its pin")
        if not self.allowed_signer_fingerprints:
            issues.append("no full archive signer fingerprint is pinned")
        return {
            "schema": PACKAGE_TRANSACTION_SCHEMA,
            "run_id": self._run_id,
            "id": transaction_id,
            "kind": kind,
            "fresh_rootfs": self.fresh_rootfs,
            "records": records,
            "inventory": inventory,
            "closure": closure,
            "complete": not issues,
            "issues": sorted(set(issues)),
        }

    def _installed_inventory(self) -> list[dict[str, str]]:
        result = self.runner.run(
            CommandSpec(
                argv=ChrootService(
                    self.runner, self.root, self.use_sudo
                ).command(
                    "dpkg-query",
                    "-W",
                    "--showformat=${Package}\\t${Version}\\t${Architecture}\\t${db:Status-Status}\\n",
                ).argv,
                needs_root=self.use_sudo,
                description="Capture installed dpkg inventory",
            )
        )
        inventory: list[dict[str, str]] = []
        for line in result.stdout.splitlines():
            fields = line.split("\t")
            if len(fields) != 4 or fields[3] != "installed":
                continue
            inventory.append(
                {
                    "package": fields[0],
                    "version": fields[1],
                    "architecture": fields[2],
                }
            )
        return sorted(
            inventory,
            key=lambda item: (
                item["package"],
                item["version"],
                item["architecture"],
            ),
        )

    def _collect_hook_transactions(self) -> None:
        staging = self.root / self._STAGING
        journal = staging / "transactions.tsv"
        try:
            with _open_confined_path(
                self.root,
                journal,
                expected="regular",
            ) as journal_descriptor:
                journal_bytes = _stable_read_fd(journal_descriptor)
        except FileNotFoundError:
            return
        grouped: dict[str, list[dict[str, object]]] = defaultdict(list)
        try:
            journal_text = journal_bytes.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ValueError("Package pre-install journal is not UTF-8") from exc
        for raw_line in journal_text.splitlines():
            fields = raw_line.split("\t")
            if len(fields) != _JOURNAL_COLUMNS or fields[0] != "F":
                raise ValueError("Package pre-install journal is malformed")
            _, txid, kind, digest, size_text, original, extra, status = fields
            if (
                not txid.isdigit()
                or kind not in {"source", "config", "keyring", "release", "index", "deb"}
                or not _HEX_SHA256.fullmatch(digest)
                or not size_text.isdigit()
                or status != "stable"
            ):
                raise ValueError("Package pre-install journal contains an invalid record")
            _inside_root(
                self.root,
                original,
                expected="regular",
            )
            source = staging / "store" / kind / digest
            with _open_confined_path(
                self.root,
                source,
                expected="regular",
            ) as source_descriptor:
                actual_sha, actual_size = _stable_digest_fd(source_descriptor)
                if actual_sha != digest or actual_size != int(size_text):
                    raise ValueError(
                        "Package pre-install CAS differs from its journal"
                    )
                suffix = ".deb" if kind == "deb" else ""
                target = (
                    self._run_dir
                    / "apt"
                    / "blobs"
                    / kind
                    / f"{digest}{suffix}"
                )
                self.runner.run(
                    CommandSpec(
                        argv=("copy-file", str(source), str(target)),
                        description=f"Copy sealed APT transaction {txid} {kind}",
                    )
                )
                _stable_copy_fd(
                    source_descriptor,
                    source,
                    target,
                    expected_sha256=digest,
                    expected_size=actual_size,
                )
            grouped[txid].append(
                {
                    "kind": kind,
                    "source_path": original,
                    "path": str(target.relative_to(self._run_dir)),
                    "size": actual_size,
                    "sha256": digest,
                    "extra": extra,
                }
            )
        for txid in sorted(grouped, key=int):
            name = f"apt-{int(txid):04d}"
            transaction = self._close_transaction(
                name,
                "apt-pre-install",
                grouped[txid],
                inventory=[],
                require_debs=True,
            )
            self._write_transaction(name, transaction)

        journal_target = self._run_dir / "apt" / "transactions.tsv"
        self.runner.run(
            CommandSpec(
                argv=("copy-file", str(journal), str(journal_target)),
                description="Seal package pre-install transaction journal",
            )
        )
        with _open_confined_path(
            self.root,
            journal,
            expected="regular",
        ) as journal_descriptor:
            _stable_copy_fd(
                journal_descriptor,
                journal,
                journal_target,
            )

    def _capture_local_debs(self) -> dict[str, object] | None:
        roots = (
            self.root
            / "usr"
            / "src"
            / "distroforge-desktops"
            / "distroforge-desktop-debs",
            self.root / "usr/src/distroforge-kernel",
        )
        paths = sorted(
            {
                path
                for directory in roots
                for path in _confined_tree_files(self.root, directory)
                if path.name.endswith(".deb")
            }
        )
        if not paths:
            return None
        records: list[dict[str, object]] = []
        for path in paths:
            record = self._seal_source("local-deb", path)
            sealed_path = self._run_dir / str(record["path"])
            result = self.runner.run(
                CommandSpec(
                    argv=(
                        "dpkg-deb",
                        "--show",
                        "--showformat=${Package}\\t${Version}\\t${Architecture}\\n",
                        str(sealed_path),
                    ),
                    description="Read locally built .deb identity",
                )
            )
            fields = result.stdout.rstrip("\n").split("\t")
            if len(fields) != 3 or not all(fields):
                raise ValueError(f"Could not read local .deb identity: {path}")
            record["package"] = fields[0]
            record["version"] = fields[1]
            record["architecture"] = fields[2]
            records.append(record)
        return {
            "schema": PACKAGE_TRANSACTION_SCHEMA,
            "run_id": self._run_id,
            "id": "local-builds",
            "kind": "local-build",
            "fresh_rootfs": self.fresh_rootfs,
            "records": records,
            "inventory": [],
            "closure": {
                "authenticated_releases": [],
                "indexes": [],
                "debs": [],
                "issues": [],
            },
            "complete": False,
            "issues": [
                "locally built .deb inputs require a separate producer attestation"
            ],
        }

    def _remove_capture_hook(self, *, force: bool = False) -> None:
        if not force and not self._capture_installed:
            return
        if not self.runner.dry_run:
            # FileSystemOps operates from the host side.  Refuse before either
            # removal or creation if a hostile extracted rootfs redirects one of
            # these paths through a symlink/mount outside the target.
            _confined_optional_regular_file(self.root, self.root / self._CONF)
            _confined_optional_regular_file(self.root, self.root / self._HOOK)
            _confined_optional_directory(
                self.root,
                self.root / self._STAGING,
            )
        fs = FileSystemOps(self.runner, self.use_sudo)
        try:
            fs.remove(
                self.root / self._CONF,
                "Remove package-input APT hook configuration",
            )
            fs.remove(
                self.root / self._HOOK,
                "Remove package-input capture hook",
            )
            fs.remove_tree(
                self.root / self._STAGING,
                "Remove package-input staging bytes from target",
            )
        finally:
            self._capture_installed = False


def validate_package_evidence(
    run_dir: Path,
    *,
    expected_run_id: str,
    expected_source_mode: str,
    expected_signer_fingerprints: Iterable[str],
    expected_keyring_sha256: str | None,
    expected_source_policies: Iterable[
        PackageSourcePolicy | Mapping[str, object]
    ] | None = None,
    expected_verification_time: str | datetime | None = None,
    apt_command_argv: Iterable[Sequence[str]] | None = None,
) -> PackageEvidenceValidation:
    path = run_dir / "PACKAGE-INPUTS.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return PackageEvidenceValidation(False, f"package evidence is unreadable: {exc}")
    if not isinstance(payload, dict) or payload.get("run_id") != expected_run_id:
        return PackageEvidenceValidation(
            False, "package evidence belongs to another build run"
        )
    return validate_package_evidence_payload(
        payload,
        run_dir,
        run_gpg=True,
        expected_source_mode=expected_source_mode,
        expected_signer_fingerprints=expected_signer_fingerprints,
        expected_keyring_sha256=expected_keyring_sha256,
        expected_source_policies=expected_source_policies,
        expected_verification_time=expected_verification_time,
        apt_command_argv=apt_command_argv,
    )


def validate_package_evidence_payload(
    payload: dict[str, object],
    run_dir: Path,
    *,
    run_gpg: bool,
    expected_source_mode: str | None = None,
    expected_signer_fingerprints: Iterable[str] | None = None,
    expected_keyring_sha256: str | None = None,
    expected_source_policies: Iterable[
        PackageSourcePolicy | Mapping[str, object]
    ] | None = None,
    expected_verification_time: str | datetime | None = None,
    apt_command_argv: Iterable[Sequence[str]] | None = None,
) -> PackageEvidenceValidation:
    if payload.get("schema") != PACKAGE_INPUTS_SCHEMA:
        return PackageEvidenceValidation(False, "package evidence schema is unsupported")
    if (
        payload.get("scope") != "target-root"
        or payload.get("capture_mode") != "dpkg-pre-install-sealed-copy"
    ):
        return PackageEvidenceValidation(
            False, "package evidence capture contract is unsupported"
        )
    run_id = payload.get("run_id")
    if not isinstance(run_id, str) or not run_id or Path(run_id).name != run_id:
        return PackageEvidenceValidation(False, "package evidence has no safe run_id")
    source_mode = payload.get("source_mode")
    if source_mode not in {"bootstrap", "iso"}:
        return PackageEvidenceValidation(False, "package evidence source mode is invalid")
    if expected_source_mode not in {"bootstrap", "iso"}:
        return PackageEvidenceValidation(
            False, "no external package source-mode policy was supplied"
        )
    if source_mode != expected_source_mode:
        return PackageEvidenceValidation(
            False, "package evidence source mode differs from the build definition"
        )
    if source_mode == "bootstrap" and payload.get("fresh_rootfs") is not True:
        return PackageEvidenceValidation(
            False, "package evidence does not prove a fresh bootstrap rootfs"
        )
    if expected_source_policies is None:
        return PackageEvidenceValidation(
            False, "no external per-source package policy was supplied"
        )
    try:
        source_policies = _normalise_source_policies(expected_source_policies)
        policy_sha256 = package_source_policy_sha256(source_policies)
    except ValueError as exc:
        return PackageEvidenceValidation(False, str(exc))
    if payload.get("source_policy_sha256") != policy_sha256:
        return PackageEvidenceValidation(
            False,
            "package source-policy digest differs from the external build policy",
        )
    if expected_verification_time is None:
        return PackageEvidenceValidation(
            False, "no external package verification time was supplied"
        )
    try:
        verification_time = _canonical_instant(
            expected_verification_time,
            "external package verification time",
        )
    except ValueError as exc:
        return PackageEvidenceValidation(False, str(exc))
    if payload.get("verification_time") != verification_time:
        return PackageEvidenceValidation(
            False,
            "package verification time differs from the external build instant",
        )
    if apt_command_argv is None:
        return PackageEvidenceValidation(
            False, "no external APT command ledger was supplied"
        )
    try:
        command_argv = tuple(tuple(command) for command in apt_command_argv)
        argv_issues = _insecure_apt_argv_issues(command_argv)
        if argv_issues:
            return PackageEvidenceValidation(False, argv_issues[0])
        command_sha256 = package_apt_command_argv_sha256(command_argv)
    except (TypeError, ValueError) as exc:
        return PackageEvidenceValidation(False, str(exc))
    if payload.get("apt_command_argv_sha256") != command_sha256:
        return PackageEvidenceValidation(
            False,
            "APT command ledger differs from the sealed package evidence",
        )
    allowed_raw = payload.get("allowed_signer_fingerprints")
    if not isinstance(allowed_raw, list) or not allowed_raw:
        return PackageEvidenceValidation(
            False, "package evidence has no externally pinned archive signer"
        )
    allowed: set[str] = set()
    for value in allowed_raw:
        if not isinstance(value, str):
            return PackageEvidenceValidation(False, "archive signer pin is malformed")
        normalized = normalize_fingerprint(value)
        if len(normalized) not in {40, 64} or any(
            char not in "0123456789ABCDEF" for char in normalized
        ):
            return PackageEvidenceValidation(False, "archive signer pin is not full")
        allowed.add(normalized)
    if len(allowed) != len(allowed_raw):
        return PackageEvidenceValidation(
            False, "archive signer pins are duplicated or non-canonical"
        )
    policy_allowed = {
        fingerprint
        for policy in source_policies
        for fingerprint in policy.signer_fingerprints
    }
    if allowed != policy_allowed:
        return PackageEvidenceValidation(
            False,
            "package evidence signer pins differ from per-source policy",
        )
    if expected_signer_fingerprints is None:
        return PackageEvidenceValidation(
            False, "no external archive signer policy was supplied"
        )
    expected_allowed = {
        normalize_fingerprint(value)
        for value in expected_signer_fingerprints
    }
    if (
        not expected_allowed
        or any(
            not _FULL_FINGERPRINT.fullmatch(value)
            for value in expected_allowed
        )
        or allowed != expected_allowed
        or expected_allowed != policy_allowed
    ):
        return PackageEvidenceValidation(
            False,
            "package evidence signer pins differ from the external build policy",
        )
    keyring = payload.get("archive_keyring")
    if not isinstance(keyring, dict):
        return PackageEvidenceValidation(False, "archive keyring identity is malformed")
    expected_keyring_sha = keyring.get("expected_sha256")
    if source_mode == "bootstrap":
        if (
            not isinstance(expected_keyring_sha, str)
            or not _HEX_SHA256.fullmatch(expected_keyring_sha)
        ):
            return PackageEvidenceValidation(
                False, "bootstrap keyring SHA256 is not externally pinned"
            )
        if (
            expected_keyring_sha256 is None
            or expected_keyring_sha.lower()
            != expected_keyring_sha256.strip().lower()
        ):
            return PackageEvidenceValidation(
                False,
                "package evidence keyring pin differs from the external build policy",
            )
        policy_keyrings = {
            digest
            for policy in source_policies
            for digest in policy.keyring_sha256
        }
        if expected_keyring_sha.lower() not in policy_keyrings:
            return PackageEvidenceValidation(
                False,
                "bootstrap keyring pin is not bound to any repository policy",
            )
    if source_mode == "iso" and expected_keyring_sha is not None and (
        not isinstance(expected_keyring_sha, str)
        or not _HEX_SHA256.fullmatch(expected_keyring_sha)
    ):
        return PackageEvidenceValidation(
            False, "archive keyring SHA256 pin is malformed"
        )

    refs = payload.get("transactions")
    if not isinstance(refs, list) or not refs:
        return PackageEvidenceValidation(False, "package evidence has no transactions")
    transactions: list[dict[str, object]] = []
    transaction_paths: set[str] = set()
    transaction_ids: set[str] = set()
    for ref in refs:
        identity_error = _identity_error(ref, run_dir)
        if identity_error:
            return PackageEvidenceValidation(False, identity_error)
        assert isinstance(ref, dict)
        relative = str(ref["path"])
        if relative in transaction_paths:
            return PackageEvidenceValidation(
                False, "package transaction is referenced more than once"
            )
        transaction_paths.add(relative)
        transaction_path = run_dir / str(ref["path"])
        try:
            transaction = json.loads(transaction_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return PackageEvidenceValidation(
                False, f"package transaction is unreadable: {exc}"
            )
        if (
            not isinstance(transaction, dict)
            or transaction.get("schema") != PACKAGE_TRANSACTION_SCHEMA
            or transaction.get("run_id") != run_id
        ):
            return PackageEvidenceValidation(
                False, "package transaction identity is inconsistent"
            )
        transaction_id = transaction.get("id")
        if (
            not isinstance(transaction_id, str)
            or not transaction_id
            or Path(transaction_id).name != transaction_id
            or transaction_id in transaction_ids
        ):
            return PackageEvidenceValidation(
                False, "package transaction id is unsafe or duplicated"
            )
        transaction_ids.add(transaction_id)
        transactions.append(transaction)

    all_archive_packages: dict[tuple[str, str, str], str] = {}
    baseline = _inventory_map(payload.get("baseline_inventory"))
    final = _inventory_map(payload.get("final_inventory"))
    if baseline is None or final is None:
        return PackageEvidenceValidation(False, "dpkg inventory is malformed")

    bootstrap_transactions: list[dict[str, object]] = []
    baseline_transactions: list[dict[str, object]] = []
    final_state_transactions: list[dict[str, object]] = []
    bootstrap_inventory: dict[
        tuple[str, str, str], tuple[str, str, str]
    ] = {}
    for transaction in transactions:
        records = transaction.get("records")
        if not isinstance(records, list):
            return PackageEvidenceValidation(False, "package transaction has no records")
        for record in records:
            identity_error = _identity_error(record, run_dir)
            if identity_error:
                return PackageEvidenceValidation(False, identity_error)
        issues = _insecure_configuration_issues(records, run_dir)
        if issues:
            return PackageEvidenceValidation(False, issues[0])
        kind = transaction.get("kind")
        if (
            transaction.get("complete") is not True
            or transaction.get("issues") != []
        ):
            return PackageEvidenceValidation(
                False, f"package transaction {transaction.get('id')} was not closed"
            )
        if kind == "source-iso-baseline":
            transaction_inventory = _inventory_map(transaction.get("inventory"))
            if transaction_inventory is None or records:
                return PackageEvidenceValidation(
                    False, "source ISO baseline transaction is malformed"
                )
            baseline_transactions.append(transaction)
            continue
        if kind == "local-build":
            return PackageEvidenceValidation(
                False,
                "locally built .deb inputs have no independently verified producer attestation",
            )
        if kind not in {"bootstrap", "apt-pre-install", "apt-state"}:
            return PackageEvidenceValidation(
                False, f"package transaction kind is unsupported: {kind}"
            )
        record_kinds = {
            record.get("kind") for record in records if isinstance(record, dict)
        }
        if kind in {"bootstrap", "apt-pre-install"} and not {
            "release",
            "index",
            "deb",
        } <= record_kinds:
            return PackageEvidenceValidation(
                False, f"{kind} transaction omitted signed package bytes"
            )
        if kind == "apt-state":
            final_state_transactions.append(transaction)
            if not {"release", "index"} <= record_kinds:
                return PackageEvidenceValidation(
                    False, "final APT state omitted signed repository indexes"
                )

        closure = _repository_closure(
            records,
            run_dir,
            runner=None,
            allowed_fingerprints=allowed,
            source_policies=source_policies,
            verification_time=verification_time,
            run_gpg=run_gpg,
        )
        closure_issues = closure.get("issues")
        if isinstance(closure_issues, list) and closure_issues:
            return PackageEvidenceValidation(
                False, str(closure_issues[0])
            )
        closure_debs = closure.get("debs")
        if not isinstance(closure_debs, list):
            return PackageEvidenceValidation(False, "invalid .deb closure")
        for item in closure_debs:
            if not isinstance(item, dict):
                return PackageEvidenceValidation(False, "invalid .deb closure")
            key = _package_key(item)
            if key is None:
                return PackageEvidenceValidation(False, ".deb package identity is incomplete")
            digest = str(item["sha256"])
            previous = all_archive_packages.get(key)
            if previous is not None and previous != digest:
                return PackageEvidenceValidation(
                    False,
                    "different .deb bytes claim the same package identity: "
                    + " ".join(key),
                )
            all_archive_packages[key] = digest
        if kind == "bootstrap":
            bootstrap_transactions.append(transaction)
            if transaction.get("fresh_rootfs") is not True:
                return PackageEvidenceValidation(
                    False, "bootstrap transaction does not prove a fresh rootfs"
                )
            transaction_inventory = _inventory_map(transaction.get("inventory"))
            if transaction_inventory is None or not transaction_inventory:
                return PackageEvidenceValidation(
                    False, "bootstrap transaction has no dpkg inventory"
                )
            bootstrap_inventory = transaction_inventory
            expected = str(expected_keyring_sha)
            if not any(
                isinstance(record, dict)
                and record.get("kind") == "keyring"
                and record.get("extra") == "host-bootstrap"
                and record.get("sha256") == expected
                for record in records
            ):
                return PackageEvidenceValidation(
                    False, "bootstrap keyring bytes differ from the external pin"
                )

    if len(final_state_transactions) != 1:
        return PackageEvidenceValidation(
            False, "package evidence must contain one final APT state"
        )
    if source_mode == "bootstrap":
        if len(bootstrap_transactions) != 1:
            return PackageEvidenceValidation(
                False, "fresh rootfs must have one bootstrap transaction"
            )
        if baseline:
            return PackageEvidenceValidation(
                False, "fresh bootstrap cannot exempt a baseline package inventory"
            )
        missing_bootstrap = sorted(set(bootstrap_inventory) - set(all_archive_packages))
        if missing_bootstrap:
            return PackageEvidenceValidation(
                False,
                "bootstrap package has no captured input bytes: "
                + " ".join(missing_bootstrap[0]),
            )
    else:
        if bootstrap_transactions:
            return PackageEvidenceValidation(
                False, "source ISO evidence contains a bootstrap transaction"
            )
        if len(baseline_transactions) != 1:
            return PackageEvidenceValidation(
                False, "source ISO package baseline transaction is missing or duplicated"
            )
        recorded_baseline = _inventory_map(
            baseline_transactions[0].get("inventory")
        )
        if recorded_baseline != baseline:
            return PackageEvidenceValidation(
                False, "source ISO baseline inventory is not bound to its transaction"
            )
    for key in sorted(final):
        if key in baseline and baseline[key] == final[key]:
            continue
        if key not in all_archive_packages:
            return PackageEvidenceValidation(
                False,
                "installed package has no captured input bytes: "
                + " ".join(key),
            )
    return PackageEvidenceValidation(
        True,
        (
            f"{len(transactions)} package transactions close "
            f"{len(all_archive_packages)} archive .deb inputs; "
            "installed-file causality remains an explicit unverified debt"
        ),
        filesystem_causality="unverified",
    )


def _repository_closure(
    records: list[dict[str, object]],
    run_dir: Path,
    *,
    runner: CommandRunner | None,
    allowed_fingerprints: Iterable[str],
    source_policies: Iterable[
        PackageSourcePolicy | Mapping[str, object]
    ] = (),
    verification_time: str | datetime | None = None,
    run_gpg: bool = True,
) -> dict[str, object]:
    allowed = {normalize_fingerprint(value) for value in allowed_fingerprints}
    try:
        policies = _normalise_source_policies(source_policies)
    except ValueError as exc:
        policies = ()
        policy_error = str(exc)
    else:
        policy_error = ""
    try:
        build_instant = (
            _parse_iso_instant(verification_time, "package verification time")
            if isinstance(verification_time, (str, datetime))
            else None
        )
    except ValueError as exc:
        build_instant = None
        time_error = str(exc)
    else:
        time_error = "" if build_instant is not None else (
            "no external package verification time was supplied"
        )
    keyring_records = [
        record for record in records if record.get("kind") == "keyring"
    ]
    releases = [record for record in records if record.get("kind") == "release"]
    indexes = [record for record in records if record.get("kind") == "index"]
    debs = [record for record in records if record.get("kind") == "deb"]
    issues: list[str] = []
    if policy_error:
        issues.append(policy_error)
    if time_error:
        issues.append(time_error)
    policy_allowed = {
        fingerprint
        for policy in policies
        for fingerprint in policy.signer_fingerprints
    }
    if policies and allowed != policy_allowed:
        issues.append(
            "global archive signer pins differ from the per-source signer policy"
        )
    authenticated_by_key: dict[tuple[str, str], dict[str, object]] = {}
    release_by_source = {
        str(record.get("source_path")): record for record in releases
    }
    if (releases or indexes or debs) and not keyring_records:
        issues.append("signed package evidence has no captured explicit keyring")

    closed_indexes: list[dict[str, object]] = []
    package_records: list[dict[str, str]] = []
    for index in indexes:
        index_path = run_dir / str(index["path"])
        try:
            binding = _bind_index_to_policy(index, policies)
        except ValueError as exc:
            issues.append(str(exc))
            continue
        policy = binding.policy
        policy_keyrings = [
            run_dir / str(record["path"])
            for record in keyring_records
            if isinstance(record.get("sha256"), str)
            and str(record["sha256"]).lower() in policy.keyring_sha256
        ]
        if not policy_keyrings:
            issues.append(
                f"repository policy {policy.policy_id} has no captured pinned keyring bytes"
            )
            continue
        try:
            source_digest, source_size = _stable_digest(index_path)
            decoded, compression = _packages_payload(index_path, runner=runner)
        except (OSError, ValueError) as exc:
            issues.append(f"Packages index cannot be parsed: {exc}")
            continue
        decoded_digest = hashlib.sha256(decoded).hexdigest()
        decoded_size = len(decoded)
        if binding.release_member == "Packages" or binding.release_member.endswith(
            "/Packages"
        ):
            release_digest, release_size = decoded_digest, decoded_size
        else:
            release_digest, release_size = source_digest, source_size

        candidates = [
            record
            for record in releases
            if _release_cache_namespace_matches(record, index)
            and (
                str(record.get("source_path", "")).endswith("InRelease")
                or (
                    str(record.get("source_path", "")).endswith("Release")
                    and not str(record.get("source_path", "")).endswith(
                        "InRelease"
                    )
                )
            )
        ]
        accepted: list[
            tuple[dict[str, object], str, list[str], str | None]
        ] = []
        candidate_issues: list[str] = []
        for release_record in candidates:
            verified = _verify_release_for_policy(
                release_record,
                release_by_source,
                run_dir,
                policy,
                policy_keyrings,
                runner=runner,
                run_gpg=run_gpg,
            )
            if verified is None:
                continue
            payload, valid_seen, signature_path = verified
            metadata_issues = _release_policy_issues(
                payload,
                binding,
                build_instant,
            )
            if metadata_issues:
                candidate_issues.extend(metadata_issues)
                continue
            member_identity = _release_sha256_members(payload).get(
                binding.release_member
            )
            if member_identity != (release_digest, release_size):
                candidate_issues.append(
                    "Packages index bytes differ from the exact signed Release "
                    f"member {binding.release_member} for policy {policy.policy_id}"
                )
                continue
            accepted.append(
                (release_record, payload, valid_seen, signature_path)
            )
        if len(accepted) != 1:
            if candidate_issues:
                issues.extend(candidate_issues)
            issues.append(
                "Packages index has no unique policy-bound signed Release: "
                f"{index['path']} ({policy.policy_id})"
            )
            continue

        matched_record, _payload, valid_seen, signature_path = accepted[0]
        authenticated_key = (
            str(matched_record["path"]),
            policy.policy_id,
        )
        authenticated_item: dict[str, object] = {
            "path": str(matched_record["path"]),
            "sha256": matched_record["sha256"],
            "policy_id": policy.policy_id,
            "base_uri": policy.base_uri,
            "signer_fingerprints": valid_seen,
            "keyring_sha256": list(policy.keyring_sha256),
        }
        if signature_path is not None:
            authenticated_item["signature_path"] = signature_path
        authenticated_by_key[authenticated_key] = authenticated_item
        parsed = _parse_packages_payload(decoded)
        package_records.extend(parsed)
        closed_indexes.append(
            {
                "path": index["path"],
                "sha256": source_digest,
                "size": source_size,
                "decoded_sha256": decoded_digest,
                "decoded_size": decoded_size,
                "compression": compression,
                "uri": binding.uri,
                "policy_id": policy.policy_id,
                "release_path": matched_record["path"],
                "release_member": binding.release_member,
                "package_records": len(parsed),
            }
        )

    records_by_digest: dict[tuple[str, int], list[dict[str, str]]] = defaultdict(list)
    for package_record in package_records:
        record_digest = package_record.get("SHA256", "").lower()
        record_size = package_record.get("Size", "")
        if _HEX_SHA256.fullmatch(record_digest) and record_size.isdigit():
            records_by_digest[(record_digest, int(record_size))].append(
                package_record
            )
    closed_debs: list[dict[str, object]] = []
    for deb in debs:
        path = run_dir / str(deb["path"])
        digest, size = _stable_digest(path)
        package_candidates = records_by_digest.get((digest, size), [])
        if not package_candidates:
            issues.append(
                f".deb bytes are absent from every signed Packages index: {deb['path']}"
            )
            continue
        metadata = _dpkg_deb_identity(path, runner=runner)
        matching = [
            candidate
            for candidate in package_candidates
            if _packages_key(candidate) == metadata
            and _safe_deb_member(candidate.get("Filename", ""))
        ]
        if not matching:
            issues.append(
                f".deb internal identity differs from its Packages stanza: {deb['path']}"
            )
            continue
        package_name, package_version, package_architecture = metadata
        closed_debs.append(
            {
                "path": deb["path"],
                "sha256": digest,
                "size": size,
                "package": package_name,
                "version": package_version,
                "architecture": package_architecture,
                "filename": matching[0].get("Filename", ""),
            }
        )
    if indexes and not authenticated_by_key:
        issues.append(
            "no Packages index has a policy-bound signature from an allowed full fingerprint"
        )
    if debs and not indexes:
        issues.append(".deb bytes were captured without any Packages index")
    return {
        "authenticated_releases": [
            authenticated_by_key[key] for key in sorted(authenticated_by_key)
        ],
        "indexes": closed_indexes,
        "debs": closed_debs,
        # Keep causal order: an unauthorised/expired index is the primary failure,
        # while the resulting absence of a .deb stanza is only a consequence.
        "issues": list(dict.fromkeys(issues)),
    }


def _bind_index_to_policy(
    index: Mapping[str, object],
    policies: Sequence[PackageSourcePolicy],
) -> _IndexPolicyBinding:
    raw_uri = index.get("extra")
    if not isinstance(raw_uri, str) or not raw_uri:
        raise ValueError(f"Packages index has no canonical URI: {index.get('path')}")
    uri = _canonical_repository_uri(raw_uri, base=False)
    parsed_uri = urlsplit(uri)
    uri_parts = tuple(part for part in parsed_uri.path.split("/") if part)
    matches: list[_IndexPolicyBinding] = []
    scope_errors: list[str] = []
    for policy in policies:
        parsed_base = urlsplit(policy.base_uri)
        if (
            parsed_uri.scheme != parsed_base.scheme
            or parsed_uri.netloc != parsed_base.netloc
        ):
            continue
        base_parts = tuple(part for part in parsed_base.path.split("/") if part)
        if uri_parts[: len(base_parts)] != base_parts:
            continue
        relative = uri_parts[len(base_parts) :]
        if (
            len(relative) != 5
            or relative[0] != "dists"
            or not relative[3].startswith("binary-")
            or not _PACKAGES_MEMBER.fullmatch(relative[4])
        ):
            scope_errors.append(
                f"Packages index URI is outside the signed repository layout: {uri}"
            )
            continue
        suite = relative[1]
        component = relative[2]
        architecture = relative[3].removeprefix("binary-")
        if suite not in policy.suites:
            continue
        if component not in policy.components:
            scope_errors.append(
                f"Packages index component {component} is forbidden by policy {policy.policy_id}"
            )
            continue
        if architecture not in policy.architectures:
            scope_errors.append(
                f"Packages index architecture {architecture} is forbidden by policy {policy.policy_id}"
            )
            continue
        matches.append(
            _IndexPolicyBinding(
                policy=policy,
                uri=uri,
                suite=suite,
                component=component,
                architecture=architecture,
                release_member="/".join(relative[2:]),
            )
        )
    if len(matches) != 1:
        if scope_errors:
            raise ValueError(scope_errors[0])
        raise ValueError(
            f"Packages index URI is not owned by exactly one external policy: {uri}"
        )
    return matches[0]


def _release_cache_namespace_matches(
    release: Mapping[str, object],
    index: Mapping[str, object],
) -> bool:
    release_name = Path(str(release.get("source_path", ""))).name
    index_name = Path(str(index.get("source_path", ""))).name
    if release_name.endswith("InRelease"):
        prefix = release_name.removesuffix("InRelease").rstrip("_")
    elif release_name.endswith("Release") and not release_name.endswith(
        "InRelease"
    ):
        prefix = release_name.removesuffix("Release").rstrip("_")
    else:
        return False
    return bool(prefix and index_name.startswith(f"{prefix}_"))


def _verify_release_for_policy(
    release_record: dict[str, object],
    release_by_source: Mapping[str, dict[str, object]],
    run_dir: Path,
    policy: PackageSourcePolicy,
    keyrings: list[Path],
    *,
    runner: CommandRunner | None,
    run_gpg: bool,
) -> tuple[str, list[str], str | None] | None:
    if not run_gpg:
        return None
    source = str(release_record.get("source_path", ""))
    release_path = run_dir / str(release_record["path"])
    if source.endswith("InRelease"):
        returncode, payload, status = _gpgv_inrelease(
            release_path,
            keyrings,
            runner=runner,
        )
        signature_path = None
    else:
        signature_record = release_by_source.get(f"{source}.gpg")
        if signature_record is None:
            return None
        signature = run_dir / str(signature_record["path"])
        returncode, status = _gpgv_detached(
            signature,
            release_path,
            keyrings,
            runner=runner,
        )
        try:
            payload = release_path.read_text(
                encoding="utf-8",
                errors="strict",
            )
        except (OSError, UnicodeError):
            return None
        signature_path = str(signature_record["path"])
    valid_seen = sorted(
        _validsig_fingerprints(status)
        & set(policy.signer_fingerprints)
    )
    if returncode != 0 or not valid_seen:
        return None
    return payload, valid_seen, signature_path


def _validsig_fingerprints(status: str) -> set[str]:
    """Return only full signing/primary fingerprints explicitly in VALIDSIG."""

    result: set[str] = set()
    for line in status.splitlines():
        marker = "[GNUPG:] VALIDSIG "
        if not line.startswith(marker):
            continue
        fields = line[len(marker) :].split()
        if not fields:
            continue
        for candidate in (fields[0], fields[-1]):
            normalised = normalize_fingerprint(candidate)
            if _FULL_FINGERPRINT.fullmatch(normalised):
                result.add(normalised)
    return result


def _release_policy_issues(
    payload: str,
    binding: _IndexPolicyBinding,
    build_instant: datetime | None,
) -> list[str]:
    policy = binding.policy
    fields = _release_fields(payload)
    issues: list[str] = []
    suite = fields.get("Suite")
    codename = fields.get("Codename")
    if suite != binding.suite or suite not in policy.suites:
        issues.append(
            f"signed Release Suite {suite!r} differs from policy {policy.policy_id}"
        )
    if codename not in policy.codenames:
        issues.append(
            f"signed Release Codename {codename!r} differs from policy {policy.policy_id}"
        )
    components = set(fields.get("Components", "").split())
    if binding.component not in components:
        issues.append(
            f"signed Release omits component {binding.component} for policy {policy.policy_id}"
        )
    architectures = set(fields.get("Architectures", "").split())
    if binding.architecture not in architectures:
        issues.append(
            "signed Release omits architecture "
            f"{binding.architecture} for policy {policy.policy_id}"
        )
    if build_instant is None:
        issues.append("no external package verification time was supplied")
        return issues
    reference = build_instant
    if policy.snapshot_at is not None:
        snapshot = _parse_iso_instant(
            policy.snapshot_at,
            f"policy {policy.policy_id} snapshot",
        )
        if snapshot > build_instant:
            issues.append(
                f"policy snapshot for {policy.policy_id} is after the build instant"
            )
        reference = snapshot
    date_value = fields.get("Date")
    try:
        release_date = _parse_release_instant(
            date_value,
            f"signed Release Date for {policy.policy_id}",
        )
    except ValueError as exc:
        issues.append(str(exc))
        return issues
    if release_date > reference + timedelta(
        seconds=policy.max_future_skew_seconds
    ):
        issues.append(
            f"signed Release Date is in the future for policy {policy.policy_id}"
        )
    if reference - release_date > timedelta(
        seconds=policy.max_release_age_seconds
    ):
        issues.append(
            f"signed Release is older than policy {policy.policy_id} permits"
        )
    valid_until_value = fields.get("Valid-Until")
    if valid_until_value is None:
        if policy.require_valid_until:
            issues.append(
                f"signed Release has no Valid-Until required by policy {policy.policy_id}"
            )
        return issues
    try:
        valid_until = _parse_release_instant(
            valid_until_value,
            f"signed Release Valid-Until for {policy.policy_id}",
        )
    except ValueError as exc:
        issues.append(str(exc))
        return issues
    if valid_until < release_date:
        issues.append(
            f"signed Release Valid-Until predates Date for policy {policy.policy_id}"
        )
    if reference > valid_until:
        issues.append(f"signed Release expired for policy {policy.policy_id}")
    return issues


def _release_fields(payload: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in payload.splitlines():
        if not line or line[:1].isspace():
            continue
        key, separator, value = line.partition(":")
        if separator and key not in fields:
            fields[key] = value.strip()
    return fields


def _parse_release_instant(value: str | None, label: str) -> datetime:
    if not value:
        raise ValueError(f"{label} is missing")
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} is malformed") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} has no UTC offset")
    return parsed.astimezone(UTC)


def _gpgv_inrelease(
    path: Path,
    keyrings: list[Path],
    *,
    runner: CommandRunner | None,
) -> tuple[int, str, str]:
    with tempfile.TemporaryDirectory(prefix="distroforge-gpgv-") as home:
        argv = [
            "gpgv",
            "--homedir",
            home,
            "--status-fd=2",
            *[token for keyring in keyrings for token in ("--keyring", str(keyring))],
            "--output",
            "-",
            str(path),
        ]
        effective_runner = runner or CommandRunner(dry_run=False)
        result = effective_runner.run(
            CommandSpec(
                argv=tuple(argv),
                description=f"Verify captured InRelease {path.name}",
            ),
            check=False,
        )
    return result.returncode, result.stdout, result.stderr


def _gpgv_detached(
    signature: Path,
    release: Path,
    keyrings: list[Path],
    *,
    runner: CommandRunner | None,
) -> tuple[int, str]:
    with tempfile.TemporaryDirectory(prefix="distroforge-gpgv-") as home:
        argv = [
            "gpgv",
            "--homedir",
            home,
            "--status-fd=1",
            *[token for keyring in keyrings for token in ("--keyring", str(keyring))],
            str(signature),
            str(release),
        ]
        effective_runner = runner or CommandRunner(dry_run=False)
        result = effective_runner.run(
            CommandSpec(
                argv=tuple(argv),
                description=f"Verify captured Release signature {signature.name}",
            ),
            check=False,
        )
    return result.returncode, result.stdout


def _release_sha256_members(payload: str) -> dict[str, tuple[str, int]]:
    entries: dict[str, tuple[str, int]] = {}
    in_sha256 = False
    for line in payload.splitlines():
        if line == "SHA256:":
            in_sha256 = True
            continue
        if not in_sha256:
            continue
        if line and not line[0].isspace():
            break
        fields = line.split()
        if (
            len(fields) == 3
            and _HEX_SHA256.fullmatch(fields[0].lower())
            and fields[1].isdigit()
        ):
            member = fields[2]
            member_path = Path(member)
            if (
                member_path.is_absolute()
                or ".." in member_path.parts
                or member in entries
            ):
                return {}
            entries[member] = (fields[0].lower(), int(fields[1]))
    return entries


def _packages_records(
    path: Path,
    *,
    runner: CommandRunner | None = None,
) -> list[dict[str, str]]:
    raw, _compression = _packages_payload(path, runner=runner)
    return _parse_packages_payload(raw)


def _packages_payload(
    path: Path,
    *,
    runner: CommandRunner | None,
) -> tuple[bytes, str]:
    raw = path.read_bytes()
    try:
        if raw.startswith(b"\x1f\x8b"):
            return gzip.decompress(raw), "gzip"
        if raw.startswith(b"\xfd7zXZ\x00"):
            return lzma.decompress(raw), "xz"
        if raw.startswith(b"BZh"):
            return bz2.decompress(raw), "bzip2"
    except (EOFError, OSError, lzma.LZMAError) as exc:
        raise ValueError(
            f"compressed Packages evidence is malformed: {path.name}"
        ) from exc
    if raw.startswith(b"\x04\x22\x4d\x18"):
        return _decompress_packages_with_tool(
            path,
            "lz4",
            runner=runner,
        ), "lz4"
    if raw.startswith(b"\x28\xb5\x2f\xfd"):
        return _decompress_packages_with_tool(
            path,
            "zstd",
            runner=runner,
        ), "zstd"
    return raw, "none"


def _decompress_packages_with_tool(
    path: Path,
    tool: str,
    *,
    runner: CommandRunner | None,
) -> bytes:
    effective_runner = runner or CommandRunner(dry_run=False)
    if not effective_runner.has_binary(tool):
        raise ValueError(
            f"{tool} decompressor is unavailable for Packages evidence"
        )
    before = _stable_digest(path)
    with tempfile.TemporaryDirectory(
        prefix=f"distroforge-packages-{tool}-"
    ) as temporary:
        output = Path(temporary) / "Packages"
        argv: tuple[str, ...]
        if tool == "lz4":
            argv = (
                "lz4",
                "--decompress",
                "--force",
                str(path),
                str(output),
            )
        elif tool == "zstd":
            argv = (
                "zstd",
                "--decompress",
                "--force",
                "--quiet",
                "-o",
                str(output),
                str(path),
            )
        else:
            raise ValueError(f"unsupported Packages decompressor: {tool}")
        try:
            effective_runner.run(
                CommandSpec(
                    argv=argv,
                    description=(
                        f"Decompress captured {tool} Packages index {path.name}"
                    ),
                )
            )
        except (CommandError, OSError) as exc:
            raise ValueError(
                f"{tool} failed to decompress Packages evidence {path.name}"
            ) from exc
        if _stable_digest(path) != before:
            raise ValueError(
                f"Packages evidence changed during {tool} decompression"
            )
        if output.is_symlink() or not output.is_file():
            raise ValueError(
                f"{tool} did not create regular Packages evidence"
            )
        output_digest = _stable_digest(output)
        decoded = output.read_bytes()
        if (
            _stable_digest(output) != output_digest
            or hashlib.sha256(decoded).hexdigest() != output_digest[0]
            or len(decoded) != output_digest[1]
        ):
            raise ValueError(
                f"{tool} output changed while Packages evidence was read"
            )
        return decoded


def _parse_packages_payload(raw: bytes) -> list[dict[str, str]]:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("Packages evidence is not valid UTF-8") from exc
    records: list[dict[str, str]] = []
    for stanza in re.split(r"\n\s*\n", text):
        fields: dict[str, str] = {}
        current = ""
        for line in stanza.splitlines():
            if line[:1].isspace() and current:
                fields[current] = f"{fields[current]}\n{line}"
                continue
            key, separator, value = line.partition(":")
            if separator:
                current = key
                fields[key] = value.strip()
        if {"Package", "Version", "Architecture", "Size", "SHA256"} <= fields.keys():
            records.append(fields)
    return records


def _packages_key(record: dict[str, str]) -> tuple[str, str, str]:
    return (
        record.get("Package", ""),
        record.get("Version", ""),
        record.get("Architecture", ""),
    )


def _safe_deb_member(value: str) -> bool:
    path = Path(value)
    return bool(
        value
        and value.endswith(".deb")
        and not path.is_absolute()
        and ".." not in path.parts
    )


def _dpkg_deb_identity(
    path: Path,
    *,
    runner: CommandRunner | None = None,
) -> tuple[str, str, str]:
    argv = (
            "dpkg-deb",
            "--show",
            "--showformat=${Package}\\t${Version}\\t${Architecture}\\n",
            str(path),
    )
    effective_runner = runner or CommandRunner(dry_run=False)
    result = effective_runner.run(
        CommandSpec(argv=argv, description=f"Verify captured .deb {path.name}")
    )
    returncode = result.returncode
    stdout = result.stdout
    fields = stdout.rstrip("\n").split("\t")
    if returncode != 0 or len(fields) != 3 or not all(fields):
        raise ValueError(f"cannot read .deb identity from {path}")
    return fields[0], fields[1], fields[2]


def _identity_error(value: object, run_dir: Path) -> str | None:
    if not isinstance(value, dict):
        return "package evidence contains a malformed file identity"
    relative = value.get("path")
    if not isinstance(relative, str) or not relative:
        return "package evidence contains an empty file path"
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        return f"package evidence path escapes the run: {relative}"
    absolute = run_dir / path
    if absolute.is_symlink() or not absolute.is_file():
        return f"package evidence file is missing or symlinked: {relative}"
    try:
        digest, size = _stable_digest(absolute)
    except OSError as exc:
        return f"package evidence file cannot be read: {exc}"
    if value.get("size") != size or value.get("sha256") != digest:
        return f"package evidence file changed: {relative}"
    return None


def _identity_for_run(path: Path, run_dir: Path) -> dict[str, object]:
    digest, size = _stable_digest(path)
    return {
        "path": str(path.relative_to(run_dir)),
        "size": size,
        "sha256": digest,
    }


def _stable_digest(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        before = os.fstat(handle.fileno())
        for chunk in iter(lambda: handle.read(_COPY_CHUNK), b""):
            digest.update(chunk)
        after = os.fstat(handle.fileno())
    before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    )
    current = path.stat()
    path_identity = (
        current.st_dev,
        current.st_ino,
        current.st_size,
        current.st_mtime_ns,
    )
    if before_identity != after_identity or after_identity != path_identity:
        raise ValueError(f"file changed while it was hashed: {path}")
    return digest.hexdigest(), after.st_size


def _stable_copy(
    source: Path,
    target: Path,
    *,
    expected_sha256: str | None = None,
    expected_size: int | None = None,
) -> None:
    source_sha, source_size = _stable_digest(source)
    if expected_sha256 is not None and source_sha != expected_sha256:
        raise ValueError(f"package-input source changed before copy: {source}")
    if expected_size is not None and source_size != expected_size:
        raise ValueError(f"package-input source size changed before copy: {source}")
    if target.exists():
        target_sha, target_size = _stable_digest(target)
        if (target_sha, target_size) != (source_sha, source_size):
            raise FileExistsError(f"content-addressed evidence collision: {target}")
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    try:
        with source.open("rb") as source_handle, target.open("xb") as target_handle:
            before = os.fstat(source_handle.fileno())
            for chunk in iter(lambda: source_handle.read(_COPY_CHUNK), b""):
                digest.update(chunk)
                target_handle.write(chunk)
            target_handle.flush()
            os.fsync(target_handle.fileno())
            after = os.fstat(source_handle.fileno())
        copied_sha, copied_size = _stable_digest(target)
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or copied_sha != digest.hexdigest()
            or copied_sha != source_sha
            or copied_size != source_size
        ):
            raise ValueError(f"package-input bytes changed during copy: {source}")
    except Exception:
        target.unlink(missing_ok=True)
        raise


def _inside_root(
    root: Path,
    configured: str,
    *,
    expected: str = "any",
) -> Path:
    """Resolve an APT path without following a rootfs symlink or mount escape."""

    value = Path(configured)
    relative = Path(str(value).lstrip("/"))
    if not relative.parts or ".." in relative.parts:
        raise ValueError(f"APT path escapes or aliases the target root: {configured}")
    root_absolute = Path(os.path.abspath(root))
    target = root_absolute / relative
    with _open_confined_path(
        root_absolute,
        target,
        expected=expected,
    ):
        pass
    return target


@contextmanager
def _open_confined_path(
    root: Path,
    target: Path,
    *,
    expected: str,
    allow_root: bool = False,
) -> Iterator[int]:
    """Open ``target`` component-by-component beneath a physical root boundary.

    Every component is opened relative to the previously verified directory with
    ``O_NOFOLLOW``.  The final descriptor therefore remains usable even if a hostile
    package later replaces a pathname.  Device changes and Linux mountpoints below
    the root are rejected, including same-device bind mounts from mountinfo.
    """

    if expected not in {"any", "directory", "regular"}:
        raise ValueError(f"unsupported confined path type: {expected}")
    root_absolute, relative = _confined_location(root, target)
    if not relative.parts and not allow_root:
        raise ValueError(f"confined path aliases the rootfs itself: {target}")
    descriptors: list[int] = []
    try:
        root_fd = _open_absolute_directory_without_symlinks(root_absolute)
        descriptors.append(root_fd)
        root_stat = os.fstat(root_fd)
        if not stat.S_ISDIR(root_stat.st_mode):
            raise ValueError(f"target rootfs is not a directory: {root_absolute}")
        if not relative.parts:
            yield root_fd
            return
        mountpoints = _linux_mountpoints()
        root_mount_id = _fd_mount_id(root_fd)
        current_fd = root_fd
        current_path = root_absolute
        for index, component in enumerate(relative.parts):
            final = index == len(relative.parts) - 1
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
            if not final or expected == "directory":
                flags |= os.O_DIRECTORY
            if final and expected != "directory":
                flags |= os.O_NONBLOCK
            try:
                opened = os.open(component, flags, dir_fd=current_fd)
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise ValueError(
                        "confined rootfs path contains a symlink or "
                        f"non-directory ancestor: {target}"
                    ) from exc
                raise
            descriptors.append(opened)
            current_fd = opened
            current_path = current_path / component
            opened_stat = os.fstat(opened)
            if (
                opened_stat.st_dev != root_stat.st_dev
                or _fd_mount_id(opened) != root_mount_id
                or current_path in mountpoints
            ):
                raise ValueError(
                    f"confined rootfs path crosses a mount boundary: {target}"
                )
            if not final and not stat.S_ISDIR(opened_stat.st_mode):
                raise ValueError(
                    f"confined rootfs path has a non-directory ancestor: {target}"
                )
        final_stat = os.fstat(current_fd)
        if expected == "directory" and not stat.S_ISDIR(final_stat.st_mode):
            raise ValueError(f"confined rootfs path is not a directory: {target}")
        if expected == "regular" and not stat.S_ISREG(final_stat.st_mode):
            raise ValueError(f"confined rootfs path is not a regular file: {target}")
        if expected == "any" and not (
            stat.S_ISDIR(final_stat.st_mode) or stat.S_ISREG(final_stat.st_mode)
        ):
            raise ValueError(
                f"confined rootfs path has an unsupported file type: {target}"
            )
        yield current_fd
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _confined_location(root: Path, target: Path) -> tuple[Path, Path]:
    root_absolute = Path(os.path.abspath(root))
    if ".." in target.parts:
        raise ValueError(f"confined rootfs path contains traversal: {target}")
    candidate = target if target.is_absolute() else root_absolute / target
    candidate_absolute = Path(os.path.abspath(candidate))
    try:
        relative = candidate_absolute.relative_to(root_absolute)
    except ValueError as exc:
        raise ValueError(
            f"confined path escapes the target rootfs: {target}"
        ) from exc
    return root_absolute, relative


def _open_absolute_directory_without_symlinks(path: Path) -> int:
    descriptor = os.open(
        "/",
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        for component in path.parts[1:]:
            try:
                opened = os.open(
                    component,
                    os.O_RDONLY
                    | os.O_CLOEXEC
                    | os.O_DIRECTORY
                    | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise ValueError(
                        "target rootfs or one of its host ancestors is a symlink: "
                        f"{path}"
                    ) from exc
                raise
            os.close(descriptor)
            descriptor = opened
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _linux_mountpoints() -> set[Path]:
    try:
        lines = Path("/proc/self/mountinfo").read_text(
            encoding="utf-8",
            errors="strict",
        ).splitlines()
    except (OSError, UnicodeError) as exc:
        raise ValueError("cannot inspect rootfs mount boundaries") from exc
    result: set[Path] = set()
    for line in lines:
        left = line.partition(" - ")[0].split()
        if len(left) < 5:
            raise ValueError("host mountinfo is malformed")
        encoded = left[4]
        decoded = re.sub(
            r"\\([0-7]{3})",
            lambda match: chr(int(match.group(1), 8)),
            encoded,
        )
        result.add(Path(decoded))
    return result


def _fd_mount_id(descriptor: int) -> int:
    try:
        lines = Path(f"/proc/self/fdinfo/{descriptor}").read_text(
            encoding="ascii",
            errors="strict",
        ).splitlines()
    except (OSError, UnicodeError) as exc:
        raise ValueError("cannot inspect confined descriptor mount identity") from exc
    for line in lines:
        key, separator, value = line.partition(":")
        if key == "mnt_id" and separator and value.strip().isdigit():
            return int(value.strip())
    raise ValueError("confined descriptor has no Linux mount identity")


def _stable_digest_fd(descriptor: int) -> tuple[str, int]:
    os.lseek(descriptor, 0, os.SEEK_SET)
    before = os.fstat(descriptor)
    digest = hashlib.sha256()
    while chunk := os.read(descriptor, _COPY_CHUNK):
        digest.update(chunk)
    after = os.fstat(descriptor)
    before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if before_identity != after_identity or not stat.S_ISREG(after.st_mode):
        raise ValueError("confined package-input file changed while it was hashed")
    return digest.hexdigest(), after.st_size


def _stable_read_fd(descriptor: int) -> bytes:
    expected = _stable_digest_fd(descriptor)
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while chunk := os.read(descriptor, _COPY_CHUNK):
        chunks.append(chunk)
    payload = b"".join(chunks)
    if (
        _stable_digest_fd(descriptor) != expected
        or hashlib.sha256(payload).hexdigest() != expected[0]
        or len(payload) != expected[1]
    ):
        raise ValueError("confined package-input file changed while it was read")
    return payload


def _stable_copy_fd(
    descriptor: int,
    source_label: Path,
    target: Path,
    *,
    expected_sha256: str | None = None,
    expected_size: int | None = None,
) -> None:
    source_sha, source_size = _stable_digest_fd(descriptor)
    if expected_sha256 is not None and source_sha != expected_sha256:
        raise ValueError(
            f"package-input source changed before copy: {source_label}"
        )
    if expected_size is not None and source_size != expected_size:
        raise ValueError(
            f"package-input source size changed before copy: {source_label}"
        )
    if target.is_symlink():
        raise FileExistsError(f"content-addressed evidence target is symlinked: {target}")
    if target.exists():
        target_sha, target_size = _stable_digest(target)
        if (target_sha, target_size) != (source_sha, source_size):
            raise FileExistsError(f"content-addressed evidence collision: {target}")
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        before = os.fstat(descriptor)
        with target.open("xb") as target_handle:
            while chunk := os.read(descriptor, _COPY_CHUNK):
                digest.update(chunk)
                target_handle.write(chunk)
            target_handle.flush()
            os.fsync(target_handle.fileno())
        after = os.fstat(descriptor)
        copied_sha, copied_size = _stable_digest(target)
        if (
            (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            or copied_sha != digest.hexdigest()
            or copied_sha != source_sha
            or copied_size != source_size
        ):
            raise ValueError(
                f"package-input bytes changed during copy: {source_label}"
            )
    except Exception:
        target.unlink(missing_ok=True)
        raise


def _confined_optional_regular_file(root: Path, path: Path) -> bool:
    try:
        with _open_confined_path(root, path, expected="regular"):
            return True
    except FileNotFoundError:
        return False


def _confined_optional_directory(root: Path, path: Path) -> bool:
    try:
        with _open_confined_path(root, path, expected="directory"):
            return True
    except FileNotFoundError:
        return False


def _confined_regular_files_by_suffix(
    root: Path,
    directory: Path,
    suffixes: tuple[str, ...],
) -> list[Path]:
    with _open_confined_path(
        root,
        directory,
        expected="directory",
    ) as directory_descriptor:
        names = sorted(os.listdir(directory_descriptor))
    result: list[Path] = []
    for name in names:
        if not name.endswith(suffixes):
            continue
        path = directory / name
        with _open_confined_path(root, path, expected="regular"):
            pass
        result.append(path)
    return result


def _confined_tree_files(root: Path, directory: Path) -> list[Path]:
    if not _confined_optional_directory(root, directory):
        return []
    files: list[Path] = []
    seen_directories: set[tuple[int, int]] = set()

    def walk(current: Path) -> None:
        with _open_confined_path(
            root,
            current,
            expected="directory",
        ) as directory_descriptor:
            current_stat = os.fstat(directory_descriptor)
            identity = (current_stat.st_dev, current_stat.st_ino)
            if identity in seen_directories:
                raise ValueError(
                    f"confined rootfs directory is reachable twice: {current}"
                )
            seen_directories.add(identity)
            names = sorted(os.listdir(directory_descriptor))
        for name in names:
            child = current / name
            with _open_confined_path(
                root,
                child,
                expected="any",
            ) as child_descriptor:
                child_mode = os.fstat(child_descriptor).st_mode
            if stat.S_ISDIR(child_mode):
                walk(child)
            elif stat.S_ISREG(child_mode):
                files.append(child)
            else:
                raise ValueError(
                    f"confined rootfs tree contains a special file: {child}"
                )

    walk(directory)
    return sorted(files)


def _insecure_configuration_issues(
    records: list[dict[str, object]],
    run_dir: Path,
) -> list[str]:
    issues: list[str] = []
    for record in records:
        if record.get("kind") not in {"source", "config"}:
            continue
        path = run_dir / str(record.get("path", ""))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for pattern in _INSECURE_APT_PATTERNS:
            if pattern.search(text):
                issues.append(
                    f"insecure APT override in captured input {record.get('path')}"
                )
                break
    return issues


def _insecure_apt_argv_issues(
    commands: Iterable[Sequence[str]],
) -> list[str]:
    relevant = _normalise_apt_command_argv(commands)
    issues: list[str] = []
    for argv in relevant:
        lowered = [token.lower() for token in argv]
        joined = " ".join(argv)
        if any(
            token.split("=", 1)[0] in _UNSAFE_APT_FLAGS
            for token in lowered
        ) or any(
            re.search(
                rf"(?:^|\s){re.escape(flag)}(?:=|\s|$)",
                joined,
                flags=re.IGNORECASE,
            )
            for flag in _UNSAFE_APT_FLAGS
        ):
            issues.append(
                "insecure APT command-line authentication override: "
                + shlex.join(argv)
            )
            continue
        option_values: list[str] = []
        for index, token in enumerate(argv):
            lowered_token = token.lower()
            if lowered_token in {"-o", "--option", "--aptopt"}:
                if index + 1 < len(argv):
                    option_values.append(argv[index + 1])
                continue
            for prefix in ("--option=", "--aptopt="):
                if lowered_token.startswith(prefix):
                    option_values.append(token[len(prefix) :])
                    break
            if lowered_token.startswith("-o") and lowered_token != "-o":
                option_values.append(token[2:])
        if re.search(
            r"\btrusted\s*=\s*(?:yes|true|1)\b",
            joined,
            flags=re.IGNORECASE,
        ):
            issues.append(
                "insecure APT command-line trust override: " + shlex.join(argv)
            )
            continue
        if any(_unsafe_apt_option(value) for value in option_values) or re.search(
            (
                r"(?:AllowInsecureRepositories|AllowWeakRepositories|"
                r"AllowUnauthenticated|Allow-Downgrade-To-Insecure)"
                r"[^A-Za-z0-9]+(?:true|yes|1)\b|"
                r"(?:Check-Valid-Until|Check-Date)"
                r"[^A-Za-z0-9]+(?:false|no|0)\b"
            ),
            joined,
            flags=re.IGNORECASE,
        ):
            issues.append(
                "insecure APT command-line configuration override: "
                + shlex.join(argv)
            )
    return sorted(set(issues))


def _unsafe_apt_option(value: str) -> bool:
    match = re.match(
        r"^\s*([^=\s]+)\s*(?:=|\s+)\s*[\"']?([^\"';\s]+)",
        value,
    )
    if match is None:
        return False
    key = re.sub(r"[^a-z0-9]", "", match.group(1).lower())
    configured = match.group(2).strip().lower()
    return (
        key in _UNSAFE_APT_TRUE_KEYS
        and configured in _TRUE_VALUES
    ) or (
        key in _UNSAFE_APT_FALSE_KEYS
        and configured in _FALSE_VALUES
    )


def _package_key(value: dict[str, object]) -> tuple[str, str, str] | None:
    fields = (
        value.get("package"),
        value.get("version"),
        value.get("architecture"),
    )
    if not all(isinstance(field, str) and field for field in fields):
        return None
    return str(fields[0]), str(fields[1]), str(fields[2])


def _inventory_map(
    value: object,
) -> dict[tuple[str, str, str], tuple[str, str, str]] | None:
    if not isinstance(value, list):
        return None
    result: dict[tuple[str, str, str], tuple[str, str, str]] = {}
    for item in value:
        if not isinstance(item, dict):
            return None
        key = _package_key(item)
        if key is None or key in result:
            return None
        result[key] = key
    return result


def _capture_hook_config() -> str:
    return "\n".join(
        [
            'APT::Keep-Downloaded-Packages "true";',
            'Binary::apt::APT::Keep-Downloaded-Packages "true";',
            'Binary::apt-get::APT::Keep-Downloaded-Packages "true";',
            'DPkg::Pre-Install-Pkgs {"/usr/lib/distroforge/capture-package-inputs";};',
            "",
        ]
    )


def _capture_hook_script() -> str:
    return """#!/bin/sh
set -eu

base=/var/lib/distroforge/package-evidence
store=$base/store
journal=$base/transactions.tsv
mkdir -p "$store"
last=0
if [ -f "$journal" ]; then
    last=$(awk -F '\\t' '$1 == "F" { value = $2 } END { print value + 0 }' "$journal")
fi
tx=$((last + 1))

seal_file() {
    kind=$1
    source=$2
    extra=${3-}
    [ -f "$source" ] || return 0
    before=$(sha256sum -- "$source")
    digest=${before%% *}
    size=$(wc -c < "$source")
    directory=$store/$kind
    target=$directory/$digest
    mkdir -p "$directory"
    if [ ! -f "$target" ]; then
        temporary=$target.part.$$
        cp -- "$source" "$temporary"
        copied=$(sha256sum -- "$temporary")
        copied=${copied%% *}
        after=$(sha256sum -- "$source")
        after=${after%% *}
        if [ "$digest" != "$copied" ] || [ "$digest" != "$after" ]; then
            rm -f -- "$temporary"
            echo "package evidence: bytes changed during capture: $source" >&2
            exit 125
        fi
        chmod 0644 "$temporary"
        mv -- "$temporary" "$target"
    fi
    printf 'F\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\tstable\\n' \
        "$tx" "$kind" "$digest" "$size" "$source" "$extra" >> "$journal"
}

for source in /etc/apt/sources.list /etc/apt/sources.list.d/*; do
    [ -f "$source" ] && seal_file source "$source"
done
for config in /etc/apt/apt.conf /etc/apt/apt.conf.d/*; do
    [ -f "$config" ] && seal_file config "$config"
done
for keyring in \
    /etc/apt/trusted.gpg \
    /etc/apt/trusted.gpg.d/* \
    /etc/apt/keyrings/* \
    /usr/share/keyrings/*; do
    [ -f "$keyring" ] && seal_file keyring "$keyring"
done

lists_line=$(apt-config shell lists Dir::State::lists/f)
lists=$(printf '%s\\n' "$lists_line" | sed -n "s/^lists='\\(.*\\)'$/\\1/p")
if [ -n "$lists" ]; then
    for release in "$lists"/*InRelease "$lists"/*Release "$lists"/*Release.gpg; do
        [ -f "$release" ] && seal_file release "$release"
    done
fi

targets=$base/index-targets.$$
apt-get indextargets --format '$(IDENTIFIER)|$(FILENAME)|$(URI)' > "$targets"
while IFS='|' read -r identifier filename uri; do
    [ "$identifier" = Packages ] && seal_file index "$filename" "$uri"
done < "$targets"
rm -f -- "$targets"

while IFS= read -r archive; do
    [ -f "$archive" ] && seal_file deb "$archive"
done
"""
