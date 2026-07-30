"""Static package-payload correspondence for the final rootfs.

M3.1 deliberately proves less than installed-file causality.  It binds the
already sealed package-input report and final rootfs manifest, asks ``dpkg-deb``
for the identity and filesystem tar stream of each package in the bootstrap
report's pre-post-host ``final_inventory`` snapshot, and classifies the
resulting static payload paths against the final rootfs entries.

That closes a useful byte-identity seam without claiming that a matching byte
was actually produced by dpkg.  Maintainer scripts, triggers, conffile policy,
diversions, alternatives, DistroForge customizers and source-ISO baseline bytes
remain outside this milestone.  Consequently every valid report keeps
``filesystem_causality=unverified`` and ``release_ready=false``.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import tarfile
import tempfile
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO, TypeGuard, cast

from .command import CommandError, CommandRunner, CommandSpec
from .evidence_run import canonical_sha256
from .package_evidence import PACKAGE_INPUTS_SCHEMA, PACKAGE_TRANSACTION_SCHEMA
from .rootfs_evidence import (
    ROOTFS_MANIFEST_SCHEMA,
    RootfsEvidenceError,
    validate_rootfs_manifest_payload,
)

PACKAGE_FILESYSTEM_CAUSALITY_SCHEMA = "distroforge.package-filesystem-causality.v1"
PACKAGE_FILESYSTEM_CAUSALITY_FILENAME = "PACKAGE-FILESYSTEM-CAUSALITY.json"

# ``dpkg-deb --fsys-tarfile`` emits an uncompressed tar stream.  The explicit
# bound prevents a small, authenticated but hostile .deb from exhausting the
# evidence filesystem during causal inspection.
MAX_DATA_TAR_BYTES_PER_DEB = 2 * 1024 * 1024 * 1024
MAX_LOGICAL_MEMBER_BYTES = MAX_DATA_TAR_BYTES_PER_DEB
MAX_MEMBERS_PER_DEB = 200_000
MAX_TOTAL_PAYLOAD_MEMBERS = 500_000
MAX_TOTAL_ROOTFS_ENTRIES = 500_000
MAX_FINAL_PACKAGES = 10_000
MAX_PACKAGE_IDENTITY_BYTES = 4 * 1024
MAX_TRANSACTION_REFERENCES = 10_000
MAX_DEB_RECORDS = 20_000
MAX_TOTAL_TRANSACTION_RECORDS = 100_000
MAX_TOTAL_TRANSACTION_JSON_BYTES = 128 * 1024 * 1024
MAX_EVIDENCE_JSON_BYTES = 96 * 1024 * 1024
MAX_TOTAL_PAYLOAD_MEMBER_JSON_BYTES = 32 * 1024 * 1024
MAX_TOTAL_CLAIM_JSON_BYTES = 48 * 1024 * 1024
MAX_TOTAL_CLASSIFICATION_JSON_BYTES = 80 * 1024 * 1024
MAX_TOTAL_PACKAGE_JSON_BYTES = 12 * 1024 * 1024
MAX_TOTAL_SELECTED_DEB_BYTES = 32 * 1024 * 1024 * 1024
MAX_TOTAL_DATA_TAR_BYTES = 32 * 1024 * 1024 * 1024
MAX_TOTAL_LOGICAL_PAYLOAD_BYTES = 32 * 1024 * 1024 * 1024
MAX_DEB_IDENTITY_BYTES = 64 * 1024
MAX_TAR_READ_BYTES = 2 * 1024 * 1024
MAX_TAR_EXTENSION_BYTES = 1024 * 1024
MAX_TOTAL_TAR_EXTENSION_BYTES = 16 * 1024 * 1024
MAX_TAR_EXTENSION_CHAIN = 32
MAX_PHYSICAL_TAR_HEADERS = 250_000
MAX_TAR_TEXT_BYTES = 4 * 1024
MAX_PAX_FIELDS_PER_MEMBER = 128
MAX_PAX_BYTES_PER_MEMBER = 64 * 1024
MAX_RUN_RELATIVE_PATH_BYTES = 4 * 1024
MAX_RUN_RELATIVE_PATH_COMPONENTS = 256
MAX_TRANSACTION_ID_BYTES = 255

_CLASSIFICATIONS = (
    "exact",
    "modified",
    "missing",
    "unattributed",
    "ambiguous",
    "structural",
    "excluded",
    "unsupported",
)
_LIMITS = (
    (
        "maintainer scripts and dpkg triggers can generate or mutate files "
        "after direct payload extraction"
    ),
    ("dpkg diversions and alternatives can redirect the effective producer of a final path"),
    (
        "conffiles can be preserved, merged or locally modified independently "
        "of their archived payload bytes"
    ),
    (
        "DistroForge customizers, hooks and other post-install writers are not "
        "attributed by this static payload comparison"
    ),
    (
        "PACKAGE-INPUTS final_inventory is sealed before post-host hooks; M3.1 "
        "does not re-snapshot dpkg state after those arbitrary writers"
    ),
    ("source ISO baseline paths have no captured package payload identity in M3.1"),
    (
        "M3.1 fixture-scale byte and cardinality budgets fail closed before "
        "unbounded parser growth; a real desktop run must still prove that its "
        "manifest fits those budgets"
    ),
    (
        "schema v1 payload_identity reports supported enumeration coverage; "
        "modified, missing and ambiguous comparison outcomes remain separate "
        "counts rather than a second coverage status"
    ),
)
_HEX_SHA256 = frozenset("0123456789abcdef")
_READ_CHUNK = 1024 * 1024
_FILE_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
_DIRECTORY_FLAGS = _FILE_FLAGS | os.O_DIRECTORY
_CREATE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW


class PackageFilesystemCausalityError(ValueError):
    """The M3.1 correspondence cannot be computed without overclaiming."""


@dataclass(frozen=True)
class PackageFilesystemCausalityValidation:
    """Authoritative validation result for the M3.1 report.

    ``payload_identity`` describes only static direct ``data.tar`` coverage.
    It is intentionally independent from the filesystem-causality and release
    fields, which this milestone can never promote.
    """

    ok: bool
    detail: str
    payload_identity: str = "unverified"
    filesystem_causality: str = "unverified"
    release_ready: bool = False


@dataclass(frozen=True)
class _StableBytes:
    data: bytes
    size: int
    sha256: str


@dataclass
class _DebPayload:
    package: dict[str, str]
    deb: dict[str, object]
    members: list[dict[str, object]]


@dataclass(frozen=True)
class _RememberedFile:
    relative: str
    label: str
    identity: tuple[int, ...]
    size: int
    sha256: str
    rehash_on_seal: bool


class _RunDirectoryWitness:
    """Anchor every M3.1 artifact operation to one non-symlinked run inode."""

    def __init__(self, path: Path) -> None:
        self.path = Path(os.path.abspath(path))
        self.descriptor: int | None = None
        self.initial_stat: os.stat_result | None = None
        self.remembered: dict[str, _RememberedFile] = {}
        self.created_files: dict[str, tuple[str, tuple[int, int]]] = {}

    def __enter__(self) -> _RunDirectoryWitness:
        descriptor = _open_absolute_directory(self.path)
        initial = os.fstat(descriptor)
        if not stat.S_ISDIR(initial.st_mode):
            os.close(descriptor)
            raise PackageFilesystemCausalityError(
                "package filesystem causality run path is not a directory"
            )
        self.descriptor = descriptor
        self.initial_stat = initial
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        try:
            if exc_type is None:
                try:
                    self.seal()
                except BaseException:
                    self._cleanup_created_files()
                    raise
            else:
                self._cleanup_created_files()
        finally:
            if self.descriptor is not None:
                os.close(self.descriptor)
                self.descriptor = None

    def open_file(self, value: str, label: str) -> tuple[str, int]:
        """Open a regular-file candidate beneath the held run fd via openat."""

        canonical, parent, name = self._open_parent(value, label)
        try:
            descriptor = os.open(name, _FILE_FLAGS, dir_fd=parent)
        except OSError as exc:
            raise PackageFilesystemCausalityError(
                f"{label} cannot be opened beneath the witnessed run directory: {exc}"
            ) from exc
        finally:
            os.close(parent)
        return canonical, descriptor

    def write_new_text(self, value: str, content: str, label: str) -> None:
        """Create one immutable evidence file through the witnessed run fd."""

        canonical, parent, name = self._open_parent(value, label)
        data = content.encode("utf-8")
        if len(data) > MAX_EVIDENCE_JSON_BYTES:
            os.close(parent)
            raise PackageFilesystemCausalityError(f"{label} exceeds the evidence-size bound")
        descriptor: int | None = None
        created = False
        created_stat: os.stat_result | None = None
        try:
            descriptor = os.open(name, _CREATE_FLAGS, 0o644, dir_fd=parent)
            created = True
            before = os.fstat(descriptor)
            created_stat = before
            offset = 0
            while offset < len(data):
                written = os.write(descriptor, data[offset:])
                if written <= 0:
                    raise PackageFilesystemCausalityError(f"{label} write made no progress")
                offset += written
            os.fsync(descriptor)
            after = os.fstat(descriptor)
            if (
                not stat.S_ISREG(after.st_mode)
                or before.st_dev != after.st_dev
                or before.st_ino != after.st_ino
                or after.st_size != len(data)
            ):
                raise PackageFilesystemCausalityError(f"{label} changed while it was written")
            os.close(descriptor)
            descriptor = None
            _relative, reopened = self.open_file(canonical, label)
            try:
                reopened_stat = os.fstat(reopened)
                digest, size = _hash_descriptor(reopened, reopened_stat, label)
            finally:
                os.close(reopened)
            if (
                reopened_stat.st_dev != after.st_dev
                or reopened_stat.st_ino != after.st_ino
                or size != len(data)
                or digest != hashlib.sha256(data).hexdigest()
            ):
                raise PackageFilesystemCausalityError(
                    f"{label} path no longer names the written bytes"
                )
            self.remember_file(
                canonical,
                label,
                reopened_stat,
                size=size,
                sha256=digest,
                rehash_on_seal=True,
            )
            self.created_files[canonical] = (
                label,
                (reopened_stat.st_dev, reopened_stat.st_ino),
            )
        except BaseException:
            if descriptor is not None:
                os.close(descriptor)
            if created and created_stat is not None:
                try:
                    candidate = os.open(name, _FILE_FLAGS, dir_fd=parent)
                except OSError:
                    pass
                else:
                    try:
                        candidate_stat = os.fstat(candidate)
                    finally:
                        os.close(candidate)
                    if (
                        candidate_stat.st_dev == created_stat.st_dev
                        and candidate_stat.st_ino == created_stat.st_ino
                    ):
                        try:
                            os.unlink(name, dir_fd=parent)
                        except OSError:
                            pass
            raise
        finally:
            os.close(parent)

    def seal(self) -> None:
        descriptor = self.descriptor
        initial = self.initial_stat
        if descriptor is None or initial is None:
            raise PackageFilesystemCausalityError(
                "package filesystem causality run witness is not open"
            )
        held = os.fstat(descriptor)
        if (
            held.st_dev != initial.st_dev
            or held.st_ino != initial.st_ino
            or not stat.S_ISDIR(held.st_mode)
        ):
            raise PackageFilesystemCausalityError(
                "package filesystem causality run inode changed during inspection"
            )
        for relative in sorted(self.remembered, key=lambda item: item.encode()):
            remembered = self.remembered[relative]
            _canonical, leaf = self.open_file(relative, remembered.label)
            try:
                current_leaf = os.fstat(leaf)
                if _stat_identity(current_leaf) != remembered.identity:
                    raise PackageFilesystemCausalityError(
                        f"{remembered.label} path changed before run sealing"
                    )
                if remembered.rehash_on_seal:
                    digest, size = _hash_descriptor(
                        leaf,
                        current_leaf,
                        remembered.label,
                    )
                    if digest != remembered.sha256 or size != remembered.size:
                        raise PackageFilesystemCausalityError(
                            f"{remembered.label} bytes changed before run sealing"
                        )
            finally:
                os.close(leaf)
        reopened = _open_absolute_directory(self.path)
        try:
            current = os.fstat(reopened)
        finally:
            os.close(reopened)
        if (
            current.st_dev != initial.st_dev
            or current.st_ino != initial.st_ino
            or not stat.S_ISDIR(current.st_mode)
        ):
            raise PackageFilesystemCausalityError(
                "package filesystem causality run path changed during inspection"
            )

    def remember_file(
        self,
        relative: str,
        label: str,
        identity: os.stat_result,
        *,
        size: int,
        sha256: str,
        rehash_on_seal: bool,
    ) -> None:
        remembered = _RememberedFile(
            relative=relative,
            label=label,
            identity=_stat_identity(identity),
            size=size,
            sha256=sha256,
            rehash_on_seal=rehash_on_seal,
        )
        previous = self.remembered.get(relative)
        if previous is not None and (
            previous.identity != remembered.identity
            or previous.size != remembered.size
            or previous.sha256 != remembered.sha256
        ):
            raise PackageFilesystemCausalityError(f"{label} changed between witnessed reads")
        if previous is None or rehash_on_seal:
            self.remembered[relative] = remembered

    def _cleanup_created_files(self) -> None:
        for relative, (label, identity) in tuple(self.created_files.items()):
            try:
                _canonical, parent, name = self._open_parent(relative, label)
            except PackageFilesystemCausalityError:
                continue
            try:
                try:
                    candidate = os.open(name, _FILE_FLAGS, dir_fd=parent)
                except OSError:
                    continue
                try:
                    current = os.fstat(candidate)
                finally:
                    os.close(candidate)
                if (current.st_dev, current.st_ino) == identity:
                    try:
                        os.unlink(name, dir_fd=parent)
                    except OSError:
                        pass
            finally:
                os.close(parent)

    def _open_parent(self, value: str, label: str) -> tuple[str, int, str]:
        descriptor = self.descriptor
        if descriptor is None:
            raise PackageFilesystemCausalityError(
                "package filesystem causality run witness is not open"
            )
        path = _canonical_run_path(value, label)
        parent = os.dup(descriptor)
        try:
            for part in path.parts[:-1]:
                child = os.open(part, _DIRECTORY_FLAGS, dir_fd=parent)
                os.close(parent)
                parent = child
        except OSError as exc:
            os.close(parent)
            raise PackageFilesystemCausalityError(
                f"{label} path cannot be traversed beneath the witnessed run "
                f"directory: {value}: {exc}"
            ) from exc
        return path.as_posix(), parent, path.parts[-1]


class _DebWitness:
    """Keep the exact recorded .deb inode open across both dpkg-deb commands."""

    def __init__(
        self,
        run: _RunDirectoryWitness,
        relative: str,
        *,
        expected_size: int,
        expected_sha256: str,
    ) -> None:
        self.run = run
        self.relative = relative
        self.path = run.path.joinpath(*PurePosixPath(relative).parts)
        self.expected_size = expected_size
        self.expected_sha256 = expected_sha256
        self.descriptor: int | None = None
        self.initial_stat: os.stat_result | None = None

    def __enter__(self) -> _DebWitness:
        try:
            _relative, descriptor = self.run.open_file(
                self.relative,
                "captured .deb",
            )
        except OSError as exc:
            raise PackageFilesystemCausalityError(
                f"captured .deb cannot be opened without following links: {self.path}: {exc}"
            ) from exc
        initial = os.fstat(descriptor)
        if not stat.S_ISREG(initial.st_mode):
            os.close(descriptor)
            raise PackageFilesystemCausalityError(
                f"captured .deb is not a regular file: {self.path}"
            )
        try:
            digest, size = _hash_descriptor(descriptor, initial, str(self.path))
        except BaseException:
            os.close(descriptor)
            raise
        if size != self.expected_size or digest != self.expected_sha256:
            os.close(descriptor)
            raise PackageFilesystemCausalityError(
                f"captured .deb changed from its sealed identity: {self.path}"
            )
        self.descriptor = descriptor
        self.initial_stat = initial
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        try:
            if exc_type is None:
                self.seal()
        finally:
            if self.descriptor is not None:
                os.close(self.descriptor)
                self.descriptor = None

    @property
    def command_path(self) -> str:
        if self.descriptor is None:
            raise PackageFilesystemCausalityError(".deb witness is not open")
        os.lseek(self.descriptor, 0, os.SEEK_SET)
        return f"/proc/{os.getpid()}/fd/{self.descriptor}"

    def seal(self) -> None:
        descriptor = self.descriptor
        initial = self.initial_stat
        if descriptor is None or initial is None:
            raise PackageFilesystemCausalityError(".deb witness is not open")
        current = os.fstat(descriptor)
        if _stat_identity(current) != _stat_identity(initial):
            raise PackageFilesystemCausalityError(
                f"captured .deb metadata changed during payload inspection: {self.path}"
            )
        digest, size = _hash_descriptor(descriptor, current, str(self.path))
        if digest != self.expected_sha256 or size != self.expected_size:
            raise PackageFilesystemCausalityError(
                f"captured .deb bytes changed during payload inspection: {self.path}"
            )
        try:
            _relative, path_descriptor = self.run.open_file(
                self.relative,
                "captured .deb",
            )
        except OSError as exc:
            raise PackageFilesystemCausalityError(
                f"captured .deb path changed during payload inspection: {self.path}: {exc}"
            ) from exc
        try:
            path_stat = os.fstat(path_descriptor)
            path_digest, path_size = _hash_descriptor(
                path_descriptor,
                path_stat,
                str(self.path),
            )
        finally:
            os.close(path_descriptor)
        if (
            path_stat.st_dev != initial.st_dev
            or path_stat.st_ino != initial.st_ino
            or _stat_identity(path_stat) != _stat_identity(initial)
            or path_digest != self.expected_sha256
            or path_size != self.expected_size
        ):
            raise PackageFilesystemCausalityError(
                f"captured .deb path no longer names the inspected bytes: {self.path}"
            )
        self.run.remember_file(
            self.relative,
            "captured .deb",
            path_stat,
            size=path_size,
            sha256=path_digest,
            rehash_on_seal=False,
        )


def write_package_filesystem_causality(
    run_dir: Path,
    expected_run_id: str,
    runner: CommandRunner,
) -> Path:
    """Write the immutable M3.1 static payload-to-rootfs report.

    A dry-run records one virtual write intent and deliberately performs no
    filesystem reads.  An executing runner must use the descriptor-bound binary
    command path for each selected ``.deb``.
    """

    target = run_dir / PACKAGE_FILESYSTEM_CAUSALITY_FILENAME
    _validate_expected_run_id(expected_run_id)
    if runner.dry_run:
        runner.run(
            CommandSpec(
                argv=("write-file", str(target)),
                description="Write package-to-rootfs static causality evidence",
            )
        )
        return target
    with _RunDirectoryWitness(run_dir) as run:
        payload = _recompute_payload(run, expected_run_id, runner)
        run.write_new_text(
            PACKAGE_FILESYSTEM_CAUSALITY_FILENAME,
            _json_text(payload),
            "package filesystem causality report",
        )
    return target


def validate_package_filesystem_causality(
    run_dir: Path,
    expected_run_id: str,
    runner: CommandRunner | None = None,
) -> PackageFilesystemCausalityValidation:
    """Recompute the report from bound .deb bytes and the final rootfs manifest."""

    try:
        _validate_expected_run_id(expected_run_id)
        with _RunDirectoryWitness(run_dir) as run:
            recorded, report_identity = _load_json_stable(
                run,
                PACKAGE_FILESYSTEM_CAUSALITY_FILENAME,
                "causality report",
            )
            if report_identity.data != _json_text(recorded).encode("utf-8"):
                raise PackageFilesystemCausalityError(
                    "package filesystem causality report bytes are not canonical"
                )
            if recorded.get("schema") != PACKAGE_FILESYSTEM_CAUSALITY_SCHEMA:
                raise PackageFilesystemCausalityError(
                    "package filesystem causality schema is unsupported"
                )
            if recorded.get("run_id") != expected_run_id:
                raise PackageFilesystemCausalityError(
                    "package filesystem causality report belongs to another run"
                )
            if (
                recorded.get("filesystem_causality") != "unverified"
                or recorded.get("release_ready") is not False
            ):
                raise PackageFilesystemCausalityError(
                    "package filesystem causality report contains a forbidden release promotion"
                )
            if recorded.get("payload_identity") not in {"partial", "verified"}:
                raise PackageFilesystemCausalityError(
                    "package payload identity status is malformed"
                )
            effective_runner = runner or CommandRunner(dry_run=False)
            if effective_runner.dry_run:
                raise PackageFilesystemCausalityError(
                    "authoritative package causality validation requires execution"
                )
            recomputed = _recompute_payload(
                run,
                expected_run_id,
                effective_runner,
            )
            if recorded != recomputed:
                raise PackageFilesystemCausalityError(
                    "package filesystem causality report differs from authoritative recomputation"
                )
        payload_identity = cast(str, recomputed["payload_identity"])
        return PackageFilesystemCausalityValidation(
            True,
            (
                "package filesystem causality report recomputes exactly; "
                f"payload_identity={payload_identity}, while installed-file "
                "causality remains unverified"
            ),
            payload_identity=payload_identity,
        )
    except (
        CommandError,
        json.JSONDecodeError,
        OSError,
        RootfsEvidenceError,
        PackageFilesystemCausalityError,
        tarfile.TarError,
        UnicodeError,
    ) as exc:
        return PackageFilesystemCausalityValidation(
            False,
            f"package filesystem causality validation failed: {exc}",
        )


def _recompute_payload(
    run: _RunDirectoryWitness,
    expected_run_id: str,
    runner: CommandRunner,
) -> dict[str, object]:
    if runner.dry_run:
        raise PackageFilesystemCausalityError(
            "package filesystem causality requires an executing CommandRunner"
        )
    package_inputs, package_inputs_identity = _load_json_stable(
        run,
        "PACKAGE-INPUTS.json",
        "package-input report",
    )
    if package_inputs.get("schema") != PACKAGE_INPUTS_SCHEMA:
        raise PackageFilesystemCausalityError("package-input report schema is unsupported")
    if package_inputs.get("run_id") != expected_run_id:
        raise PackageFilesystemCausalityError("package-input report belongs to another run")
    source_mode = package_inputs.get("source_mode")
    if source_mode not in {"bootstrap", "iso"}:
        raise PackageFilesystemCausalityError("package-input report has an unsupported source mode")
    if source_mode == "bootstrap" and package_inputs.get("fresh_rootfs") is not True:
        raise PackageFilesystemCausalityError(
            "bootstrap package inputs do not describe a fresh rootfs"
        )

    rootfs_raw, rootfs_identity = _load_json_stable(
        run,
        "ROOTFS-MANIFEST.json",
        "rootfs manifest",
    )
    rootfs = validate_rootfs_manifest_payload(rootfs_raw)
    if rootfs.get("run_id") != expected_run_id:
        raise PackageFilesystemCausalityError("rootfs manifest belongs to another run")
    rootfs_entry_list = cast(list[dict[str, object]], rootfs["entries"])
    if len(rootfs_entry_list) > MAX_TOTAL_ROOTFS_ENTRIES:
        raise PackageFilesystemCausalityError("rootfs manifest exceeds the aggregate entry bound")
    for entry in rootfs_entry_list:
        _assert_bounded_tar_text(
            cast(str, entry["path"]),
            "rootfs manifest path",
        )

    transactions, deb_records = _load_transactions(
        run,
        package_inputs,
        expected_run_id,
    )
    package_binding: dict[str, object] = {
        "path": "PACKAGE-INPUTS.json",
        "schema": PACKAGE_INPUTS_SCHEMA,
        "source_mode": source_mode,
        "size": package_inputs_identity.size,
        "sha256": package_inputs_identity.sha256,
        "transaction_count": len(transactions),
        "transactions_sha256": canonical_sha256(transactions),
    }
    rootfs_binding = {
        "path": "ROOTFS-MANIFEST.json",
        "schema": ROOTFS_MANIFEST_SCHEMA,
        "size": rootfs_identity.size,
        "sha256": rootfs_identity.sha256,
        "tree_sha256": rootfs["tree_sha256"],
        "object_count": rootfs["object_count"],
        "excluded_descendants": rootfs["excluded_descendants"],
    }

    if source_mode == "iso":
        paths: list[dict[str, object]] = []
        classification_json_bytes = 0
        for entry in rootfs_entry_list:
            classification_json_bytes = _append_bounded_classification(
                paths,
                _classification(
                    str(entry["path"]),
                    "unsupported",
                    ("source ISO baseline has no captured package payload identity in M3.1"),
                    payloads=[],
                    rootfs=entry,
                ),
                classification_json_bytes,
            )
        counts = _counts(paths)
        return _report(
            expected_run_id,
            source_mode,
            package_binding,
            rootfs_binding,
            packages=[],
            paths=paths,
            counts=counts,
            payload_identity="partial",
            status="unsupported-unverified",
        )

    final_inventory = _inventory(package_inputs.get("final_inventory"))
    if not final_inventory:
        raise PackageFilesystemCausalityError(
            "bootstrap package-input report has an empty final inventory"
        )
    packages, payloads = _inspect_debs(
        run,
        deb_records,
        final_inventory,
        runner,
    )
    rootfs_entries = {str(entry["path"]): entry for entry in rootfs_entry_list}
    exclusions = tuple(cast(list[str], rootfs["excluded_descendants"]))
    paths, payload_partial = _classify_paths(
        payloads,
        rootfs_entries,
        exclusions,
    )
    counts = _counts(paths)
    payload_identity = "partial" if payload_partial else "verified"
    return _report(
        expected_run_id,
        source_mode,
        package_binding,
        rootfs_binding,
        packages=packages,
        paths=paths,
        counts=counts,
        payload_identity=payload_identity,
        status="measured-unverified",
    )


def _report(
    run_id: str,
    source_mode: object,
    package_binding: dict[str, object],
    rootfs_binding: dict[str, object],
    *,
    packages: list[dict[str, object]],
    paths: list[dict[str, object]],
    counts: dict[str, int],
    payload_identity: str,
    status: str,
) -> dict[str, object]:
    return {
        "schema": PACKAGE_FILESYSTEM_CAUSALITY_SCHEMA,
        "run_id": run_id,
        "scope": "sealed-recorded-deb-direct-payload-to-final-rootfs-m3.1",
        "assurance_dependency": (
            "PACKAGE-INPUTS authentication and policy must be validated "
            "independently before this static map"
        ),
        "status": status,
        "digest": "sha256",
        "package_inputs": package_binding,
        "rootfs_manifest": rootfs_binding,
        "bounds": {
            "max_data_tar_bytes_per_deb": MAX_DATA_TAR_BYTES_PER_DEB,
            "max_logical_member_bytes": MAX_LOGICAL_MEMBER_BYTES,
            "max_members_per_deb": MAX_MEMBERS_PER_DEB,
            "max_total_payload_members": MAX_TOTAL_PAYLOAD_MEMBERS,
            "max_total_rootfs_entries": MAX_TOTAL_ROOTFS_ENTRIES,
            "max_final_packages": MAX_FINAL_PACKAGES,
            "max_package_identity_bytes": MAX_PACKAGE_IDENTITY_BYTES,
            "max_transaction_references": MAX_TRANSACTION_REFERENCES,
            "max_deb_records": MAX_DEB_RECORDS,
            "max_total_transaction_records": MAX_TOTAL_TRANSACTION_RECORDS,
            "max_total_transaction_json_bytes": MAX_TOTAL_TRANSACTION_JSON_BYTES,
            "max_evidence_json_bytes": MAX_EVIDENCE_JSON_BYTES,
            "max_total_payload_member_json_bytes": (MAX_TOTAL_PAYLOAD_MEMBER_JSON_BYTES),
            "max_total_claim_json_bytes": MAX_TOTAL_CLAIM_JSON_BYTES,
            "max_total_classification_json_bytes": (MAX_TOTAL_CLASSIFICATION_JSON_BYTES),
            "max_total_package_json_bytes": MAX_TOTAL_PACKAGE_JSON_BYTES,
            "max_total_selected_deb_bytes": MAX_TOTAL_SELECTED_DEB_BYTES,
            "max_total_data_tar_bytes": MAX_TOTAL_DATA_TAR_BYTES,
            "max_total_logical_payload_bytes": MAX_TOTAL_LOGICAL_PAYLOAD_BYTES,
            "max_deb_identity_bytes": MAX_DEB_IDENTITY_BYTES,
            "max_tar_extension_bytes": MAX_TAR_EXTENSION_BYTES,
            "max_total_tar_extension_bytes": MAX_TOTAL_TAR_EXTENSION_BYTES,
            "max_tar_extension_chain": MAX_TAR_EXTENSION_CHAIN,
            "max_physical_tar_headers": MAX_PHYSICAL_TAR_HEADERS,
            "max_tar_text_bytes": MAX_TAR_TEXT_BYTES,
            "max_pax_fields_per_member": MAX_PAX_FIELDS_PER_MEMBER,
            "max_pax_bytes_per_member": MAX_PAX_BYTES_PER_MEMBER,
            "max_run_relative_path_bytes": MAX_RUN_RELATIVE_PATH_BYTES,
            "max_run_relative_path_components": (MAX_RUN_RELATIVE_PATH_COMPONENTS),
            "max_transaction_id_bytes": MAX_TRANSACTION_ID_BYTES,
        },
        "limits": list(_LIMITS),
        "packages": packages,
        "paths": paths,
        "counts": counts,
        "payload_identity": payload_identity,
        "filesystem_causality": "unverified",
        "release_ready": False,
        "detail": (
            f"static payload identity is {payload_identity}; "
            f"{counts['exact']} exact, {counts['modified']} modified, "
            f"{counts['missing']} missing, {counts['unattributed']} unattributed, "
            f"{counts['ambiguous']} ambiguous, {counts['structural']} structural, "
            f"{counts['excluded']} excluded and {counts['unsupported']} unsupported "
            "paths; runtime producer causality remains outside M3.1"
        ),
    }


def _load_transactions(
    run: _RunDirectoryWitness,
    package_inputs: Mapping[str, object],
    expected_run_id: str,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    raw_refs = package_inputs.get("transactions")
    if not isinstance(raw_refs, list) or not raw_refs:
        raise PackageFilesystemCausalityError("package-input report has no transaction references")
    if len(raw_refs) > MAX_TRANSACTION_REFERENCES:
        raise PackageFilesystemCausalityError(
            "package-input report exceeds the transaction-reference bound"
        )
    transactions: list[dict[str, object]] = []
    debs_by_path: dict[str, dict[str, object]] = {}
    seen_transactions: set[str] = set()
    total_transaction_bytes = 0
    total_transaction_records = 0
    for raw_ref in raw_refs:
        ref = _identity_mapping(raw_ref, "package transaction")
        total_transaction_bytes += cast(int, ref["size"])
        if total_transaction_bytes > MAX_TOTAL_TRANSACTION_JSON_BYTES:
            raise PackageFilesystemCausalityError(
                "package-input report exceeds the aggregate transaction-byte bound"
            )
        relative = _canonical_run_path(
            cast(str, ref["path"]),
            "package transaction",
        ).as_posix()
        transaction, identity = _load_json_stable(
            run,
            relative,
            "package transaction",
        )
        _assert_recorded_identity(ref, identity, "package transaction")
        if transaction.get("schema") != PACKAGE_TRANSACTION_SCHEMA:
            raise PackageFilesystemCausalityError(
                f"package transaction schema is unsupported: {relative}"
            )
        if transaction.get("run_id") != expected_run_id:
            raise PackageFilesystemCausalityError(
                f"package transaction belongs to another run: {relative}"
            )
        transaction_id = transaction.get("id")
        if (
            not _safe_single_component(
                transaction_id,
                max_bytes=MAX_TRANSACTION_ID_BYTES,
            )
            or transaction_id in seen_transactions
        ):
            raise PackageFilesystemCausalityError("package transaction id is unsafe or duplicated")
        seen_transactions.add(transaction_id)
        records = transaction.get("records")
        if not isinstance(records, list):
            raise PackageFilesystemCausalityError(
                f"package transaction has malformed records: {relative}"
            )
        if len(records) > MAX_DEB_RECORDS:
            raise PackageFilesystemCausalityError(
                f"package transaction exceeds the record bound: {relative}"
            )
        total_transaction_records += len(records)
        if total_transaction_records > MAX_TOTAL_TRANSACTION_RECORDS:
            raise PackageFilesystemCausalityError(
                "package-input report exceeds the aggregate transaction-record bound"
            )
        for raw_record in records:
            if not isinstance(raw_record, dict) or raw_record.get("kind") != "deb":
                continue
            record = _identity_mapping(raw_record, "captured .deb")
            deb_relative = _canonical_run_path(
                cast(str, record["path"]),
                "captured .deb",
            ).as_posix()
            previous = debs_by_path.get(deb_relative)
            if previous is not None and previous != record:
                raise PackageFilesystemCausalityError(
                    f"captured .deb path has conflicting identities: {deb_relative}"
                )
            debs_by_path[deb_relative] = record
            if len(debs_by_path) > MAX_DEB_RECORDS:
                raise PackageFilesystemCausalityError(
                    "package-input report exceeds the captured .deb bound"
                )
        transactions.append(
            {
                "id": transaction_id,
                "path": relative,
                "size": identity.size,
                "sha256": identity.sha256,
            }
        )
    transactions.sort(key=lambda item: str(item["path"]).encode())
    deb_records = [
        debs_by_path[path] for path in sorted(debs_by_path, key=lambda item: item.encode())
    ]
    return transactions, deb_records


def _inspect_debs(
    run: _RunDirectoryWitness,
    records: list[dict[str, object]],
    final_inventory: set[tuple[str, str, str]],
    runner: CommandRunner,
) -> tuple[list[dict[str, object]], list[_DebPayload]]:
    if not records:
        raise PackageFilesystemCausalityError(
            "bootstrap package-input report has no captured .deb records"
        )
    by_identity: dict[
        tuple[str, str, str],
        tuple[
            str,
            str,
            int,
            list[dict[str, object]],
            dict[str, object],
        ],
    ] = {}
    excluded: list[dict[str, object]] = []
    package_json_bytes = 0
    total_payload_members = 0
    total_payload_member_json_bytes = 0
    total_selected_deb_bytes = 0
    total_data_tar_bytes = 0
    total_logical_payload_bytes = 0
    for record in records:
        relative = _canonical_run_path(
            cast(str, record["path"]),
            "captured .deb",
        ).as_posix()
        size = cast(int, record["size"])
        digest = cast(str, record["sha256"])
        total_selected_deb_bytes += size
        if total_selected_deb_bytes > MAX_TOTAL_SELECTED_DEB_BYTES:
            raise PackageFilesystemCausalityError(
                "captured .deb records exceed the aggregate byte bound"
            )
        with _DebWitness(
            run,
            relative,
            expected_size=size,
            expected_sha256=digest,
        ) as witness:
            package_key = _show_deb_identity(witness, runner)
            package = _package_dict(package_key)
            if package_key not in final_inventory:
                excluded_item = {
                    "identity": package,
                    "deb": {
                        "path": relative,
                        "size": size,
                        "sha256": digest,
                    },
                    "selection": "excluded-not-final-inventory",
                    "member_count": 0,
                    "members_sha256": canonical_sha256([]),
                }
                package_json_bytes = _append_bounded_package(
                    excluded,
                    excluded_item,
                    package_json_bytes,
                )
                continue
            previous = by_identity.get(package_key)
            if previous is not None:
                (
                    previous_digest,
                    previous_path,
                    _previous_size,
                    _previous_members,
                    _previous_summary,
                ) = previous
                if previous_digest != digest:
                    raise PackageFilesystemCausalityError(
                        "different .deb bytes claim one final package identity: "
                        f"{' '.join(package_key)}"
                    )
                if previous_path != relative:
                    raise PackageFilesystemCausalityError(
                        "one final .deb identity is captured at multiple paths: "
                        f"{' '.join(package_key)}"
                    )
                continue
            remaining_tar_bytes = MAX_TOTAL_DATA_TAR_BYTES - total_data_tar_bytes
            if remaining_tar_bytes <= 0:
                raise PackageFilesystemCausalityError(
                    "selected .deb tar streams exceed the aggregate byte bound"
                )
            remaining_members = MAX_TOTAL_PAYLOAD_MEMBERS - total_payload_members
            if remaining_members <= 0:
                raise PackageFilesystemCausalityError(
                    "selected .deb payloads exceed the aggregate member bound"
                )
            remaining_logical_bytes = MAX_TOTAL_LOGICAL_PAYLOAD_BYTES - total_logical_payload_bytes
            if remaining_logical_bytes <= 0:
                raise PackageFilesystemCausalityError(
                    "selected .deb logical payloads exceed the aggregate byte bound"
                )
            remaining_member_json_bytes = (
                MAX_TOTAL_PAYLOAD_MEMBER_JSON_BYTES - total_payload_member_json_bytes
            )
            if remaining_member_json_bytes <= 0:
                raise PackageFilesystemCausalityError(
                    "selected .deb member metadata exceeds the aggregate JSON budget"
                )
            with tempfile.TemporaryFile(mode="w+b") as tar_output:
                result = runner.run_binary_to_file(
                    CommandSpec(
                        argv=(
                            "dpkg-deb",
                            "--fsys-tarfile",
                            witness.command_path,
                        ),
                        description=f"Read witnessed .deb payload {relative}",
                    ),
                    tar_output,
                    max_output_bytes=min(
                        MAX_DATA_TAR_BYTES_PER_DEB,
                        remaining_tar_bytes,
                    ),
                    check=False,
                )
                if result.returncode != 0:
                    if result.returncode == 125 and "binary stdout exceeded" in result.stderr:
                        raise PackageFilesystemCausalityError(
                            "selected .deb tar streams exceed the aggregate "
                            "or per-package byte bound"
                        )
                    raise CommandError(result)
                tar_size = tar_output.tell()
                total_data_tar_bytes += tar_size
                tar_output.seek(0)
                members, logical_size, member_json_bytes = _read_payload_members(
                    tar_output,
                    relative,
                    max_member_json_bytes=remaining_member_json_bytes,
                    max_members=min(
                        MAX_MEMBERS_PER_DEB,
                        remaining_members,
                    ),
                    max_logical_bytes=min(
                        MAX_DATA_TAR_BYTES_PER_DEB,
                        remaining_logical_bytes,
                    ),
                )
                total_logical_payload_bytes += logical_size
                total_payload_member_json_bytes += member_json_bytes
                total_payload_members += len(members)
        package_summary = {
            "identity": package,
            "deb": {
                "path": relative,
                "size": size,
                "sha256": digest,
            },
            "selection": "final-inventory",
            "member_count": len(members),
            "members_sha256": canonical_sha256(members),
        }
        package_json_bytes = _bounded_package_json_bytes(
            package_summary,
            package_json_bytes,
        )
        by_identity[package_key] = (
            digest,
            relative,
            size,
            members,
            package_summary,
        )

    missing_packages = sorted(final_inventory - set(by_identity))
    if missing_packages:
        raise PackageFilesystemCausalityError(
            "final package has no captured direct payload: " + " ".join(missing_packages[0])
        )

    packages: list[dict[str, object]] = []
    payloads: list[_DebPayload] = []
    for key in sorted(by_identity):
        digest, relative, size, members, package_summary = by_identity[key]
        package = _package_dict(key)
        deb = {
            "path": relative,
            "size": size,
            "sha256": digest,
        }
        packages.append(package_summary)
        payloads.append(_DebPayload(package=package, deb=deb, members=members))
    packages.extend(excluded)
    packages.sort(
        key=lambda item: (
            str(cast(dict[str, str], item["identity"])["package"]).encode(),
            str(cast(dict[str, str], item["identity"])["version"]).encode(),
            str(cast(dict[str, str], item["identity"])["architecture"]).encode(),
            str(cast(dict[str, object], item["deb"])["path"]).encode(),
        )
    )
    return packages, payloads


def _show_deb_identity(
    witness: _DebWitness,
    runner: CommandRunner,
) -> tuple[str, str, str]:
    with tempfile.TemporaryFile(mode="w+b") as identity_output:
        runner.run_binary_to_file(
            CommandSpec(
                argv=(
                    "dpkg-deb",
                    "--show",
                    "--showformat=${Package}\\t${Version}\\t${Architecture}\\n",
                    witness.command_path,
                ),
                description=f"Read witnessed .deb identity {witness.path.name}",
            ),
            identity_output,
            max_output_bytes=MAX_DEB_IDENTITY_BYTES,
        )
        identity_output.seek(0)
        raw_output = identity_output.read(MAX_DEB_IDENTITY_BYTES + 1)
    if len(raw_output) > MAX_DEB_IDENTITY_BYTES:
        raise PackageFilesystemCausalityError("dpkg-deb package identity exceeds the capture bound")
    try:
        output = raw_output.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PackageFilesystemCausalityError(
            "dpkg-deb returned a non-UTF-8 package identity"
        ) from exc
    if output.count("\n") != 1 or not output.endswith("\n"):
        raise PackageFilesystemCausalityError(
            f"dpkg-deb returned a non-canonical package identity: {witness.path}"
        )
    fields = output[:-1].split("\t")
    if len(fields) != 3 or not all(fields):
        raise PackageFilesystemCausalityError(
            f"dpkg-deb returned an incomplete package identity: {witness.path}"
        )
    if any(
        any(ord(character) < 0x20 or ord(character) == 0x7F for character in field)
        for field in fields
    ):
        raise PackageFilesystemCausalityError(
            f"dpkg-deb returned an unsafe package identity: {witness.path}"
        )
    if sum(len(field.encode("utf-8")) for field in fields) > MAX_PACKAGE_IDENTITY_BYTES:
        raise PackageFilesystemCausalityError(
            f"dpkg-deb returned an oversized package identity: {witness.path}"
        )
    return fields[0], fields[1], fields[2]


class _BoundedTarStream:
    """Refuse large individual reads requested by tar metadata parsers."""

    def __init__(self, source: BinaryIO) -> None:
        self.source = source

    def read(self, size: int = -1) -> bytes:
        if size < 0 or size > MAX_TAR_READ_BYTES:
            raise PackageFilesystemCausalityError("tar parser requested an unbounded metadata read")
        return self.source.read(size)

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        return self.source.seek(offset, whence)

    def tell(self) -> int:
        return self.source.tell()


def _prescan_uncompressed_tar(stream: BinaryIO, deb_relative: str) -> None:
    """Bound physical headers and extension chains before ``tarfile`` recurses."""

    stream.seek(0, os.SEEK_END)
    stream_size = stream.tell()
    stream.seek(0)
    physical_headers = 0
    extension_chain = 0
    total_extension_bytes = 0
    zero_blocks = 0
    while stream.tell() < stream_size:
        block = stream.read(512)
        if len(block) != 512:
            raise PackageFilesystemCausalityError(f"truncated tar header in {deb_relative}")
        if block == b"\0" * 512:
            zero_blocks += 1
            if zero_blocks == 2:
                while trailing := stream.read(_READ_CHUNK):
                    if any(trailing):
                        raise PackageFilesystemCausalityError(
                            f"non-zero bytes follow the tar terminator in {deb_relative}"
                        )
                stream.seek(0)
                return
            continue
        if zero_blocks:
            raise PackageFilesystemCausalityError(
                f"tar terminator is interrupted in {deb_relative}"
            )
        physical_headers += 1
        if physical_headers > MAX_PHYSICAL_TAR_HEADERS:
            raise PackageFilesystemCausalityError(
                f".deb payload exceeds the physical tar-header bound: {deb_relative}"
            )
        stored_checksum = _parse_tar_octal(block[148:156], "checksum", deb_relative)
        checksum_block = block[:148] + (b" " * 8) + block[156:]
        unsigned_checksum = sum(checksum_block)
        signed_checksum = sum(byte if byte < 128 else byte - 256 for byte in checksum_block)
        if stored_checksum not in {unsigned_checksum, signed_checksum}:
            raise PackageFilesystemCausalityError(
                f"tar header checksum is invalid in {deb_relative}"
            )
        size = _parse_tar_size(block[124:136], deb_relative)
        padded_size = ((size + 511) // 512) * 512
        if stream.tell() + padded_size > stream_size:
            raise PackageFilesystemCausalityError(
                f"tar member exceeds the witnessed stream in {deb_relative}"
            )
        typeflag = block[156:157]
        if typeflag == b"S":
            raise PackageFilesystemCausalityError(
                f"GNU sparse tar metadata is unsupported in {deb_relative}"
            )
        if typeflag in {b"x", b"X", b"g", b"L", b"K"}:
            extension_chain += 1
            total_extension_bytes += size
            if (
                extension_chain > MAX_TAR_EXTENSION_CHAIN
                or size > MAX_TAR_EXTENSION_BYTES
                or total_extension_bytes > MAX_TOTAL_TAR_EXTENSION_BYTES
            ):
                raise PackageFilesystemCausalityError(
                    f"tar extension metadata exceeds its bound in {deb_relative}"
                )
        else:
            extension_chain = 0
        if typeflag in {b"x", b"X", b"g"}:
            extension = stream.read(size)
            if len(extension) != size:
                raise PackageFilesystemCausalityError(f"truncated PAX metadata in {deb_relative}")
            _validate_raw_pax_extension(extension, deb_relative)
            stream.seek(padded_size - size, os.SEEK_CUR)
        else:
            stream.seek(padded_size, os.SEEK_CUR)
    raise PackageFilesystemCausalityError(
        f"tar stream has no complete terminator in {deb_relative}"
    )


def _parse_tar_octal(field: bytes, label: str, deb_relative: str) -> int:
    stripped = field.rstrip(b"\0 ").lstrip(b" ")
    if not stripped:
        return 0
    if any(byte < ord("0") or byte > ord("7") for byte in stripped):
        raise PackageFilesystemCausalityError(
            f"tar {label} is not canonical octal in {deb_relative}"
        )
    return int(stripped, 8)


def _validate_raw_pax_extension(payload: bytes, deb_relative: str) -> None:
    offset = 0
    fields = 0
    while offset < len(payload):
        separator = payload.find(b" ", offset)
        if separator <= offset:
            raise PackageFilesystemCausalityError(
                f"PAX record length is malformed in {deb_relative}"
            )
        raw_length = payload[offset:separator]
        if len(raw_length) > 20 or any(byte < ord("0") or byte > ord("9") for byte in raw_length):
            raise PackageFilesystemCausalityError(
                f"PAX record length is malformed in {deb_relative}"
            )
        record_length = int(raw_length)
        end = offset + record_length
        if (
            record_length <= separator - offset + 2
            or end > len(payload)
            or payload[end - 1 : end] != b"\n"
        ):
            raise PackageFilesystemCausalityError(
                f"PAX record boundary is malformed in {deb_relative}"
            )
        record = payload[separator + 1 : end - 1]
        key_separator = record.find(b"=")
        if key_separator <= 0:
            raise PackageFilesystemCausalityError(
                f"PAX record has no key/value boundary in {deb_relative}"
            )
        key = record[:key_separator]
        if key.startswith(b"GNU.sparse."):
            raise PackageFilesystemCausalityError(
                f"GNU sparse PAX metadata is unsupported in {deb_relative}"
            )
        fields += 1
        if fields > MAX_PAX_FIELDS_PER_MEMBER:
            raise PackageFilesystemCausalityError(
                f"PAX metadata exceeds its field-count bound in {deb_relative}"
            )
        offset = end


def _parse_tar_size(field: bytes, deb_relative: str) -> int:
    if field and field[0] & 0x80:
        if field[0] != 0x80:
            raise PackageFilesystemCausalityError(
                f"negative or non-canonical tar size in {deb_relative}"
            )
        size = int.from_bytes(bytes([0]) + field[1:], "big")
    else:
        size = _parse_tar_octal(field, "size", deb_relative)
    if size < 0 or size > MAX_DATA_TAR_BYTES_PER_DEB:
        raise PackageFilesystemCausalityError(
            f"tar member size exceeds its bound in {deb_relative}"
        )
    return size


def _read_payload_members(
    stream: BinaryIO,
    deb_relative: str,
    *,
    max_member_json_bytes: int,
    max_members: int,
    max_logical_bytes: int,
) -> tuple[list[dict[str, object]], int, int]:
    raw: dict[str, dict[str, object]] = {}
    logical_size = 0
    raw_member_json_bytes = 0
    try:
        _prescan_uncompressed_tar(stream, deb_relative)
        bounded_stream = _BoundedTarStream(stream)
        with tarfile.open(fileobj=cast(BinaryIO, bounded_stream), mode="r:") as archive:
            for index, info in enumerate(archive, start=1):
                if index > max_members:
                    raise PackageFilesystemCausalityError(
                        ".deb payload exceeds the remaining aggregate or "
                        f"per-package member bound: {deb_relative}"
                    )
                path = _normalise_member_path(info.name, "payload member")
                if path in raw:
                    raise PackageFilesystemCausalityError(
                        f"duplicate canonical payload member {path!r} in {deb_relative}"
                    )
                if (
                    not isinstance(info.uid, int)
                    or not isinstance(info.gid, int)
                    or info.uid < 0
                    or info.gid < 0
                ):
                    raise PackageFilesystemCausalityError(
                        f"payload member has invalid ownership: {path}"
                    )
                _validate_pax_numeric_headers(info, path)
                unsupported_headers = sorted(
                    key
                    for key in info.pax_headers
                    if key
                    not in {
                        "atime",
                        "ctime",
                        "gid",
                        "gname",
                        "linkpath",
                        "mtime",
                        "path",
                        "size",
                        "uid",
                        "uname",
                    }
                )
                common: dict[str, object] = {
                    "path": path,
                    "mode": f"{info.mode & 0o7777:04o}",
                    "uid": info.uid,
                    "gid": info.gid,
                }
                if unsupported_headers:
                    common["unsupported_metadata"] = unsupported_headers
                if info.isreg():
                    if info.size < 0 or info.size > MAX_LOGICAL_MEMBER_BYTES:
                        raise PackageFilesystemCausalityError(
                            f"payload member exceeds the logical size bound: {path}"
                        )
                    logical_size += info.size
                    if logical_size > max_logical_bytes:
                        raise PackageFilesystemCausalityError(
                            "selected .deb logical payloads exceed the remaining "
                            f"aggregate or per-package byte bound: {deb_relative}"
                        )
                    source = archive.extractfile(info)
                    if source is None:
                        raise PackageFilesystemCausalityError(
                            f"regular payload member cannot be read: {path}"
                        )
                    digest, size = _hash_member(
                        cast(BinaryIO, source),
                        info.size,
                        path,
                    )
                    common.update(
                        {
                            "type": "regular",
                            "archive_type": "regular",
                            "size": size,
                            "sha256": digest,
                        }
                    )
                elif info.isdir():
                    common["type"] = "directory"
                    common["archive_type"] = "directory"
                elif info.issym():
                    _assert_bounded_tar_text(
                        info.linkname,
                        f"symlink target for {path}",
                    )
                    common["type"] = "symlink"
                    common["archive_type"] = "symlink"
                    common["target"] = info.linkname
                elif info.islnk():
                    common["type"] = "hardlink"
                    common["archive_type"] = "hardlink"
                    common["target"] = _normalise_member_path(
                        info.linkname,
                        f"hardlink target for {path}",
                    )
                elif info.isfifo():
                    common["type"] = "fifo"
                    common["archive_type"] = "fifo"
                elif info.ischr():
                    common["type"] = "character-device"
                    common["archive_type"] = "character-device"
                    common["device"] = {
                        "major": info.devmajor,
                        "minor": info.devminor,
                    }
                elif info.isblk():
                    common["type"] = "block-device"
                    common["archive_type"] = "block-device"
                    common["device"] = {
                        "major": info.devmajor,
                        "minor": info.devminor,
                    }
                else:
                    common["type"] = "unsupported"
                    common["archive_type"] = (
                        info.type.hex() if isinstance(info.type, bytes) else str(info.type)
                    )
                raw_member_json_bytes += _compact_json_size(common)
                if raw_member_json_bytes > max_member_json_bytes:
                    raise PackageFilesystemCausalityError(
                        "selected .deb member metadata exceeds the aggregate JSON budget"
                    )
                raw[path] = common
    except PackageFilesystemCausalityError:
        raise
    except (
        tarfile.TarError,
        OSError,
        ValueError,
        OverflowError,
        RecursionError,
        EOFError,
    ) as exc:
        raise PackageFilesystemCausalityError(
            f"cannot parse .deb filesystem tar stream {deb_relative}: {exc}"
        ) from exc
    resolved = _resolve_hardlinks(raw, deb_relative)
    resolved_json_bytes = sum(_compact_json_size(item) for item in resolved)
    if resolved_json_bytes > max_member_json_bytes:
        raise PackageFilesystemCausalityError(
            "resolved .deb member metadata exceeds the aggregate JSON budget"
        )
    return resolved, logical_size, resolved_json_bytes


def _validate_pax_numeric_headers(info: tarfile.TarInfo, path: str) -> None:
    if len(info.pax_headers) > MAX_PAX_FIELDS_PER_MEMBER:
        raise PackageFilesystemCausalityError(f"PAX metadata exceeds its field-count bound: {path}")
    metadata_bytes = 0
    for key, value in info.pax_headers.items():
        _assert_bounded_tar_text(key, f"PAX key for {path}")
        _assert_bounded_tar_text(value, f"PAX value for {path}")
        metadata_bytes += len(key.encode("utf-8")) + len(value.encode("utf-8"))
    if metadata_bytes > MAX_PAX_BYTES_PER_MEMBER:
        raise PackageFilesystemCausalityError(f"PAX metadata exceeds its per-member bound: {path}")
    for key in ("uid", "gid", "size"):
        numeric_value = info.pax_headers.get(key)
        if numeric_value is None:
            continue
        if not numeric_value or any(
            character < "0" or character > "9" for character in numeric_value
        ):
            raise PackageFilesystemCausalityError(
                f"PAX {key} is not a non-negative decimal value: {path}"
            )
        if int(numeric_value) != getattr(info, key):
            raise PackageFilesystemCausalityError(
                f"PAX {key} disagrees with the parsed tar member: {path}"
            )


def _resolve_hardlinks(
    raw: dict[str, dict[str, object]],
    deb_relative: str,
) -> list[dict[str, object]]:
    resolved_target: dict[str, str] = {}

    def regular_source(start: str) -> str:
        cached = resolved_target.get(start)
        if cached is not None:
            return cached
        chain: list[str] = []
        positions: dict[str, int] = {}
        current = start
        while current not in resolved_target:
            if current in positions:
                raise PackageFilesystemCausalityError(
                    f"cyclic hardlink payload in {deb_relative}: {current}"
                )
            positions[current] = len(chain)
            item = raw.get(current)
            if item is None:
                raise PackageFilesystemCausalityError(
                    f"hardlink target is absent from payload {deb_relative}: {current}"
                )
            if item.get("type") == "regular":
                resolved_target[current] = current
                break
            if item.get("type") != "hardlink":
                raise PackageFilesystemCausalityError(
                    f"hardlink target is not a regular payload member: {current}"
                )
            chain.append(current)
            current = cast(str, item["target"])
        source = resolved_target[current]
        for member in chain:
            resolved_target[member] = source
        return source

    groups: dict[str, list[str]] = defaultdict(list)
    for path, item in raw.items():
        if item.get("type") in {"regular", "hardlink"}:
            groups[regular_source(path)].append(path)
    sorted_groups = {
        source: sorted(members, key=lambda member: member.encode())
        for source, members in groups.items()
    }

    result: list[dict[str, object]] = []
    for path in sorted(raw, key=lambda item: item.encode()):
        item = dict(raw[path])
        if item.get("type") != "hardlink":
            if item.get("type") == "regular":
                group = sorted_groups[resolved_target[path]]
                item["link_count"] = len(group)
                if len(group) > 1:
                    item["hardlink_master"] = group[0]
            result.append(item)
            continue
        source_path = resolved_target[path]
        source = raw[source_path]
        group = sorted_groups[source_path]
        item.pop("target", None)
        item.update(
            {
                "type": "regular",
                "mode": source["mode"],
                "uid": source["uid"],
                "gid": source["gid"],
                "size": source["size"],
                "sha256": source["sha256"],
                "link_count": len(group),
                "hardlink_master": group[0],
            }
        )
        if "unsupported_metadata" in source:
            item["unsupported_metadata"] = source["unsupported_metadata"]
        result.append(item)
    return result


def _classify_paths(
    payloads: list[_DebPayload],
    rootfs_entries: dict[str, dict[str, object]],
    exclusions: tuple[str, ...],
) -> tuple[list[dict[str, object]], bool]:
    claims: dict[str, list[dict[str, object]]] = defaultdict(list)
    claim_json_bytes = 0
    for payload in payloads:
        for member in payload.members:
            claim = {
                "package": payload.package,
                "deb": payload.deb,
                "entry": member,
            }
            claim_json_bytes += _compact_json_size(claim)
            if claim_json_bytes > MAX_TOTAL_CLAIM_JSON_BYTES:
                raise PackageFilesystemCausalityError(
                    "package payload claims exceed the aggregate JSON budget"
                )
            claims[cast(str, member["path"])].append(claim)
    paths: list[dict[str, object]] = []
    classification_json_bytes = 0
    payload_partial = False
    for path in sorted(claims, key=lambda item: item.encode()):
        path_claims = claims[path]
        rootfs = rootfs_entries.get(path)
        entries = [cast(dict[str, object], claim["entry"]) for claim in path_claims]
        if _is_excluded_descendant(path, exclusions):
            classification = "excluded"
            detail = "payload path is below a rootfs-manifest excluded descendant"
            payload_partial = True
        elif any(
            entry.get("type") == "unsupported"
            or "unsupported_metadata" in entry
            or entry.get("type") in {"fifo", "character-device", "block-device"}
            for entry in entries
        ):
            classification = "unsupported"
            detail = "payload object or metadata is outside the M3.1 representation"
            payload_partial = True
        elif rootfs is not None and rootfs.get("type") not in {"directory", "regular", "symlink"}:
            classification = "unsupported"
            detail = "final rootfs object type is outside the M3.1 representation"
            payload_partial = True
        elif all(entry.get("type") == "directory" for entry in entries):
            if rootfs is None:
                classification = "missing"
                detail = "payload directory is absent from the final rootfs"
            elif rootfs.get("type") != "directory":
                classification = "modified"
                detail = "payload directory path has another final object type"
            else:
                classification = "structural"
                detail = "directory merge cannot identify one package producer"
        elif (
            len(
                {
                    (
                        cast(dict[str, str], claim["package"])["package"],
                        cast(dict[str, str], claim["package"])["version"],
                        cast(dict[str, str], claim["package"])["architecture"],
                    )
                    for claim in path_claims
                }
            )
            > 1
        ):
            classification = "ambiguous"
            detail = "multiple final packages claim the same non-structural path"
        elif rootfs is None:
            classification = "missing"
            detail = "supported payload path is absent from the final rootfs"
        elif _payload_matches_rootfs(entries[0], rootfs):
            classification = "exact"
            detail = "static payload semantics match the final rootfs entry"
        else:
            classification = "modified"
            detail = "final rootfs semantics differ from the static payload"
        classification_json_bytes = _append_bounded_classification(
            paths,
            _classification(
                path,
                classification,
                detail,
                payloads=path_claims,
                rootfs=rootfs,
            ),
            classification_json_bytes,
        )

    for path in sorted(set(rootfs_entries) - set(claims), key=lambda item: item.encode()):
        rootfs = rootfs_entries[path]
        if rootfs.get("type") == "directory":
            classification = "structural"
            detail = "final directory has no unique static package producer"
        elif rootfs.get("type") in {"regular", "symlink"}:
            classification = "unattributed"
            detail = "final rootfs entry has no selected direct package payload claim"
        else:
            classification = "unsupported"
            detail = "final rootfs object type is outside the M3.1 representation"
            payload_partial = True
        classification_json_bytes = _append_bounded_classification(
            paths,
            _classification(
                path,
                classification,
                detail,
                payloads=[],
                rootfs=rootfs,
            ),
            classification_json_bytes,
        )
    paths.sort(key=lambda item: str(item["path"]).encode())
    return paths, payload_partial


def _payload_matches_rootfs(
    payload: Mapping[str, object],
    rootfs: Mapping[str, object],
) -> bool:
    kind = payload.get("type")
    if kind != rootfs.get("type"):
        return False
    if any(payload.get(field) != rootfs.get(field) for field in ("mode", "uid", "gid")):
        return False
    if rootfs.get("xattrs") != []:
        return False
    if kind == "regular":
        if any(
            payload.get(field) != rootfs.get(field) for field in ("size", "sha256", "link_count")
        ):
            return False
        return payload.get("hardlink_master") == rootfs.get("hardlink_master")
    if kind == "symlink":
        return payload.get("target") == rootfs.get("target") and rootfs.get("link_count") == 1
    return False


def _classification(
    path: str,
    classification: str,
    detail: str,
    *,
    payloads: list[dict[str, object]],
    rootfs: dict[str, object] | None,
) -> dict[str, object]:
    if classification not in _CLASSIFICATIONS:
        raise PackageFilesystemCausalityError(
            f"internal unsupported classification: {classification}"
        )
    return {
        "path": path,
        "classification": classification,
        "detail": detail,
        "payloads": payloads,
        "rootfs": rootfs,
    }


def _append_bounded_classification(
    paths: list[dict[str, object]],
    item: dict[str, object],
    current_json_bytes: int,
) -> int:
    updated_json_bytes = current_json_bytes + _compact_json_size(item)
    if updated_json_bytes > MAX_TOTAL_CLASSIFICATION_JSON_BYTES:
        raise PackageFilesystemCausalityError(
            "path classifications exceed the aggregate JSON budget"
        )
    paths.append(item)
    return updated_json_bytes


def _bounded_package_json_bytes(
    item: dict[str, object],
    current_json_bytes: int,
) -> int:
    updated_json_bytes = current_json_bytes + _compact_json_size(item)
    if updated_json_bytes > MAX_TOTAL_PACKAGE_JSON_BYTES:
        raise PackageFilesystemCausalityError("package summaries exceed the aggregate JSON budget")
    return updated_json_bytes


def _append_bounded_package(
    packages: list[dict[str, object]],
    item: dict[str, object],
    current_json_bytes: int,
) -> int:
    updated_json_bytes = _bounded_package_json_bytes(
        item,
        current_json_bytes,
    )
    packages.append(item)
    return updated_json_bytes


def _counts(paths: list[dict[str, object]]) -> dict[str, int]:
    return {
        classification: sum(item.get("classification") == classification for item in paths)
        for classification in _CLASSIFICATIONS
    }


def _inventory(value: object) -> set[tuple[str, str, str]]:
    if not isinstance(value, list):
        raise PackageFilesystemCausalityError("package-input final inventory is malformed")
    if len(value) > MAX_FINAL_PACKAGES:
        raise PackageFilesystemCausalityError(
            "package-input final inventory exceeds the package bound"
        )
    result: set[tuple[str, str, str]] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {
            "package",
            "version",
            "architecture",
        }:
            raise PackageFilesystemCausalityError(
                "package-input final inventory entry is malformed"
            )
        fields = (item["package"], item["version"], item["architecture"])
        if not all(isinstance(field, str) and field for field in fields):
            raise PackageFilesystemCausalityError(
                "package-input final inventory identity is incomplete"
            )
        typed_fields = cast(tuple[str, str, str], fields)
        try:
            for field in typed_fields:
                _assert_utf8(field, "package-input final inventory identity")
        except UnicodeError as exc:
            raise PackageFilesystemCausalityError(str(exc)) from exc
        if sum(
            len(field.encode("utf-8")) for field in typed_fields
        ) > MAX_PACKAGE_IDENTITY_BYTES or any(
            any(ord(character) < 0x20 or ord(character) == 0x7F for character in field)
            for field in typed_fields
        ):
            raise PackageFilesystemCausalityError(
                "package-input final inventory identity is unsafe or oversized"
            )
        key = typed_fields
        if key in result:
            raise PackageFilesystemCausalityError(
                "package-input final inventory contains a duplicate identity"
            )
        result.add(key)
    return result


def _package_dict(key: tuple[str, str, str]) -> dict[str, str]:
    return {
        "package": key[0],
        "version": key[1],
        "architecture": key[2],
    }


def _identity_mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise PackageFilesystemCausalityError(f"{label} identity is malformed")
    path = value.get("path")
    size = value.get("size")
    digest = value.get("sha256")
    if (
        not isinstance(path, str)
        or not path
        or not isinstance(size, int)
        or isinstance(size, bool)
        or size < 0
        or not isinstance(digest, str)
        or not _is_sha256(digest)
    ):
        raise PackageFilesystemCausalityError(f"{label} identity is malformed")
    return {"path": path, "size": size, "sha256": digest}


def _assert_recorded_identity(
    recorded: Mapping[str, object],
    actual: _StableBytes,
    label: str,
) -> None:
    if recorded.get("size") != actual.size or recorded.get("sha256") != actual.sha256:
        raise PackageFilesystemCausalityError(f"{label} changed from its sealed identity")


def _canonical_run_path(value: str, label: str) -> PurePosixPath:
    try:
        _assert_utf8(value, f"{label} path")
    except UnicodeError as exc:
        raise PackageFilesystemCausalityError(str(exc)) from exc
    encoded = value.encode("utf-8")
    if (
        len(encoded) > MAX_RUN_RELATIVE_PATH_BYTES
        or value.count("/") >= MAX_RUN_RELATIVE_PATH_COMPONENTS
    ):
        raise PackageFilesystemCausalityError(
            f"{label} path exceeds its size or depth bound: {value[:80]!r}"
        )
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or value != path.as_posix()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise PackageFilesystemCausalityError(f"{label} path escapes or is non-canonical: {value}")
    return path


def _load_json_stable(
    run: _RunDirectoryWitness,
    relative: str,
    label: str,
) -> tuple[dict[str, object], _StableBytes]:
    stable = _read_stable(run, relative, label)
    try:
        decoded = stable.data.decode("utf-8")
        payload = json.loads(decoded)
    except (
        UnicodeDecodeError,
        ValueError,
        OverflowError,
        RecursionError,
    ) as exc:
        raise PackageFilesystemCausalityError(f"{label} is unreadable: {exc}") from exc
    if not isinstance(payload, dict):
        raise PackageFilesystemCausalityError(f"{label} is not a JSON object")
    return payload, stable


def _json_text(payload: Mapping[str, object]) -> str:
    try:
        encoder = json.JSONEncoder(
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        output = io.StringIO()
        encoded_size = 1
        for chunk in encoder.iterencode(payload):
            encoded_size += len(chunk.encode("utf-8"))
            if encoded_size > MAX_EVIDENCE_JSON_BYTES:
                raise PackageFilesystemCausalityError(
                    "package filesystem causality JSON exceeds the evidence-size bound"
                )
            output.write(chunk)
        output.write("\n")
        content = output.getvalue()
    except PackageFilesystemCausalityError:
        raise
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise PackageFilesystemCausalityError(
            f"package filesystem causality JSON is not serializable: {exc}"
        ) from exc
    return content


def _compact_json_size(value: object) -> int:
    try:
        return len(
            json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        )
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise PackageFilesystemCausalityError(
            f"package payload metadata is not serializable: {exc}"
        ) from exc


def _read_stable(
    run: _RunDirectoryWitness,
    relative: str,
    label: str,
) -> _StableBytes:
    try:
        canonical, descriptor = run.open_file(relative, label)
    except OSError as exc:
        raise PackageFilesystemCausalityError(
            f"{label} cannot be opened without following links: {exc}"
        ) from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise PackageFilesystemCausalityError(f"{label} is not a regular file")
        chunks: list[bytes] = []
        digest = hashlib.sha256()
        size = 0
        while chunk := os.read(descriptor, _READ_CHUNK):
            if size + len(chunk) > MAX_EVIDENCE_JSON_BYTES:
                raise PackageFilesystemCausalityError(f"{label} exceeds the evidence-size bound")
            chunks.append(chunk)
            digest.update(chunk)
            size += len(chunk)
        after = os.fstat(descriptor)
        if _stat_identity(before) != _stat_identity(after) or size != before.st_size:
            raise PackageFilesystemCausalityError(f"{label} changed while it was read")
        result = _StableBytes(b"".join(chunks), size, digest.hexdigest())
    finally:
        os.close(descriptor)
    _relative, path_descriptor = run.open_file(canonical, label)
    try:
        path_stat = os.fstat(path_descriptor)
        path_digest, path_size = _hash_descriptor(
            path_descriptor,
            path_stat,
            label,
        )
    finally:
        os.close(path_descriptor)
    if (
        path_stat.st_dev != before.st_dev
        or path_stat.st_ino != before.st_ino
        or _stat_identity(path_stat) != _stat_identity(before)
        or path_digest != result.sha256
        or path_size != result.size
    ):
        raise PackageFilesystemCausalityError(f"{label} path no longer names the read inode")
    run.remember_file(
        canonical,
        label,
        path_stat,
        size=result.size,
        sha256=result.sha256,
        rehash_on_seal=True,
    )
    return result


def _hash_descriptor(
    descriptor: int,
    before: os.stat_result,
    label: str,
) -> tuple[str, int]:
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    size = 0
    while chunk := os.read(descriptor, _READ_CHUNK):
        digest.update(chunk)
        size += len(chunk)
    after = os.fstat(descriptor)
    if _stat_identity(before) != _stat_identity(after) or size != before.st_size:
        raise PackageFilesystemCausalityError(f"{label} changed while it was hashed")
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest(), size


def _hash_member(
    source: BinaryIO,
    expected_size: int,
    path: str,
) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    while chunk := source.read(_READ_CHUNK):
        size += len(chunk)
        if size > expected_size:
            raise PackageFilesystemCausalityError(f"payload member exceeds its tar size: {path}")
        digest.update(chunk)
    if size != expected_size:
        raise PackageFilesystemCausalityError(f"payload member is truncated: {path}")
    return digest.hexdigest(), size


def _normalise_member_path(value: str, label: str) -> str:
    try:
        _assert_bounded_tar_text(value, label)
    except UnicodeError as exc:
        raise PackageFilesystemCausalityError(str(exc)) from exc
    if not value:
        raise PackageFilesystemCausalityError(f"unsafe empty {label}")
    if value.startswith("/") or PurePosixPath(value).is_absolute():
        raise PackageFilesystemCausalityError(f"absolute {label} is forbidden: {value}")
    raw_parts = value.split("/")
    if ".." in raw_parts:
        raise PackageFilesystemCausalityError(f"unsafe path traversal in {label}: {value}")
    parts = [part for part in raw_parts if part not in {"", "."}]
    if not parts:
        return "."
    return "/".join(parts)


def _assert_utf8(value: str, label: str) -> None:
    if "\x00" in value:
        raise UnicodeError(f"{label} contains NUL")
    value.encode("utf-8", errors="strict")


def _assert_bounded_tar_text(value: str, label: str) -> None:
    try:
        _assert_utf8(value, label)
    except UnicodeError as exc:
        raise PackageFilesystemCausalityError(str(exc)) from exc
    if len(value.encode("utf-8")) > MAX_TAR_TEXT_BYTES:
        raise PackageFilesystemCausalityError(f"{label} exceeds the tar text bound")


def _is_excluded_descendant(path: str, exclusions: tuple[str, ...]) -> bool:
    return any(path != exclusion and path.startswith(f"{exclusion}/") for exclusion in exclusions)


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and set(value) <= _HEX_SHA256


def _stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _validate_expected_run_id(expected_run_id: str) -> None:
    if not _safe_single_component(
        expected_run_id,
        max_bytes=MAX_TRANSACTION_ID_BYTES,
    ):
        raise PackageFilesystemCausalityError(
            "expected package filesystem causality run_id is unsafe"
        )


def _safe_single_component(value: object, *, max_bytes: int) -> TypeGuard[str]:
    if not isinstance(value, str) or not value or value in {".", ".."}:
        return False
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        return False
    return (
        len(encoded) <= max_bytes
        and "\x00" not in value
        and not any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        and PurePosixPath(value).name == value
    )


def _open_absolute_directory(path: Path) -> int:
    """Open an absolute directory path one non-symlink component at a time."""

    absolute = Path(os.path.abspath(path))
    if not absolute.is_absolute() or absolute == Path("/"):
        raise PackageFilesystemCausalityError(
            "package filesystem causality run directory is unsafe"
        )
    descriptor: int | None = None
    try:
        descriptor = os.open("/", _DIRECTORY_FLAGS)
        for part in absolute.parts[1:]:
            child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        raise PackageFilesystemCausalityError(
            f"package filesystem causality run directory is symlinked or unavailable: {exc}"
        ) from exc
    assert descriptor is not None
    return descriptor
