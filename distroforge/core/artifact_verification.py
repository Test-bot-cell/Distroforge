"""Descriptor-backed, invocation-scoped verification of immutable artifacts.

The release chain must never trust a pathname cache.  This module instead keeps
each regular-file inode open for one verdict, reuses only bytes measured through
that descriptor, and revalidates both the held inode and its descriptor-relative
pathname before closing the verdict.

This is deliberately a Linux/POSIX contract.  A host without the required
``openat`` flags is unsupported and fails closed; falling back to ``Path.open``
would silently restore the symlink and FIFO races this boundary exists to stop.
Sessions are intentionally single-threaded; the release gate currently forbids
parallel artifact I/O so its causal order and structural counters stay explicit.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import stat
from collections.abc import Callable, Hashable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TypeVar, cast

_CHUNK = 1024 * 1024
_REQUIRED_OPEN_FLAGS = (
    "O_CLOEXEC",
    "O_DIRECTORY",
    "O_NOFOLLOW",
    "O_NONBLOCK",
    "O_PATH",
)
_T = TypeVar("_T")


class ArtifactVerificationError(RuntimeError):
    """An artifact cannot support a stable, bounded verification verdict."""


@dataclass(frozen=True)
class ArtifactLimits:
    """Structural budgets for one verification verdict."""

    max_open_files: int = 256
    max_file_bytes: int = 64 * 1024 * 1024 * 1024
    max_buffered_bytes: int = 512 * 1024 * 1024
    max_hashed_bytes: int = 256 * 1024 * 1024 * 1024
    max_json_depth: int = 256
    max_json_nodes: int = 2_000_000
    max_path_components: int = 256
    max_closing_fds: int = 1024

    def __post_init__(self) -> None:
        for name, value in vars(self).items():
            if value <= 0:
                raise ValueError(f"{name} must be positive")


@dataclass(frozen=True)
class ArtifactIdentity:
    """Host identity which must remain equal for the lifetime of a verdict."""

    dev: int
    ino: int
    mode: int
    uid: int
    gid: int
    nlink: int
    rdev: int
    size: int
    mtime_ns: int
    ctime_ns: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> ArtifactIdentity:
        return cls(
            dev=value.st_dev,
            ino=value.st_ino,
            mode=value.st_mode,
            uid=value.st_uid,
            gid=value.st_gid,
            nlink=value.st_nlink,
            rdev=value.st_rdev,
            size=value.st_size,
            mtime_ns=value.st_mtime_ns,
            ctime_ns=value.st_ctime_ns,
        )


@dataclass
class ArtifactMetrics:
    """Structural evidence about work performed; never a wall-clock threshold."""

    files_opened: int = 0
    directories_opened: int = 0
    bytes_hashed: int = 0
    digest_reuse: int = 0
    json_parses: int = 0
    json_reuse: int = 0
    replays: int = 0


@dataclass
class _ArtifactRecord:
    descriptor: int
    identity: ArtifactIdentity
    digest: str | None = None
    body: bytes | None = None
    text: str | None = None
    json_value: object | None = None
    json_loaded: bool = False
    closed: bool = False


@dataclass(frozen=True)
class _PathBinding:
    relative: Path
    label: str
    max_bytes: int
    allow_empty: bool
    ancestor_identities: tuple[tuple[str, ArtifactIdentity], ...]
    leaf_identity: ArtifactIdentity
    record: _ArtifactRecord


class ArtifactHandle:
    """One logical path bound to an inode held by its owning session."""

    def __init__(
        self,
        session: ArtifactVerificationSession,
        binding: _PathBinding,
    ) -> None:
        self._session = session
        self._binding = binding

    @property
    def logical_path(self) -> Path:
        return self._session.anchor_path / self._binding.relative

    @property
    def identity(self) -> ArtifactIdentity:
        return self._binding.record.identity

    @property
    def fileno(self) -> int:
        def measured_descriptor() -> int:
            self._session._digest(self._binding)
            if self._binding.record.closed:
                raise ArtifactVerificationError(
                    f"{self._binding.label} is already closed"
                )
            return self._binding.record.descriptor

        return self._session._guard(measured_descriptor)

    @property
    def proc_fd_path(self) -> Path:
        """A consumer path naming the inode held for this verdict."""
        def measured_path() -> Path:
            proc_root = Path(f"/proc/{os.getpid()}/fd")
            if not proc_root.is_dir():
                raise ArtifactVerificationError(
                    f"{self._binding.label} cannot be pinned: "
                    "/proc PID fds are unavailable"
                )
            return proc_root / str(self.fileno)

        return self._session._guard(measured_path)

    @property
    def pass_fds(self) -> tuple[int, ...]:
        return (self.fileno,)

    def digest(self) -> str:
        return self._session._guard(lambda: self._session._digest(self._binding))

    def read_bytes(self) -> bytes:
        return self._session._guard(lambda: self._session._read_bytes(self._binding))

    def read_text(self) -> str:
        return self._session._guard(lambda: self._session._read_text(self._binding))

    def json(self) -> object:
        return self._session._guard(lambda: self._session._parse_json(self._binding))

    def json_object(self) -> dict[str, object]:
        def object_value() -> dict[str, object]:
            value = self._session._parse_json(self._binding)
            if not isinstance(value, dict):
                raise ArtifactVerificationError(
                    f"{self._binding.label} must contain one JSON object"
                )
            return cast(dict[str, object], value)

        return self._session._guard(object_value)


class ArtifactVerificationSession:
    """Hold and verify artifacts for exactly one independently computed verdict."""

    def __init__(
        self,
        anchor: Path,
        *,
        label: str = "artifact verification",
        limits: ArtifactLimits | None = None,
    ) -> None:
        _require_platform_contract()
        if (
            not anchor.is_absolute()
            or ".." in anchor.parts
            or "\x00" in str(anchor)
        ):
            raise ArtifactVerificationError(f"{label} anchor is not canonical: {anchor}")
        self.anchor_path = Path(os.path.abspath(anchor))
        self.label = label
        self.limits = limits or ArtifactLimits()
        self._metrics = ArtifactMetrics()
        self._anchor_descriptor, self._anchor_identity = self._open_absolute_anchor(
            self.anchor_path
        )
        self._bindings: dict[str, _PathBinding] = {}
        self._records: list[_ArtifactRecord] = []
        self._records_by_inode: dict[tuple[int, int], _ArtifactRecord] = {}
        self._memo: dict[Hashable, object] = {}
        self._replays: dict[Hashable, object] = {}
        self._operation_errors: list[str] = []
        self._buffered_bytes = 0
        self._sealed = False
        self._seal_error: ArtifactVerificationError | None = None
        self._closed = False

    def __enter__(self) -> ArtifactVerificationSession:
        self._assert_active()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if exc_type is not None:
            self.close()
            return
        self.seal()

    @property
    def metrics(self) -> ArtifactMetrics:
        return replace(self._metrics)

    def metrics_dict(self) -> dict[str, int]:
        return dict(vars(self.metrics))

    def file(
        self,
        relative: Path,
        *,
        label: str | None = None,
        max_bytes: int | None = None,
        allow_empty: bool = False,
    ) -> ArtifactHandle:
        """Open a canonical relative path without following any path component."""
        return self._guard(
            lambda: self._file(
                relative,
                label=label,
                max_bytes=max_bytes,
                allow_empty=allow_empty,
            )
        )

    def _file(
        self,
        relative: Path,
        *,
        label: str | None,
        max_bytes: int | None,
        allow_empty: bool,
    ) -> ArtifactHandle:
        self._assert_active()
        canonical = _canonical_relative(relative)
        if len(canonical.parts) > self.limits.max_path_components:
            raise ArtifactVerificationError(
                f"artifact path exceeds {self.limits.max_path_components} components: "
                f"{relative}"
            )
        key = canonical.as_posix()
        file_label = label or key
        byte_limit = max_bytes if max_bytes is not None else self.limits.max_file_bytes
        if byte_limit <= 0 or byte_limit > self.limits.max_file_bytes:
            raise ArtifactVerificationError(
                f"{file_label} has an invalid byte limit: {byte_limit}"
            )
        existing = self._bindings.get(key)
        if existing is not None:
            _enforce_size(
                existing.record.identity,
                min(byte_limit, existing.max_bytes),
                allow_empty and existing.allow_empty,
                file_label,
            )
            return ArtifactHandle(self, existing)
        if len(self._bindings) >= self.limits.max_open_files:
            raise ArtifactVerificationError(
                f"{self.label} exceeds its open-file budget "
                f"({self.limits.max_open_files})"
            )

        descriptor, identity, ancestors = self._open_relative(canonical, file_label)
        try:
            if not stat.S_ISREG(identity.mode):
                raise ArtifactVerificationError(f"{file_label} is not a regular file")
            _enforce_size(identity, byte_limit, allow_empty, file_label)
            inode_key = (identity.dev, identity.ino)
            record = self._records_by_inode.get(inode_key)
            if record is None:
                record = _ArtifactRecord(descriptor=descriptor, identity=identity)
                self._records.append(record)
                self._records_by_inode[inode_key] = record
                descriptor = -1
            elif record.identity != identity:
                raise ArtifactVerificationError(
                    f"{file_label} aliases an inode whose identity changed"
                )
            binding = _PathBinding(
                relative=canonical,
                label=file_label,
                max_bytes=byte_limit,
                allow_empty=allow_empty,
                ancestor_identities=ancestors,
                leaf_identity=identity,
                record=record,
            )
            self._bindings[key] = binding
            return ArtifactHandle(self, binding)
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def file_path(
        self,
        path: Path,
        *,
        label: str | None = None,
        max_bytes: int | None = None,
        allow_empty: bool = False,
    ) -> ArtifactHandle:
        """Bind an absolute caller path after reducing it to this anchor."""
        def bind_absolute() -> ArtifactHandle:
            if not path.is_absolute() or ".." in path.parts or "\x00" in str(path):
                raise ArtifactVerificationError(
                    f"artifact path is not canonical: {path}"
                )
            absolute = Path(os.path.abspath(path))
            try:
                relative = absolute.relative_to(self.anchor_path)
            except ValueError as exc:
                raise ArtifactVerificationError(
                    f"artifact path escapes {self.label} anchor: {path}"
                ) from exc
            return self._file(
                relative,
                label=label,
                max_bytes=max_bytes,
                allow_empty=allow_empty,
            )

        return self._guard(bind_absolute)

    def memo(self, key: Hashable, factory: Callable[[], _T]) -> _T:
        """Reuse an expensive semantic validation only inside this verdict."""
        self._assert_active()
        if key not in self._memo:
            self._memo[key] = factory()
        return cast(_T, self._memo[key])

    def replay_once(self, key: Hashable, factory: Callable[[], _T]) -> _T:
        """Run one named external replay at most once inside this verdict."""
        self._assert_active()
        if key not in self._replays:
            self._metrics.replays += 1
            self._replays[key] = factory()
        return cast(_T, self._replays[key])

    def seal(self) -> ArtifactMetrics:
        """Re-hash held inodes, revalidate every path, close, and fail on drift."""
        if self._sealed:
            if self._seal_error is not None:
                raise ArtifactVerificationError(str(self._seal_error)) from self._seal_error
            return self.metrics
        if self._closed:
            raise ArtifactVerificationError(f"{self.label} is already closed")
        errors: list[str] = list(self._operation_errors)
        closing_anchor = -1
        closing_pins: list[tuple[int, ArtifactIdentity, str]] = []
        try:
            try:
                try:
                    current_anchor = ArtifactIdentity.from_stat(
                        os.fstat(self._anchor_descriptor)
                    )
                    if current_anchor != self._anchor_identity:
                        errors.append(f"{self.label} anchor changed during verification")
                except OSError as exc:
                    errors.append(f"{self.label} anchor cannot be rechecked: {exc}")

                try:
                    closing_anchor, identity = self._open_absolute_anchor(
                        self.anchor_path
                    )
                except ArtifactVerificationError as exc:
                    errors.append(str(exc))
                else:
                    if identity != self._anchor_identity:
                        errors.append(
                            f"{self.label} anchor path identity changed "
                            "during verification"
                        )
                    try:
                        closing_pins = self._pin_bindings_for_close(closing_anchor)
                    except ArtifactVerificationError as exc:
                        errors.append(str(exc))

                # Hash held artifact descriptors only after every closing pathname
                # has been pinned.  The final fstats below therefore establish one
                # common closing interval without a later pathname open creating a
                # new mutation window.
                for record in self._records:
                    try:
                        self._seal_record(record)
                    except ArtifactVerificationError as exc:
                        errors.append(str(exc))

                for descriptor, expected, pin_label in closing_pins:
                    try:
                        current = ArtifactIdentity.from_stat(os.fstat(descriptor))
                    except OSError as exc:
                        errors.append(f"{pin_label} closing pin failed: {exc}")
                    else:
                        if current != expected:
                            errors.append(
                                f"{pin_label} identity changed during closure"
                            )
                for descriptor, expected, anchor_label in (
                    (
                        self._anchor_descriptor,
                        self._anchor_identity,
                        f"{self.label} held anchor",
                    ),
                    (
                        closing_anchor,
                        self._anchor_identity,
                        f"{self.label} closing anchor",
                    ),
                ):
                    if descriptor < 0:
                        continue
                    try:
                        current = ArtifactIdentity.from_stat(os.fstat(descriptor))
                    except OSError as exc:
                        errors.append(f"{anchor_label} failed: {exc}")
                    else:
                        if current != expected:
                            errors.append(f"{anchor_label} identity changed")
            except Exception as exc:
                errors.append(
                    f"{self.label} closure raised {type(exc).__name__}: {exc}"
                )
        finally:
            for descriptor, _identity, _label in reversed(closing_pins):
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            if closing_anchor >= 0:
                try:
                    os.close(closing_anchor)
                except OSError:
                    pass
            self._sealed = True
            self.close()
        if errors:
            self._seal_error = ArtifactVerificationError(
                "; ".join(dict.fromkeys(errors))
            )
            raise self._seal_error
        return self.metrics

    def close(self) -> None:
        """Close without making a verdict; idempotent and exception-safe."""
        if self._closed:
            return
        for record in self._records:
            if not record.closed:
                try:
                    os.close(record.descriptor)
                except OSError:
                    pass
                record.closed = True
            record.digest = None
            record.body = None
            record.text = None
            record.json_value = None
            record.json_loaded = False
        try:
            os.close(self._anchor_descriptor)
        except OSError:
            pass
        self._memo.clear()
        self._replays.clear()
        self._buffered_bytes = 0
        self._closed = True

    def _assert_active(self) -> None:
        if self._closed or self._sealed:
            raise ArtifactVerificationError(f"{self.label} is already closed")

    def _guard(self, operation: Callable[[], _T]) -> _T:
        try:
            return operation()
        except ArtifactVerificationError as exc:
            message = str(exc)
            if message not in self._operation_errors:
                self._operation_errors.append(message)
            raise

    def _open_absolute_anchor(
        self,
        anchor: Path,
    ) -> tuple[int, ArtifactIdentity]:
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
        try:
            descriptor = os.open("/", flags)
            self._metrics.directories_opened += 1
        except OSError as exc:
            raise ArtifactVerificationError(
                f"cannot open {self.label} filesystem root: {exc}"
            ) from exc
        try:
            for component in anchor.parts[1:]:
                try:
                    child = os.open(component, flags, dir_fd=descriptor)
                    self._metrics.directories_opened += 1
                except OSError as exc:
                    raise ArtifactVerificationError(
                        f"{self.label} anchor contains a symlink, non-directory, "
                        f"or unreadable component: {anchor}"
                    ) from exc
                os.close(descriptor)
                descriptor = child
            try:
                identity = ArtifactIdentity.from_stat(os.fstat(descriptor))
            except OSError as exc:
                raise ArtifactVerificationError(
                    f"{self.label} anchor cannot be identified: {exc}"
                ) from exc
            if not stat.S_ISDIR(identity.mode):
                raise ArtifactVerificationError(
                    f"{self.label} anchor is not a directory: {anchor}"
                )
            return descriptor, identity
        except BaseException:
            os.close(descriptor)
            raise

    def _open_relative(
        self,
        relative: Path,
        label: str,
    ) -> tuple[int, ArtifactIdentity, tuple[tuple[str, ArtifactIdentity], ...]]:
        directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
        probe_flags = os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW
        read_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
        parent = self._anchor_descriptor
        owned_parent = -1
        ancestors: list[tuple[str, ArtifactIdentity]] = []
        prefix: list[str] = []
        try:
            for component in relative.parts[:-1]:
                prefix.append(component)
                try:
                    child = os.open(component, directory_flags, dir_fd=parent)
                    self._metrics.directories_opened += 1
                except OSError as exc:
                    raise ArtifactVerificationError(
                        f"{label} contains a symlink, non-directory, or unreadable "
                        "ancestor"
                    ) from exc
                if owned_parent >= 0:
                    os.close(owned_parent)
                owned_parent = child
                parent = child
                try:
                    identity = ArtifactIdentity.from_stat(os.fstat(child))
                except OSError as exc:
                    raise ArtifactVerificationError(
                        f"{label} ancestor cannot be identified: {exc}"
                    ) from exc
                if not stat.S_ISDIR(identity.mode):
                    raise ArtifactVerificationError(
                        f"{label} contains a non-directory ancestor"
                    )
                ancestors.append(("/".join(prefix), identity))
            probe = -1
            try:
                probe = os.open(relative.name, probe_flags, dir_fd=parent)
                self._metrics.files_opened += 1
            except OSError as exc:
                raise ArtifactVerificationError(
                    f"{label} cannot be opened without following links: {exc}"
                ) from exc
            try:
                identity = ArtifactIdentity.from_stat(os.fstat(probe))
            except OSError as exc:
                os.close(probe)
                raise ArtifactVerificationError(
                    f"{label} cannot be identified after opening: {exc}"
                ) from exc
            if stat.S_ISLNK(identity.mode):
                os.close(probe)
                raise ArtifactVerificationError(
                    f"{label} cannot be opened without following links: "
                    "leaf is a symlink"
                )
            if not stat.S_ISREG(identity.mode):
                return probe, identity, tuple(ancestors)
            descriptor = -1
            try:
                descriptor = os.open(
                    f"/proc/{os.getpid()}/fd/{probe}",
                    read_flags,
                )
                read_identity = ArtifactIdentity.from_stat(os.fstat(descriptor))
            except OSError as exc:
                if descriptor >= 0:
                    os.close(descriptor)
                raise ArtifactVerificationError(
                    f"{label} pinned regular file cannot be opened for reading: {exc}"
                ) from exc
            finally:
                os.close(probe)
            if read_identity != identity:
                os.close(descriptor)
                raise ArtifactVerificationError(
                    f"{label} changed while its regular-file descriptor was opened"
                )
            return descriptor, identity, tuple(ancestors)
        finally:
            if owned_parent >= 0:
                try:
                    os.close(owned_parent)
                except OSError:
                    pass

    def _digest(self, binding: _PathBinding) -> str:
        self._assert_active()
        record = binding.record
        if record.digest is not None:
            self._metrics.digest_reuse += 1
            return record.digest
        body, digest = self._measure(record, binding, capture=False)
        assert body is None
        record.digest = digest
        return digest

    def _read_bytes(self, binding: _PathBinding) -> bytes:
        self._assert_active()
        record = binding.record
        if record.body is not None:
            if len(record.body) > binding.max_bytes:
                raise ArtifactVerificationError(
                    f"{binding.label} exceeds its {binding.max_bytes}-byte limit"
                )
            return record.body
        if record.digest is not None:
            raise ArtifactVerificationError(
                f"{binding.label} bytes must be captured before requesting its "
                "standalone digest"
            )
        remaining = self.limits.max_buffered_bytes - self._buffered_bytes
        if record.identity.size > remaining:
            raise ArtifactVerificationError(
                f"{self.label} exceeds its buffered-byte budget "
                f"({self.limits.max_buffered_bytes})"
            )
        body, digest = self._measure(
            record,
            binding,
            capture=True,
            capture_limit=remaining,
        )
        assert body is not None
        if self._buffered_bytes + len(body) > self.limits.max_buffered_bytes:
            raise ArtifactVerificationError(
                f"{self.label} exceeds its buffered-byte budget "
                f"({self.limits.max_buffered_bytes})"
            )
        self._buffered_bytes += len(body)
        record.digest = digest
        record.body = body
        return body

    def _read_text(self, binding: _PathBinding) -> str:
        self._assert_active()
        record = binding.record
        if record.text is not None:
            return record.text
        try:
            text = self._read_bytes(binding).decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise ArtifactVerificationError(
                f"{binding.label} is not strict UTF-8"
            ) from exc
        record.text = text
        return text

    def _parse_json(self, binding: _PathBinding) -> object:
        self._assert_active()
        record = binding.record
        if record.json_loaded:
            self._metrics.json_reuse += 1
            return copy.deepcopy(record.json_value)
        text = self._read_text(binding)
        try:
            value = json.loads(
                text,
                object_pairs_hook=_unique_json_object,
                parse_constant=_reject_json_constant,
            )
            _validate_json_shape(
                value,
                max_depth=self.limits.max_json_depth,
                max_nodes=self.limits.max_json_nodes,
            )
        except (
            json.JSONDecodeError,
            UnicodeError,
            OverflowError,
            RecursionError,
            ValueError,
        ) as exc:
            raise ArtifactVerificationError(
                f"{binding.label} is not bounded canonical JSON: {exc}"
            ) from exc
        self._metrics.json_parses += 1
        record.json_value = value
        record.json_loaded = True
        return copy.deepcopy(value)

    def _measure(
        self,
        record: _ArtifactRecord,
        binding: _PathBinding,
        *,
        capture: bool,
        capture_limit: int | None = None,
    ) -> tuple[bytes | None, str]:
        try:
            before = ArtifactIdentity.from_stat(os.fstat(record.descriptor))
            if before != record.identity:
                raise ArtifactVerificationError(
                    f"{binding.label} changed before it could be read"
                )
            _enforce_size(before, binding.max_bytes, binding.allow_empty, binding.label)
            hashed_remaining = (
                self.limits.max_hashed_bytes - self._metrics.bytes_hashed
            )
            if before.size > hashed_remaining:
                raise ArtifactVerificationError(
                    f"{binding.label} exceeds the session hashed-byte budget "
                    f"({self.limits.max_hashed_bytes})"
                )
            if capture and capture_limit is not None and before.size > capture_limit:
                raise ArtifactVerificationError(
                    f"{self.label} exceeds its buffered-byte budget "
                    f"({self.limits.max_buffered_bytes})"
                )
            os.lseek(record.descriptor, 0, os.SEEK_SET)
            digest = hashlib.sha256()
            chunks: list[bytes] | None = [] if capture else None
            total = 0
            while True:
                read_ceiling = min(binding.max_bytes, hashed_remaining)
                if capture_limit is not None:
                    read_ceiling = min(read_ceiling, capture_limit)
                chunk = os.read(
                    record.descriptor,
                    min(_CHUNK, read_ceiling + 1 - total),
                )
                if not chunk:
                    break
                total += len(chunk)
                if total > binding.max_bytes:
                    raise ArtifactVerificationError(
                        f"{binding.label} grew beyond its {binding.max_bytes}-byte limit"
                    )
                if total > hashed_remaining:
                    raise ArtifactVerificationError(
                        f"{binding.label} exceeds the session hashed-byte budget "
                        f"({self.limits.max_hashed_bytes})"
                    )
                if capture_limit is not None and total > capture_limit:
                    raise ArtifactVerificationError(
                        f"{self.label} exceeds its buffered-byte budget "
                        f"({self.limits.max_buffered_bytes})"
                    )
                self._charge_hashed(len(chunk), binding.label)
                digest.update(chunk)
                if chunks is not None:
                    chunks.append(chunk)
            after = ArtifactIdentity.from_stat(os.fstat(record.descriptor))
        except OSError as exc:
            raise ArtifactVerificationError(
                f"{binding.label} cannot be read through its held descriptor: {exc}"
            ) from exc
        if before != after or after != record.identity or total != after.size:
            raise ArtifactVerificationError(f"{binding.label} changed while it was read")
        return (b"".join(chunks) if chunks is not None else None), digest.hexdigest()

    def _charge_hashed(self, amount: int, label: str) -> None:
        if self._metrics.bytes_hashed + amount > self.limits.max_hashed_bytes:
            raise ArtifactVerificationError(
                f"{label} exceeds the session hashed-byte budget "
                f"({self.limits.max_hashed_bytes})"
            )
        self._metrics.bytes_hashed += amount

    def _seal_record(self, record: _ArtifactRecord) -> None:
        try:
            current = ArtifactIdentity.from_stat(os.fstat(record.descriptor))
        except OSError as exc:
            raise ArtifactVerificationError(
                f"{self.label} held artifact cannot be rechecked: {exc}"
            ) from exc
        if current != record.identity:
            raise ArtifactVerificationError(
                f"{self.label} held artifact identity changed before closure"
            )
        if record.digest is None:
            return
        binding = next(
            candidate
            for candidate in self._bindings.values()
            if candidate.record is record
        )
        _, closing_digest = self._measure(record, binding, capture=False)
        if closing_digest != record.digest:
            raise ArtifactVerificationError(
                f"{binding.label} bytes changed before session closure"
            )

    def _pin_bindings_for_close(
        self,
        anchor_descriptor: int,
    ) -> list[tuple[int, ArtifactIdentity, str]]:
        directory_flags = os.O_PATH | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
        leaf_flags = os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW
        directories: dict[str, tuple[int, ArtifactIdentity, str]] = {}
        leaves: list[tuple[int, ArtifactIdentity, str]] = []

        def reserve_pin(label: str) -> None:
            used = 1 + len(directories) + len(leaves)
            if used >= self.limits.max_closing_fds:
                raise ArtifactVerificationError(
                    f"{label} exceeds the session closing-FD budget "
                    f"({self.limits.max_closing_fds})"
                )

        try:
            for binding in self._bindings.values():
                expected_ancestors = dict(binding.ancestor_identities)
                parent = anchor_descriptor
                prefix: list[str] = []
                for component in binding.relative.parts[:-1]:
                    prefix.append(component)
                    key = "/".join(prefix)
                    expected = expected_ancestors.get(key)
                    if expected is None:
                        raise ArtifactVerificationError(
                            f"{binding.label} lacks an opening ancestor identity"
                        )
                    existing = directories.get(key)
                    if existing is not None:
                        descriptor, prior_expected, _label = existing
                        if prior_expected != expected:
                            raise ArtifactVerificationError(
                                f"{binding.label} ancestor identity is inconsistent"
                            )
                        parent = descriptor
                        continue
                    reserve_pin(binding.label)
                    descriptor = -1
                    try:
                        descriptor = os.open(
                            component,
                            directory_flags,
                            dir_fd=parent,
                        )
                        self._metrics.directories_opened += 1
                        identity = ArtifactIdentity.from_stat(os.fstat(descriptor))
                    except OSError as exc:
                        if descriptor >= 0:
                            os.close(descriptor)
                        raise ArtifactVerificationError(
                            f"{binding.label} ancestor cannot be pinned at closure: "
                            f"{exc}"
                        ) from exc
                    if identity != expected:
                        os.close(descriptor)
                        raise ArtifactVerificationError(
                            f"{binding.label} ancestor identity changed before closure"
                        )
                    directories[key] = (
                        descriptor,
                        expected,
                        f"{binding.label} ancestor {key}",
                    )
                    parent = descriptor

                reserve_pin(binding.label)
                leaf = -1
                try:
                    leaf = os.open(
                        binding.relative.name,
                        leaf_flags,
                        dir_fd=parent,
                    )
                    self._metrics.files_opened += 1
                    identity = ArtifactIdentity.from_stat(os.fstat(leaf))
                except OSError as exc:
                    if leaf >= 0:
                        os.close(leaf)
                    raise ArtifactVerificationError(
                        f"{binding.label} path cannot be pinned at closure: {exc}"
                    ) from exc
                if identity != binding.leaf_identity:
                    os.close(leaf)
                    raise ArtifactVerificationError(
                        f"{binding.label} path resolves to another inode before closure"
                    )
                leaves.append((leaf, binding.leaf_identity, binding.label))
            return [*directories.values(), *leaves]
        except BaseException:
            for descriptor, _identity, _label in [
                *directories.values(),
                *leaves,
            ]:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            raise


def _canonical_relative(value: Path) -> Path:
    if value.is_absolute() or not value.parts or value == Path("."):
        raise ArtifactVerificationError(
            f"artifact path must be a non-empty relative path: {value}"
        )
    if "\x00" in str(value) or any(part in {"", ".", ".."} for part in value.parts):
        raise ArtifactVerificationError(f"artifact path is not canonical: {value}")
    canonical = Path(*value.parts)
    if canonical.as_posix() != value.as_posix():
        raise ArtifactVerificationError(f"artifact path is not canonical: {value}")
    return canonical


def _enforce_size(
    identity: ArtifactIdentity,
    max_bytes: int,
    allow_empty: bool,
    label: str,
) -> None:
    if identity.size > max_bytes:
        raise ArtifactVerificationError(f"{label} exceeds its {max_bytes}-byte limit")
    if identity.size == 0 and not allow_empty:
        raise ArtifactVerificationError(f"{label} is empty")


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON number: {value}")


def _validate_json_shape(value: object, *, max_depth: int, max_nodes: int) -> None:
    nodes = 0
    stack: list[tuple[object, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes:
            raise ValueError(f"JSON exceeds {max_nodes} nodes")
        if depth > max_depth:
            raise ValueError(f"JSON exceeds depth {max_depth}")
        if isinstance(current, dict):
            stack.extend((item, depth + 1) for pair in current.items() for item in pair)
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
        elif isinstance(current, float) and not math.isfinite(current):
            raise ValueError("JSON contains a non-finite number")
        elif isinstance(current, str):
            try:
                current.encode("utf-8", errors="strict")
            except UnicodeError as exc:
                raise ValueError("JSON contains an invalid Unicode scalar") from exc


def _require_platform_contract() -> None:
    missing = [name for name in _REQUIRED_OPEN_FLAGS if not hasattr(os, name)]
    if os.open not in os.supports_dir_fd:
        missing.append("open(dir_fd=)")
    if missing:
        raise ArtifactVerificationError(
            "descriptor-backed artifact verification is unsupported: "
            + ", ".join(missing)
        )


__all__ = [
    "ArtifactHandle",
    "ArtifactIdentity",
    "ArtifactLimits",
    "ArtifactMetrics",
    "ArtifactVerificationError",
    "ArtifactVerificationSession",
]
