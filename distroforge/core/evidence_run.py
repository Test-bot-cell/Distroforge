from __future__ import annotations

import ctypes
import dataclasses
import errno
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from distroforge import __version__

from .artifact_verification import ArtifactIdentity
from .command import VIRTUAL_COMMANDS, CommandSpec
from .hashing import sha256_file

if TYPE_CHECKING:
    from .project import Project


EVIDENCE_SCHEMA = "distroforge.evidence-run.v1"
IDENTITY_CLOSURE_SCHEMA = "distroforge.run-identity-closure.v1"
MAX_RUN_ID_BYTES = 255
TOOLCHAIN_BINARIES: tuple[str, ...] = (
    "python3",
    "git",
    "mmdebstrap",
    "debootstrap",
    "apt-get",
    "dpkg",
    "dpkg-deb",
    "mksquashfs",
    "unsquashfs",
    "lz4",
    "zstd",
    "xorriso",
    "grub-mkimage",
    "gpgv",
    "mformat",
    "mmd",
    "mcopy",
    "mdir",
    "qemu-system-x86_64",
    "sha256sum",
    "chroot",
    "sudo",
)


def new_run_id(now: datetime | None = None) -> str:
    stamp = (now or datetime.now(UTC)).strftime("%Y%m%dT%H%M%S.%fZ")
    return f"{stamp}-{uuid.uuid4().hex[:12]}"


def is_safe_run_id(value: object) -> bool:
    """Return whether ``value`` is one canonical, portable evidence component."""

    if not isinstance(value, str) or value in {"", ".", ".."}:
        return False
    if "/" in value or "\\" in value or "\x00" in value:
        return False
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        return False
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError:
        return False
    if len(encoded) > MAX_RUN_ID_BYTES:
        return False
    return Path(value).name == value


def evidence_run_path(
    output_dir: Path,
    run_id: str,
    filename: str,
    *,
    executed: bool,
) -> Path:
    if not is_safe_run_id(run_id):
        raise ValueError(f"invalid evidence run_id: {run_id!r}")
    relative = Path(filename)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"evidence filename must stay inside its run directory: {filename}")
    kind = "runs" if executed else "plans"
    return output_dir / "evidence" / kind / run_id / relative


def reserve_evidence_run(output_dir: Path, run_id: str, *, executed: bool) -> Path:
    directory = evidence_run_path(
        output_dir,
        run_id,
        ".reserved",
        executed=executed,
    ).parent
    directory.mkdir(parents=True, exist_ok=False)
    return directory


def first_symlink_in_confined_tree(anchor: Path, root: Path) -> Path | None:
    """Find a symlink from ``anchor`` through ``root`` and below it.

    Looking only below ``root`` misses a symlinked ``evidence`` or ``runs`` parent:
    ``root.is_symlink()`` is false for a child reached through that link.  Component
    checks therefore happen before recursion.
    """
    confined_anchor = anchor.absolute()
    confined_root = root.absolute()
    try:
        relative = confined_root.relative_to(confined_anchor)
    except ValueError:
        return confined_root
    current = confined_anchor
    if current.is_symlink():
        return current
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            return current
    if not confined_root.is_dir():
        return None
    return next(
        (path for path in confined_root.rglob("*") if path.is_symlink()),
        None,
    )


def write_immutable_text(
    path: Path,
    content: str,
    *,
    expected_parent_identity: StableParentIdentity | ArtifactIdentity | None = None,
) -> ImmutableCopyReceipt:
    """Durably create an evidence file once and refuse replacement.

    ``os.replace`` is deliberately unsuitable here: immutable evidence must never
    displace an existing path.  A same-filesystem unnamed inode is fully written
    and synced before its sole no-replace link is created.  No temporary pathname
    exists for another process to substitute or for cleanup to unlink.
    """
    encoded = content.encode("utf-8", errors="strict")
    return _publish_regular_bytes(
        path,
        encoded,
        replace=False,
        max_bytes=len(encoded),
        expected_parent_identity=expected_parent_identity,
    )


@dataclasses.dataclass(frozen=True)
class ImmutableCopyReceipt:
    """Identity of the bytes durably published by :func:`copy_immutable_file`."""

    size: int
    sha256: str


StableParentIdentity = tuple[int, int, int, int, int, int, int]
FullFilesystemIdentity = tuple[int, int, int, int, int, int, int, int, int, int]


@dataclasses.dataclass(frozen=True)
class ImmutableTreeCopyReceipt:
    """Bounded result of a descriptor-relative immutable tree copy."""

    files: tuple[str, ...]
    bytes_copied: int
    digests: tuple[tuple[str, str], ...]
    target_identity: FullFilesystemIdentity
    target_stable_identity: StableParentIdentity


@dataclasses.dataclass
class OwnedTemporaryDirectory:
    """A temporary tree retired without deleting through recycled pathnames."""

    path: Path
    identity: StableParentIdentity
    cleanup_outcome: CleanupOutcome | None = None

    @property
    def cleanup_succeeded(self) -> bool | None:
        """Compatibility view: whether the requested scrub completed."""

        if self.cleanup_outcome is None:
            return None
        return self.cleanup_outcome.scrub_complete

    @property
    def retained_quarantine(self) -> bool | None:
        """Compatibility view: whether the workspace was durably detached."""

        if self.cleanup_outcome is None:
            return None
        return self.cleanup_outcome.durably_detached

    def __enter__(self) -> Path:
        return self.path

    def __exit__(
        self,
        exc_type: object,
        exc: object,
        traceback: object,
    ) -> None:
        try:
            self.cleanup_outcome = cleanup_owned_tree(
                self.path,
                self.identity,
            )
        except BaseException as cleanup_exc:
            message = (
                "owned temporary directory cleanup failed closed: "
                f"{type(cleanup_exc).__name__}: {cleanup_exc}"
            )
            if isinstance(exc, BaseException):
                raise OSError(message) from exc
            raise OSError(message) from cleanup_exc
        if not self.cleanup_outcome.durably_detached:
            cleanup_error = OSError(
                "owned temporary directory cleanup refused a missing or "
                "substituted workspace: "
                + "; ".join(self.cleanup_outcome.errors)
            )
            if isinstance(exc, BaseException):
                raise cleanup_error from exc
            raise cleanup_error
        if not self.cleanup_outcome.scrub_complete:
            cleanup_error = OSError(
                "owned temporary directory was durably detached but its scrub "
                "remains incomplete: "
                + "; ".join(self.cleanup_outcome.errors)
            )
            if isinstance(exc, BaseException):
                raise cleanup_error from exc
            raise cleanup_error


@dataclasses.dataclass(frozen=True)
class CleanupOutcome:
    """Durable namespace retirement and bounded content-scrub result.

    ``durably_detached`` only becomes true after the exact held directory was
    renamed to a verified quarantine name, its parent was synced, and the
    operational name was proven absent through the still-anchored parent.
    ``scrub_complete`` is deliberately independent: the quarantine is retained,
    and residual entries/bytes describe its terminal descriptor-relative
    inventory.  Regular-file bytes are counted once per ``(device, inode)`` so
    internal hardlink aliases cannot inflate the residual byte total.
    """

    durably_detached: bool
    scrub_complete: bool
    residual_entries: int
    residual_bytes: int
    errors: tuple[str, ...]

    def __bool__(self) -> bool:
        """Preserve the former detach-success truthiness for legacy callers."""

        return self.durably_detached


@dataclasses.dataclass(frozen=True)
class _ImmutableTreeSnapshot:
    """Descriptor-bound identities and digests for one complete tree."""

    entries: tuple[str, ...]
    files: tuple[str, ...]
    identities: dict[str, tuple[int, int, int, int, int, int]]
    digests: dict[str, str]
    bytes_hashed: int


_COPY_CHUNK_SIZE = 1024 * 1024
_COPY_MAX_BYTES = 64 * 1024 * 1024 * 1024
_TEXT_MAX_BYTES = 16 * 1024 * 1024
_TREE_MAX_FILES = 65_536
_TREE_MAX_BYTES = 16 * 1024 * 1024 * 1024
_TREE_MAX_ENTRIES = 65_536
_TREE_MAX_DEPTH = 256
CLEANUP_MAX_ENTRIES = 65_536
CLEANUP_MAX_BYTES = 16 * 1024 * 1024 * 1024
CLEANUP_MAX_DEPTH = 128


def owned_temporary_directory(
    *,
    prefix: str,
    directory: Path | None = None,
    mode: int = 0o700,
    expected_parent_identity: StableParentIdentity | ArtifactIdentity | None = None,
) -> OwnedTemporaryDirectory:
    """Create a random directory descriptor-relatively without following links."""

    _require_safe_leaf_name(f"{prefix}probe")
    parent = Path(
        os.path.abspath(
            directory if directory is not None else tempfile.gettempdir()
        )
    )
    parent_fd = _open_or_create_directory_nofollow(parent)
    descriptor = -1
    name = ""
    created = False
    try:
        parent_anchor = _stable_parent_identity(os.fstat(parent_fd))
        expected_parent = _normalise_expected_parent_identity(
            expected_parent_identity
        )
        if expected_parent is not None and parent_anchor != expected_parent:
            raise ValueError(
                "temporary directory parent differs from its expected identity"
            )
        _require_parent_path_identity(parent, parent_anchor)
        for _ in range(16):
            candidate = f"{prefix}{uuid.uuid4().hex}"
            _require_safe_leaf_name(candidate)
            try:
                os.mkdir(candidate, mode, dir_fd=parent_fd)
            except FileExistsError:
                continue
            name = candidate
            created = True
            break
        if not created:
            raise FileExistsError(
                "could not reserve a unique owned temporary directory"
            )
        descriptor = os.open(
            name,
            _directory_open_flags(),
            dir_fd=parent_fd,
        )
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        os.fsync(parent_fd)
        identity = _stable_parent_identity(os.fstat(descriptor))
        _require_parent_path_identity(parent, parent_anchor)
        _require_named_held_identity(
            parent_fd,
            name,
            descriptor,
            label="owned temporary directory",
        )
        return OwnedTemporaryDirectory(parent / name, identity)
    except BaseException as exc:
        if created and descriptor >= 0:
            try:
                _remove_owned_tree_entry(
                    parent_fd,
                    name,
                    descriptor,
                )
                os.fsync(parent_fd)
            except BaseException as cleanup_exc:
                raise OSError(
                    "owned temporary directory reservation failed and its "
                    f"descriptor-bound quarantine also failed: {cleanup_exc}"
                ) from exc
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_fd)


def ensure_directory_nofollow(path: Path) -> StableParentIdentity:
    """Create missing components and return a no-follow parent receipt."""

    absolute = Path(os.path.abspath(path))
    directory_fd = _open_or_create_directory_nofollow(absolute)
    try:
        identity = _stable_parent_identity(os.fstat(directory_fd))
        _require_parent_path_identity(absolute, identity)
        return identity
    finally:
        os.close(directory_fd)


def entry_exists_nofollow(
    path: Path,
    *,
    expected_parent_identity: StableParentIdentity | ArtifactIdentity,
) -> bool:
    """Inspect one leaf only while its parent still matches a held receipt."""

    absolute = Path(os.path.abspath(path))
    _require_safe_leaf_name(absolute.name)
    parent_fd = _open_directory_nofollow(absolute.parent)
    try:
        expected = _normalise_expected_parent_identity(
            expected_parent_identity
        )
        assert expected is not None
        if _stable_parent_identity(os.fstat(parent_fd)) != expected:
            raise ValueError(
                "entry inspection parent differs from its expected identity"
            )
        try:
            os.stat(
                absolute.name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            exists = False
        else:
            exists = True
        _require_parent_path_identity(absolute.parent, expected)
        return exists
    finally:
        os.close(parent_fd)


def publish_regular_text(
    path: Path,
    content: str,
    *,
    max_bytes: int = _TEXT_MAX_BYTES,
    expected_parent_identity: StableParentIdentity | ArtifactIdentity | None = None,
) -> ImmutableCopyReceipt:
    """Durably create or idempotently reuse one bounded strict-UTF-8 file.

    An existing regular target is accepted only when its stable descriptor-bound
    receipt already equals ``content``.  Different bytes, symlinks, special files,
    and pathname swaps block without moving or deleting the existing entry.
    """

    if max_bytes < 0:
        raise ValueError("regular text publication byte budget must be non-negative")
    try:
        encoded = content.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ValueError("regular text publication is not strict UTF-8") from exc
    if len(encoded) > max_bytes:
        raise ValueError(
            f"regular text publication exceeds its byte budget ({len(encoded)} > {max_bytes})"
        )
    return _publish_regular_bytes(
        path,
        encoded,
        replace=True,
        max_bytes=max_bytes,
        expected_parent_identity=expected_parent_identity,
    )


def stable_parent_identity(path: Path) -> StableParentIdentity:
    """Return the stable owner/type identity accepted by text publication."""

    directory_fd = _open_directory_nofollow(path)
    try:
        return _stable_parent_identity(os.fstat(directory_fd))
    finally:
        os.close(directory_fd)


def _publish_regular_bytes(
    path: Path,
    content: bytes,
    *,
    replace: bool,
    max_bytes: int,
    expected_parent_identity: StableParentIdentity | ArtifactIdentity | None = None,
) -> ImmutableCopyReceipt:
    """Publish bytes from ``O_TMPFILE`` with one no-replace link."""

    if len(content) > max_bytes:
        raise ValueError(
            f"regular publication exceeds its byte budget ({len(content)} > {max_bytes})"
        )
    _require_safe_leaf_name(path.name)
    directory_fd = (
        _open_directory_nofollow(path.parent)
        if expected_parent_identity is not None
        else _open_or_create_directory_nofollow(path.parent)
    )
    try:
        expected_parent = _normalise_expected_parent_identity(expected_parent_identity)
        parent_anchor = _stable_parent_identity(os.fstat(directory_fd))
        if expected_parent is not None and parent_anchor != expected_parent:
            raise ValueError("regular publication parent identity changed before writing")
        _require_parent_path_identity(path.parent, parent_anchor)
    except BaseException:
        os.close(directory_fd)
        raise
    expected = ImmutableCopyReceipt(
        size=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
    )
    temporary_fd = -1
    existing_fd = -1
    published_fd = -1
    try:
        if replace:
            try:
                existing_fd = os.open(
                    path.name,
                    getattr(os, "O_PATH", os.O_RDONLY)
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=directory_fd,
                )
            except FileNotFoundError:
                existing_fd = -1
            if existing_fd >= 0:
                if not stat.S_ISREG(os.fstat(existing_fd).st_mode):
                    raise ValueError("regular text publication can reuse only a regular file")
                existing_identity = _descriptor_identity(os.fstat(existing_fd))
                existing_receipt = _rehash_held_regular_fd(
                    existing_fd,
                    max_bytes=max_bytes,
                    label="existing regular publication target",
                )
                if existing_receipt != expected:
                    raise FileExistsError(
                        "regular publication target already exists with different bytes"
                    )
                _fsync_held_regular_fd(
                    existing_fd,
                    expected_identity=existing_identity,
                    label="existing regular publication target",
                )
                os.fsync(directory_fd)
                _require_parent_path_identity(path.parent, parent_anchor)
                _require_named_held_identity(
                    directory_fd,
                    path.name,
                    existing_fd,
                    label="existing regular publication target",
                )
                if _descriptor_identity(os.fstat(existing_fd)) != existing_identity:
                    raise ValueError(
                        "existing regular publication target changed before receipt"
                    )
                return existing_receipt
        if not hasattr(os, "O_TMPFILE"):
            raise OSError(
                errno.ENOSYS,
                "unnamed immutable publication is unavailable",
            )
        temporary_fd = os.open(
            ".",
            os.O_RDWR | os.O_TMPFILE | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            0o666,
            dir_fd=directory_fd,
        )
        temporary_metadata_contract = _publication_metadata_contract(
            os.fstat(temporary_fd)
        )
        _write_all(temporary_fd, content)
        os.fsync(temporary_fd)
        if (
            _rehash_held_regular_fd(
                temporary_fd,
                max_bytes=max_bytes,
                label="regular publication temporary",
            )
            != expected
        ):
            raise ValueError("regular publication temporary bytes changed")
        if (
            _publication_metadata_contract(os.fstat(temporary_fd))
            != temporary_metadata_contract
        ):
            raise ValueError(
                "regular publication temporary metadata changed before publication"
            )
        _require_parent_path_identity(path.parent, parent_anchor)
        os.link(
            f"/proc/self/fd/{temporary_fd}",
            path.name,
            dst_dir_fd=directory_fd,
            follow_symlinks=True,
        )
        published_fd = os.open(
            path.name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=directory_fd,
        )
        if _descriptor_identity(os.fstat(published_fd)) != _descriptor_identity(
            os.fstat(temporary_fd)
        ):
            raise ValueError("regular publication target is not the held unnamed inode")
        if (
            _publication_metadata_contract(os.fstat(published_fd))
            != temporary_metadata_contract
        ):
            raise ValueError("regular publication target metadata changed during publication")
        final_identity = _descriptor_identity(os.fstat(published_fd))
        _require_named_held_identity(
            directory_fd,
            path.name,
            published_fd,
            label="regular publication target",
        )
        if (
            _rehash_held_regular_fd(
                published_fd,
                max_bytes=max_bytes,
                label="regular publication target",
            )
            != expected
            or _descriptor_identity(os.fstat(published_fd)) != final_identity
            or _publication_metadata_contract(os.fstat(published_fd))
            != temporary_metadata_contract
        ):
            raise ValueError("regular publication target changed before receipt")
        os.fsync(directory_fd)
        if (
            expected_parent is not None
            and _stable_parent_identity(os.fstat(directory_fd)) != expected_parent
        ):
            raise ValueError("regular publication parent identity changed before receipt")
        _require_parent_path_identity(path.parent, parent_anchor)
        _require_named_held_identity(
            directory_fd,
            path.name,
            published_fd,
            label="regular publication target",
        )
        if (
            _publication_metadata_contract(os.fstat(published_fd))
            != temporary_metadata_contract
        ):
            raise ValueError("regular publication target metadata changed before receipt")
        return expected
    except BaseException:
        # Once linked, the immutable target is deliberately retained even when a
        # later sync or identity check fails.  Deleting it by pathname would
        # reopen the substituted-name race this primitive exists to close.
        raise
    finally:
        if published_fd >= 0:
            os.close(published_fd)
        if existing_fd >= 0:
            os.close(existing_fd)
        if temporary_fd >= 0:
            os.close(temporary_fd)
        os.close(directory_fd)


def copy_immutable_file(
    source: Path,
    target: Path,
    *,
    max_bytes: int = _COPY_MAX_BYTES,
    expected_parent_identity: StableParentIdentity | ArtifactIdentity | None = None,
    expected_source_identity: ArtifactIdentity | None = None,
) -> ImmutableCopyReceipt:
    """Durably copy one stable regular-file inode without replacing ``target``.

    Every source path component is opened descriptor-relatively without following
    links.  An ``O_PATH`` descriptor first pins the leaf inode; the readable
    descriptor is then obtained from that pinned object rather than by reopening the
    pathname.  Publication uses a fully written and synced same-directory temporary
    inode plus a no-replace hard link, followed by both directory sync points.
    """
    if max_bytes < 0:
        raise ValueError("immutable copy byte budget must be non-negative")
    source_path_fd = _open_path_nofollow(source, getattr(os, "O_PATH", os.O_RDONLY))
    try:
        directory_fd = (
            _open_directory_nofollow(target.parent)
            if expected_parent_identity is not None
            else _open_or_create_directory_nofollow(target.parent)
        )
        try:
            parent_anchor = _require_expected_parent_identity(
                target.parent,
                directory_fd,
                expected_parent_identity,
            )
            receipt = _copy_immutable_from_path_fd(
                source_path_fd,
                directory_fd,
                target.name,
                max_bytes=max_bytes,
                expected_source_identity=expected_source_identity,
                parent_path=target.parent,
                parent_anchor=parent_anchor,
            )
            return receipt
        finally:
            os.close(directory_fd)
    finally:
        os.close(source_path_fd)


def copy_immutable_file_descriptor(
    source_fd: int,
    target: Path,
    *,
    max_bytes: int = _COPY_MAX_BYTES,
    expected_parent_identity: StableParentIdentity | ArtifactIdentity | None = None,
    expected_source_identity: ArtifactIdentity | None = None,
    idempotent: bool = False,
) -> ImmutableCopyReceipt:
    """Durably publish bytes from an already-held regular-file descriptor.

    The caller's descriptor and file offset are left untouched.  Reading happens
    through a fresh descriptor for the same held inode, and both descriptors are
    revalidated by the common immutable-copy implementation.  With ``idempotent``,
    a no-replace collision is accepted only after the existing regular inode is
    opened without following links, hashed, and proven to remain at the target name.
    """
    if max_bytes < 0:
        raise ValueError("immutable copy byte budget must be non-negative")
    directory_fd = (
        _open_directory_nofollow(target.parent)
        if expected_parent_identity is not None
        else _open_or_create_directory_nofollow(target.parent)
    )
    try:
        parent_anchor = _require_expected_parent_identity(
            target.parent,
            directory_fd,
            expected_parent_identity,
        )
        receipt = _copy_immutable_from_path_fd(
            source_fd,
            directory_fd,
            target.name,
            max_bytes=max_bytes,
            expected_source_identity=expected_source_identity,
            idempotent=idempotent,
            parent_path=target.parent,
            parent_anchor=parent_anchor,
        )
        return receipt
    finally:
        os.close(directory_fd)


def cleanup_owned_tree(
    path: Path,
    expected_identity: StableParentIdentity | ArtifactIdentity,
    *,
    scrub: bool = True,
    max_entries: int = CLEANUP_MAX_ENTRIES,
    max_bytes: int = CLEANUP_MAX_BYTES,
    max_depth: int = CLEANUP_MAX_DEPTH,
) -> CleanupOutcome:
    """Durably detach an owned tree, then scrub and inventory it best-effort.

    Detachment is a small, independent durability transaction.  The exact held
    inode is renamed to an unpredictable no-replace quarantine name, that name is
    verified, the parent is synced immediately, and the old operational name is
    proven absent through the still-anchored parent.  Only then may content
    scrubbing begin.

    Scrubbing never follows symlinks and never truncates a regular inode whose
    link count is not exactly one.  Entry, byte and recursion budgets are explicit.
    Failures are accumulated while safe siblings continue, and a separate terminal
    descriptor-relative inventory reports what remains.  The quarantine is never
    physically removed because POSIX has no unlink-by-held-descriptor primitive.
    """

    if max_entries < 0 or max_bytes < 0 or max_depth < 0:
        raise ValueError("cleanup budgets must be non-negative")
    errors: list[str] = []
    try:
        absolute = Path(os.path.abspath(path))
        _require_safe_leaf_name(absolute.name)
        parent_fd = _open_directory_nofollow(absolute.parent)
    except (OSError, RuntimeError, ValueError) as exc:
        return CleanupOutcome(
            durably_detached=False,
            scrub_complete=False,
            residual_entries=0,
            residual_bytes=0,
            errors=(_cleanup_error("workspace could not be anchored", exc),),
        )
    tree_fd = -1
    try:
        parent_anchor = _stable_parent_identity(os.fstat(parent_fd))
        try:
            _require_parent_path_identity(absolute.parent, parent_anchor)
        except (OSError, ValueError) as exc:
            return CleanupOutcome(
                False,
                False,
                0,
                0,
                (_cleanup_error("workspace parent changed before detach", exc),),
            )
        try:
            tree_fd = os.open(
                absolute.name,
                _directory_open_flags(),
                dir_fd=parent_fd,
            )
        except (OSError, ValueError) as exc:
            return CleanupOutcome(
                False,
                False,
                0,
                0,
                (_cleanup_error("workspace name could not be held", exc),),
            )
        try:
            expected = _normalise_expected_parent_identity(expected_identity)
        except ValueError as exc:
            return CleanupOutcome(False, False, 0, 0, (str(exc),))
        assert expected is not None
        current = _stable_parent_identity(os.fstat(tree_fd))
        if current[:5] != expected[:5] or current[6] != expected[6]:
            return CleanupOutcome(
                False,
                False,
                0,
                0,
                ("workspace name identifies a missing or substituted inode",),
            )
        try:
            _require_parent_path_identity(absolute.parent, parent_anchor)
        except (OSError, ValueError) as exc:
            return CleanupOutcome(
                False,
                False,
                0,
                0,
                (_cleanup_error("workspace parent changed before detach", exc),),
            )
        quarantine_name = f".{absolute.name}.cleanup-{uuid.uuid4().hex}"
        try:
            _rename_directory_noreplace(
                parent_fd,
                absolute.name,
                quarantine_name,
            )
            _require_named_held_identity(
                parent_fd,
                quarantine_name,
                tree_fd,
                label="owned cleanup quarantine",
            )
            # The rename is made durable before any potentially long scrub.
            os.fsync(parent_fd)
            try:
                os.stat(
                    absolute.name,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            else:
                raise ValueError(
                    "operational workspace name still exists after quarantine rename"
                )
            if not _anchored_parent_leaf_absent(
                absolute.parent,
                parent_anchor,
                absolute.name,
            ):
                raise ValueError(
                    "operational workspace absence could not be proven through "
                    "its anchored parent"
                )
        except (OSError, RuntimeError, ValueError) as exc:
            return CleanupOutcome(
                False,
                False,
                0,
                0,
                (_cleanup_error("workspace detach was not durably proven", exc),),
            )

        if scrub:
            scrub_state = _CleanupTraversalState(
                max_entries=max_entries,
                max_bytes=max_bytes,
                max_depth=max_depth,
            )
            _scrub_owned_tree_best_effort(tree_fd, scrub_state, depth=0)
            errors.extend(scrub_state.errors)

        inventory = _CleanupTraversalState(
            max_entries=max_entries,
            max_bytes=max_bytes,
            max_depth=max_depth,
        )
        _inventory_owned_tree(tree_fd, inventory, depth=0)
        errors.extend(inventory.errors)
        try:
            _require_named_held_identity(
                parent_fd,
                quarantine_name,
                tree_fd,
                label="owned cleanup terminal quarantine",
            )
        except (OSError, ValueError) as exc:
            _record_cleanup_error(
                errors,
                _cleanup_error("terminal quarantine identity changed", exc),
            )
        scrub_complete = (
            scrub
            and not errors
            and inventory.complete
            and inventory.bytes_seen == 0
        )
        return CleanupOutcome(
            durably_detached=True,
            scrub_complete=scrub_complete,
            residual_entries=inventory.entries_seen,
            residual_bytes=inventory.bytes_seen,
            errors=tuple(errors),
        )
    finally:
        if tree_fd >= 0:
            os.close(tree_fd)
        os.close(parent_fd)


def copy_immutable_tree(
    source: Path,
    target: Path,
    *,
    expected_parent_identity: StableParentIdentity | ArtifactIdentity | None = None,
    expected_source_identity: ArtifactIdentity | None = None,
    expected_source_inventory: Mapping[str, ArtifactIdentity] | None = None,
    max_files: int = _TREE_MAX_FILES,
    max_bytes: int = _TREE_MAX_BYTES,
    max_entries: int = _TREE_MAX_ENTRIES,
    max_depth: int = _TREE_MAX_DEPTH,
) -> ImmutableTreeCopyReceipt:
    """Copy a bounded regular-file tree using held source and target directories.

    Symlinks and every non-regular, non-directory entry are refused.  Each file gets
    the same durable no-replace publication as :func:`copy_immutable_file`; directory
    descriptors are revalidated after traversal so a concurrent mutation blocks the
    operation instead of being silently omitted.
    """
    if max_files < 0 or max_bytes < 0 or max_entries < 0 or max_depth < 0:
        raise ValueError("immutable tree copy budgets must be non-negative")
    source_fd = _open_path_nofollow(
        source,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        target_parent_fd = (
            _open_directory_nofollow(target.parent)
            if expected_parent_identity is not None
            else _open_or_create_directory_nofollow(target.parent)
        )
    except BaseException:
        os.close(source_fd)
        raise
    target_fd = -1
    temporary_name = f".{target.name}.tmp-{uuid.uuid4().hex}"
    temporary_created = False
    published = False
    try:
        target_parent_anchor = _require_expected_parent_identity(
            target.parent,
            target_parent_fd,
            expected_parent_identity,
        )
        source_identity = ArtifactIdentity.from_stat(os.fstat(source_fd))
        if not stat.S_ISDIR(source_identity.mode):
            raise ValueError(f"immutable tree source is not a directory: {source}")
        if (
            expected_source_identity is not None
            and source_identity != expected_source_identity
        ):
            raise ValueError(
                "immutable tree source identity differs from the expected verdict"
            )
        opening_inventory: dict[str, ArtifactIdentity] = {}
        _inspect_immutable_tree(
            source_fd,
            (),
            [0, 0, 0],
            opening_inventory,
            max_files=max_files,
            max_bytes=max_bytes,
            max_entries=max_entries,
            max_depth=max_depth,
        )
        if ArtifactIdentity.from_stat(os.fstat(source_fd)) != source_identity:
            raise ValueError("immutable tree source changed during preflight")
        if expected_source_inventory is not None:
            expected_inventory = dict(expected_source_inventory)
        else:
            expected_inventory = None
        if (
            expected_inventory is not None
            and opening_inventory != expected_inventory
        ):
            actual_names = set(opening_inventory)
            expected_names = set(expected_inventory)
            unexpected = sorted(actual_names - expected_names)
            missing = sorted(expected_names - actual_names)
            changed = sorted(
                name
                for name in actual_names & expected_names
                if opening_inventory[name] != expected_inventory[name]
            )
            raise ValueError(
                "immutable tree source inventory differs from the expected verdict "
                f"(unexpected={unexpected}, missing={missing}, changed={changed})"
            )
        _require_safe_leaf_name(target.name)
        os.mkdir(temporary_name, 0o755, dir_fd=target_parent_fd)
        temporary_created = True
        os.fsync(target_parent_fd)
        target_fd = os.open(
            temporary_name,
            _directory_open_flags(),
            dir_fd=target_parent_fd,
        )
        target_metadata_contract = _publication_metadata_contract(
            os.fstat(target_fd)
        )
        files: list[str] = []
        copied_digests: dict[str, str] = {}
        seen_entries: set[str] = set()
        counters = [0, 0, 0]
        _copy_immutable_tree_directory(
            source_fd,
            target_fd,
            (),
            files,
            copied_digests,
            seen_entries,
            counters,
            opening_inventory,
            max_files=max_files,
            max_bytes=max_bytes,
            max_entries=max_entries,
            max_depth=max_depth,
        )
        if seen_entries != set(opening_inventory):
            raise ValueError("immutable tree changed between preflight and copy")
        if ArtifactIdentity.from_stat(os.fstat(source_fd)) != source_identity:
            raise ValueError("immutable tree source changed during copy")
        os.fsync(target_fd)
        staged_snapshot = _capture_immutable_tree_snapshot(
            target_fd,
            max_files=max_files,
            max_bytes=max_bytes,
            max_entries=max_entries,
            max_depth=max_depth,
            sync=True,
        )
        if (
            staged_snapshot.files != tuple(files)
            or staged_snapshot.bytes_hashed != counters[1]
            or staged_snapshot.digests != copied_digests
        ):
            raise ValueError("immutable staged tree differs from the completed copy receipt")
        if (
            _publication_metadata_contract(os.fstat(target_fd))
            != target_metadata_contract
        ):
            raise ValueError("immutable staged tree metadata changed before publication")
        _rename_directory_noreplace(
            target_parent_fd,
            temporary_name,
            target.name,
        )
        temporary_created = False
        published = True
        target_identity = _descriptor_identity(os.fstat(target_fd))
        published_fd = os.open(
            target.name,
            _directory_open_flags(),
            dir_fd=target_parent_fd,
        )
        try:
            if _descriptor_identity(os.fstat(published_fd)) != target_identity:
                raise ValueError("immutable tree publication did not preserve the staged directory")
            if (
                _publication_metadata_contract(os.fstat(published_fd))
                != target_metadata_contract
            ):
                raise ValueError("immutable tree publication changed staged directory metadata")
        finally:
            os.close(published_fd)
        published_snapshot = _capture_immutable_tree_snapshot(
            target_fd,
            max_files=max_files,
            max_bytes=max_bytes,
            max_entries=max_entries,
            max_depth=max_depth,
            sync=False,
        )
        if published_snapshot != staged_snapshot:
            raise ValueError("immutable staged tree content changed during directory publication")
        os.fsync(target_parent_fd)
        receipt_identity = full_filesystem_identity(os.fstat(target_fd))
        if (
            _publication_metadata_contract(os.fstat(target_fd))
            != target_metadata_contract
        ):
            raise ValueError("immutable published tree metadata changed before receipt")
        _require_parent_path_identity(target.parent, target_parent_anchor)
        _require_named_held_full_identity(
            target_parent_fd,
            target.name,
            target_fd,
            expected=receipt_identity,
            label="immutable published tree",
        )
        return ImmutableTreeCopyReceipt(
            tuple(files),
            counters[1],
            tuple(sorted(copied_digests.items())),
            receipt_identity,
            stable_identity_from_full(receipt_identity),
        )
    except BaseException as exc:
        if published:
            try:
                _rollback_owned_tree_publication(
                    target_parent_fd,
                    target.name,
                    target_fd,
                    preserve_as=temporary_name,
                )
                os.fsync(target_parent_fd)
            except BaseException as cleanup_exc:
                raise OSError(
                    "immutable published tree rollback failed after publication "
                    f"error: {cleanup_exc}"
                ) from exc
        elif temporary_created:
            try:
                _remove_owned_tree_entry(
                    target_parent_fd,
                    temporary_name,
                    target_fd,
                )
                os.fsync(target_parent_fd)
            except BaseException as cleanup_exc:
                raise OSError(
                    f"immutable tree staging cleanup failed after publication error: {cleanup_exc}"
                ) from exc
        raise
    finally:
        if target_fd >= 0:
            os.close(target_fd)
        os.close(target_parent_fd)
        os.close(source_fd)


def publish_immutable_tree(
    staging: Path,
    target: Path,
    *,
    expected_files: Iterable[str] | None = None,
    expected_digests: Mapping[str, str] | None = None,
    expected_staging_identity: StableParentIdentity | ArtifactIdentity | None = None,
    max_files: int = _TREE_MAX_FILES,
    max_bytes: int = _TREE_MAX_BYTES,
    max_entries: int = _TREE_MAX_ENTRIES,
    max_depth: int = _TREE_MAX_DEPTH,
) -> ImmutableTreeCopyReceipt:
    """Durably publish a complete neighbouring tree without replacing ``target``.

    ``staging`` must be a sibling of ``target``.  Every contained inode is synced
    and revalidated descriptor-relatively before the Linux no-replace rename.  The
    caller retains ownership of the staging path when publication fails.
    """
    if max_files < 0 or max_bytes < 0 or max_entries < 0 or max_depth < 0:
        raise ValueError("immutable tree publication budgets must be non-negative")
    expected_digest_contract = (
        _expected_tree_digests(expected_digests) if expected_digests is not None else None
    )
    if expected_digest_contract is not None and len(expected_digest_contract) > max_files:
        raise ValueError("immutable publication digest contract exceeds its file budget")
    staging_absolute = Path(os.path.abspath(staging))
    target_absolute = Path(os.path.abspath(target))
    if staging_absolute.parent != target_absolute.parent:
        raise ValueError("immutable tree staging must be a sibling of its target")
    _require_safe_leaf_name(staging_absolute.name)
    _require_safe_leaf_name(target_absolute.name)
    parent_fd = _open_directory_nofollow(target_absolute.parent)
    staging_fd = -1
    published = False
    try:
        parent_anchor = _require_expected_parent_identity(
            target_absolute.parent,
            parent_fd,
            None,
        )
        staging_fd = os.open(
            staging_absolute.name,
            _directory_open_flags(),
            dir_fd=parent_fd,
        )
        expected_staging = _normalise_expected_parent_identity(expected_staging_identity)
        if (
            expected_staging is not None
            and _stable_parent_identity(os.fstat(staging_fd)) != expected_staging
        ):
            raise ValueError("immutable staging tree differs from its ownership receipt")
        opening_identity = _descriptor_identity(os.fstat(staging_fd))
        staging_metadata_contract = _publication_metadata_contract(
            os.fstat(staging_fd)
        )
        staged_snapshot = _capture_immutable_tree_snapshot(
            staging_fd,
            max_files=max_files,
            max_bytes=max_bytes,
            max_entries=max_entries,
            max_depth=max_depth,
            sync=True,
        )
        expected = _expected_tree_entries(expected_files) if expected_files is not None else None
        if expected is not None and set(staged_snapshot.entries) != expected:
            unexpected = sorted(set(staged_snapshot.entries) - expected)
            missing = sorted(expected - set(staged_snapshot.entries))
            raise ValueError(
                "immutable staging tree differs from its publication contract "
                f"(unexpected={unexpected}, missing={missing})"
            )
        if (
            expected_digest_contract is not None
            and staged_snapshot.digests != expected_digest_contract
        ):
            staged_names = set(staged_snapshot.digests)
            expected_names = set(expected_digest_contract)
            unexpected = sorted(staged_names - expected_names)
            missing = sorted(expected_names - staged_names)
            changed = sorted(
                name
                for name in staged_names & expected_names
                if staged_snapshot.digests[name] != expected_digest_contract[name]
            )
            raise ValueError(
                "immutable staging tree differs from its digest contract "
                f"(unexpected={unexpected}, missing={missing}, changed={changed})"
            )
        if _descriptor_identity(os.fstat(staging_fd)) != opening_identity:
            raise ValueError("immutable staging tree changed before publication")
        _rename_directory_noreplace(
            parent_fd,
            staging_absolute.name,
            target_absolute.name,
        )
        published = True
        published_fd = os.open(
            target_absolute.name,
            _directory_open_flags(),
            dir_fd=parent_fd,
        )
        try:
            if not _same_inode_kind(
                _descriptor_identity(os.fstat(published_fd)),
                opening_identity,
            ):
                raise ValueError("immutable tree publication changed the staged directory identity")
            if (
                _publication_metadata_contract(os.fstat(published_fd))
                != staging_metadata_contract
            ):
                raise ValueError("immutable tree publication changed staged directory metadata")
        finally:
            os.close(published_fd)
        published_snapshot = _capture_immutable_tree_snapshot(
            staging_fd,
            max_files=max_files,
            max_bytes=max_bytes,
            max_entries=max_entries,
            max_depth=max_depth,
            sync=False,
        )
        if published_snapshot != staged_snapshot:
            raise ValueError("immutable staging tree content changed during directory publication")
        os.fsync(parent_fd)
        target_identity = full_filesystem_identity(os.fstat(staging_fd))
        if (
            _publication_metadata_contract(os.fstat(staging_fd))
            != staging_metadata_contract
        ):
            raise ValueError("immutable published tree metadata changed before receipt")
        _require_parent_path_identity(target_absolute.parent, parent_anchor)
        _require_named_held_full_identity(
            parent_fd,
            target_absolute.name,
            staging_fd,
            expected=target_identity,
            label="immutable published tree",
        )
        return ImmutableTreeCopyReceipt(
            staged_snapshot.files,
            staged_snapshot.bytes_hashed,
            tuple(sorted(staged_snapshot.digests.items())),
            target_identity,
            stable_identity_from_full(target_identity),
        )
    except BaseException as exc:
        if published:
            try:
                _rollback_owned_tree_publication(
                    parent_fd,
                    target_absolute.name,
                    staging_fd,
                    preserve_as=staging_absolute.name,
                )
                os.fsync(parent_fd)
            except BaseException as cleanup_exc:
                raise OSError(
                    f"immutable staged tree rollback failed after publication error: {cleanup_exc}"
                ) from exc
        raise
    finally:
        if staging_fd >= 0:
            os.close(staging_fd)
        os.close(parent_fd)


def _inspect_immutable_tree(
    source_directory_fd: int,
    relative_parent: tuple[str, ...],
    counters: list[int],
    inventory: dict[str, ArtifactIdentity],
    *,
    max_files: int,
    max_bytes: int,
    max_entries: int,
    max_depth: int,
) -> None:
    """Reject unsafe entries and exhausted budgets before creating a target tree."""
    opening_identity = ArtifactIdentity.from_stat(os.fstat(source_directory_fd))
    names = _bounded_directory_names(
        source_directory_fd,
        counters,
        max_entries=max_entries,
        label="immutable tree preflight",
    )
    for name in names:
        entry_stat = os.stat(
            name,
            dir_fd=source_directory_fd,
            follow_symlinks=False,
        )
        entry_identity = ArtifactIdentity.from_stat(entry_stat)
        relative = (*relative_parent, name)
        _require_tree_depth(
            relative,
            max_depth=max_depth,
            label="immutable tree preflight",
        )
        relative_name = "/".join(relative)
        inventory[relative_name] = entry_identity
        if stat.S_ISDIR(entry_identity.mode):
            child_fd = os.open(
                name,
                _directory_open_flags(),
                dir_fd=source_directory_fd,
            )
            try:
                if ArtifactIdentity.from_stat(os.fstat(child_fd)) != entry_identity:
                    raise ValueError(
                        f"immutable tree directory changed during preflight: {'/'.join(relative)}"
                    )
                _inspect_immutable_tree(
                    child_fd,
                    relative,
                    counters,
                    inventory,
                    max_files=max_files,
                    max_bytes=max_bytes,
                    max_entries=max_entries,
                    max_depth=max_depth,
                )
            finally:
                os.close(child_fd)
            continue
        if not stat.S_ISREG(entry_stat.st_mode):
            raise ValueError(f"immutable tree contains a non-regular entry: {'/'.join(relative)}")
        path_fd = os.open(
            name,
            getattr(os, "O_PATH", os.O_RDONLY)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=source_directory_fd,
        )
        try:
            if ArtifactIdentity.from_stat(os.fstat(path_fd)) != entry_identity:
                raise ValueError(
                    f"immutable tree file changed during preflight: {'/'.join(relative)}"
                )
        finally:
            os.close(path_fd)
        counters[0] += 1
        counters[1] += entry_identity.size
        if counters[0] > max_files or counters[1] > max_bytes:
            raise ValueError(
                f"immutable tree exceeds its copy budget ({counters[0]} files, {counters[1]} bytes)"
            )
    if ArtifactIdentity.from_stat(os.fstat(source_directory_fd)) != opening_identity:
        raise ValueError(
            f"immutable tree directory changed during preflight: {'/'.join(relative_parent) or '.'}"
        )


def _sync_immutable_tree_directory(
    directory_fd: int,
    relative_parent: tuple[str, ...],
    files: list[str],
    entries: list[str],
    counters: list[int],
    *,
    max_files: int,
    max_bytes: int,
    max_entries: int,
    max_depth: int,
) -> None:
    """Sync and revalidate a complete regular-file tree descriptor-relatively."""
    opening_identity = _descriptor_identity(os.fstat(directory_fd))
    names = _bounded_directory_names(
        directory_fd,
        counters,
        max_entries=max_entries,
        label="immutable staging tree",
    )
    for name in names:
        entry_stat = os.stat(
            name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        entry_identity = _descriptor_identity(entry_stat)
        relative = (*relative_parent, name)
        _require_tree_depth(
            relative,
            max_depth=max_depth,
            label="immutable staging tree",
        )
        entries.append("/".join(relative))
        if stat.S_ISDIR(entry_stat.st_mode):
            child_fd = os.open(
                name,
                _directory_open_flags(),
                dir_fd=directory_fd,
            )
            try:
                if _descriptor_identity(os.fstat(child_fd)) != entry_identity:
                    raise ValueError(
                        f"immutable staging directory changed while opening: {'/'.join(relative)}"
                    )
                _sync_immutable_tree_directory(
                    child_fd,
                    relative,
                    files,
                    entries,
                    counters,
                    max_files=max_files,
                    max_bytes=max_bytes,
                    max_entries=max_entries,
                    max_depth=max_depth,
                )
                if _descriptor_identity(os.fstat(child_fd)) != entry_identity:
                    raise ValueError(
                        f"immutable staging directory changed while syncing: {'/'.join(relative)}"
                    )
            finally:
                os.close(child_fd)
            continue
        if not stat.S_ISREG(entry_stat.st_mode):
            raise ValueError(
                f"immutable staging tree contains a non-regular entry: {'/'.join(relative)}"
            )
        counters[0] += 1
        counters[1] += entry_stat.st_size
        if counters[0] > max_files or counters[1] > max_bytes:
            raise ValueError(
                "immutable staging tree exceeds its publication budget "
                f"({counters[0]} files, {counters[1]} bytes)"
            )
        file_fd = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=directory_fd,
        )
        try:
            if _descriptor_identity(os.fstat(file_fd)) != entry_identity:
                raise ValueError(
                    f"immutable staging file changed while opening: {'/'.join(relative)}"
                )
            os.fsync(file_fd)
            if _descriptor_identity(os.fstat(file_fd)) != entry_identity:
                raise ValueError(
                    f"immutable staging file changed while syncing: {'/'.join(relative)}"
                )
        finally:
            os.close(file_fd)
        files.append("/".join(relative))
    os.fsync(directory_fd)
    if _descriptor_identity(os.fstat(directory_fd)) != opening_identity:
        raise ValueError(
            f"immutable staging directory changed while syncing: {'/'.join(relative_parent) or '.'}"
        )


def _capture_immutable_tree_snapshot(
    directory_fd: int,
    *,
    max_files: int,
    max_bytes: int,
    max_entries: int,
    max_depth: int,
    sync: bool,
) -> _ImmutableTreeSnapshot:
    """Hash a bounded tree through held descriptors and revalidate every inode."""

    files: list[str] = []
    entries: list[str] = []
    identities: dict[str, tuple[int, int, int, int, int, int]] = {}
    digests: dict[str, str] = {}
    counters = [0, 0, 0]
    _capture_immutable_tree_directory(
        directory_fd,
        (),
        files,
        entries,
        identities,
        digests,
        counters,
        max_files=max_files,
        max_bytes=max_bytes,
        max_entries=max_entries,
        max_depth=max_depth,
        sync=sync,
    )
    return _ImmutableTreeSnapshot(
        entries=tuple(entries),
        files=tuple(files),
        identities=identities,
        digests=digests,
        bytes_hashed=counters[1],
    )


def _capture_immutable_tree_directory(
    directory_fd: int,
    relative_parent: tuple[str, ...],
    files: list[str],
    entries: list[str],
    identities: dict[str, tuple[int, int, int, int, int, int]],
    digests: dict[str, str],
    counters: list[int],
    *,
    max_files: int,
    max_bytes: int,
    max_entries: int,
    max_depth: int,
    sync: bool,
) -> None:
    opening_identity = _descriptor_identity(os.fstat(directory_fd))
    names = _bounded_directory_names(
        directory_fd,
        counters,
        max_entries=max_entries,
        label="immutable staging snapshot",
    )
    for name in names:
        entry_identity = _descriptor_identity(
            os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        )
        relative = (*relative_parent, name)
        _require_tree_depth(
            relative,
            max_depth=max_depth,
            label="immutable staging snapshot",
        )
        relative_name = "/".join(relative)
        entries.append(relative_name)
        identities[relative_name] = entry_identity
        if stat.S_ISDIR(entry_identity[2]):
            child_fd = os.open(name, _directory_open_flags(), dir_fd=directory_fd)
            try:
                if _descriptor_identity(os.fstat(child_fd)) != entry_identity:
                    raise ValueError(
                        f"immutable staging directory changed while opening: {relative_name}"
                    )
                _capture_immutable_tree_directory(
                    child_fd,
                    relative,
                    files,
                    entries,
                    identities,
                    digests,
                    counters,
                    max_files=max_files,
                    max_bytes=max_bytes,
                    max_entries=max_entries,
                    max_depth=max_depth,
                    sync=sync,
                )
                if sync:
                    os.fsync(child_fd)
                if _descriptor_identity(os.fstat(child_fd)) != entry_identity:
                    raise ValueError(
                        f"immutable staging directory changed while hashing: {relative_name}"
                    )
            finally:
                os.close(child_fd)
            continue
        if not stat.S_ISREG(entry_identity[2]):
            raise ValueError(
                f"immutable staging tree contains a non-regular entry: {relative_name}"
            )
        counters[0] += 1
        counters[1] += entry_identity[3]
        if counters[0] > max_files or counters[1] > max_bytes:
            raise ValueError(
                "immutable staging tree exceeds its snapshot budget "
                f"({counters[0]} files, {counters[1]} bytes)"
            )
        file_fd = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=directory_fd,
        )
        try:
            if _descriptor_identity(os.fstat(file_fd)) != entry_identity:
                raise ValueError(f"immutable staging file changed while opening: {relative_name}")
            if sync:
                os.fsync(file_fd)
            receipt = _rehash_held_regular_fd(
                file_fd,
                max_bytes=entry_identity[3],
                label=f"immutable staging file {relative_name}",
            )
            if receipt.size != entry_identity[3]:
                raise ValueError(f"immutable staging file changed while hashing: {relative_name}")
            if _descriptor_identity(os.fstat(file_fd)) != entry_identity:
                raise ValueError(f"immutable staging file changed while hashing: {relative_name}")
        finally:
            os.close(file_fd)
        files.append(relative_name)
        digests[relative_name] = receipt.sha256
    if sync:
        os.fsync(directory_fd)
    if _descriptor_identity(os.fstat(directory_fd)) != opening_identity:
        raise ValueError(
            f"immutable staging directory changed while hashing: {'/'.join(relative_parent) or '.'}"
        )


def _copy_immutable_tree_directory(
    source_directory_fd: int,
    target_directory_fd: int,
    relative_parent: tuple[str, ...],
    files: list[str],
    copied_digests: dict[str, str],
    seen_entries: set[str],
    counters: list[int],
    expected_inventory: dict[str, ArtifactIdentity],
    *,
    max_files: int,
    max_bytes: int,
    max_entries: int,
    max_depth: int,
) -> None:
    opening_identity = ArtifactIdentity.from_stat(os.fstat(source_directory_fd))
    names = _bounded_directory_names(
        source_directory_fd,
        counters,
        max_entries=max_entries,
        label="immutable tree copy",
    )
    for name in names:
        entry_stat = os.stat(
            name,
            dir_fd=source_directory_fd,
            follow_symlinks=False,
        )
        entry_identity = ArtifactIdentity.from_stat(entry_stat)
        relative = (*relative_parent, name)
        _require_tree_depth(
            relative,
            max_depth=max_depth,
            label="immutable tree copy",
        )
        relative_name = "/".join(relative)
        if expected_inventory.get(relative_name) != entry_identity:
            raise ValueError(f"immutable tree entry changed after preflight: {relative_name}")
        seen_entries.add(relative_name)
        if stat.S_ISDIR(entry_identity.mode):
            source_child_fd = os.open(
                name,
                _directory_open_flags(),
                dir_fd=source_directory_fd,
            )
            if ArtifactIdentity.from_stat(os.fstat(source_child_fd)) != entry_identity:
                os.close(source_child_fd)
                raise ValueError(
                    f"immutable tree directory changed while opening: {'/'.join(relative)}"
                )
            os.mkdir(name, 0o755, dir_fd=target_directory_fd)
            target_child_fd = os.open(
                name,
                _directory_open_flags(),
                dir_fd=target_directory_fd,
            )
            try:
                _copy_immutable_tree_directory(
                    source_child_fd,
                    target_child_fd,
                    relative,
                    files,
                    copied_digests,
                    seen_entries,
                    counters,
                    expected_inventory,
                    max_files=max_files,
                    max_bytes=max_bytes,
                    max_entries=max_entries,
                    max_depth=max_depth,
                )
                os.fsync(target_child_fd)
                os.fsync(target_directory_fd)
            finally:
                os.close(target_child_fd)
                os.close(source_child_fd)
            continue
        if not stat.S_ISREG(entry_identity.mode):
            raise ValueError(f"immutable tree contains a non-regular entry: {'/'.join(relative)}")
        counters[0] += 1
        counters[1] += entry_identity.size
        if counters[0] > max_files or counters[1] > max_bytes:
            raise ValueError(
                f"immutable tree exceeds its copy budget ({counters[0]} files, {counters[1]} bytes)"
            )
        source_path_fd = os.open(
            name,
            getattr(os, "O_PATH", os.O_RDONLY)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=source_directory_fd,
        )
        try:
            if ArtifactIdentity.from_stat(os.fstat(source_path_fd)) != entry_identity:
                raise ValueError(f"immutable tree file changed while opening: {'/'.join(relative)}")
            receipt = _copy_immutable_from_path_fd(
                source_path_fd,
                target_directory_fd,
                name,
                max_bytes=max_bytes,
                expected_source_identity=entry_identity,
            )
        finally:
            os.close(source_path_fd)
        if receipt.size != entry_identity.size:
            raise ValueError(f"immutable tree file changed while copying: {'/'.join(relative)}")
        copied_name = "/".join(relative)
        files.append(copied_name)
        copied_digests[copied_name] = receipt.sha256
    if ArtifactIdentity.from_stat(os.fstat(source_directory_fd)) != opening_identity:
        raise ValueError(
            f"immutable tree directory changed during traversal: {'/'.join(relative_parent) or '.'}"
        )


def _copy_immutable_from_path_fd(
    source_path_fd: int,
    directory_fd: int,
    target_name: str,
    *,
    max_bytes: int = _COPY_MAX_BYTES,
    expected_source_identity: ArtifactIdentity | None = None,
    idempotent: bool = False,
    parent_path: Path | None = None,
    parent_anchor: StableParentIdentity | None = None,
) -> ImmutableCopyReceipt:
    source_stat = os.fstat(source_path_fd)
    source_before = _descriptor_identity(source_stat)
    source_full_before = ArtifactIdentity.from_stat(source_stat)
    target_mode_contract = _immutable_copy_mode_contract(source_stat)
    if not stat.S_ISREG(source_before[2]):
        raise ValueError("immutable copy source must be a regular file")
    if (
        expected_source_identity is not None
        and source_full_before != expected_source_identity
    ):
        raise ValueError(
            "immutable copy source identity differs from the expected verdict"
        )
    if max_bytes < 0:
        raise ValueError("immutable copy byte budget must be non-negative")
    if source_before[3] > max_bytes:
        raise ValueError(
            f"immutable copy source exceeds its byte budget ({source_before[3]} > {max_bytes})"
        )
    readable_fd = os.open(
        f"/proc/self/fd/{source_path_fd}",
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0),
    )
    temporary_fd = -1
    published_fd = -1
    try:
        if ArtifactIdentity.from_stat(os.fstat(readable_fd)) != source_full_before:
            raise ValueError("immutable copy source changed while acquiring its read FD")
        if not hasattr(os, "O_TMPFILE"):
            raise OSError(
                errno.ENOSYS,
                "unnamed immutable copy staging is unavailable",
            )
        temporary_fd = os.open(
            ".",
            os.O_RDWR | os.O_TMPFILE | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            stat.S_IMODE(source_before[2]) & 0o777,
            dir_fd=directory_fd,
        )
        os.fchmod(temporary_fd, stat.S_IMODE(source_before[2]) & 0o777)
        if _immutable_copy_mode_contract(os.fstat(temporary_fd)) != target_mode_contract:
            raise ValueError("immutable copy temporary has unexpected permissions")
        digest = hashlib.sha256()
        size = 0
        remaining = source_before[3]
        while remaining:
            chunk = os.read(readable_fd, min(_COPY_CHUNK_SIZE, remaining))
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
            remaining -= len(chunk)
            _write_all(temporary_fd, chunk)
        if os.read(readable_fd, 1):
            raise ValueError("immutable copy source grew while it was read")
        os.fsync(temporary_fd)
        temporary_identity = os.fstat(temporary_fd)
        source_after = ArtifactIdentity.from_stat(os.fstat(readable_fd))
        if (
            source_after != source_full_before
            or ArtifactIdentity.from_stat(os.fstat(source_path_fd))
            != source_full_before
            or size != source_before[3]
        ):
            raise ValueError("immutable copy source changed while it was read")
        if temporary_identity.st_size != size:
            raise OSError("immutable copy temporary size does not match written bytes")
        expected_receipt = ImmutableCopyReceipt(
            size=size,
            sha256=digest.hexdigest(),
        )
        if (
            _rehash_held_regular_fd(
                temporary_fd,
                max_bytes=max_bytes,
                label="immutable copy temporary",
            )
            != expected_receipt
        ):
            raise ValueError("immutable copy temporary differs from the copied source bytes")
        if _immutable_copy_mode_contract(os.fstat(temporary_fd)) != target_mode_contract:
            raise ValueError("immutable copy temporary permissions changed before publication")
        try:
            os.link(
                f"/proc/self/fd/{temporary_fd}",
                target_name,
                dst_dir_fd=directory_fd,
                follow_symlinks=True,
            )
        except FileExistsError as collision:
            if not idempotent:
                raise
            existing_fd = os.open(
                target_name,
                getattr(os, "O_PATH", os.O_RDONLY)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_fd,
            )
            try:
                existing_identity = _descriptor_identity(os.fstat(existing_fd))
                existing_receipt = _rehash_held_regular_fd(
                    existing_fd,
                    max_bytes=max_bytes,
                    label="existing immutable copy target",
                )
                _require_named_held_identity(
                    directory_fd,
                    target_name,
                    existing_fd,
                    label="existing immutable copy target",
                )
                if (
                    ArtifactIdentity.from_stat(os.fstat(readable_fd))
                    != source_full_before
                    or ArtifactIdentity.from_stat(os.fstat(source_path_fd))
                    != source_full_before
                ):
                    raise ValueError(
                        "immutable copy source changed while validating an idempotent target"
                    )
                if existing_receipt != expected_receipt:
                    raise FileExistsError(
                        "immutable copy target already exists with different bytes"
                    ) from collision
                if (
                    _immutable_copy_mode_contract(os.fstat(existing_fd))
                    != target_mode_contract
                ):
                    raise FileExistsError(
                        "immutable copy target already exists with different permissions"
                    ) from collision
                _fsync_held_regular_fd(
                    existing_fd,
                    expected_identity=existing_identity,
                    label="existing immutable copy target",
                )
                os.fsync(directory_fd)
                if parent_path is not None:
                    assert parent_anchor is not None
                    _require_parent_path_identity(parent_path, parent_anchor)
                _require_named_held_identity(
                    directory_fd,
                    target_name,
                    existing_fd,
                    label="existing immutable copy target",
                )
                if _descriptor_identity(os.fstat(existing_fd)) != existing_identity:
                    raise ValueError(
                        "existing immutable copy target changed before receipt"
                    )
                return existing_receipt
            finally:
                os.close(existing_fd)
        published_fd = os.open(
            target_name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=directory_fd,
        )
        published_identity = _descriptor_identity(os.fstat(published_fd))
        if published_identity != _descriptor_identity(os.fstat(temporary_fd)):
            raise ValueError("immutable copy target is not the held unnamed inode")
        if (
            _immutable_copy_mode_contract(os.fstat(published_fd))
            != target_mode_contract
        ):
            raise ValueError("immutable copy target permissions changed during publication")
        if (
            _rehash_held_regular_fd(
                temporary_fd,
                max_bytes=max_bytes,
                label="immutable copy published temporary",
            )
            != expected_receipt
        ):
            raise ValueError("immutable copy temporary changed during publication")
        os.fsync(directory_fd)
        final_identity = _descriptor_identity(os.fstat(published_fd))
        _require_named_held_identity(
            directory_fd,
            target_name,
            published_fd,
            label="immutable copy published target",
        )
        if (
            _rehash_held_regular_fd(
                published_fd,
                max_bytes=max_bytes,
                label="immutable copy published target",
            )
            != expected_receipt
            or _descriptor_identity(os.fstat(published_fd)) != final_identity
            or _immutable_copy_mode_contract(os.fstat(published_fd))
            != target_mode_contract
        ):
            raise ValueError("immutable copy target changed before receipt creation")
        if (
            ArtifactIdentity.from_stat(os.fstat(readable_fd))
            != source_full_before
            or ArtifactIdentity.from_stat(os.fstat(source_path_fd))
            != source_full_before
        ):
            raise ValueError(
                "immutable copy source changed before receipt creation"
            )
        if parent_path is not None:
            assert parent_anchor is not None
            _require_parent_path_identity(parent_path, parent_anchor)
        _require_named_held_identity(
            directory_fd,
            target_name,
            published_fd,
            label="immutable copy published target",
        )
        if (
            _immutable_copy_mode_contract(os.fstat(published_fd))
            != target_mode_contract
        ):
            raise ValueError("immutable copy target permissions changed before receipt")
        return expected_receipt
    except BaseException:
        # A linked target is retained on every later error.  POSIX has no safe
        # unlink-by-held-descriptor operation.
        raise
    finally:
        if published_fd >= 0:
            os.close(published_fd)
        if temporary_fd >= 0:
            os.close(temporary_fd)
        os.close(readable_fd)


def _rehash_held_regular_fd(
    file_descriptor: int,
    *,
    max_bytes: int,
    label: str,
) -> ImmutableCopyReceipt:
    """Hash exactly one held regular inode without changing the caller's offset."""

    opening = _descriptor_identity(os.fstat(file_descriptor))
    if not stat.S_ISREG(opening[2]):
        raise ValueError(f"{label} is not a regular file")
    if opening[3] > max_bytes:
        raise ValueError(f"{label} exceeds its byte budget ({opening[3]} > {max_bytes})")
    readable_fd = os.open(
        f"/proc/self/fd/{file_descriptor}",
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        if _descriptor_identity(os.fstat(readable_fd)) != opening:
            raise ValueError(f"{label} changed while acquiring its hash descriptor")
        digest = hashlib.sha256()
        size = 0
        remaining = opening[3]
        while remaining:
            chunk = os.read(readable_fd, min(_COPY_CHUNK_SIZE, remaining))
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
            remaining -= len(chunk)
        if os.read(readable_fd, 1):
            raise ValueError(f"{label} grew while it was hashed")
        if (
            size != opening[3]
            or _descriptor_identity(os.fstat(readable_fd)) != opening
            or _descriptor_identity(os.fstat(file_descriptor)) != opening
        ):
            raise ValueError(f"{label} changed while it was hashed")
        return ImmutableCopyReceipt(size=size, sha256=digest.hexdigest())
    finally:
        os.close(readable_fd)


def _fsync_held_regular_fd(
    file_descriptor: int,
    *,
    expected_identity: tuple[int, int, int, int, int, int],
    label: str,
) -> None:
    """Sync one held regular inode without trusting a reopened pathname."""

    if _descriptor_identity(os.fstat(file_descriptor)) != expected_identity:
        raise ValueError(f"{label} changed before durability sync")
    sync_fd = os.open(
        f"/proc/self/fd/{file_descriptor}",
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        if _descriptor_identity(os.fstat(sync_fd)) != expected_identity:
            raise ValueError(f"{label} changed while acquiring its durability FD")
        os.fsync(sync_fd)
        if (
            _descriptor_identity(os.fstat(sync_fd)) != expected_identity
            or _descriptor_identity(os.fstat(file_descriptor)) != expected_identity
        ):
            raise ValueError(f"{label} changed during durability sync")
    finally:
        os.close(sync_fd)


def _write_all(file_descriptor: int, content: bytes) -> None:
    offset = 0
    while offset < len(content):
        written = os.write(file_descriptor, content[offset:])
        if written <= 0:
            raise OSError("immutable copy write made no progress")
        offset += written


def _open_path_nofollow(path: Path, final_flags: int) -> int:
    absolute = Path(os.path.abspath(path))
    parts = absolute.parts[1:]
    if not parts:
        raise ValueError(f"immutable copy requires a non-root path: {path}")
    directory_fd = os.open(os.sep, _directory_open_flags())
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, _directory_open_flags(), dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        return os.open(
            parts[-1],
            final_flags | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
    finally:
        os.close(directory_fd)


def _open_directory_nofollow(path: Path) -> int:
    return _open_path_nofollow(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )


def _open_or_create_directory_nofollow(path: Path) -> int:
    """Create missing directory components without ever traversing a symlink."""
    absolute = Path(os.path.abspath(path))
    directory_fd = os.open(os.sep, _directory_open_flags())
    try:
        for part in absolute.parts[1:]:
            try:
                next_fd = os.open(
                    part,
                    _directory_open_flags(),
                    dir_fd=directory_fd,
                )
            except FileNotFoundError:
                os.mkdir(part, 0o755, dir_fd=directory_fd)
                os.fsync(directory_fd)
                next_fd = os.open(
                    part,
                    _directory_open_flags(),
                    dir_fd=directory_fd,
                )
            os.close(directory_fd)
            directory_fd = next_fd
        result = directory_fd
        directory_fd = -1
        return result
    finally:
        if directory_fd >= 0:
            os.close(directory_fd)


def _directory_open_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _require_safe_leaf_name(name: str) -> None:
    if name in {"", ".", ".."} or "/" in name or "\x00" in name:
        raise ValueError(f"unsafe immutable publication name: {name!r}")
    try:
        name.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ValueError("immutable publication contains a non-UTF-8 entry name") from exc


def _require_tree_depth(
    relative: tuple[str, ...],
    *,
    max_depth: int,
    label: str,
) -> None:
    if len(relative) > max_depth:
        raise ValueError(
            f"{label} exceeds its {max_depth}-component depth budget: "
            f"{'/'.join(relative)}"
        )


def _bounded_directory_names(
    directory_fd: int,
    counters: list[int],
    *,
    max_entries: int,
    label: str,
) -> list[str]:
    """Enumerate at most the remaining structural budget before sorting."""

    names: list[str] = []
    with os.scandir(directory_fd) as iterator:
        for entry in iterator:
            counters[2] += 1
            if counters[2] > max_entries:
                raise ValueError(f"{label} exceeds its {max_entries}-entry budget")
            _require_safe_leaf_name(entry.name)
            names.append(entry.name)
    names.sort()
    return names


def _expected_tree_entries(expected_files: Iterable[str]) -> set[str]:
    """Expand a canonical file contract to its exact implied directory set."""

    entries: set[str] = set()
    for raw_name in expected_files:
        relative = Path(raw_name)
        if (
            relative.is_absolute()
            or not relative.parts
            or relative == Path(".")
            or any(part in {"", ".", ".."} for part in relative.parts)
            or relative.as_posix() != raw_name
        ):
            raise ValueError(f"immutable publication contract has an unsafe path: {raw_name!r}")
        for part in relative.parts:
            _require_safe_leaf_name(part)
        entries.add(relative.as_posix())
        for parent in relative.parents:
            if parent == Path("."):
                break
            entries.add(parent.as_posix())
    return entries


def _expected_tree_digests(
    expected_digests: Mapping[str, str],
) -> dict[str, str]:
    """Copy and validate an exact canonical SHA-256 contract."""

    digests: dict[str, str] = {}
    for raw_name, digest in expected_digests.items():
        if not isinstance(raw_name, str):
            raise ValueError("immutable publication digest contract contains a non-string path")
        _expected_tree_entries((raw_name,))
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ValueError(
                f"immutable publication digest contract has an invalid SHA-256 for {raw_name!r}"
            )
        digests[raw_name] = digest
    return digests


def _rename_directory_noreplace(
    parent_fd: int,
    source_name: str,
    target_name: str,
) -> None:
    """Invoke Linux renameat2(RENAME_NOREPLACE), with no unsafe fallback."""
    _renameat2(parent_fd, source_name, target_name, flags=1)


def _exchange_entries(
    parent_fd: int,
    first_name: str,
    second_name: str,
) -> None:
    """Atomically exchange two sibling entries through Linux renameat2."""
    _renameat2(parent_fd, first_name, second_name, flags=2)


def _renameat2(
    parent_fd: int,
    source_name: str,
    target_name: str,
    *,
    flags: int,
) -> None:
    _require_safe_leaf_name(source_name)
    _require_safe_leaf_name(target_name)
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise OSError(
            errno.ENOSYS,
            "atomic no-replace directory publication is unavailable",
        )
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    result = renameat2(
        parent_fd,
        os.fsencode(source_name),
        parent_fd,
        os.fsencode(target_name),
        flags,
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), target_name)


def _remove_tree_entry(
    parent_fd: int,
    name: str,
    *,
    counters: list[int] | None = None,
) -> None:
    """Remove one entry only after binding cleanup to its held inode."""
    counters = counters or [0, 0, 0]
    _require_safe_leaf_name(name)
    path_fd = os.open(
        name,
        getattr(os, "O_PATH", os.O_RDONLY)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=parent_fd,
    )
    try:
        held_identity = _descriptor_identity(os.fstat(path_fd))
        if stat.S_ISREG(held_identity[2]):
            _remove_owned_regular_entry(parent_fd, name, path_fd)
            return
        if not stat.S_ISDIR(held_identity[2]):
            raise ValueError(f"refuse to clean non-regular immutable staging entry: {name}")
        directory_fd = os.open(name, _directory_open_flags(), dir_fd=parent_fd)
        try:
            if _descriptor_identity(os.fstat(directory_fd)) != held_identity:
                raise ValueError(f"refuse to clean replaced immutable staging entry: {name}")
            _remove_owned_tree_entry(parent_fd, name, directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        os.close(path_fd)


def _remove_tree_contents(directory_fd: int, counters: list[int]) -> None:
    children = _bounded_directory_names(
        directory_fd,
        counters,
        max_entries=_TREE_MAX_ENTRIES,
        label="immutable staging cleanup",
    )
    for child in children:
        _remove_tree_entry(directory_fd, child, counters=counters)
    os.fsync(directory_fd)


def _rollback_owned_tree_publication(
    parent_fd: int,
    name: str,
    held_directory_fd: int,
    *,
    preserve_as: str,
) -> None:
    """Retire the held publication without ever moving a substituted target."""

    held = _descriptor_identity(os.fstat(held_directory_fd))
    try:
        current = _descriptor_identity(os.stat(name, dir_fd=parent_fd, follow_symlinks=False))
    except FileNotFoundError:
        return
    if _same_inode_kind(current, held):
        _remove_owned_tree_entry(parent_fd, name, held_directory_fd)
        return
    raise ValueError(
        f"refuse to roll back substituted immutable tree target {name!r}; "
        f"foreign pathname left intact (owned staging remains {preserve_as!r})"
    )


def _rollback_owned_regular_publication(
    parent_fd: int,
    name: str,
    held_file_fd: int,
    *,
    preserve_as: str,
) -> None:
    """Retire the held file without ever moving a substituted target."""

    held = _descriptor_identity(os.fstat(held_file_fd))
    try:
        current = _descriptor_identity(os.stat(name, dir_fd=parent_fd, follow_symlinks=False))
    except FileNotFoundError:
        return
    if _same_inode_kind(current, held):
        _remove_owned_regular_entry(parent_fd, name, held_file_fd)
        return
    raise ValueError(
        f"refuse to roll back substituted immutable file target {name!r}; "
        f"foreign pathname left intact (owned staging remains {preserve_as!r})"
    )


def _remove_owned_tree_entry(
    parent_fd: int,
    name: str,
    held_directory_fd: int,
    *,
    scrub: bool = True,
) -> None:
    """Quarantine and retain the exact directory inode already held.

    POSIX cannot remove a directory by held descriptor.  Renaming to an
    unpredictable no-replace name detaches it from its operational pathname while
    preserving every inode for explicit maintainer cleanup.
    """

    expected = _descriptor_identity(os.fstat(held_directory_fd))
    quarantine_name = f".{name}.cleanup-{uuid.uuid4().hex}"
    _rename_directory_noreplace(parent_fd, name, quarantine_name)
    held_after_rename = _descriptor_identity(os.fstat(held_directory_fd))
    if not _same_inode_kind(held_after_rename, expected):
        _restore_quarantined_name(parent_fd, quarantine_name, name)
        raise ValueError(f"refuse to clean changed immutable publication target: {name}")
    os.fsync(parent_fd)
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise ValueError(
            f"refuse cleanup because the operational name still exists: {name}"
        )
    quarantine_fd = -1
    try:
        try:
            quarantine_fd = os.open(
                quarantine_name,
                _directory_open_flags(),
                dir_fd=parent_fd,
            )
        except OSError as exc:
            _restore_quarantined_name(
                parent_fd,
                quarantine_name,
                name,
                cause=exc,
            )
            raise ValueError(
                f"refuse to remove replaced immutable publication target: {name}"
            ) from exc
        if _descriptor_identity(os.fstat(quarantine_fd)) != held_after_rename:
            os.close(quarantine_fd)
            quarantine_fd = -1
            _restore_quarantined_name(parent_fd, quarantine_name, name)
            raise ValueError(f"refuse to remove changed immutable publication target: {name}")
        if scrub:
            _scrub_owned_tree_contents(quarantine_fd, [0, 0, 0])
        closing_held = _descriptor_identity(os.fstat(held_directory_fd))
        closing_quarantine = _descriptor_identity(os.fstat(quarantine_fd))
        if closing_quarantine != closing_held or not _same_inode_kind(closing_held, expected):
            raise ValueError(f"refuse to finish cleanup of changed immutable target: {name}")
        os.fsync(parent_fd)
    finally:
        if quarantine_fd >= 0:
            os.close(quarantine_fd)


_CLEANUP_MAX_RECORDED_ERRORS = 64


@dataclasses.dataclass
class _CleanupTraversalState:
    """Bounded mutable state shared by one scrub or inventory traversal."""

    max_entries: int
    max_bytes: int
    max_depth: int
    entries_seen: int = 0
    bytes_seen: int = 0
    complete: bool = True
    errors: list[str] = dataclasses.field(default_factory=list)
    regular_inodes: set[tuple[int, int]] = dataclasses.field(default_factory=set)


def _cleanup_error(label: str, exc: BaseException) -> str:
    return f"{label}: {type(exc).__name__}: {exc}"


def _record_cleanup_error(errors: list[str], message: str) -> None:
    """Keep hostile trees from making the outcome itself unbounded."""

    if len(errors) < _CLEANUP_MAX_RECORDED_ERRORS:
        errors.append(message)
    elif len(errors) == _CLEANUP_MAX_RECORDED_ERRORS:
        errors.append("additional cleanup errors were suppressed")


def _cleanup_directory_names(
    directory_fd: int,
    state: _CleanupTraversalState,
    *,
    label: str,
) -> list[str]:
    """Enumerate from a fresh descriptor without inheriting a prior scan offset."""

    scan_fd = -1
    names: list[str] = []
    try:
        scan_fd = os.open(".", _directory_open_flags(), dir_fd=directory_fd)
        with os.scandir(scan_fd) as iterator:
            for entry in iterator:
                if state.entries_seen >= state.max_entries:
                    state.complete = False
                    _record_cleanup_error(
                        state.errors,
                        f"{label} exceeds its {state.max_entries}-entry budget",
                    )
                    break
                state.entries_seen += 1
                try:
                    _require_safe_leaf_name(entry.name)
                except ValueError as exc:
                    state.complete = False
                    _record_cleanup_error(
                        state.errors,
                        _cleanup_error(f"{label} contains an unsafe entry", exc),
                    )
                    continue
                names.append(entry.name)
    except (OSError, ValueError) as exc:
        state.complete = False
        _record_cleanup_error(
            state.errors,
            _cleanup_error(f"{label} could not be enumerated", exc),
        )
    finally:
        if scan_fd >= 0:
            os.close(scan_fd)
    names.sort()
    return names


def _scrub_owned_tree_best_effort(
    directory_fd: int,
    state: _CleanupTraversalState,
    *,
    depth: int,
) -> None:
    """Truncate provably private regular inodes while continuing safe siblings."""

    if depth > state.max_depth:
        state.complete = False
        _record_cleanup_error(
            state.errors,
            f"owned temporary tree scrub exceeds its {state.max_depth}-level "
            "depth budget",
        )
        return
    for name in _cleanup_directory_names(
        directory_fd,
        state,
        label="owned temporary tree scrub",
    ):
        try:
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            state.complete = False
            _record_cleanup_error(
                state.errors,
                _cleanup_error(f"scrub entry {name!r} could not be inspected", exc),
            )
            continue
        opening = full_filesystem_identity(info)
        if stat.S_ISDIR(info.st_mode):
            if depth >= state.max_depth:
                state.complete = False
                _record_cleanup_error(
                    state.errors,
                    f"scrub directory {name!r} exceeds the "
                    f"{state.max_depth}-level depth budget",
                )
                continue
            child_fd = -1
            try:
                child_fd = os.open(
                    name,
                    _directory_open_flags(),
                    dir_fd=directory_fd,
                )
                if full_filesystem_identity(os.fstat(child_fd)) != opening:
                    raise ValueError(
                        f"owned temporary directory changed before scrub: {name}"
                    )
                _scrub_owned_tree_best_effort(
                    child_fd,
                    state,
                    depth=depth + 1,
                )
            except (OSError, ValueError) as exc:
                state.complete = False
                _record_cleanup_error(
                    state.errors,
                    _cleanup_error(f"scrub directory {name!r} failed", exc),
                )
            finally:
                if child_fd >= 0:
                    os.close(child_fd)
            continue
        # Symlinks and special files are intentionally retained and never opened
        # for content I/O.  Their presence is visible in the terminal inventory.
        if not stat.S_ISREG(info.st_mode):
            continue
        inode = (info.st_dev, info.st_ino)
        if inode in state.regular_inodes:
            continue
        state.regular_inodes.add(inode)
        next_bytes = state.bytes_seen + info.st_size
        if next_bytes > state.max_bytes:
            state.complete = False
            _record_cleanup_error(
                state.errors,
                f"scrub entry {name!r} exceeds the {state.max_bytes}-byte budget",
            )
            state.bytes_seen = next_bytes
            continue
        state.bytes_seen = next_bytes
        if info.st_nlink != 1:
            state.complete = False
            _record_cleanup_error(
                state.errors,
                f"scrub entry {name!r} has {info.st_nlink} hardlinks and was "
                "retained without truncation",
            )
            continue
        try:
            _scrub_owned_regular_file(directory_fd, name, opening)
        except (OSError, ValueError) as exc:
            state.complete = False
            _record_cleanup_error(
                state.errors,
                _cleanup_error(f"scrub entry {name!r} failed", exc),
            )
    try:
        os.fsync(directory_fd)
    except OSError as exc:
        state.complete = False
        _record_cleanup_error(
            state.errors,
            _cleanup_error("scrub directory sync failed", exc),
        )


def _scrub_owned_regular_file(
    directory_fd: int,
    name: str,
    opening: FullFilesystemIdentity,
) -> None:
    """Descriptor-relatively truncate one still-private regular inode."""

    held_fd = os.open(
        name,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0),
        dir_fd=directory_fd,
    )
    writable_fd = -1
    try:
        if full_filesystem_identity(os.fstat(held_fd)) != opening:
            raise ValueError(f"owned temporary file changed before scrub: {name}")
        os.fchmod(held_fd, 0o600)
        held_after_chmod = full_filesystem_identity(os.fstat(held_fd))
        if held_after_chmod[5] != 1:
            raise ValueError(
                f"owned temporary file acquired an external hardlink before scrub: {name}"
            )
        writable_fd = os.open(
            name,
            os.O_WRONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=directory_fd,
        )
        writable_identity = full_filesystem_identity(os.fstat(writable_fd))
        if (
            writable_identity[0] != held_after_chmod[0]
            or writable_identity[1] != held_after_chmod[1]
            or stat.S_IFMT(writable_identity[2])
            != stat.S_IFMT(held_after_chmod[2])
            or writable_identity[5] != 1
        ):
            raise ValueError(
                f"owned temporary file changed while acquiring scrub FD: {name}"
            )
        os.ftruncate(writable_fd, 0)
        os.fsync(writable_fd)
        if os.fstat(writable_fd).st_size != 0:
            raise OSError(f"owned temporary file did not scrub to zero bytes: {name}")
    finally:
        if writable_fd >= 0:
            os.close(writable_fd)
        os.close(held_fd)


def _inventory_owned_tree(
    directory_fd: int,
    state: _CleanupTraversalState,
    *,
    depth: int,
) -> None:
    """Reinventory a quarantine without following names outside held directories."""

    if depth > state.max_depth:
        state.complete = False
        _record_cleanup_error(
            state.errors,
            f"terminal cleanup inventory exceeds its {state.max_depth}-level "
            "depth budget",
        )
        return
    opening_directory = full_filesystem_identity(os.fstat(directory_fd))
    for name in _cleanup_directory_names(
        directory_fd,
        state,
        label="terminal cleanup inventory",
    ):
        path_fd = -1
        child_fd = -1
        try:
            path_fd = os.open(
                name,
                getattr(os, "O_PATH", os.O_RDONLY)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0),
                dir_fd=directory_fd,
            )
            info = os.fstat(path_fd)
            identity = full_filesystem_identity(info)
            named = full_filesystem_identity(
                os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            )
            if named != identity:
                raise ValueError(
                    f"terminal cleanup inventory entry changed: {name}"
                )
            if stat.S_ISREG(info.st_mode):
                inode = (info.st_dev, info.st_ino)
                if inode not in state.regular_inodes:
                    state.regular_inodes.add(inode)
                    state.bytes_seen += info.st_size
                    if state.bytes_seen > state.max_bytes:
                        state.complete = False
                        _record_cleanup_error(
                            state.errors,
                            "terminal cleanup inventory exceeds its "
                            f"{state.max_bytes}-byte budget",
                        )
                continue
            if not stat.S_ISDIR(info.st_mode):
                continue
            if depth >= state.max_depth:
                state.complete = False
                _record_cleanup_error(
                    state.errors,
                    f"terminal inventory directory {name!r} exceeds the "
                    f"{state.max_depth}-level depth budget",
                )
                continue
            child_fd = os.open(
                name,
                _directory_open_flags(),
                dir_fd=directory_fd,
            )
            if full_filesystem_identity(os.fstat(child_fd)) != identity:
                raise ValueError(
                    f"terminal cleanup inventory directory changed: {name}"
                )
            _inventory_owned_tree(child_fd, state, depth=depth + 1)
        except (OSError, ValueError) as exc:
            state.complete = False
            _record_cleanup_error(
                state.errors,
                _cleanup_error(f"terminal inventory entry {name!r} failed", exc),
            )
        finally:
            if child_fd >= 0:
                os.close(child_fd)
            if path_fd >= 0:
                os.close(path_fd)
    if full_filesystem_identity(os.fstat(directory_fd)) != opening_directory:
        state.complete = False
        _record_cleanup_error(
            state.errors,
            "terminal cleanup inventory directory changed during traversal",
        )


def _scrub_owned_tree_contents(
    directory_fd: int,
    counters: list[int],
) -> None:
    """Zero private regular-file contents without unlinking any pathname."""

    names = _bounded_directory_names(
        directory_fd,
        counters,
        max_entries=_TREE_MAX_ENTRIES,
        label="owned temporary tree scrub",
    )
    for name in names:
        info = os.stat(
            name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        opening = full_filesystem_identity(info)
        if stat.S_ISDIR(info.st_mode):
            child_fd = os.open(
                name,
                _directory_open_flags(),
                dir_fd=directory_fd,
            )
            try:
                if full_filesystem_identity(os.fstat(child_fd)) != opening:
                    raise ValueError(f"owned temporary directory changed before scrub: {name}")
                _scrub_owned_tree_contents(child_fd, counters)
                os.fsync(child_fd)
            finally:
                os.close(child_fd)
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError(f"owned temporary tree contains an unsafe scrub entry: {name}")
        held_fd = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=directory_fd,
        )
        writable_fd = -1
        try:
            if full_filesystem_identity(os.fstat(held_fd)) != opening:
                raise ValueError(f"owned temporary file changed before scrub: {name}")
            os.fchmod(held_fd, 0o600)
            writable_fd = os.open(
                f"/proc/self/fd/{held_fd}",
                os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0),
            )
            held_after_chmod = os.fstat(held_fd)
            writable_identity = os.fstat(writable_fd)
            if (
                held_after_chmod.st_dev != writable_identity.st_dev
                or held_after_chmod.st_ino != writable_identity.st_ino
                or not stat.S_ISREG(writable_identity.st_mode)
                or writable_identity.st_nlink != 1
            ):
                raise ValueError(f"owned temporary file changed while acquiring scrub FD: {name}")
            os.ftruncate(writable_fd, 0)
            os.fsync(writable_fd)
            if os.fstat(writable_fd).st_size != 0:
                raise OSError(f"owned temporary file did not scrub to zero bytes: {name}")
        finally:
            if writable_fd >= 0:
                os.close(writable_fd)
            os.close(held_fd)
    os.fsync(directory_fd)


def _remove_owned_regular_entry(
    parent_fd: int,
    name: str,
    held_file_fd: int,
) -> None:
    """Quarantine and retain a regular inode already held by the caller."""

    expected = _descriptor_identity(os.fstat(held_file_fd))
    if not stat.S_ISREG(expected[2]):
        raise ValueError(f"refuse to unlink non-regular immutable entry: {name}")
    quarantine_name = f".{name}.cleanup-{uuid.uuid4().hex}"
    _rename_directory_noreplace(parent_fd, name, quarantine_name)
    held_after_rename = _descriptor_identity(os.fstat(held_file_fd))
    if not _same_inode_kind(held_after_rename, expected):
        _restore_quarantined_name(parent_fd, quarantine_name, name)
        raise ValueError(f"refuse to clean changed immutable file: {name}")
    os.fsync(parent_fd)
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise ValueError(
            f"refuse cleanup because the operational file name still exists: {name}"
        )
    quarantine_fd = -1
    try:
        try:
            quarantine_fd = os.open(
                quarantine_name,
                getattr(os, "O_PATH", os.O_RDONLY)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_fd,
            )
        except BaseException as exc:
            _restore_quarantined_name(
                parent_fd,
                quarantine_name,
                name,
                cause=exc,
            )
            raise
        quarantine_identity = _descriptor_identity(os.fstat(quarantine_fd))
        if quarantine_identity != held_after_rename or not stat.S_ISREG(quarantine_identity[2]):
            _restore_quarantined_name(parent_fd, quarantine_name, name)
            raise ValueError(f"refuse to remove replaced immutable cleanup file: {name}")
        os.fsync(parent_fd)
    finally:
        if quarantine_fd >= 0:
            os.close(quarantine_fd)


def _require_named_held_identity(
    parent_fd: int,
    name: str,
    held_fd: int,
    *,
    label: str,
) -> tuple[int, int, int, int, int, int]:
    """Require a sibling name to resolve to the exact inode held by ``held_fd``."""

    held = _descriptor_identity(os.fstat(held_fd))
    current = _descriptor_identity(os.stat(name, dir_fd=parent_fd, follow_symlinks=False))
    if current != held:
        raise ValueError(f"{label} path no longer names its held inode")
    return held


def _require_named_held_full_identity(
    parent_fd: int,
    name: str,
    held_fd: int,
    *,
    expected: FullFilesystemIdentity,
    label: str,
) -> FullFilesystemIdentity:
    """Require the final name, held inode and complete receipt identity to agree."""

    held = full_filesystem_identity(os.fstat(held_fd))
    if held != expected:
        raise ValueError(f"{label} held inode changed before receipt creation")
    current = full_filesystem_identity(
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    )
    if current != held:
        raise ValueError(f"{label} path no longer names its held inode")
    return held


def _restore_quarantined_name(
    parent_fd: int,
    quarantine_name: str,
    original_name: str,
    *,
    cause: BaseException | None = None,
) -> None:
    try:
        _rename_directory_noreplace(
            parent_fd,
            quarantine_name,
            original_name,
        )
    except BaseException as restore_exc:
        raise OSError(
            "immutable cleanup quarantined a substituted entry but could not "
            f"restore its original name: {restore_exc}"
        ) from cause
    os.fsync(parent_fd)


def _same_inode_kind(
    first: tuple[int, int, int, int, int, int],
    second: tuple[int, int, int, int, int, int],
) -> bool:
    return (
        first[0] == second[0]
        and first[1] == second[1]
        and stat.S_IFMT(first[2]) == stat.S_IFMT(second[2])
    )


def _descriptor_identity(
    info: os.stat_result,
) -> tuple[int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _immutable_copy_mode_contract(info: os.stat_result) -> tuple[int, int]:
    """Metadata deliberately inherited by an immutable regular-file copy."""

    return (stat.S_IFMT(info.st_mode), stat.S_IMODE(info.st_mode))


def _publication_metadata_contract(
    info: os.stat_result,
) -> tuple[int, int, int, int, int]:
    """Tree-root fields which a rename or child write cannot legitimately alter."""

    return (
        stat.S_IFMT(info.st_mode),
        stat.S_IMODE(info.st_mode),
        info.st_uid,
        info.st_gid,
        info.st_rdev,
    )


def full_filesystem_identity(info: os.stat_result) -> FullFilesystemIdentity:
    """Return the complete stat identity carried by immutable-tree receipts."""

    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_rdev,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def stable_identity_from_full(
    identity: FullFilesystemIdentity,
) -> StableParentIdentity:
    """Project a receipt identity to fields stable across child-file writes."""

    return (
        identity[0],
        identity[1],
        stat.S_IFMT(identity[2]),
        identity[3],
        identity[4],
        identity[5],
        identity[6],
    )


def _stable_parent_identity(info: os.stat_result) -> StableParentIdentity:
    return (
        info.st_dev,
        info.st_ino,
        stat.S_IFMT(info.st_mode),
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_rdev,
    )


def _normalise_expected_parent_identity(
    expected: StableParentIdentity | ArtifactIdentity | None,
) -> StableParentIdentity | None:
    if expected is None:
        return None
    if isinstance(expected, tuple):
        if len(expected) != 7 or not all(isinstance(item, int) for item in expected):
            raise ValueError("invalid stable parent identity")
        return expected
    return (
        expected.dev,
        expected.ino,
        stat.S_IFMT(expected.mode),
        expected.uid,
        expected.gid,
        expected.nlink,
        expected.rdev,
    )


def _require_expected_parent_identity(
    path: Path,
    directory_fd: int,
    expected: StableParentIdentity | ArtifactIdentity | None,
) -> StableParentIdentity:
    anchor = _stable_parent_identity(os.fstat(directory_fd))
    required = _normalise_expected_parent_identity(expected)
    if required is not None and anchor != required:
        raise ValueError("immutable copy parent differs from its publication receipt")
    _require_parent_path_identity(path, anchor)
    return anchor


def _require_parent_path_identity(
    path: Path,
    expected: StableParentIdentity,
) -> None:
    current_fd = _open_directory_nofollow(path)
    try:
        current = _stable_parent_identity(os.fstat(current_fd))
        # Publishing a directory legitimately changes its parent's link count.
        # Path binding therefore compares the held inode, kind and ownership,
        # while the caller's exact receipt (including nlink) is still enforced
        # before the first mutation.
        if current[:5] != expected[:5] or current[6] != expected[6]:
            raise ValueError("regular publication parent path no longer names its held anchor")
    finally:
        os.close(current_fd)


def _anchored_parent_leaf_absent(
    parent: Path,
    expected: StableParentIdentity,
    leaf_name: str,
) -> bool:
    """Prove that the requested parent is still held and its leaf is absent."""

    _require_safe_leaf_name(leaf_name)
    try:
        current_fd = _open_directory_nofollow(parent)
    except (FileNotFoundError, NotADirectoryError, OSError):
        return False
    try:
        current = _stable_parent_identity(os.fstat(current_fd))
        if current[:5] != expected[:5] or current[6] != expected[6]:
            return False
        try:
            os.stat(leaf_name, dir_fd=current_fd, follow_symlinks=False)
        except FileNotFoundError:
            return True
        return False
    finally:
        os.close(current_fd)


def write_json_alias(
    path: Path,
    payload: dict[str, object],
) -> ImmutableCopyReceipt:
    """Write a compatibility pointer; the immutable copy is the evidence."""
    return write_text_alias(path, json.dumps(payload, indent=2) + "\n")


def write_text_alias(
    path: Path,
    content: str,
    *,
    expected_parent_identity: StableParentIdentity | ArtifactIdentity | None = None,
    idempotent: bool = True,
) -> ImmutableCopyReceipt:
    """Publish one compatibility alias without replacing any existing inode.

    ``idempotent`` retains the historical convenience contract for aliases whose
    caller treats identical existing bytes as success.  Transactional callers can
    set it to false: the one no-replace link is then the only target operation and
    every collision is reported as :class:`FileExistsError` without opening the
    existing leaf.
    """

    absolute = Path(os.path.abspath(path))
    parent_identity = (
        expected_parent_identity
        if expected_parent_identity is not None
        else stable_parent_identity(absolute.parent)
    )
    encoded = content.encode("utf-8", errors="strict")
    if idempotent:
        return publish_regular_text(
            absolute,
            content,
            max_bytes=len(encoded),
            expected_parent_identity=parent_identity,
        )
    return _publish_regular_bytes(
        absolute,
        encoded,
        replace=False,
        max_bytes=len(encoded),
        expected_parent_identity=parent_identity,
    )


def publish_optional_text_alias_receipt(
    path: Path,
    content: str,
    *,
    schema: str,
    run_id: str,
    authoritative_source_path: Path,
    authoritative_source_receipt: ImmutableCopyReceipt,
    authoritative_source_key: str = "authoritative_source",
    expected_parent_identity: StableParentIdentity | ArtifactIdentity | None = None,
) -> dict[str, object]:
    """Attempt one optional no-replace alias and return its evidence payload.

    The immutable, run-scoped source remains authoritative.  A target collision is
    deliberately not inspected: regular files, symlinks, FIFOs, sockets and devices
    all receive the same ``collision-preserved`` result.  Any other publication
    error is ``unconfirmed`` because a failure after ``link(2)`` may have left the
    intended inode at the target and POSIX offers no safe unlink-by-descriptor.
    """

    if not schema or not isinstance(schema, str):
        raise ValueError("optional alias receipt schema must be a non-empty string")
    if not is_safe_run_id(run_id):
        raise ValueError(f"invalid evidence run_id: {run_id!r}")
    if (
        not authoritative_source_key
        or not isinstance(authoritative_source_key, str)
        or any(character.isspace() for character in authoritative_source_key)
    ):
        raise ValueError("optional alias authoritative source key is invalid")
    encoded = content.encode("utf-8", errors="strict")
    content_receipt = ImmutableCopyReceipt(
        size=len(encoded),
        sha256=hashlib.sha256(encoded).hexdigest(),
    )
    if content_receipt != authoritative_source_receipt:
        raise ValueError(
            "optional alias bytes differ from their authoritative source receipt"
        )

    absolute = Path(os.path.abspath(path))
    try:
        write_text_alias(
            absolute,
            content,
            expected_parent_identity=expected_parent_identity,
            idempotent=False,
        )
    except FileExistsError as exc:
        status = "collision-preserved"
        detail = (
            "The optional alias target collided with an existing entry; that entry "
            f"was preserved without inspection, unlink, or replacement: {exc}"
        )
    except (OSError, ValueError) as exc:
        status = "unconfirmed"
        detail = (
            "The optional no-replace alias publication is unconfirmed; the intended "
            "inode may have been linked before a later durability or identity check "
            f"failed: {type(exc).__name__}: {exc}"
        )
    else:
        status = "matched"
        detail = (
            "The optional alias was durably linked without replacement and its bytes "
            "match the authoritative source receipt."
        )

    return {
        "schema": schema,
        "run_id": run_id,
        "target": str(absolute),
        authoritative_source_key: {
            "path": str(Path(os.path.abspath(authoritative_source_path))),
            "size": authoritative_source_receipt.size,
            "sha256": authoritative_source_receipt.sha256,
        },
        "status": status,
        "detail": detail,
    }


def canonical_sha256(value: object) -> str:
    body = json.dumps(_normalise(value), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def make_run_context(
    project: Project,
    options: object,
    *,
    definition: Path | None = None,
    run_id: str | None = None,
    mode: str = "execute",
) -> dict[str, object]:
    # Measure Git before asking it to describe the builder.  The closing toolchain
    # identity then catches an in-place rewrite or pathname swap around those probes.
    toolchain = toolchain_identity(include_versions=mode == "execute")
    builder_identity = builder_source_identity(use_git=mode == "execute")
    definition_identity = _definition_identity(project, options, definition)
    source_iso_identity = _source_iso_identity(project)
    opening_identity = {
        "builder_source": builder_identity,
        "definition": definition_identity,
        "source_iso": source_iso_identity,
        "toolchain": toolchain,
    }
    return {
        "schema": EVIDENCE_SCHEMA,
        "run_id": run_id or new_run_id(),
        "created_at": datetime.now(UTC).isoformat(),
        "mode": mode,
        "distroforge": {
            "version": __version__,
            "python": _file_identity(Path(sys.executable).resolve()),
        },
        "builder_source": builder_identity,
        "definition": definition_identity,
        "source_iso": source_iso_identity,
        "opening_identity_sha256": canonical_sha256(opening_identity),
        "toolchain": toolchain,
    }


def close_run_identity(
    project: Project,
    options: object,
    evidence_context: dict[str, object] | None,
) -> dict[str, object]:
    """Re-measure every mutable build identity and refuse a non-identical close.

    SHA equality alone cannot prove that a file stayed put: an input can be changed,
    consumed, and restored before the final hash.  The file identities below therefore
    bind the descriptor's device/inode and its ctime/mtime as well as its bytes.  The
    builder worktree applies the same rule to every tracked and non-ignored untracked
    entry.  A same-byte atomic replacement changes the inode; an A→B→A rewrite changes
    ctime even when the attacker restores mtime.
    """
    if not isinstance(evidence_context, dict):
        raise RuntimeError("Run identity closure requires an injected evidence context.")

    initial_builder = evidence_context.get("builder_source")
    initial_definition = evidence_context.get("definition")
    initial_source_iso = evidence_context.get("source_iso")
    initial_toolchain = evidence_context.get("toolchain")
    opening_identity = {
        "builder_source": initial_builder,
        "definition": initial_definition,
        "source_iso": initial_source_iso,
        "toolchain": initial_toolchain,
    }
    opening_digest = canonical_sha256(opening_identity)
    recorded_opening_digest = evidence_context.get("opening_identity_sha256")
    opening_issues: list[str] = []
    if recorded_opening_digest != opening_digest:
        opening_issues.append("the opening identity record changed after make_run_context")

    definition_path = _identity_path(initial_definition)
    source_trusted_path = _source_trusted_path(initial_source_iso)
    use_git = not (
        isinstance(initial_builder, dict) and initial_builder.get("kind") == "source-tree-plan"
    )
    final_components: dict[str, object] = {
        "builder_source": builder_source_identity(use_git=use_git),
        "definition": _definition_identity(
            project,
            options,
            definition_path,
        ),
        "source_iso": _source_iso_identity(
            project,
            trusted_path=source_trusted_path,
        ),
        "toolchain": toolchain_identity(include_versions=evidence_context.get("mode") == "execute"),
    }
    initial_components = {
        "builder_source": initial_builder,
        "definition": initial_definition,
        "source_iso": initial_source_iso,
        "toolchain": initial_toolchain,
    }

    checks: list[dict[str, object]] = []
    failure_messages = list(opening_issues)
    for name in ("builder_source", "definition", "source_iso", "toolchain"):
        initial = initial_components[name]
        final = final_components[name]
        initial_sha256 = canonical_sha256(initial)
        final_sha256 = canonical_sha256(final)
        issues = [
            *_measurement_issues(name, initial, moment="opening"),
            *_measurement_issues(name, final, moment="closing"),
        ]
        if initial_sha256 != final_sha256:
            issues.append("opening and closing identities differ")
        status = "closed" if not issues else "blocked"
        checks.append(
            {
                "name": name,
                "status": status,
                "initial_sha256": initial_sha256,
                "final_sha256": final_sha256,
                "final": final,
                "issues": issues,
            }
        )
        failure_messages.extend(f"{name}: {issue}" for issue in issues)

    closure: dict[str, object] = {
        "schema": IDENTITY_CLOSURE_SCHEMA,
        "status": "closed" if not failure_messages else "blocked",
        "checked_at": datetime.now(UTC).isoformat(),
        "opening_identity_sha256": recorded_opening_digest,
        "checks": checks,
        "checks_sha256": canonical_sha256(checks),
        "issues": failure_messages,
    }
    # Record the failed close before raising, so ISO-BUILD.json can say exactly which
    # input moved even though no provenance is allowed to be sealed.
    evidence_context["identity_closure"] = closure
    if failure_messages:
        raise RuntimeError("Run identity closure refused: " + "; ".join(failure_messages))
    return closure


def builder_source_identity(*, use_git: bool = True) -> dict[str, object]:
    """Describe the source bytes at the instant a run starts.

    This must not be cached: one long-lived CLI or GUI process can launch several
    builds while the worktree changes between them. Reusing the first identity would
    bind a later ISO to source bytes that were no longer present.
    """
    source_root = Path(__file__).resolve().parents[2]
    if not use_git:
        first_guard = _builder_filesystem_guard(
            source_root,
            _source_tree_paths(source_root),
        )
        second_guard = _builder_filesystem_guard(
            source_root,
            _source_tree_paths(source_root),
        )
        return {
            "kind": "source-tree-plan",
            "root": str(source_root),
            "source_tree_sha256": second_guard["content_sha256"],
            "filesystem_guard": second_guard,
            "stable_while_measured": first_guard == second_guard,
        }
    git_root_text = _git_text(source_root, "rev-parse", "--show-toplevel")
    if git_root_text is None:
        first_guard = _builder_filesystem_guard(
            source_root,
            _source_tree_paths(source_root),
        )
        second_guard = _builder_filesystem_guard(
            source_root,
            _source_tree_paths(source_root),
        )
        return {
            "kind": "source-tree",
            "root": str(source_root),
            "source_tree_sha256": second_guard["content_sha256"],
            "filesystem_guard": second_guard,
            "stable_while_measured": first_guard == second_guard,
        }
    git_root = Path(git_root_text)
    raw_head = _git_text(git_root, "rev-parse", "HEAD")
    raw_tree = _git_text(git_root, "rev-parse", "HEAD^{tree}")
    raw_branch = _git_text(git_root, "branch", "--show-current")
    raw_diff = _git_bytes(git_root, "diff", "--binary", "HEAD", "--")
    head = raw_head or ""
    tree = raw_tree or ""
    branch = raw_branch or ""
    diff = raw_diff or b""
    diff_sha256 = hashlib.sha256(diff).hexdigest()
    untracked: list[dict[str, str]] = []
    raw_untracked = _git_bytes(
        git_root,
        "ls-files",
        "--others",
        "--exclude-standard",
        "-z",
    )
    if raw_untracked:
        for raw_name in raw_untracked.split(b"\0"):
            if not raw_name:
                continue
            name = os.fsdecode(raw_name)
            path = git_root / name
            identity = _stable_regular_file_identity(path, required=True)
            digest = identity.get("sha256")
            untracked.append(
                {
                    "path": name,
                    "sha256": digest if isinstance(digest, str) else "",
                }
            )
    raw_tracked_result = _git_bytes(
        git_root,
        "ls-files",
        "--cached",
        "-z",
    )
    raw_tracked = raw_tracked_result or b""
    tracked_paths = {os.fsdecode(raw_name) for raw_name in raw_tracked.split(b"\0") if raw_name}
    untracked_paths = {
        os.fsdecode(raw_name) for raw_name in (raw_untracked or b"").split(b"\0") if raw_name
    }
    runtime_paths = set(_source_tree_paths(git_root))
    guarded_paths = sorted(tracked_paths | untracked_paths | runtime_paths)
    ignored_runtime_paths = sorted(
        relative
        for relative in runtime_paths - tracked_paths - untracked_paths
        if (git_root / relative).is_file() or (git_root / relative).is_symlink()
    )
    first_guard = _builder_filesystem_guard(git_root, guarded_paths)
    second_guard = _builder_filesystem_guard(git_root, guarded_paths)
    raw_signature = _git_text(git_root, "log", "-1", "--format=%G? %GF")
    signature = raw_signature or ""
    git_measurements_complete = all(
        item is not None
        for item in (
            raw_head,
            raw_tree,
            raw_branch,
            raw_diff,
            raw_untracked,
            raw_tracked_result,
            raw_signature,
        )
    )
    worktree_sha256 = canonical_sha256(
        {
            "head": head,
            "tracked_diff_sha256": diff_sha256,
            "untracked": untracked,
        }
    )
    return {
        "kind": "git",
        "root": str(git_root),
        "head": head,
        "tree": tree,
        "branch": branch,
        "commit_signature": signature.strip(),
        "git_measurements_complete": git_measurements_complete,
        "dirty": bool(diff or untracked),
        "tracked_diff_sha256": diff_sha256,
        "untracked": untracked,
        "ignored_runtime_paths": ignored_runtime_paths,
        "worktree_sha256": worktree_sha256,
        "filesystem_guard": second_guard,
        "stable_while_measured": first_guard == second_guard,
    }


def toolchain_identity(
    names: tuple[str, ...] = TOOLCHAIN_BINARIES,
    *,
    include_versions: bool = True,
) -> dict[str, object]:
    tools: dict[str, object] = {}
    for name in names:
        resolved = shutil.which(name)
        if resolved is None:
            tools[name] = {"available": False}
            continue
        path = Path(resolved).resolve()
        file_identity = _stable_regular_file_identity(path, required=True)
        tools[name] = {
            "available": True,
            "path": str(path),
            "sha256": file_identity.get("sha256"),
            "stable_while_hashed": file_identity.get("stable_while_hashed"),
            "file_identity": file_identity,
            "version": _tool_version(path) if include_versions else "not-probed-in-plan",
        }
    return tools


def observed_toolchain_identity(history: Iterable[CommandSpec]) -> dict[str, object]:
    """Bind the executable entry points actually present in the command history.

    Privilege and chroot wrappers are expanded far enough to identify both the host
    wrapper and the command it launched. A command executed inside the target root may
    not resolve on the host; recording it as unavailable is still preferable to
    silently pretending it was never invoked.
    """
    specs = tuple(history)
    observed = observed_executable_counts(spec.argv for spec in specs)
    real_names = tuple(sorted(name for name in observed if name not in VIRTUAL_COMMANDS))
    resolved = toolchain_identity(real_names)
    tools: dict[str, object] = {}
    for name in sorted(observed):
        raw_identity = resolved.get(name)
        identity = {"available": True, "kind": "virtual"}
        if name not in VIRTUAL_COMMANDS:
            identity = (
                dict(raw_identity) if isinstance(raw_identity, dict) else {"available": False}
            )
        identity["observed_count"] = observed[name]
        tools[name] = identity
    return {
        "command_count": len(specs),
        "resolution_scope": "post-run-path-snapshot",
        "tools": tools,
    }


def observed_executable_counts(
    commands: Iterable[Sequence[str]],
) -> dict[str, int]:
    observed: dict[str, int] = {}
    for argv in commands:
        for name in _executable_candidates(argv):
            observed[name] = observed.get(name, 0) + 1
    return observed


def critical_artifact_identity(
    project: Project, output_iso: Path | None
) -> list[dict[str, object]]:
    paths: set[Path] = set()
    if output_iso and output_iso.is_file():
        paths.add(output_iso)
    if project.iso_root.is_dir():
        for pattern in (
            "**/filesystem.squashfs",
            "**/filesystem.manifest",
            "**/vmlinuz*",
            "**/initrd*",
            "**/BOOTX64.EFI",
            "**/bootx64.efi",
            "**/grubx64.efi",
            "**/efi.img",
            "**/eltorito.img",
            "**/filesystem.manifest-desktop",
            "**/md5sum.txt",
            "**/grub.cfg",
        ):
            paths.update(path for path in project.iso_root.glob(pattern) if path.is_file())
    return [
        {
            "path": str(path),
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in sorted(paths)
    ]


def artifact_identity(path: Path, *, role: str = "") -> dict[str, object]:
    identity = _file_identity(path)
    if role:
        identity["role"] = role
    return identity


def _executable_candidates(argv: Sequence[str]) -> tuple[str, ...]:
    if not argv:
        return ()
    candidates: list[str] = []
    nested = tuple(argv)
    while nested:
        command = nested[0]
        if command not in candidates:
            candidates.append(command)
        leaf = Path(command).name
        if leaf == "sudo":
            index = 1
            while index < len(nested) and nested[index] in {"-A", "-n"}:
                index += 1
            nested = nested[index:]
            continue
        if leaf == "pkexec":
            nested = nested[1:]
            continue
        if leaf == "chroot":
            nested = nested[2:] if len(nested) >= 3 else ()
            continue
        if leaf == "systemd-nspawn":
            index = 1
            options_with_value = {
                "--directory",
                "-D",
                "--machine",
                "-M",
                "--image",
                "-i",
                "--setenv",
                "-E",
            }
            while index < len(nested) and nested[index].startswith("-"):
                token = nested[index]
                index += 2 if token in options_with_value else 1
            nested = nested[index:]
            continue
        if leaf == "env":
            index = 1
            while index < len(nested):
                token = nested[index]
                if token == "--":
                    index += 1
                    break
                if token.startswith("-") or "=" in token:
                    index += 1
                    continue
                break
            nested = nested[index:]
            continue
        break
    return tuple(candidates)


def _definition_identity(
    project: Project,
    options: object,
    definition: Path | None,
) -> dict[str, object]:
    definition_file = _stable_regular_file_identity(
        definition,
        required=definition is not None,
    )
    project_file_path = project.root / "project.json"
    project_file = _stable_regular_file_identity(project_file_path, required=True)
    identity: dict[str, object] = {
        # Keep the original convenience fields for existing evidence readers while
        # carrying the full stable identities needed by the closing comparison.
        "path": str(definition) if definition else None,
        "sha256": definition_file.get("sha256"),
        "file": definition_file,
        "effective_sha256": canonical_sha256(
            {
                "project": project.to_dict(),
                "options": _normalise_effective(options),
            }
        ),
        "project_file": str(project_file_path),
        "project_file_sha256": project_file.get("sha256"),
        "project_file_identity": project_file,
    }
    return identity


def _source_iso_identity(
    project: Project,
    *,
    trusted_path: Path | None = None,
) -> dict[str, object]:
    configured_path = project.source_iso
    opening_path = trusted_path if trusted_path is not None else configured_path
    required = project.source_mode == "iso"
    file_identity = _stable_regular_file_identity(
        opening_path,
        required=required,
    )
    return {
        "source_mode": project.source_mode,
        "path": str(configured_path) if configured_path else None,
        "trusted_path": str(opening_path) if opening_path else None,
        "sha256": file_identity.get("sha256"),
        "file": file_identity,
    }


def _identity_path(identity: object) -> Path | None:
    if not isinstance(identity, dict):
        return None
    path = identity.get("path")
    return Path(path) if isinstance(path, str) and path else None


def _source_trusted_path(identity: object) -> Path | None:
    if not isinstance(identity, dict):
        return None
    path = identity.get("trusted_path")
    return Path(path) if isinstance(path, str) and path else None


def _measurement_issues(
    name: str,
    identity: object,
    *,
    moment: str,
) -> list[str]:
    if not isinstance(identity, dict):
        return [f"{moment} identity is absent or malformed"]
    issues: list[str] = []
    if name == "builder_source":
        if identity.get("stable_while_measured") is not True:
            issues.append(f"{moment} builder worktree moved while it was measured")
        guard = identity.get("filesystem_guard")
        if not isinstance(guard, dict):
            issues.append(f"{moment} builder filesystem guard is absent")
        elif guard.get("stable") is not True:
            issues.append(f"{moment} builder filesystem guard is incomplete")
        return issues
    if name == "toolchain":
        for tool_name, tool_identity in identity.items():
            if not isinstance(tool_identity, dict):
                issues.append(f"{moment} toolchain entry {tool_name} is malformed")
                continue
            if tool_identity.get("available") is not True:
                continue
            if tool_identity.get("stable_while_hashed") is not True:
                issues.append(f"{moment} toolchain binary {tool_name} moved while hashed")
            if not isinstance(tool_identity.get("path"), str) or not isinstance(
                tool_identity.get("sha256"),
                str,
            ):
                issues.append(f"{moment} toolchain binary {tool_name} lacks path/SHA256")
        return issues

    file_keys = (
        (
            ("definition file", "file"),
            ("project definition", "project_file_identity"),
        )
        if name == "definition"
        else (("source ISO", "file"),)
    )
    for label, key in file_keys:
        file_identity = identity.get(key)
        if not isinstance(file_identity, dict):
            issues.append(f"{moment} {label} identity is absent")
            continue
        required = file_identity.get("required") is True
        if required and file_identity.get("exists") is not True:
            issues.append(f"{moment} {label} is missing")
        if file_identity.get("stable_while_hashed") is not True:
            issues.append(f"{moment} {label} moved while it was hashed")
        error = file_identity.get("error")
        if isinstance(error, str) and error:
            issues.append(f"{moment} {label}: {error}")
    return issues


def _stable_regular_file_identity(
    path: Path | None,
    *,
    required: bool,
) -> dict[str, object]:
    """Hash one path through a stable descriptor and bind it back to the pathname."""
    if path is None:
        return {
            "path": None,
            "required": required,
            "exists": False,
            "kind": "not-configured",
            "size": 0,
            "sha256": None,
            "stable_while_hashed": not required,
        }
    measured_path = path.absolute()
    identity: dict[str, object] = {
        "path": str(measured_path),
        "required": required,
        "exists": False,
        "kind": "missing",
        "size": 0,
        "sha256": None,
        "stable_while_hashed": False,
    }
    try:
        parent_before = measured_path.parent.lstat()
        path_before = measured_path.lstat()
    except OSError as exc:
        identity["error"] = f"cannot lstat: {exc}"
        return identity
    identity["exists"] = True
    identity["path_stat"] = _stat_identity(path_before)
    if stat.S_ISLNK(path_before.st_mode):
        identity["kind"] = "symlink"
        identity["error"] = "trusted inputs must not be symlinks"
        return identity
    if not stat.S_ISREG(path_before.st_mode):
        identity["kind"] = _mode_kind(path_before.st_mode)
        identity["error"] = "trusted input is not a regular file"
        return identity

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(measured_path, flags)
        descriptor_before = os.fstat(descriptor)
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        descriptor_after = os.fstat(descriptor)
        path_after = measured_path.lstat()
        parent_after = measured_path.parent.lstat()
    except OSError as exc:
        identity["error"] = f"cannot hash through stable descriptor: {exc}"
        return identity
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    stable = (
        _stable_stat_equal(path_before, descriptor_before)
        and _stable_stat_equal(descriptor_before, descriptor_after)
        and _stable_stat_equal(descriptor_after, path_after)
        and _stable_stat_equal(parent_before, parent_after)
    )
    identity.update(
        {
            "kind": "regular",
            "size": descriptor_after.st_size,
            "sha256": digest.hexdigest(),
            "descriptor_stat": _stat_identity(descriptor_after),
            "parent_stat": _stat_identity(parent_after),
            "stable_while_hashed": stable,
        }
    )
    if not stable:
        identity["error"] = "pathname/descriptor identity changed during hashing"
    return identity


def _builder_filesystem_guard(
    root: Path,
    relative_paths: Iterable[str],
) -> dict[str, object]:
    safe_relative_paths: list[Path] = []
    entries: list[dict[str, object]] = []
    content_entries: list[dict[str, object]] = []
    metadata_entries: list[dict[str, object]] = []
    problems: list[str] = []
    for relative in sorted(set(relative_paths)):
        relative_path = Path(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts or not relative_path.parts:
            problems.append(f"unsafe worktree path {relative!r}")
            continue
        safe_relative_paths.append(relative_path)
        guarded = _guard_path_identity(root / relative_path)
        entry = {"path": relative_path.as_posix(), **guarded}
        entries.append(entry)
        content_entries.append(
            {
                key: value
                for key, value in entry.items()
                if key
                in {
                    "path",
                    "exists",
                    "kind",
                    "size",
                    "sha256",
                    "link_target",
                }
            }
        )
        metadata_entries.append(
            {
                "path": entry["path"],
                "stat": entry.get("stat"),
                "stable_while_hashed": entry.get("stable_while_hashed"),
            }
        )
        error = guarded.get("error")
        if isinstance(error, str) and error:
            problems.append(f"{relative}: {error}")
    directory_paths = {Path(".")}
    for relative_path in safe_relative_paths:
        absolute_path = root / relative_path
        if absolute_path.is_dir() and not absolute_path.is_symlink():
            directory_paths.add(relative_path)
        directory_paths.update(
            parent for parent in relative_path.parents if parent != Path(".") and parent.parts
        )
    directories: list[dict[str, object]] = []
    for relative_directory in sorted(
        directory_paths,
        key=lambda item: item.as_posix(),
    ):
        guarded = _guard_directory_identity(root / relative_directory)
        label = relative_directory.as_posix()
        entry = {"path": label, **guarded}
        directories.append(entry)
        error = guarded.get("error")
        if isinstance(error, str) and error:
            problems.append(f"directory {label}: {error}")
    metadata_record = {
        "files": metadata_entries,
        "directories": directories,
    }
    return {
        "entry_count": len(entries),
        "directory_count": len(directories),
        "entries_sha256": canonical_sha256({"files": entries, "directories": directories}),
        "content_sha256": canonical_sha256(content_entries),
        "metadata_sha256": canonical_sha256(metadata_record),
        "directory_metadata_sha256": canonical_sha256(directories),
        "stable": not problems,
        "problems": problems,
    }


def _guard_path_identity(path: Path) -> dict[str, object]:
    try:
        before = path.lstat()
    except FileNotFoundError:
        # A tracked deletion is a legitimate, measurable dirty-worktree state.  The
        # parent-directory guard detects a create/delete transition, and the second
        # whole-tree pass proves that "missing" itself stayed stable while captured.
        return {
            "exists": False,
            "kind": "missing",
            "stable_while_hashed": True,
        }
    except OSError as exc:
        return {
            "exists": False,
            "kind": "missing",
            "stable_while_hashed": False,
            "error": f"cannot lstat: {exc}",
        }
    if stat.S_ISREG(before.st_mode):
        identity = _stable_regular_file_identity(path, required=True)
        return {
            key: value
            for key, value in identity.items()
            if key not in {"path", "required", "path_stat", "descriptor_stat"}
        } | {"stat": identity.get("descriptor_stat", identity.get("path_stat"))}
    if stat.S_ISLNK(before.st_mode):
        try:
            first_target = os.readlink(path)
            after = path.lstat()
            second_target = os.readlink(path)
        except OSError as exc:
            return {
                "exists": True,
                "kind": "symlink",
                "stat": _stat_identity(before),
                "stable_while_hashed": False,
                "error": f"cannot measure symlink: {exc}",
            }
        stable = _stable_stat_equal(before, after) and first_target == second_target
        return {
            "exists": True,
            "kind": "symlink",
            "size": len(os.fsencode(second_target)),
            "link_target": second_target,
            "sha256": hashlib.sha256(os.fsencode(second_target)).hexdigest(),
            "stat": _stat_identity(after),
            "stable_while_hashed": stable,
            **({} if stable else {"error": "symlink changed while measured"}),
        }
    return {
        "exists": True,
        "kind": _mode_kind(before.st_mode),
        "size": before.st_size,
        "stat": _stat_identity(before),
        "stable_while_hashed": True,
    }


def _guard_directory_identity(path: Path) -> dict[str, object]:
    try:
        before = path.lstat()
        after = path.lstat()
    except OSError as exc:
        return {
            "exists": False,
            "kind": "missing",
            "stable_while_measured": False,
            "error": f"cannot lstat: {exc}",
        }
    is_directory = stat.S_ISDIR(before.st_mode)
    stable = is_directory and _stable_stat_equal(before, after)
    return {
        "exists": True,
        "kind": _mode_kind(after.st_mode),
        "stat": _stat_identity(after),
        "stable_while_measured": stable,
        **({} if stable else {"error": "directory is not stable while measured"}),
    }


def _source_tree_paths(root: Path) -> list[str]:
    return [
        path.relative_to(root).as_posix()
        for path in sorted((root / "distroforge").rglob("*"))
        if path.is_file() or path.is_dir() or path.is_symlink()
    ]


def _stat_identity(value: os.stat_result) -> dict[str, int]:
    return {
        "device": value.st_dev,
        "inode": value.st_ino,
        "mode": value.st_mode,
        "links": value.st_nlink,
        "size": value.st_size,
        "mtime_ns": value.st_mtime_ns,
        "ctime_ns": value.st_ctime_ns,
    }


def _stable_stat_equal(first: os.stat_result, second: os.stat_result) -> bool:
    return _stat_identity(first) == _stat_identity(second)


def _mode_kind(mode: int) -> str:
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISCHR(mode):
        return "character-device"
    if stat.S_ISBLK(mode):
        return "block-device"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    return "other"


def _normalise_effective(value: Any) -> Any:
    """Normalise user-visible options without mutable internal run bookkeeping."""
    if isinstance(value, Path):
        return str(value)
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _normalise_effective(getattr(value, field.name))
            for field in dataclasses.fields(value)
            if not field.name.startswith("_")
        }
    if isinstance(value, dict):
        return {
            str(key): _normalise_effective(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
            if not str(key).startswith("_")
        }
    if isinstance(value, (list, tuple)):
        return [_normalise_effective(item) for item in value]
    if isinstance(value, set):
        return sorted(_normalise_effective(item) for item in value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)


def _normalise(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return _normalise(dataclasses.asdict(value))
    if isinstance(value, dict):
        return {
            str(key): _normalise(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_normalise(item) for item in value]
    if isinstance(value, set):
        return sorted(_normalise(item) for item in value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)


def _git_bytes(cwd: Path, *args: str) -> bytes | None:
    try:
        completed = subprocess.run(
            ("git", *args),
            cwd=cwd,
            capture_output=True,
            check=False,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return completed.stdout if completed.returncode == 0 else None


def _git_text(cwd: Path, *args: str) -> str | None:
    output = _git_bytes(cwd, *args)
    if output is None:
        return None
    return output.decode("utf-8", errors="replace").strip()


def _source_tree_sha256(root: Path) -> str:
    entries = [
        {
            "path": path.relative_to(root).as_posix(),
            "sha256": sha256_file(path),
        }
        for path in sorted((root / "distroforge").rglob("*.py"))
        if path.is_file()
    ]
    return canonical_sha256(entries)


def _tool_version(path: Path) -> str:
    for flag in ("--version", "-V"):
        try:
            completed = subprocess.run(
                (str(path), flag),
                text=True,
                capture_output=True,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            return "unavailable"
        output = (completed.stdout or completed.stderr).strip()
        if output:
            return output.splitlines()[0][:500]
    return "unavailable"


def _file_identity(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {"path": str(path), "size": 0, "sha256": ""}
    return {
        "path": str(path),
        "size": path.stat().st_size,
        "sha256": sha256_file(path),
    }
