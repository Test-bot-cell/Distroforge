"""Deterministic identity and packing-window proof for the final rootfs.

The semantic digest is intentionally independent from host inode numbers and
timestamps: it can identify the same rootfs materialised on another filesystem.
The packing guard is deliberately host-specific.  It binds inode, device, ctime
and mtime so an in-place edit or a replace-then-restore during ``mksquashfs``
cannot disappear behind byte-identical final contents.

Only descendants excluded by :mod:`distroforge.core.squashfs` are outside the
semantic scope.  Their mount-point objects remain in scope and the exclusions
are recorded in the manifest.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import stat
import sys
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import cast

from .command import CommandSpec, sudo
from .evidence_run import canonical_sha256, write_immutable_text

ROOTFS_MANIFEST_SCHEMA = "distroforge.rootfs-manifest.v1"
ROOTFS_PACKING_VERIFICATION_SCHEMA = "distroforge.rootfs-packing-verification.v1"
DEFAULT_EXCLUDED_DESCENDANTS = ("dev", "proc", "run", "sys")

_CHUNK = 1024 * 1024
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
_FILE_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK


class RootfsEvidenceError(RuntimeError):
    """The final rootfs cannot be represented by a trustworthy manifest."""


class RootfsChangedError(RootfsEvidenceError):
    """The rootfs changed while it was scanned or across the packing window."""

    def __init__(self, message: str, report: RootfsPackingVerification | None = None) -> None:
        super().__init__(message)
        self.report = report


@dataclass(frozen=True)
class RootfsEvidenceValidation:
    ok: bool
    detail: str


@dataclass(frozen=True)
class RootfsPackingVerification:
    ok: bool
    detail: str
    before_tree_sha256: str
    after_tree_sha256: str
    before_host_guard_sha256: str
    after_host_guard_sha256: str
    added: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()
    changed: tuple[str, ...] = ()
    packed_image: dict[str, object] | None = None
    packed_image_witness: dict[str, object] | None = None
    packed_image_matches_witness: bool = False
    packed_tree_sha256: str | None = None
    packed_added: tuple[str, ...] = ()
    packed_removed: tuple[str, ...] = ()
    packed_changed: tuple[str, ...] = ()

    def to_dict(self, manifest: dict[str, object]) -> dict[str, object]:
        return {
            "schema": ROOTFS_PACKING_VERIFICATION_SCHEMA,
            "run_id": manifest["run_id"],
            "status": "verified" if self.ok else "drifted",
            "detail": self.detail,
            "manifest": {
                "schema": manifest["schema"],
                "tree_sha256": self.before_tree_sha256,
                "host_scan_guard_sha256": self.before_host_guard_sha256,
                "object_count": manifest["object_count"],
            },
            "after_packing": {
                "tree_sha256": self.after_tree_sha256,
                "host_scan_guard_sha256": self.after_host_guard_sha256,
            },
            "drift": {
                "added": list(self.added),
                "removed": list(self.removed),
                "changed": list(self.changed),
                "host_identity_changed": (
                    self.before_host_guard_sha256 != self.after_host_guard_sha256
                ),
            },
            "packed_image": {
                "witness": self.packed_image_witness,
                "after_extraction": self.packed_image,
                "matches_witness": self.packed_image_matches_witness,
            },
            "packed_rootfs": {
                "tree_sha256": self.packed_tree_sha256,
                "matches_manifest": (
                    self.packed_tree_sha256 == self.before_tree_sha256
                    and not self.packed_added
                    and not self.packed_removed
                    and not self.packed_changed
                ),
                "added": list(self.packed_added),
                "removed": list(self.packed_removed),
                "changed": list(self.packed_changed),
            },
        }


@dataclass(frozen=True)
class _Scan:
    entries: tuple[dict[str, object], ...]
    host_guards: tuple[dict[str, object], ...]


class StableFileWitness:
    """Keep one exact regular-file inode open across a consuming command.

    The extraction command reads ``/proc/<this-pid>/fd/<fd>`` rather than resolving
    the path again.  The context exit re-hashes both that still-open inode and the
    original path.  A path swap before, during or after consumption therefore cannot
    associate the consumer's result with another file digest.
    """

    def __init__(self, packed_image: Path) -> None:
        self.packed_image = packed_image.absolute()
        try:
            self._descriptor = os.open(self.packed_image, _FILE_FLAGS)
        except OSError as exc:
            raise RootfsEvidenceError(
                f"Cannot open packed image witness {packed_image}: {exc}"
            ) from exc
        self._initial_stat = os.fstat(self._descriptor)
        if not stat.S_ISREG(self._initial_stat.st_mode):
            os.close(self._descriptor)
            raise RootfsEvidenceError(f"Packed image witness is not a regular file: {packed_image}")
        try:
            self._initial_digest = _rehash_fd(
                self._descriptor,
                self._initial_stat,
                str(self.packed_image),
            )
        except BaseException:
            os.close(self._descriptor)
            raise
        self._sealed_identity: dict[str, object] | None = None
        self._closed = False

    def __enter__(self) -> StableFileWitness:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        try:
            if exc_type is None:
                self.seal_after_extraction()
        finally:
            self.close()

    @property
    def proc_fd_path(self) -> Path:
        if self._closed:
            raise RootfsEvidenceError("Packed image witness is already closed")
        return Path(f"/proc/{os.getpid()}/fd/{self._descriptor}")

    @property
    def initial_identity(self) -> dict[str, object]:
        """Identity hashed from the pinned descriptor before consumer dispatch."""
        if self._closed:
            raise RootfsEvidenceError("File witness is already closed")
        return {
            "name": self.packed_image.name,
            "size": self._initial_stat.st_size,
            "sha256": self._initial_digest,
        }

    @property
    def sealed_identity(self) -> dict[str, object]:
        if self._sealed_identity is None:
            raise RootfsEvidenceError("Packed image witness has not been sealed after extraction")
        return dict(self._sealed_identity)

    def unpack_command(
        self,
        destination: Path,
        *,
        use_sudo: bool = True,
    ) -> CommandSpec:
        """Extract from the pinned FD; destination must not exist."""
        if destination.exists() or destination.is_symlink():
            raise RootfsEvidenceError(
                f"Packed rootfs extraction destination is not fresh: {destination}"
            )
        return CommandSpec(
            argv=sudo(
                (
                    "unsquashfs",
                    "-no-progress",
                    "-d",
                    str(destination),
                    str(self.proc_fd_path),
                ),
                use_sudo,
            ),
            needs_root=use_sudo,
            description="Extract witnessed packed rootfs into a fresh verification tree",
        )

    def seal_after_extraction(self) -> dict[str, object]:
        if self._sealed_identity is not None:
            return dict(self._sealed_identity)
        if self._closed:
            raise RootfsEvidenceError("Packed image witness is already closed")
        current = os.fstat(self._descriptor)
        if _stat_identity(self._initial_stat) != _stat_identity(current):
            raise RootfsChangedError("The witnessed packed-image inode changed during extraction")
        digest = _rehash_fd(self._descriptor, current, str(self.packed_image))
        if digest != self._initial_digest:
            raise RootfsChangedError("The witnessed packed-image bytes changed during extraction")

        try:
            path_descriptor = os.open(self.packed_image, _FILE_FLAGS)
        except OSError as exc:
            raise RootfsChangedError(
                f"The packed-image path disappeared after extraction: {exc}"
            ) from exc
        try:
            path_stat = os.fstat(path_descriptor)
            if (
                path_stat.st_dev != self._initial_stat.st_dev
                or path_stat.st_ino != self._initial_stat.st_ino
            ):
                raise RootfsChangedError(
                    "The packed-image path resolves to another inode after extraction"
                )
            path_digest = _rehash_fd(
                path_descriptor,
                path_stat,
                str(self.packed_image),
            )
        finally:
            os.close(path_descriptor)
        if path_digest != self._initial_digest:
            raise RootfsChangedError(
                "The packed-image path bytes differ from the extraction witness"
            )
        self._sealed_identity = {
            "name": self.packed_image.name,
            "size": self._initial_stat.st_size,
            "sha256": self._initial_digest,
        }
        return dict(self._sealed_identity)

    def close(self) -> None:
        if not self._closed:
            os.close(self._descriptor)
            self._closed = True


class PackedImageWitness(StableFileWitness):
    """Backward-compatible semantic name for a witnessed SquashFS image."""


class RootfsEvidenceService:
    """Seal a rootfs immediately before packing and prove it did not drift."""

    def __init__(
        self,
        root: Path,
        *,
        excluded_descendants: Iterable[str] = DEFAULT_EXCLUDED_DESCENDANTS,
        run_id: str | None = None,
    ) -> None:
        self.root = root.absolute()
        self.excluded_descendants = _normalise_exclusions(excluded_descendants)
        if run_id is not None and (not run_id or Path(run_id).name != run_id):
            raise RootfsEvidenceError(f"Unsafe rootfs evidence run_id: {run_id!r}")
        self.run_id = run_id

    def capture_before_packing(self, manifest_path: Path) -> dict[str, object]:
        """Write the immutable semantic identity and its host packing guard."""
        self._assert_external_path(manifest_path, "rootfs manifest")
        payload = self.snapshot()
        write_immutable_text(manifest_path, _json_text(payload))
        return payload

    def snapshot(self) -> dict[str, object]:
        """Return a stable two-pass snapshot without writing an artifact."""
        _assert_physical_root(self.root)
        _assert_unmounted(self.root)
        first = _scan_once(self.root, self.excluded_descendants)
        second = _scan_once(self.root, self.excluded_descendants)
        if first != second:
            raise RootfsChangedError(
                "The rootfs changed between the two identity scans; refusing an "
                "unstable pre-packing proof."
            )
        entries = list(second.entries)
        return {
            "schema": ROOTFS_MANIFEST_SCHEMA,
            "run_id": self.run_id,
            "scope": "mksquashfs-input",
            "digest": "sha256",
            "excluded_descendants": list(self.excluded_descendants),
            "object_count": len(entries),
            "tree_sha256": canonical_sha256(entries),
            "host_scan_guard_sha256": canonical_sha256(list(second.host_guards)),
            "entries": entries,
        }

    def verify_after_packing(
        self,
        manifest_path: Path,
        packed_image: Path,
        unpacked_image_root: Path,
        packed_image_witness: dict[str, object],
        verification_path: Path | None = None,
    ) -> RootfsPackingVerification:
        """Re-scan source and extracted image, bind bytes, and reject any drift."""
        self._assert_external_path(manifest_path, "rootfs manifest")
        self._assert_external_path(packed_image, "packed image")
        self._assert_disjoint_tree(unpacked_image_root, "unpacked packed image")
        if verification_path is not None:
            self._assert_external_path(verification_path, "rootfs verification")
            RootfsEvidenceService(unpacked_image_root)._assert_external_path(
                verification_path,
                "rootfs verification",
            )

        before = load_rootfs_manifest(manifest_path)
        if before.get("run_id") != self.run_id:
            raise RootfsEvidenceError("The rootfs manifest belongs to another build run")
        expected_exclusions = tuple(cast(list[str], before["excluded_descendants"]))
        if expected_exclusions != self.excluded_descendants:
            raise RootfsEvidenceError(
                "The rootfs manifest exclusion scope differs from the verifier scope"
            )

        after = self.snapshot()
        _validate_file_identity(packed_image_witness, "packed image witness")
        packed_identity = _stable_regular_file_identity(packed_image)
        packed_snapshot = RootfsEvidenceService(
            unpacked_image_root,
            excluded_descendants=self.excluded_descendants,
            run_id=self.run_id,
        ).snapshot()
        verification = _compare(
            before,
            after,
            packed_identity,
            packed_image_witness=packed_image_witness,
            packed_snapshot=packed_snapshot,
            require_packed_snapshot=True,
        )
        if verification_path is not None:
            write_immutable_text(
                verification_path,
                _json_text(verification.to_dict(before)),
            )
        if not verification.ok:
            raise RootfsChangedError(verification.detail, verification)
        return verification

    def _assert_external_path(self, path: Path, label: str) -> None:
        try:
            physical_root = self.root.resolve(strict=True)
            candidate = path.resolve(strict=False)
        except OSError as exc:
            raise RootfsEvidenceError(f"Cannot resolve the {label} boundary: {exc}") from exc
        try:
            candidate.relative_to(physical_root)
        except ValueError:
            return
        raise RootfsEvidenceError(
            f"The {label} must be outside the rootfs or writing it would alter the proof"
        )

    def _assert_disjoint_tree(self, other: Path, label: str) -> None:
        try:
            root = self.root.resolve(strict=True)
            candidate = other.resolve(strict=True)
        except OSError as exc:
            raise RootfsEvidenceError(f"Cannot resolve {label}: {exc}") from exc
        if _contains(root, candidate) or _contains(candidate, root):
            raise RootfsEvidenceError(f"The {label} must be disjoint from the source rootfs")


def rootfs_capture_command(
    root: Path,
    manifest_path: Path,
    *,
    run_id: str | None = None,
    excluded_descendants: Iterable[str] = DEFAULT_EXCLUDED_DESCENDANTS,
    use_sudo: bool = True,
    python: Path | None = None,
) -> CommandSpec:
    """Build the audited command that can read a protected final rootfs."""
    exclusions = _normalise_exclusions(excluded_descendants)
    exclusion_argv = (
        tuple(argument for exclusion in exclusions for argument in ("--exclude", exclusion))
        if exclusions
        else ("--no-default-exclusions",)
    )
    argv = (
        str(python or Path(sys.executable)),
        "-m",
        "distroforge.core.rootfs_evidence",
        "capture",
        "--root",
        str(root),
        "--manifest",
        str(manifest_path),
        *(("--run-id", run_id) if run_id is not None else ()),
        *exclusion_argv,
    )
    return CommandSpec(
        argv=sudo(argv, use_sudo),
        cwd=Path(__file__).resolve().parents[2],
        needs_root=use_sudo,
        description="Capture final rootfs identity before packing",
    )


def rootfs_verify_command(
    root: Path,
    manifest_path: Path,
    packed_image: Path,
    unpacked_image_root: Path,
    packed_image_witness: dict[str, object],
    verification_path: Path,
    *,
    run_id: str | None = None,
    excluded_descendants: Iterable[str] = DEFAULT_EXCLUDED_DESCENDANTS,
    use_sudo: bool = True,
    python: Path | None = None,
) -> CommandSpec:
    """Build the audited command that closes the post-packing boundary."""
    _validate_file_identity(packed_image_witness, "packed image witness")
    exclusions = _normalise_exclusions(excluded_descendants)
    exclusion_argv = (
        tuple(argument for exclusion in exclusions for argument in ("--exclude", exclusion))
        if exclusions
        else ("--no-default-exclusions",)
    )
    argv = (
        str(python or Path(sys.executable)),
        "-m",
        "distroforge.core.rootfs_evidence",
        "verify",
        "--root",
        str(root),
        "--manifest",
        str(manifest_path),
        "--packed-image",
        str(packed_image),
        "--unpacked-image-root",
        str(unpacked_image_root),
        "--packed-image-sha256",
        str(packed_image_witness["sha256"]),
        "--packed-image-size",
        str(packed_image_witness["size"]),
        "--packed-image-name",
        str(packed_image_witness["name"]),
        *(("--run-id", run_id) if run_id is not None else ()),
        "--verification",
        str(verification_path),
        *exclusion_argv,
    )
    return CommandSpec(
        argv=sudo(argv, use_sudo),
        cwd=Path(__file__).resolve().parents[2],
        needs_root=use_sudo,
        description="Verify final rootfs identity after packing",
    )


def rootfs_unpack_command(
    witness: PackedImageWitness,
    destination: Path,
    *,
    use_sudo: bool = True,
) -> CommandSpec:
    """Build the audited extraction command from the witness's pinned FD."""
    return witness.unpack_command(destination, use_sudo=use_sudo)


def load_rootfs_manifest(path: Path) -> dict[str, object]:
    """Load and structurally validate a rootfs manifest before trusting it."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RootfsEvidenceError(f"Rootfs manifest is unreadable: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema") != ROOTFS_MANIFEST_SCHEMA:
        raise RootfsEvidenceError("Rootfs manifest has an unsupported schema")
    if set(payload) != {
        "schema",
        "run_id",
        "scope",
        "digest",
        "excluded_descendants",
        "object_count",
        "tree_sha256",
        "host_scan_guard_sha256",
        "entries",
    }:
        raise RootfsEvidenceError("Rootfs manifest fields are not canonical")
    run_id = payload.get("run_id")
    if run_id is not None and (
        not isinstance(run_id, str) or not run_id or Path(run_id).name != run_id
    ):
        raise RootfsEvidenceError("Rootfs manifest run identity is malformed")

    entries = payload.get("entries")
    exclusions = payload.get("excluded_descendants")
    if not isinstance(entries, list) or not all(isinstance(item, dict) for item in entries):
        raise RootfsEvidenceError("Rootfs manifest entries are malformed")
    if not isinstance(exclusions, list) or not all(isinstance(item, str) for item in exclusions):
        raise RootfsEvidenceError("Rootfs manifest exclusions are malformed")
    try:
        normalised = _normalise_exclusions(exclusions)
    except ValueError as exc:
        raise RootfsEvidenceError(str(exc)) from exc
    if list(normalised) != exclusions:
        raise RootfsEvidenceError("Rootfs manifest exclusions are not canonical")

    paths = [item.get("path") for item in entries]
    if not paths or paths[0] != "." or not all(isinstance(item, str) for item in paths):
        raise RootfsEvidenceError("Rootfs manifest paths are malformed")
    canonical_paths = cast(list[str], paths)
    if canonical_paths != sorted(canonical_paths, key=_path_key) or len(canonical_paths) != len(
        set(canonical_paths)
    ):
        raise RootfsEvidenceError("Rootfs manifest paths are not unique and canonical")
    if any(not _safe_relative_path(item) for item in canonical_paths):
        raise RootfsEvidenceError("Rootfs manifest contains an unsafe path")
    if payload.get("object_count") != len(entries):
        raise RootfsEvidenceError("Rootfs manifest object count is inconsistent")
    if payload.get("scope") != "mksquashfs-input" or payload.get("digest") != "sha256":
        raise RootfsEvidenceError("Rootfs manifest digest contract is malformed")
    for entry in entries:
        _validate_entry(entry)
    if entries[0].get("type") != "directory":
        raise RootfsEvidenceError("Rootfs manifest root entry is not a directory")
    _validate_hardlinks(entries)
    for entry_path in canonical_paths[1:]:
        if any(
            entry_path != exclusion and entry_path.startswith(f"{exclusion}/")
            for exclusion in exclusions
        ):
            raise RootfsEvidenceError(f"Rootfs manifest includes excluded descendant {entry_path}")
    if payload.get("tree_sha256") != canonical_sha256(entries):
        raise RootfsEvidenceError("Rootfs manifest semantic digest is inconsistent")
    guard = payload.get("host_scan_guard_sha256")
    if not isinstance(guard, str) or not _is_sha256(guard):
        raise RootfsEvidenceError("Rootfs manifest host scan guard is malformed")
    return payload


def validate_rootfs_evidence(
    run_dir: Path,
    *,
    expected_run_id: str,
) -> RootfsEvidenceValidation:
    """Validate the immutable pre-pack and packed-product proof offline.

    This validates the recorded evidence itself.  It deliberately does not claim
    that arbitrary SquashFS bytes still contain that tree; an authoritative
    product refresh must unpack the product and call
    :func:`validate_replayed_rootfs_manifest`.
    """
    if not expected_run_id or Path(expected_run_id).name != expected_run_id:
        return RootfsEvidenceValidation(False, "expected rootfs run_id is unsafe")
    manifest_path = run_dir / "ROOTFS-MANIFEST.json"
    verification_path = run_dir / "ROOTFS-PACKING-VERIFICATION.json"
    if manifest_path.is_symlink() or verification_path.is_symlink():
        return RootfsEvidenceValidation(False, "rootfs evidence uses a symlink")
    try:
        manifest = load_rootfs_manifest(manifest_path)
        verification = json.loads(verification_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, RootfsEvidenceError) as exc:
        return RootfsEvidenceValidation(False, f"rootfs evidence is unreadable: {exc}")
    if manifest.get("run_id") != expected_run_id:
        return RootfsEvidenceValidation(False, "rootfs manifest belongs to another run")
    if not isinstance(verification, dict) or set(verification) != {
        "schema",
        "run_id",
        "status",
        "detail",
        "manifest",
        "after_packing",
        "drift",
        "packed_image",
        "packed_rootfs",
    }:
        return RootfsEvidenceValidation(False, "rootfs verification fields are malformed")
    if (
        verification.get("schema") != ROOTFS_PACKING_VERIFICATION_SCHEMA
        or verification.get("run_id") != expected_run_id
        or verification.get("status") != "verified"
    ):
        return RootfsEvidenceValidation(False, "rootfs verification did not close this run")

    manifest_binding = verification.get("manifest")
    after = verification.get("after_packing")
    drift = verification.get("drift")
    image = verification.get("packed_image")
    packed = verification.get("packed_rootfs")
    if (
        not isinstance(manifest_binding, dict)
        or set(manifest_binding)
        != {
            "schema",
            "tree_sha256",
            "host_scan_guard_sha256",
            "object_count",
        }
        or manifest_binding.get("schema") != ROOTFS_MANIFEST_SCHEMA
        or manifest_binding.get("tree_sha256") != manifest.get("tree_sha256")
        or manifest_binding.get("host_scan_guard_sha256") != manifest.get("host_scan_guard_sha256")
        or manifest_binding.get("object_count") != manifest.get("object_count")
    ):
        return RootfsEvidenceValidation(False, "verification does not bind the rootfs manifest")
    if (
        not isinstance(after, dict)
        or set(after) != {"tree_sha256", "host_scan_guard_sha256"}
        or after.get("tree_sha256") != manifest.get("tree_sha256")
        or after.get("host_scan_guard_sha256") != manifest.get("host_scan_guard_sha256")
    ):
        return RootfsEvidenceValidation(False, "source rootfs drifted across packing")
    if (
        not isinstance(drift, dict)
        or set(drift)
        != {
            "added",
            "removed",
            "changed",
            "host_identity_changed",
        }
        or drift.get("added") != []
        or drift.get("removed") != []
        or drift.get("changed") != []
        or drift.get("host_identity_changed") is not False
    ):
        return RootfsEvidenceValidation(False, "rootfs drift report is not closed")
    if (
        not isinstance(image, dict)
        or set(image) != {"witness", "after_extraction", "matches_witness"}
        or image.get("matches_witness") is not True
        or not isinstance(image.get("witness"), dict)
        or not isinstance(image.get("after_extraction"), dict)
        or image["witness"] != image["after_extraction"]
    ):
        return RootfsEvidenceValidation(False, "packed image does not match its FD witness")
    try:
        _validate_file_identity(
            cast(dict[str, object], image["witness"]),
            "packed image witness",
        )
    except RootfsEvidenceError as exc:
        return RootfsEvidenceValidation(False, str(exc))
    if (
        not isinstance(packed, dict)
        or set(packed)
        != {
            "tree_sha256",
            "matches_manifest",
            "added",
            "removed",
            "changed",
        }
        or packed.get("matches_manifest") is not True
        or packed.get("tree_sha256") != manifest.get("tree_sha256")
        or packed.get("added") != []
        or packed.get("removed") != []
        or packed.get("changed") != []
    ):
        return RootfsEvidenceValidation(
            False, "extracted SquashFS differs from the rootfs manifest"
        )
    return RootfsEvidenceValidation(
        True,
        f"rootfs manifest and packed product verified for run {expected_run_id}",
    )


def validate_replayed_rootfs_manifest(
    manifest_path: Path,
    replay_manifest_path: Path,
    *,
    expected_run_id: str,
) -> RootfsEvidenceValidation:
    """Compare an independently unpacked rootfs with the sealed semantic manifest.

    ``replay_manifest_path`` must have been captured from a fresh extraction of the
    product, not copied from the evidence directory.  Host inode/timestamp guards
    necessarily differ after extraction, so the comparison is exact over the
    portable semantic contract: exclusion scope, object count, canonical entries
    and their aggregate SHA256.
    """
    if not expected_run_id or Path(expected_run_id).name != expected_run_id:
        return RootfsEvidenceValidation(False, "expected rootfs replay run_id is unsafe")
    if manifest_path.is_symlink() or replay_manifest_path.is_symlink():
        return RootfsEvidenceValidation(False, "rootfs replay evidence uses a symlink")
    try:
        expected = load_rootfs_manifest(manifest_path)
        replayed = load_rootfs_manifest(replay_manifest_path)
    except RootfsEvidenceError as exc:
        return RootfsEvidenceValidation(False, f"rootfs replay manifest is unreadable: {exc}")
    if (
        expected.get("run_id") != expected_run_id
        or replayed.get("run_id") != expected_run_id
    ):
        return RootfsEvidenceValidation(False, "rootfs replay belongs to another run")
    semantic_fields = (
        "scope",
        "digest",
        "excluded_descendants",
        "object_count",
        "tree_sha256",
        "entries",
    )
    differing = [
        field for field in semantic_fields if expected.get(field) != replayed.get(field)
    ]
    if differing:
        return RootfsEvidenceValidation(
            False,
            "authoritative SquashFS replay differs from ROOTFS-MANIFEST.json: "
            + ", ".join(differing),
        )
    return RootfsEvidenceValidation(
        True,
        f"authoritative SquashFS replay matches the rootfs manifest for run {expected_run_id}",
    )


def _scan_once(root: Path, exclusions: tuple[str, ...]) -> _Scan:
    if root.is_symlink():
        raise RootfsEvidenceError("The rootfs path itself must not be a symlink")
    try:
        root_fd = os.open(root, _DIRECTORY_FLAGS)
    except OSError as exc:
        raise RootfsEvidenceError(f"Cannot open rootfs {root}: {exc}") from exc

    entries: list[dict[str, object]] = []
    guards: list[dict[str, object]] = []
    hardlinks: dict[tuple[int, int], list[str]] = defaultdict(list)
    try:
        root_stat = os.fstat(root_fd)
        entries.append(_entry(".", root_stat, _xattrs_fd(root_fd)))
        guards.append(_host_guard(".", root_stat))
        _walk_directory(
            root_fd,
            PurePosixPath("."),
            root_stat.st_dev,
            exclusions,
            entries,
            guards,
            hardlinks,
        )
        if _stat_identity(root_stat) != _stat_identity(os.fstat(root_fd)):
            raise RootfsChangedError("The rootfs directory changed while it was scanned")
    finally:
        os.close(root_fd)

    by_path = {str(item["path"]): item for item in entries}
    for paths in hardlinks.values():
        ordered = sorted(paths, key=_path_key)
        entry = by_path[ordered[0]]
        raw_link_count = entry["link_count"]
        if not isinstance(raw_link_count, int):
            raise RootfsEvidenceError(f"Malformed link count while scanning {ordered[0]}")
        expected = raw_link_count
        if expected != len(ordered):
            raise RootfsEvidenceError(
                f"Regular file hardlink group escapes the packing scope: {ordered[0]} "
                f"has link_count={expected}, observed={len(ordered)}"
            )
        if len(ordered) > 1:
            for path in ordered:
                by_path[path]["hardlink_master"] = ordered[0]

    entries.sort(key=lambda item: _path_key(str(item["path"])))
    guards.sort(key=lambda item: _path_key(str(item["path"])))
    return _Scan(tuple(entries), tuple(guards))


def _walk_directory(
    directory_fd: int,
    parent: PurePosixPath,
    root_device: int,
    exclusions: tuple[str, ...],
    entries: list[dict[str, object]],
    guards: list[dict[str, object]],
    hardlinks: dict[tuple[int, int], list[str]],
) -> None:
    try:
        with os.scandir(directory_fd) as iterator:
            names = sorted((item.name for item in iterator), key=os.fsencode)
    except OSError as exc:
        raise RootfsEvidenceError(f"Cannot list rootfs path {parent}: {exc}") from exc

    for name in names:
        relative = PurePosixPath(name) if parent == PurePosixPath(".") else parent / name
        path_text = relative.as_posix()
        try:
            initial = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            raise RootfsChangedError(f"Cannot stat rootfs path {path_text}: {exc}") from exc

        if stat.S_ISDIR(initial.st_mode):
            _scan_directory_entry(
                directory_fd,
                name,
                relative,
                initial,
                root_device,
                exclusions,
                entries,
                guards,
                hardlinks,
            )
            continue
        if stat.S_ISREG(initial.st_mode):
            file_fd = _open_stable_entry(directory_fd, name, initial, _FILE_FLAGS, path_text)
            try:
                current = os.fstat(file_fd)
                digest = _hash_fd(file_fd, current, path_text)
                item = _entry(path_text, current, _xattrs_fd(file_fd))
                item["size"] = current.st_size
                item["sha256"] = digest
                entries.append(item)
                guards.append(_host_guard(path_text, current))
                hardlinks[(current.st_dev, current.st_ino)].append(path_text)
            finally:
                os.close(file_fd)
            continue

        target: str | None = None
        if stat.S_ISLNK(initial.st_mode):
            try:
                target = os.readlink(name, dir_fd=directory_fd)
            except OSError as exc:
                raise RootfsChangedError(f"Cannot read rootfs symlink {path_text}: {exc}") from exc
        xattrs = _xattrs_relative(directory_fd, name, path_text)
        try:
            final = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            raise RootfsChangedError(
                f"Rootfs path disappeared during scan: {path_text}: {exc}"
            ) from exc
        if _stat_identity(initial) != _stat_identity(final):
            raise RootfsChangedError(f"Rootfs path changed during scan: {path_text}")
        item = _entry(path_text, final, xattrs)
        if target is not None:
            item["target"] = target
        entries.append(item)
        guards.append(_host_guard(path_text, final))


def _scan_directory_entry(
    parent_fd: int,
    name: str,
    relative: PurePosixPath,
    initial: os.stat_result,
    root_device: int,
    exclusions: tuple[str, ...],
    entries: list[dict[str, object]],
    guards: list[dict[str, object]],
    hardlinks: dict[tuple[int, int], list[str]],
) -> None:
    path_text = relative.as_posix()
    child_fd = _open_stable_entry(parent_fd, name, initial, _DIRECTORY_FLAGS, path_text)
    try:
        current = os.fstat(child_fd)
        entries.append(_entry(path_text, current, _xattrs_fd(child_fd)))
        guards.append(_host_guard(path_text, current))
        if not _excluded(path_text, exclusions):
            if current.st_dev != root_device:
                raise RootfsEvidenceError(
                    f"Rootfs path crosses onto another filesystem: {path_text}"
                )
            _walk_directory(
                child_fd,
                relative,
                root_device,
                exclusions,
                entries,
                guards,
                hardlinks,
            )
        if _stat_identity(current) != _stat_identity(os.fstat(child_fd)):
            raise RootfsChangedError(f"Rootfs directory changed during scan: {path_text}")
    finally:
        os.close(child_fd)


def _open_stable_entry(
    parent_fd: int,
    name: str,
    expected: os.stat_result,
    flags: int,
    path_text: str,
) -> int:
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise RootfsChangedError(
            f"Cannot open rootfs path without following links: {path_text}: {exc}"
        ) from exc
    if _stat_identity(expected) != _stat_identity(os.fstat(descriptor)):
        os.close(descriptor)
        raise RootfsChangedError(f"Rootfs path changed before it was opened: {path_text}")
    return descriptor


def _hash_fd(descriptor: int, before: os.stat_result, path_text: str) -> str:
    digest = hashlib.sha256()
    while True:
        chunk = os.read(descriptor, _CHUNK)
        if not chunk:
            break
        digest.update(chunk)
    after = os.fstat(descriptor)
    if _stat_identity(before) != _stat_identity(after):
        raise RootfsChangedError(f"Rootfs file changed while hashed: {path_text}")
    return digest.hexdigest()


def _rehash_fd(descriptor: int, before: os.stat_result, path_text: str) -> str:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
    except OSError as exc:
        raise RootfsEvidenceError(f"Cannot rewind regular file witness {path_text}: {exc}") from exc
    return _hash_fd(descriptor, before, path_text)


def _entry(path: str, metadata: os.stat_result, xattrs: list[dict[str, str]]) -> dict[str, object]:
    item: dict[str, object] = {
        "path": path,
        "type": _file_type(metadata.st_mode),
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "link_count": metadata.st_nlink,
        "xattrs": xattrs,
    }
    if stat.S_ISCHR(metadata.st_mode) or stat.S_ISBLK(metadata.st_mode):
        item["device"] = {
            "major": os.major(metadata.st_rdev),
            "minor": os.minor(metadata.st_rdev),
        }
    return item


def _host_guard(path: str, metadata: os.stat_result) -> dict[str, object]:
    return {
        "path": path,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "ctime_ns": metadata.st_ctime_ns,
        "mtime_ns": metadata.st_mtime_ns,
    }


def _xattrs_fd(descriptor: int) -> list[dict[str, str]]:
    try:
        names = os.listxattr(descriptor)
    except OSError as exc:
        raise RootfsEvidenceError(f"Cannot list rootfs extended attributes: {exc}") from exc
    values: list[dict[str, str]] = []
    for name in sorted(names, key=os.fsencode):
        try:
            value = os.getxattr(descriptor, name)
        except OSError as exc:
            raise RootfsEvidenceError(
                f"Cannot read rootfs extended attribute {name!r}: {exc}"
            ) from exc
        values.append(
            {
                "name": name,
                "value_base64": base64.b64encode(value).decode("ascii"),
            }
        )
    return values


def _xattrs_relative(parent_fd: int, name: str, path_text: str) -> list[dict[str, str]]:
    proc_path = Path(f"/proc/self/fd/{parent_fd}") / name
    try:
        names = os.listxattr(proc_path, follow_symlinks=False)
    except OSError as exc:
        raise RootfsEvidenceError(
            f"Cannot list rootfs extended attributes for {path_text}: {exc}"
        ) from exc
    values: list[dict[str, str]] = []
    for attribute in sorted(names, key=os.fsencode):
        try:
            value = os.getxattr(proc_path, attribute, follow_symlinks=False)
        except OSError as exc:
            raise RootfsEvidenceError(
                f"Cannot read rootfs extended attribute {attribute!r} for {path_text}: {exc}"
            ) from exc
        values.append(
            {
                "name": attribute,
                "value_base64": base64.b64encode(value).decode("ascii"),
            }
        )
    return values


def _stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
        value.st_rdev,
    )


def _file_type(mode: int) -> str:
    if stat.S_ISREG(mode):
        return "regular"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISCHR(mode):
        return "character-device"
    if stat.S_ISBLK(mode):
        return "block-device"
    if stat.S_ISSOCK(mode):
        return "socket"
    raise RootfsEvidenceError(f"Unsupported rootfs object type: mode={mode:#o}")


def _validate_entry(entry: dict[str, object]) -> None:
    common = {"path", "type", "mode", "uid", "gid", "link_count", "xattrs"}
    kind = entry.get("type")
    expected = set(common)
    if kind == "regular":
        expected.update({"size", "sha256"})
        if "hardlink_master" in entry:
            expected.add("hardlink_master")
    elif kind == "symlink":
        expected.add("target")
    elif kind in {"character-device", "block-device"}:
        expected.add("device")
    elif kind not in {"directory", "fifo", "socket"}:
        raise RootfsEvidenceError(f"Rootfs manifest has invalid object type {kind!r}")
    if set(entry) != expected:
        raise RootfsEvidenceError(f"Rootfs manifest entry {entry.get('path')!r} has invalid fields")

    mode = entry.get("mode")
    if (
        not isinstance(mode, str)
        or len(mode) != 4
        or any(character not in "01234567" for character in mode)
    ):
        raise RootfsEvidenceError("Rootfs manifest contains an invalid mode")
    for field in ("uid", "gid"):
        value = entry.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise RootfsEvidenceError(f"Rootfs manifest contains an invalid {field}")
    link_count = entry.get("link_count")
    if not isinstance(link_count, int) or isinstance(link_count, bool) or link_count < 1:
        raise RootfsEvidenceError("Rootfs manifest contains an invalid link count")
    _validate_xattrs(entry.get("xattrs"))

    if kind == "regular":
        size = entry.get("size")
        digest = entry.get("sha256")
        master = entry.get("hardlink_master")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise RootfsEvidenceError("Rootfs manifest contains an invalid file size")
        if not isinstance(digest, str) or not _is_sha256(digest):
            raise RootfsEvidenceError("Rootfs manifest contains an invalid file digest")
        if master is not None and not _safe_relative_path(master):
            raise RootfsEvidenceError("Rootfs manifest contains an invalid hardlink master")
    elif kind == "symlink" and not isinstance(entry.get("target"), str):
        raise RootfsEvidenceError("Rootfs manifest contains an invalid symlink target")
    elif kind in {"character-device", "block-device"}:
        device = entry.get("device")
        if not isinstance(device, dict) or set(device) != {"major", "minor"}:
            raise RootfsEvidenceError("Rootfs manifest contains invalid device metadata")
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in device.values()
        ):
            raise RootfsEvidenceError("Rootfs manifest contains invalid device numbers")


def _validate_xattrs(value: object) -> None:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise RootfsEvidenceError("Rootfs manifest extended attributes are malformed")
    names: list[str] = []
    for raw in value:
        if set(raw) != {"name", "value_base64"}:
            raise RootfsEvidenceError("Rootfs manifest extended attribute is malformed")
        name = raw.get("name")
        encoded = raw.get("value_base64")
        if not isinstance(name, str) or not isinstance(encoded, str):
            raise RootfsEvidenceError("Rootfs manifest extended attribute is malformed")
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except ValueError as exc:
            raise RootfsEvidenceError(
                "Rootfs manifest extended attribute is not canonical base64"
            ) from exc
        if base64.b64encode(decoded).decode("ascii") != encoded:
            raise RootfsEvidenceError("Rootfs manifest extended attribute is not canonical base64")
        names.append(name)
    if names != sorted(names, key=os.fsencode) or len(names) != len(set(names)):
        raise RootfsEvidenceError(
            "Rootfs manifest extended attributes are not unique and canonical"
        )


def _validate_hardlinks(entries: list[dict[str, object]]) -> None:
    regular = {str(entry["path"]): entry for entry in entries if entry.get("type") == "regular"}
    groups: dict[str, list[dict[str, object]]] = defaultdict(list)
    for entry in regular.values():
        count = entry["link_count"]
        master = entry.get("hardlink_master")
        if count == 1 and master is not None:
            raise RootfsEvidenceError("Single-link file declares a hardlink master")
        if count != 1 and not isinstance(master, str):
            raise RootfsEvidenceError("Hardlinked file is missing its canonical master")
        if isinstance(master, str):
            groups[master].append(entry)
    for master, members in groups.items():
        paths = sorted((str(item["path"]) for item in members), key=_path_key)
        if master != paths[0] or master not in regular:
            raise RootfsEvidenceError("Hardlink group has a non-canonical master")
        if any(item["link_count"] != len(members) for item in members):
            raise RootfsEvidenceError("Hardlink group count is inconsistent")
        comparable = {
            key: value
            for key, value in members[0].items()
            if key not in {"path", "hardlink_master"}
        }
        if any(
            {key: value for key, value in item.items() if key not in {"path", "hardlink_master"}}
            != comparable
            for item in members[1:]
        ):
            raise RootfsEvidenceError("Hardlink group metadata is inconsistent")


def _compare(
    before: dict[str, object],
    after: dict[str, object],
    packed_image: dict[str, object] | None,
    *,
    packed_image_witness: dict[str, object] | None = None,
    packed_snapshot: dict[str, object] | None = None,
    require_packed_snapshot: bool = False,
) -> RootfsPackingVerification:
    before_items = cast(list[dict[str, object]], before["entries"])
    after_items = cast(list[dict[str, object]], after["entries"])
    before_entries = {
        str(item["path"]): item
        for item in before_items
        if isinstance(item, dict) and "path" in item
    }
    after_entries = {
        str(item["path"]): item for item in after_items if isinstance(item, dict) and "path" in item
    }
    added = tuple(sorted(set(after_entries) - set(before_entries), key=_path_key))
    removed = tuple(sorted(set(before_entries) - set(after_entries), key=_path_key))
    changed = tuple(
        sorted(
            (
                path
                for path in set(before_entries) & set(after_entries)
                if before_entries[path] != after_entries[path]
            ),
            key=_path_key,
        )
    )
    before_tree = str(before["tree_sha256"])
    after_tree = str(after["tree_sha256"])
    before_guard = str(before["host_scan_guard_sha256"])
    after_guard = str(after["host_scan_guard_sha256"])
    source_ok = (
        before_tree == after_tree
        and before_guard == after_guard
        and not added
        and not removed
        and not changed
    )
    packed_tree: str | None = None
    packed_added: tuple[str, ...] = ()
    packed_removed: tuple[str, ...] = ()
    packed_changed: tuple[str, ...] = ()
    if packed_snapshot is not None:
        packed_items = cast(list[dict[str, object]], packed_snapshot["entries"])
        packed_entries = {
            str(item["path"]): item
            for item in packed_items
            if isinstance(item, dict) and "path" in item
        }
        packed_added = tuple(sorted(set(packed_entries) - set(before_entries), key=_path_key))
        packed_removed = tuple(sorted(set(before_entries) - set(packed_entries), key=_path_key))
        packed_changed = tuple(
            sorted(
                (
                    path
                    for path in set(before_entries) & set(packed_entries)
                    if before_entries[path] != packed_entries[path]
                ),
                key=_path_key,
            )
        )
        packed_tree = str(packed_snapshot["tree_sha256"])
    packed_ok = (
        packed_snapshot is not None
        and packed_tree == before_tree
        and not packed_added
        and not packed_removed
        and not packed_changed
    )
    image_matches_witness = (
        packed_image is not None
        and packed_image_witness is not None
        and packed_image == packed_image_witness
    )
    ok = source_ok and ((packed_ok and image_matches_witness) or not require_packed_snapshot)
    detail = (
        "Rootfs source remained unchanged and the packed tree matches its manifest."
        if ok
        else "Rootfs drifted across packing: "
        f"added={len(added)}, removed={len(removed)}, changed={len(changed)}, "
        f"host_identity_changed={before_guard != after_guard}, "
        f"packed_added={len(packed_added)}, packed_removed={len(packed_removed)}, "
        f"packed_changed={len(packed_changed)}, packed_tree_missing="
        f"{require_packed_snapshot and packed_snapshot is None}, "
        f"packed_image_matches_witness={image_matches_witness}."
    )
    return RootfsPackingVerification(
        ok=ok,
        detail=detail,
        before_tree_sha256=before_tree,
        after_tree_sha256=after_tree,
        before_host_guard_sha256=before_guard,
        after_host_guard_sha256=after_guard,
        added=added,
        removed=removed,
        changed=changed,
        packed_image=packed_image,
        packed_image_witness=packed_image_witness,
        packed_image_matches_witness=image_matches_witness,
        packed_tree_sha256=packed_tree,
        packed_added=packed_added,
        packed_removed=packed_removed,
        packed_changed=packed_changed,
    )


def _stable_regular_file_identity(path: Path) -> dict[str, object]:
    try:
        descriptor = os.open(path, _FILE_FLAGS)
    except OSError as exc:
        raise RootfsEvidenceError(f"Cannot open packed image {path}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise RootfsEvidenceError(f"Packed image is not a regular file: {path}")
        digest = _rehash_fd(descriptor, before, str(path))
        return {
            "name": path.name,
            "size": before.st_size,
            "sha256": digest,
        }
    finally:
        os.close(descriptor)


def _validate_file_identity(value: dict[str, object], label: str) -> None:
    if set(value) != {"name", "size", "sha256"}:
        raise RootfsEvidenceError(f"{label} fields are malformed")
    name = value.get("name")
    size = value.get("size")
    digest = value.get("sha256")
    if (
        not isinstance(name, str)
        or not name
        or Path(name).name != name
        or not isinstance(size, int)
        or isinstance(size, bool)
        or size < 0
        or not isinstance(digest, str)
        or not _is_sha256(digest)
    ):
        raise RootfsEvidenceError(f"{label} is malformed")


def _assert_unmounted(root: Path) -> None:
    mounted = _mounts_under_strict(root)
    if mounted:
        raise RootfsEvidenceError(
            "Refusing to attest a rootfs with mounted filesystems: " + ", ".join(sorted(mounted))
        )


def _contains(parent: Path, child: Path) -> bool:
    try:
        child.relative_to(parent)
    except ValueError:
        return False
    return True


def _assert_physical_root(root: Path) -> None:
    try:
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise RootfsEvidenceError(f"Cannot resolve rootfs {root}: {exc}") from exc
    if resolved != root:
        raise RootfsEvidenceError(
            f"The sealed rootfs path contains a symlink component: {root} -> {resolved}"
        )


def _mounts_under_strict(root: Path) -> list[str]:
    try:
        mountinfo = Path("/proc/self/mountinfo").read_text(encoding="utf-8")
    except OSError as exc:
        raise RootfsEvidenceError(
            f"Cannot prove the rootfs is unmounted without /proc/self/mountinfo: {exc}"
        ) from exc
    base = str(root)
    prefix = f"{base.rstrip('/')}/"
    found: list[str] = []
    for line in mountinfo.splitlines():
        fields = line.split(" ")
        if len(fields) < 5:
            raise RootfsEvidenceError("Malformed /proc/self/mountinfo entry")
        point = _unescape_mountinfo(fields[4])
        if point == base or point.startswith(prefix):
            found.append(point)
    return found


def _unescape_mountinfo(value: str) -> str:
    for escaped, literal in (
        ("\\040", " "),
        ("\\011", "\t"),
        ("\\012", "\n"),
        ("\\134", "\\"),
    ):
        value = value.replace(escaped, literal)
    return value


def _normalise_exclusions(values: Iterable[str]) -> tuple[str, ...]:
    normalised: set[str] = set()
    for value in values:
        path = PurePosixPath(value)
        text = path.as_posix()
        if not _safe_relative_path(text) or text == ".":
            raise ValueError(f"Unsafe rootfs exclusion: {value!r}")
        normalised.add(text)
    return tuple(sorted(normalised, key=_path_key))


def _safe_relative_path(value: object) -> bool:
    if not isinstance(value, str) or not value or value.startswith("/"):
        return False
    path = PurePosixPath(value)
    return not any(part in {"", ".."} for part in path.parts)


def _excluded(path: str, exclusions: tuple[str, ...]) -> bool:
    return path in exclusions


def _path_key(value: str) -> bytes:
    return os.fsencode(value)


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _json_text(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m distroforge.core.rootfs_evidence")
    subcommands = parser.add_subparsers(dest="operation", required=True)
    capture = subcommands.add_parser("capture")
    capture.add_argument("--root", type=Path, required=True)
    capture.add_argument("--manifest", type=Path, required=True)
    capture.add_argument("--run-id")
    capture_scope = capture.add_mutually_exclusive_group()
    capture_scope.add_argument("--exclude", action="append", default=None)
    capture_scope.add_argument("--no-default-exclusions", action="store_true")
    verify = subcommands.add_parser("verify")
    verify.add_argument("--root", type=Path, required=True)
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--packed-image", type=Path, required=True)
    verify.add_argument("--unpacked-image-root", type=Path, required=True)
    verify.add_argument("--packed-image-sha256", required=True)
    verify.add_argument("--packed-image-size", type=int, required=True)
    verify.add_argument("--packed-image-name", required=True)
    verify.add_argument("--verification", type=Path, required=True)
    verify.add_argument("--run-id")
    verify_scope = verify.add_mutually_exclusive_group()
    verify_scope.add_argument("--exclude", action="append", default=None)
    verify_scope.add_argument("--no-default-exclusions", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Privileged helper entrypoint; all host dispatch still goes through CommandRunner."""
    arguments = _argument_parser().parse_args(argv)
    if arguments.no_default_exclusions:
        exclusions: Iterable[str] = ()
    elif arguments.exclude is not None:
        exclusions = arguments.exclude
    else:
        exclusions = DEFAULT_EXCLUDED_DESCENDANTS
    service = RootfsEvidenceService(
        arguments.root,
        excluded_descendants=exclusions,
        run_id=arguments.run_id,
    )
    try:
        if arguments.operation == "capture":
            service.capture_before_packing(arguments.manifest)
        else:
            image_witness = {
                "name": arguments.packed_image_name,
                "size": arguments.packed_image_size,
                "sha256": arguments.packed_image_sha256,
            }
            service.verify_after_packing(
                arguments.manifest,
                arguments.packed_image,
                arguments.unpacked_image_root,
                image_witness,
                arguments.verification,
            )
    except RootfsEvidenceError as exc:
        print(f"rootfs evidence refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
