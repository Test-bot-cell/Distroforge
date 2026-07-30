"""Canonical SHA-256 helpers for the artifact chain.

Digests are deliberately recomputed from the file bytes on every call.  A
persistent cache keyed by path, size, and mtime can return a digest for an inode
that has since been atomically replaced with different, same-size bytes while
its timestamp is restored.  Safe reuse belongs to a bounded verification
session that keeps the verified file descriptor open; this low-level fallback
therefore never reuses a result across calls.
"""

from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath

from .artifact_verification import ArtifactVerificationSession

_CHUNK = 1024 * 1024
MAX_SHA256_SUMS_BYTES = 1024 * 1024


def sha256_file(path: Path) -> str:
    """Return the SHA-256 hex digest of the bytes opened for this invocation."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_sha256_sums(data: bytes) -> dict[str, str]:
    """Parse one canonical GNU-style text SHA256SUMS payload.

    Only lower-case SHA-256, the two-space text separator, canonical relative
    POSIX paths, unique entries, strict UTF-8, and LF line endings are accepted.
    """
    if not data or len(data) > MAX_SHA256_SUMS_BYTES or not data.endswith(b"\n"):
        raise ValueError("SHA256SUMS is empty, oversized, or lacks a final LF")
    if b"\r" in data or b"\x00" in data:
        raise ValueError("SHA256SUMS contains a forbidden control byte")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ValueError("SHA256SUMS is not strict UTF-8") from exc
    entries: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        if len(line) < 67 or line[64:66] != "  ":
            raise ValueError(f"SHA256SUMS line {line_number} is not canonical")
        digest = line[:64]
        name = line[66:]
        if (
            any(character not in "0123456789abcdef" for character in digest)
            or not name
            or "\\" in name
        ):
            raise ValueError(f"SHA256SUMS line {line_number} is malformed")
        path = PurePosixPath(name)
        if (
            path.is_absolute()
            or any(part in {"", ".", ".."} for part in path.parts)
            or path.as_posix() != name
        ):
            raise ValueError(
                f"SHA256SUMS line {line_number} has a non-canonical path"
            )
        if name in entries:
            raise ValueError(f"SHA256SUMS duplicates {name}")
        entries[name] = digest
    return entries


def sha256_from_sums_bytes(data: bytes, name: str) -> str | None:
    """Return the unique canonical digest recorded for exactly ``name``."""
    return parse_sha256_sums(data).get(name)


def sha256_from_sums(
    sums: Path,
    name: str,
    *,
    max_bytes: int = MAX_SHA256_SUMS_BYTES,
) -> str | None:
    """Return the digest ``sums`` records for ``name``, or None when absent.

    This is the sidecar side of the same question: it answers from the
    ``SHA256SUMS`` a build already wrote instead of re-reading the artifact, the
    way :func:`html_report._sha256_text` does for the HTML report.
    """
    if max_bytes <= 0 or max_bytes > MAX_SHA256_SUMS_BYTES:
        raise ValueError("SHA256SUMS byte limit is invalid")
    with ArtifactVerificationSession(Path("/"), label="SHA256SUMS reader") as session:
        data = session.file_path(
            sums.absolute(),
            label="SHA256SUMS",
            max_bytes=max_bytes,
        ).read_bytes()
        return sha256_from_sums_bytes(data, name)


__all__ = [
    "MAX_SHA256_SUMS_BYTES",
    "parse_sha256_sums",
    "sha256_file",
    "sha256_from_sums",
    "sha256_from_sums_bytes",
]
