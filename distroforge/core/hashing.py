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
from pathlib import Path

_CHUNK = 1024 * 1024


def sha256_file(path: Path) -> str:
    """Return the SHA-256 hex digest of the bytes opened for this invocation."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_from_sums(sums: Path, name: str) -> str | None:
    """Return the digest ``sums`` records for ``name``, or None when absent.

    This is the sidecar side of the same question: it answers from the
    ``SHA256SUMS`` a build already wrote instead of re-reading the artifact, the
    way :func:`html_report._sha256_text` does for the HTML report.
    """
    for line in sums.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split()
        if len(parts) >= 2 and Path(parts[-1]).name == name:
            return parts[0]
    return None
