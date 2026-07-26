"""One canonical SHA-256 helper for the artifact chain.

The release chain used to carry a private byte-identical ``_sha256`` per module,
so a single request re-read the same immutable ISO two or three times: the
evidence status runs release readiness (one full read), then the release gate,
which hashes the ISO against SHA256SUMS (a second read) and re-runs release
readiness internally (a third read). The digest is memoised on the path plus
``st_size``/``st_mtime_ns``, so repeating a read of an unchanged artifact is
free while any rewrite of the file invalidates its own entry.

The cache is deliberately identity-based rather than trust-based: sites that
*verify* a digest against a sidecar (release gate, release verification) keep
re-hashing the bytes, they simply stop doing it several times per request.
"""

from __future__ import annotations

import hashlib
from functools import lru_cache
from pathlib import Path

_CHUNK = 1024 * 1024


def sha256_file(path: Path) -> str:
    """Return the SHA-256 hex digest of ``path``, reusing a still-valid digest."""
    stat = path.stat()
    return _sha256_cached(str(path), stat.st_size, stat.st_mtime_ns)


@lru_cache(maxsize=64)
def _sha256_cached(path: str, size: int, mtime_ns: int) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
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
