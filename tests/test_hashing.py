from __future__ import annotations

import hashlib

import pytest

from distroforge.core.hashing import (
    MAX_SHA256_SUMS_BYTES,
    parse_sha256_sums,
    sha256_from_sums_bytes,
)


def test_sha256sums_parser_accepts_one_canonical_entry() -> None:
    digest = hashlib.sha256(b"iso").hexdigest()
    payload = f"{digest}  distroforge.iso\n".encode()

    assert parse_sha256_sums(payload) == {"distroforge.iso": digest}
    assert sha256_from_sums_bytes(payload, "distroforge.iso") == digest


@pytest.mark.parametrize(
    "payload",
    (
        b"\xff  distroforge.iso\n",
        b"0" * 64 + b"  distroforge.iso",
        b"0" * 64 + b" *distroforge.iso\n",
        b"0" * 64 + b"  ../distroforge.iso\n",
        b"0" * 64 + b"  distroforge.iso\r\n",
        (b"0" * 64 + b"  distroforge.iso\n") * 2,
        b"A" * 64 + b"  distroforge.iso\n",
        b"0" * (MAX_SHA256_SUMS_BYTES + 1),
    ),
)
def test_sha256sums_parser_rejects_noncanonical_or_unbounded_input(
    payload: bytes,
) -> None:
    with pytest.raises(ValueError):
        parse_sha256_sums(payload)
