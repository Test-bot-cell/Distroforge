from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class PackageEntry:
    name: str
    version: str


def read_manifest(path: Path) -> dict[str, PackageEntry]:
    packages: dict[str, PackageEntry] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split()
        if len(parts) >= 2:
            packages[parts[0]] = PackageEntry(parts[0], parts[1])
    return packages

