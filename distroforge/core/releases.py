from __future__ import annotations

import tomllib
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files
from pathlib import Path


@dataclass(frozen=True)
class UbuntuRelease:
    version: str
    family: str
    codename: str
    label: str
    series: str
    supported: bool
    installer: str
    livefs: str
    archive_url: str
    security_url: str
    components: tuple[str, ...]
    compression: str

    @property
    def apt_suites(self) -> tuple[str, ...]:
        if self.family == "debian":
            return (
                self.codename,
                f"{self.codename}-updates",
                f"{self.codename}-security",
                f"{self.codename}-backports",
            )
        return (
            self.codename,
            f"{self.codename}-updates",
            f"{self.codename}-security",
            f"{self.codename}-backports",
        )


@lru_cache(maxsize=1)
def load_releases() -> dict[str, UbuntuRelease]:
    path = files("distroforge.data").joinpath("releases.toml")
    raw = tomllib.loads(path.read_text(encoding="utf-8"))
    releases: dict[str, UbuntuRelease] = {}
    for version, data in raw["releases"].items():
        releases[version] = UbuntuRelease(
            version=version,
            family=data.get("family", "ubuntu"),
            codename=data["codename"],
            label=data["label"],
            series=data["series"],
            supported=bool(data["supported"]),
            installer=data["installer"],
            livefs=data["livefs"],
            archive_url=data["archive_url"],
            security_url=data["security_url"],
            components=tuple(data["components"]),
            compression=data["compression"],
        )
    return releases


def get_release(version: str) -> UbuntuRelease:
    releases = load_releases()
    try:
        return releases[version]
    except KeyError as exc:
        known = ", ".join(sorted(releases))
        raise ValueError(f"Unknown DistroForge release {version!r}. Known: {known}") from exc


def read_os_release(root: Path) -> dict[str, str]:
    """What a tree says it is, read from wherever it says it.

    os-release(5) defines two locations: ``/etc/os-release`` is the configuration
    copy and ``/usr/lib/os-release`` the vendor one, the first shadowing the second,
    and a tree that ships only the vendor copy is perfectly valid. A reader that
    looks at ``/etc`` alone therefore reports such a tree as having no identity at
    all -- which is exactly the answer that lets a rootfs of the wrong suite pass
    for the right one.

    This lives here, next to the release facts it answers questions about, because
    two divergent copies of it already existed: one that read both locations and one
    that read only ``/etc``. Whether a tree's identity can be established must not
    depend on which caller is asking.
    """
    data: dict[str, str] = {}
    for path in (root / "etc/os-release", root / "usr/lib/os-release"):
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in line and not line.startswith("#"):
                key, value = line.split("=", 1)
                data[key] = value.strip().strip('"')
        break
    return data
