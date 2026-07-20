from __future__ import annotations

import tomllib
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files


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
