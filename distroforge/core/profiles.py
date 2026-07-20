from __future__ import annotations

import tomllib
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files

from .apt import PackagePlan


@dataclass(frozen=True)
class RemixProfile:
    key: str
    label: str
    description: str
    install: tuple[str, ...]
    remove: tuple[str, ...]

    def package_plan(self) -> PackagePlan:
        return PackagePlan(install=list(self.install), remove=list(self.remove))


@lru_cache(maxsize=1)
def load_profiles() -> dict[str, RemixProfile]:
    path = files("distroforge.data").joinpath("profiles.toml")
    raw = tomllib.loads(path.read_text(encoding="utf-8"))
    profiles: dict[str, RemixProfile] = {}
    for key, data in raw["profiles"].items():
        profiles[key] = RemixProfile(
            key=key,
            label=data["label"],
            description=data["description"],
            install=tuple(data.get("install", [])),
            remove=tuple(data.get("remove", [])),
        )
    return profiles


def get_profile(key: str) -> RemixProfile:
    profiles = load_profiles()
    try:
        return profiles[key]
    except KeyError as exc:
        known = ", ".join(sorted(profiles))
        raise ValueError(f"Unknown profile {key!r}. Known: {known}") from exc

