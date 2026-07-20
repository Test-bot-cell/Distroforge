from __future__ import annotations

import tomllib
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files

from .workflows import LEVEL_KEYS


@dataclass(frozen=True)
class Persona:
    key: str
    label: str
    description: str
    level: str
    sanitize_apt_lists: bool
    sanitize_ssh_host_keys: bool
    drivers_auto: bool
    qemu_matrix: tuple[str, ...]
    sbom: bool


@lru_cache(maxsize=1)
def load_personas() -> dict[str, Persona]:
    path = files("distroforge.data").joinpath("personas.toml")
    raw = tomllib.loads(path.read_text(encoding="utf-8"))
    personas: dict[str, Persona] = {}
    for key, data in raw["personas"].items():
        level = data["level"]
        if level not in LEVEL_KEYS:
            known = ", ".join(LEVEL_KEYS)
            raise ValueError(
                f"Persona {key!r} declares unknown workflow level {level!r}. Known: {known}"
            )
        personas[key] = Persona(
            key=key,
            label=data["label"],
            description=data["description"],
            level=level,
            sanitize_apt_lists=bool(data["sanitize_apt_lists"]),
            sanitize_ssh_host_keys=bool(data["sanitize_ssh_host_keys"]),
            drivers_auto=bool(data["drivers_auto"]),
            qemu_matrix=tuple(data.get("qemu_matrix", [])),
            sbom=bool(data["sbom"]),
        )
    return personas


def get_persona(key: str) -> Persona:
    personas = load_personas()
    try:
        return personas[key]
    except KeyError as exc:
        known = ", ".join(sorted(personas))
        raise ValueError(f"Unknown persona {key!r}. Known: {known}") from exc

