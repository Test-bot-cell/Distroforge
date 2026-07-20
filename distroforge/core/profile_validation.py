from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

import yaml

_ALLOWED_PROFILE_KEYS = {"base", "layers", "overrides"}


def load_profile_resolver_spec(path: Path) -> dict[str, object]:
    """Load and strictly validate a profile composition config.

    Accepted shapes:
    - {base: ..., layers: [...], overrides: [...]}
    - {profiles: {base: ..., layers: [...], overrides: [...]}}

    Extra keys are rejected so malformed or ambiguous files fail fast with a readable
    message.
    """
    data = _load_profile_definition(path)
    if not isinstance(data, dict):
        raise ValueError(f"Profile composition config must be a mapping: {path}")

    if "profiles" in data:
        if len(data) != 1:
            extra = ", ".join(sorted(k for k in data.keys() if k != "profiles"))
            raise ValueError(
                f"Profile composition config {path} must only define the 'profiles' section: extra keys {extra}"
            )
        raw = data["profiles"]
    else:
        raw = data

    if not isinstance(raw, dict):
        raise ValueError(f"Profile composition config must map keys to values in {path}")

    unknown = set(raw) - _ALLOWED_PROFILE_KEYS
    if unknown:
        known = ", ".join(sorted(_ALLOWED_PROFILE_KEYS))
        missing = ", ".join(sorted(unknown))
        raise ValueError(f"Profile composition config {path} has unknown keys: {missing}. Known: {known}")

    result: dict[str, object] = {}
    if "base" in raw:
        base = raw["base"]
        if not isinstance(base, str) or not base.strip():
            raise ValueError(f"Profile composition key 'base' must be a non-empty string in {path}")
        result["base"] = base.strip()

    if "layers" in raw:
        result["layers"] = _coerce_string_list(raw["layers"], "layers", path)

    if "overrides" in raw:
        result["overrides"] = _coerce_string_list(raw["overrides"], "overrides", path)

    return result


def _load_profile_definition(path: Path) -> dict[str, Any] | Any:
    if not path.exists():
        raise ValueError(f"Profile composition config not found: {path}")
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        raise ValueError(f"Profile composition config is empty: {path}")
    try:
        if path.suffix.lower() == ".toml":
            return tomllib.loads(text)
        return yaml.safe_load(text)
    except (yaml.YAMLError, tomllib.TOMLDecodeError, ValueError) as exc:
        raise ValueError(f"Profile composition config has invalid syntax: {path}: {exc}") from exc


def _coerce_string_list(value: object, key: str, path: Path) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"Profile composition key '{key}' must be a list in {path}")
    items: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            raise ValueError(
                f"Profile composition key '{key}[{index}]' must be a non-empty string in {path}"
            )
        items.append(item.strip())
    return items
