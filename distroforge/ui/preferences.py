"""Persisted desktop-UI preferences.

The redesigned shell chooses one workflow level (beginner -> developer) and
remembers it across runs so the guided journey discloses the right amount of
complexity without asking again. This is the single home for small UI state;
it stays offline and rootless under ``$XDG_CONFIG_HOME/distroforge``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from distroforge.core.workflows import LEVEL_KEYS

DEFAULT_LEVEL = "beginner"
_FILENAME = "ui.json"
_LEVEL_KEY = "workflow_level"
_CHROOT_BACKEND_KEY = "chroot_backend"
CHROOT_BACKENDS = ("auto", "chroot", "nspawn")


def config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return Path(base) / "distroforge"


def config_path() -> Path:
    return config_dir() / _FILENAME


def _read() -> dict[str, object]:
    try:
        data = json.loads(config_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write(data: dict[str, object]) -> None:
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    part = path.with_name(path.name + ".part")
    part.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    part.replace(path)


def _saved_level() -> str | None:
    level = _read().get(_LEVEL_KEY)
    return level if isinstance(level, str) and level in LEVEL_KEYS else None


def load_workflow_level(default: str = DEFAULT_LEVEL) -> str:
    return _saved_level() or default


def save_workflow_level(level: str) -> None:
    if level not in LEVEL_KEYS:
        raise ValueError(f"Unknown workflow level: {level!r}. Known: {', '.join(LEVEL_KEYS)}")
    data = _read()
    data[_LEVEL_KEY] = level
    _write(data)


def has_saved_level() -> bool:
    return _saved_level() is not None


def load_chroot_backend(default: str = "auto") -> str:
    backend = _read().get(_CHROOT_BACKEND_KEY)
    return backend if isinstance(backend, str) and backend in CHROOT_BACKENDS else default


def save_chroot_backend(backend: str) -> None:
    if backend not in CHROOT_BACKENDS:
        raise ValueError(f"Unknown chroot backend: {backend!r}. Known: {', '.join(CHROOT_BACKENDS)}")
    data = _read()
    data[_CHROOT_BACKEND_KEY] = backend
    _write(data)
