from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path

from .capture_report import CaptureFinding

MAX_CAPTURED_CONFIG_BYTES = 64 * 1024

SECRET_PATTERNS = (
    "/home",
    "/root/.ssh",
    "/root/.gnupg",
    "/etc/ssh/ssh_host_",
    "/etc/machine-id",
    "/var/lib/dbus/machine-id",
    "/var/log",
    "/var/cache",
    "/tmp",
    "/var/tmp",
    ".bash_history",
    ".zsh_history",
    "Crash Reports",
    "token",
    "secret",
    "password",
    "passwd",
    "private",
    "credential",
    "keyring",
    ".pem",
    ".key",
)

DEFAULT_CONFIG_WHITELIST = (
    "/etc/default/locale",
    "/etc/default/keyboard",
    "/etc/timezone",
    "/etc/hostname",
    "/etc/X11/default-display-manager",
    "/etc/netplan",
)


@dataclass(frozen=True)
class ConfigCapturePolicy:
    whitelist: tuple[str, ...]
    max_bytes: int = MAX_CAPTURED_CONFIG_BYTES

    @classmethod
    def from_user_paths(cls, values: list[str]) -> ConfigCapturePolicy:
        return cls(tuple(sorted(set(DEFAULT_CONFIG_WHITELIST) | {_normalize_rule(value) for value in values})))


def classify_config_with_policy(path: Path, root: Path, policy: ConfigCapturePolicy) -> CaptureFinding:
    display = _display_path(path, root)
    lowered = display.lower()
    if not _is_inside_root(path, root):
        return CaptureFinding("config", display, "dangerous", "Outside target root")
    if path.is_symlink():
        return CaptureFinding("config", display, "ignored", "Symlinks are recorded as findings only")
    if path.is_dir():
        return CaptureFinding("config", display, "ignored", "Directory scanned; files are evaluated individually")
    if path.exists() and not path.is_file():
        return CaptureFinding("config", display, "ignored", "Not a regular file")
    for pattern in SECRET_PATTERNS:
        if pattern.lower() in lowered:
            return CaptureFinding("config", display, "dangerous", "Excluded by secret/cache rule")
    if path.exists() and path.stat().st_size > policy.max_bytes:
        return CaptureFinding("config", display, "ignored", f"Config exceeds {policy.max_bytes} byte capture limit")
    for value in policy.whitelist:
        if _matches_rule(display, value):
            return CaptureFinding("config", display, "captured", "Whitelisted configuration path")
    return CaptureFinding("config", display, "ignored", "Not whitelisted; review before including")


def _display_path(path: Path, root: Path) -> str:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return str(path)
    return "/" + str(relative)


def _is_inside_root(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _normalize_rule(value: str) -> str:
    text = value.strip()
    if not text:
        return text
    return text if text.startswith("/") else "/" + text


def _matches_rule(display: str, rule: str) -> bool:
    if any(char in rule for char in "*?["):
        return fnmatch.fnmatchcase(display, rule)
    return display == rule or display.startswith(rule.rstrip("/") + "/")
