from __future__ import annotations

from pathlib import Path

from distroforge.core.workflows import workflow_level_status_text
from distroforge.ui.build_options_mapper import PRESET_ONLY_SUMMARY

WORKFLOW_LEVEL_STATUS_TEXT = workflow_level_status_text()

SNAPSHOT_STATUS_TEXT = (
    "Rollback snapshots are staged before risky phases and published only after tar succeeds."
)

NO_PRESET_STATUS_TEXT = "No build preset imported; every setting on screen is the one that builds."


def preset_status_text(preset_path: Path | None) -> str:
    """One line, in words, on what an imported preset still controls.

    An imported preset used to replace the whole option set silently. It now
    lands in the widgets, so the screen is what builds; only the settings with no
    widget of their own are still taken from the preset, and they are named here.
    """
    if preset_path is None:
        return NO_PRESET_STATUS_TEXT
    return (
        f"Preset {preset_path.name} was loaded into the fields below; edit any of them and the "
        f"edit wins, exactly like a CLI flag after --definition. Only settings with no field of "
        f"their own still come from the preset: {PRESET_ONLY_SUMMARY}. Use Clear preset to drop them."
    )


def privilege_status_text(use_sudo: bool, use_pkexec: bool) -> str:
    if not use_sudo:
        return "Privileged rootfs writes are disabled; builds can fail on extracted files owned by root."
    if use_pkexec:
        return "Rootfs writes use pkexec. Use this only when a graphical policy prompt is reliable for long builds."
    return (
        "Rootfs and ISO writes use sudo with askpass when needed; protected files are handled "
        "without manual terminal steps."
    )
