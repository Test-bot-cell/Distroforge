from __future__ import annotations

from distroforge.core.workflows import workflow_level_status_text

WORKFLOW_LEVEL_STATUS_TEXT = workflow_level_status_text()

SNAPSHOT_STATUS_TEXT = (
    "Rollback snapshots are staged before risky phases and published only after tar succeeds."
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
