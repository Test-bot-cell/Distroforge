from __future__ import annotations

from distroforge.core.command import CommandRunner
from distroforge.core.mirrors import MirrorService


def render_mirrors_action(window) -> None:
    if not window._require_project():
        return
    window._sync_project_from_ui()
    assert window.project
    options = window._build_options()
    service = MirrorService(
        CommandRunner(dry_run=True),
        window.project,
        options.mirrors,
        use_sudo=options.use_sudo,
    )
    window.mirrors_view.setPlainText(service.render_sources())
    window._log("Rendered deb822 mirror sources")
    window._open_surface("source")


def apply_mirrors_action(window) -> None:
    if not window._require_project():
        return
    window._sync_project_from_ui()
    assert window.project
    options = window._build_options()
    report = MirrorService(
        CommandRunner(dry_run=False),
        window.project,
        options.mirrors,
        use_sudo=options.use_sudo,
    ).apply(
        strict=window.policy_strict_check.isChecked()
    )
    window.mirrors_view.setPlainText(report.render_text())
    window._log(f"Applied mirror policy: {report.status}")
    window._open_surface("source")


def restore_mirrors_action(window) -> None:
    if not window._require_project():
        return
    window._sync_project_from_ui()
    assert window.project
    try:
        options = window._build_options()
        backup = MirrorService(
            CommandRunner(dry_run=False),
            window.project,
            options.mirrors,
            use_sudo=options.use_sudo,
        ).restore()
    except Exception as exc:
        window._error(str(exc))
        return
    window.mirrors_view.setPlainText(f"Restored {backup}\n")
    window._log(f"Restored mirror backup {backup}")
    window._open_surface("source")
