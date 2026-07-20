from __future__ import annotations

from distroforge.core.iso_toolchain import check_iso_toolchain


def render_iso_toolchain(install: bool = False, no_sudo: bool = False, json_output: bool = False) -> tuple[str, bool]:
    report = check_iso_toolchain(install=install, use_sudo=not no_sudo)
    return report.render_json() if json_output else report.render_text(), report.blocked
