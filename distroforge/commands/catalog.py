from __future__ import annotations

import json

from distroforge.core.autoinstall_templates import TEMPLATES, render_template
from distroforge.core.branding_palettes import load_branding_palettes
from distroforge.core.chroot import detect_chroot_backends
from distroforge.core.command import CommandRunner
from distroforge.core.customize import load_desktops
from distroforge.core.desktop_source import load_desktop_source_profiles
from distroforge.core.host import detect_host_capabilities
from distroforge.core.persona import load_personas
from distroforge.core.profiles import load_profiles
from distroforge.core.source_starter import list_source_starters


def render_host_capabilities(json_output: bool = False) -> str:
    capabilities = detect_host_capabilities(CommandRunner(dry_run=True))
    if json_output:
        return json.dumps([item.__dict__ for item in capabilities], indent=2)
    lines = []
    for item in capabilities:
        mark = "ok" if item.available else "missing"
        lines.append(f"{mark:8} {item.name:18} {item.detail}")
    return "\n".join(lines)


def render_chroot_backends(json_output: bool = False) -> str:
    backends = detect_chroot_backends()
    if json_output:
        return json.dumps([item.to_dict() for item in backends], indent=2)
    lines = []
    for item in backends:
        mark = "ok" if item.available else "missing"
        selected = "selected" if item.selected else "active" if item.active else ""
        package = f" ({item.package})" if item.package else ""
        lines.append(f"{mark:8} {item.name:8} {selected:8} {item.detail}{package}")
    return "\n".join(lines)


def render_profiles() -> str:
    return "\n".join(
        f"{profile.key:10} {profile.label} - {profile.description}"
        for profile in load_profiles().values()
    )


def render_personas() -> str:
    lines = []
    for persona in load_personas().values():
        scenarios = ",".join(persona.qemu_matrix)
        lines.append(
            f"{persona.key:13} {persona.label:14} level={persona.level:11} "
            f"qa={scenarios:45} {persona.description}"
        )
    return "\n".join(lines)


def render_desktops() -> str:
    source_profiles = load_desktop_source_profiles()
    lines = []
    for desktop in load_desktops().values():
        ubuntu_packages = ", ".join(desktop.packages_for("ubuntu"))
        debian_packages = ", ".join(desktop.packages_for("debian"))
        source = source_profiles.get(desktop.key)
        source_version = source.current_version if source else "-"
        lines.append(
            f"{desktop.key:15} {desktop.label:24} dm={desktop.display_manager:7} "
            f"source={source_version:8} ubuntu=[{ubuntu_packages}] debian=[{debian_packages}]"
        )
    return "\n".join(lines)


def render_source_starters(release: str | None, json_output: bool = False) -> str:
    starters = list_source_starters(release)
    if json_output:
        return json.dumps([starter.to_dict() for starter in starters], indent=2)
    return "\n".join(
        f"{starter.key:28} {starter.kind:16} {starter.release:12} "
        f"{starter.label} [{starter.checksum_algorithm}]"
        for starter in starters
    )


def render_branding_palettes() -> str:
    lines = [
        f"{palette.key:12} {palette.summary()}"
        for palette in load_branding_palettes().values()
    ]
    lines.append("generate     Generate a deterministic palette from --brand-palette-seed")
    return "\n".join(lines)


def render_autoinstall_templates(render: str | None = None) -> str:
    if render:
        return render_template(render)
    return "\n".join(TEMPLATES)
