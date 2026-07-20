from __future__ import annotations

import argparse
from dataclasses import dataclass
from typing import Any

from distroforge.core.command_registry import CLI_GUI_OPTION_ALIASES, OptionGuiException


@dataclass(frozen=True)
class BuildOptionContract:
    option: str
    dest: str
    level: str
    gui_surface: str
    gui_token: str | None
    exception: str | None = None
    default: str = ""
    help_text: str = ""

    @property
    def requires_gui_token(self) -> bool:
        return self.exception is None


BUILD_OPTION_EXCEPTIONS: tuple[OptionGuiException, ...] = (
    OptionGuiException("--help", "argparse-generated help"),
    OptionGuiException("--definition", "covered by build preset import/export workflow"),
    OptionGuiException("--execute", "covered by explicit Execute action"),
)

BEGINNER_PREFIXES = (
    "source_iso",
    "from_scratch",
    "output_iso",
    "install",
    "remove",
    "profile",
    "snap",
    "desktop",
    "display_manager",
    "autologin",
    "wallpaper",
    "hostname",
    "locale",
    "timezone",
    "keyboard",
)

POWER_PREFIXES = (
    "ppa",
    "apt",
    "mirror",
    "snapshot",
    "auto_restore",
    "oem",
    "enable_service",
    "disable_service",
    "mask_service",
    "user",
    "netplan",
    "dns",
    "kiosk",
    "drivers",
    "release_track",
    "devel_suite",
    "enable_backports",
    "enable_proposed",
    "proposed_pin",
    "rolling",
    "system_sync",
    "autoinstall",
    "purge",
    "preview",
    "synaptic",
    "sanitize",
    "no_sanitize",
    "keep_",
)

MAINTAINER_PREFIXES = (
    "brand",
    "secure_boot",
    "qa",
    "bootcheck",
    "prebuild_vm",
    "qemu",
    "policy",
    "size",
    "vuln",
    "sbom",
    "reproducible",
    "source_date",
    "no_release",
    "sign_artifacts",
    "artifact",
    "no_html",
    "html_report",
    "require_source",
)

DEVELOPER_PREFIXES = (
    "persona",
    "bootstrap",
    "kernel",
    "desktop_source",
    "plugin",
    "import_script",
    "ci",
    "skip_deps",
    "no_sudo",
    "privilege",
    "log_file",
)


def build_option_contracts(parser: argparse.ArgumentParser) -> tuple[BuildOptionContract, ...]:
    exceptions = {item.option: item.reason for item in BUILD_OPTION_EXCEPTIONS}
    contracts: list[BuildOptionContract] = []
    for action in parser._actions:
        option = _primary_option(action)
        if not option:
            continue
        exception = exceptions.get(option)
        contracts.append(
            BuildOptionContract(
                option=option,
                dest=action.dest,
                level=_level_for_dest(action.dest),
                gui_surface=_surface_for_dest(action.dest),
                gui_token=None if exception else _gui_token_for_option(option, action.dest),
                exception=exception,
                default=_default_text(getattr(action, "default", None)),
                help_text=getattr(action, "help", None) or "",
            )
        )
    return tuple(contracts)


def _primary_option(action: argparse.Action) -> str | None:
    return next((value for value in action.option_strings if value.startswith("--")), None)


def _level_for_dest(dest: str) -> str:
    if _matches(dest, BEGINNER_PREFIXES):
        return "beginner"
    if _matches(dest, POWER_PREFIXES):
        return "power-user"
    if _matches(dest, MAINTAINER_PREFIXES):
        return "maintainer"
    if _matches(dest, DEVELOPER_PREFIXES):
        return "developer"
    return "power-user"


def _surface_for_dest(dest: str) -> str:
    if dest.startswith(("source_iso", "from_scratch", "bootstrap")):
        return "Source page"
    if dest.startswith(("desktop", "display_manager", "autologin", "wallpaper", "hostname", "locale", "timezone", "keyboard", "brand")):
        return "Desktop & Identity page"
    if dest.startswith(("install", "remove", "profile", "snap", "ppa", "kernel", "drivers")):
        return "Packages page"
    if dest.startswith(("prebuild_vm", "qemu", "bootcheck", "qa")):
        return "Virtualization Lab"
    if dest.startswith(("policy", "secure_boot", "size", "vuln", "sbom", "reproducible", "source_date", "artifact", "sign_artifacts", "html_report", "no_release", "no_html")):
        return "Quality Lab / Artifacts pages"
    if dest.startswith(("plugin", "import_script")):
        return "Extensions page"
    return "Build & Release page"


def _gui_token_for_option(option: str, dest: str) -> str:
    aliases = CLI_GUI_OPTION_ALIASES.get(option, ())
    if aliases:
        return aliases[0]
    return dest


def _matches(dest: str, prefixes: tuple[str, ...]) -> bool:
    return any(dest == prefix or dest.startswith(prefix) for prefix in prefixes)


def _default_text(value: Any) -> str:
    if value is argparse.SUPPRESS:
        return "argparse"
    return repr(value)
