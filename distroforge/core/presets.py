from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .host_artifacts import write_host_artifact


@dataclass(frozen=True)
class Preset:
    key: str
    label: str
    definition: dict[str, object]


BUILTIN_PRESETS: dict[str, Preset] = {
    "old-pc": Preset(
        "old-pc",
        "Lightweight old PC",
        {"customization": {"desktop": "xubuntu"}, "packages": ["zram-tools"], "sanitize": {"apt_lists": True}},
    ),
    "developer": Preset(
        "developer",
        "Developer workstation",
        {"packages": ["git", "build-essential", "python3-venv"], "snaps": ["code:stable:classic"]},
    ),
    "kiosk": Preset(
        "kiosk",
        "Browser kiosk",
        {"customization": {"desktop": "ubuntu_minimal", "autologin_user": "ubuntu"}, "kiosk": {"enabled": True}},
    ),
    "privacy": Preset(
        "privacy",
        "Privacy-oriented desktop",
        {"packages": ["ufw"], "systemd": {"enable": ["ufw"], "disable": ["bluetooth"]}},
    ),
    "oem": Preset(
        "oem",
        "OEM first boot",
        {"oem": {"enabled": True}, "autoinstall": {"enabled": True}},
    ),
    "unity-remix": Preset(
        "unity-remix",
        "Unity remix",
        {
            "customization": {"desktop": "unity", "display_manager": "lightdm", "autologin_user": "ubuntu"},
            "packages": ["ubuntu-unity-desktop", "lightdm"],
            "sanitize": {"apt_lists": True, "ssh_host_keys": True},
        },
    ),
    "minimal-desktop": Preset(
        "minimal-desktop",
        "Minimal desktop from scratch",
        {
            "source_mode": "bootstrap",
            "customization": {"desktop": "ubuntu_minimal", "display_manager": "gdm3"},
            "packages": ["ubuntu-minimal", "ubuntu-standard", "network-manager"],
            "sanitize": {"apt_lists": True},
        },
    ),
    "gaming": Preset(
        "gaming",
        "Gaming workstation",
        {
            "packages": ["gamemode", "mangohud", "mesa-vulkan-drivers", "steam-installer"],
            "drivers": {"auto": True},
            "snaps": ["discord:stable"],
        },
    ),
    "education": Preset(
        "education",
        "Education lab",
        {"packages": ["gcompris-qt", "libreoffice", "vlc"], "systemd": {"disable": ["bluetooth"]}},
    ),
    "secure-workstation": Preset(
        "secure-workstation",
        "Secure workstation",
        {
            "packages": ["ufw", "apparmor-utils", "debsums"],
            "systemd": {"enable": ["ufw", "apparmor"]},
            "sanitize": {"apt_lists": True, "ssh_host_keys": True, "machine_id": True},
        },
    ),
    "rescue": Preset(
        "rescue",
        "Rescue live ISO",
        {"packages": ["gparted", "testdisk", "smartmontools", "nvme-cli", "rsync"], "profile": ["old-pc"]},
    ),
}


def list_presets() -> list[Preset]:
    return list(BUILTIN_PRESETS.values())


def write_preset(key: str, target: Path) -> None:
    preset = BUILTIN_PRESETS[key]
    write_host_artifact(target, json.dumps(preset.definition, indent=2), "Write preset export")
