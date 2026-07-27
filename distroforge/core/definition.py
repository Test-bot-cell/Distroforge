from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeVar

import yaml

from .apt import PackagePlan
from .apt_cache import AptCacheOptions
from .autoinstall import AutoinstallOptions
from .bootcheck import BootCheckOptions
from .bootstrap import BootstrapOptions
from .branding import BrandingOptions
from .build import BuildOptions
from .customize import IsoCustomization
from .desktop_source import DesktopSourceComponent, DesktopSourceOptions
from .drivers import DriverOptions
from .html_report import HtmlReportOptions
from .importer import ImportOptions
from .kernel import KernelModuleOptions
from .kiosk import KioskOptions
from .mirrors import MirrorOptions
from .network import NetworkOptions
from .oem import OemOptions
from .plugins import PluginOptions
from .policy import PolicyOptions
from .ppa import PpaOptions, PpaSpec
from .prebuild_vm import PrebuildVmOptions
from .project import Project
from .provenance import ProvenanceOptions
from .qa import QaOptions
from .qemu_screenshot import QemuScreenshotOptions
from .release_artifacts import ReleaseArtifactOptions
from .release_track import ReleaseTrackOptions
from .reproducible import ReproducibleOptions
from .sanitize import SanitizeOptions
from .schema import validate_definition_data
from .secureboot import SecureBootOptions
from .seeds import SeedOptions
from .size_analysis import SizeAnalysisOptions
from .snaps import SnapOptions, SnapSpec
from .snapshots import SnapshotOptions
from .squashfs import SquashfsOptions
from .system_sync import SystemSyncOptions
from .systemd import SystemdOptions
from .trust import TrustOptions
from .users import UserOptions, UserSpec
from .vulnscan import VulnScanOptions

PRESET_SCHEMA_VERSION = "distroforge.preset.v1"

GroupT = TypeVar("GroupT")


def load_definition(path: Path) -> dict[str, object]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        data = yaml.safe_load(text)
    else:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError(f"Definition must contain a mapping/object at top level: {path}")
    return data


def write_definition(data: dict[str, object], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix.lower() in {".yaml", ".yml"}:
        path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=False), encoding="utf-8")
        return
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def definition_from_project(
    project: Project,
    options: BuildOptions | None = None,
    metadata: dict[str, object] | None = None,
) -> dict[str, object]:
    options = options or BuildOptions()
    data: dict[str, object] = {
        "schema": PRESET_SCHEMA_VERSION,
        "metadata": {
            "name": project.name,
            "kind": "maintainer-build-preset",
            "release": project.release.version,
            "generated_by": "DistroForge",
            "created_at": datetime.now(UTC).isoformat(),
            **(metadata or {}),
        },
        "source_mode": project.source_mode,
        "source_iso": str(project.source_iso) if project.source_iso else None,
        "source_starter": project.source_starter,
        "packages": list(project.packages),
        "remove_packages": list(project.remove_packages),
        "repositories": list(project.repositories),
        "extra_install": _without_base(options.package_plan.install, project.packages),
        "extra_remove": _without_base(options.package_plan.remove, project.remove_packages),
        "preview": options.run_preview,
        "synaptic": options.run_synaptic,
        "output_iso": str(options.output_iso) if options.output_iso else None,
        "customization": project.customization.to_dict(),
        "bootstrap": _clean(options.bootstrap),
        "sanitize": _clean(options.sanitize),
        "snaps": [value.spec() for value in options.snaps.specs],
        "drivers": _clean(options.drivers),
        "release_track": _clean(options.release_track),
        "system_sync": _clean(options.system_sync),
        "autoinstall": _clean(options.autoinstall),
        "branding": _clean(options.branding),
        "secure_boot": _clean(options.secure_boot),
        "provenance": _clean(options.provenance),
        "seeds": _clean(options.seeds),
        "qa": _clean(options.qa),
        "prebuild_vm": _clean(options.prebuild_vm),
        "ppa": _ppa_definition(options.ppa),
        "apt_cache": _clean(options.apt_cache),
        "snapshots": _clean(options.snapshots),
        "squashfs": _clean(options.squashfs),
        "oem": _clean(options.oem),
        "systemd": _clean(options.systemd),
        "users": [_clean(value) for value in options.users.users],
        "network": _clean(options.network),
        "mirrors": _clean(options.mirrors),
        "kiosk": _clean(options.kiosk),
        "bootcheck": _clean(options.bootcheck),
        "qemu_screenshot": _clean(options.qemu_screenshot),
        "policy": _clean(options.policy),
        "size_analysis": _clean(options.size_analysis),
        "reproducible": _clean(options.reproducible),
        "kernel": _clean(options.kernel_module),
        "desktop_source": _desktop_source_definition(options.desktop_source),
        "plugins": _clean(options.plugins),
        "release_artifacts": _clean(options.release_artifacts),
        "html_report": _clean(options.html_report),
        "import_scripts": [str(path) for path in options.import_scripts.scripts],
        "trust": _clean(options.trust),
        "vuln_scan": _clean(options.vuln_scan),
    }
    return _drop_none(data)


def apply_definition(project: Project, data: dict[str, object]) -> BuildOptions:
    data = validate_definition_data(data)
    project.source_mode = str(data.get("source_mode", project.source_mode))
    if data.get("source_iso"):
        project.source_iso = Path(str(data["source_iso"]))
    if data.get("source_starter") and isinstance(data["source_starter"], dict):
        project.source_starter = dict(data["source_starter"])
    project.packages = list(data.get("packages", project.packages))
    project.remove_packages = list(data.get("remove_packages", project.remove_packages))
    project.repositories = list(data.get("repositories", project.repositories))
    if customization := data.get("customization"):
        project.customization = IsoCustomization.from_dict(customization)  # type: ignore[arg-type]

    qa = data.get("qa", {})
    plugins = data.get("plugins", {})
    import_scripts = data.get("import_scripts", [])
    return BuildOptions(
        output_iso=Path(str(data["output_iso"])) if data.get("output_iso") else None,
        package_plan=PackagePlan(
            install=list(data.get("extra_install", [])),
            remove=list(data.get("extra_remove", [])),
        ),
        run_preview=bool(data.get("preview", False)),
        run_synaptic=bool(data.get("synaptic", False)),
        sanitize=_group(data, "sanitize", SanitizeOptions),
        bootstrap=_group(data, "bootstrap", BootstrapOptions),
        snaps=SnapOptions([SnapSpec.parse(str(value)) for value in data.get("snaps", [])]),
        drivers=_group(data, "drivers", DriverOptions),
        autoinstall=_group(data, "autoinstall", AutoinstallOptions),
        branding=_group(data, "branding", BrandingOptions),
        secure_boot=_group(data, "secure_boot", SecureBootOptions),
        provenance=_group(data, "provenance", ProvenanceOptions),
        seeds=_group(data, "seeds", SeedOptions),
        qa=QaOptions(list(qa.get("scenarios", []))) if isinstance(qa, dict) else QaOptions(),
        release_track=_group(data, "release_track", ReleaseTrackOptions),
        system_sync=_group(data, "system_sync", SystemSyncOptions),
        ppa=_ppa_options(data.get("ppa", {})),
        apt_cache=_group(data, "apt_cache", AptCacheOptions),
        snapshots=_group(data, "snapshots", SnapshotOptions),
        squashfs=_group(data, "squashfs", SquashfsOptions),
        oem=_group(data, "oem", OemOptions),
        systemd=_group(data, "systemd", SystemdOptions),
        users=UserOptions(_user_specs(data.get("users", []))),
        network=_group(data, "network", NetworkOptions),
        mirrors=_group(data, "mirrors", MirrorOptions),
        kiosk=_group(data, "kiosk", KioskOptions),
        bootcheck=_group(data, "bootcheck", BootCheckOptions),
        prebuild_vm=_group(data, "prebuild_vm", PrebuildVmOptions),
        qemu_screenshot=_group(data, "qemu_screenshot", QemuScreenshotOptions),
        policy=_group(data, "policy", PolicyOptions),
        size_analysis=_group(data, "size_analysis", SizeAnalysisOptions),
        reproducible=_group(data, "reproducible", ReproducibleOptions),
        kernel_module=_group(data, "kernel", KernelModuleOptions),
        desktop_source=_desktop_source_options(data.get("desktop_source", {})),
        plugins=PluginOptions(Path(str(plugins["plugins_dir"])))
        if isinstance(plugins, dict) and plugins.get("plugins_dir")
        else PluginOptions(),
        release_artifacts=_group(data, "release_artifacts", ReleaseArtifactOptions),
        html_report=_group(data, "html_report", HtmlReportOptions),
        import_scripts=ImportOptions([Path(str(path)) for path in import_scripts])
        if isinstance(import_scripts, list)
        else ImportOptions([]),
        trust=_trust_options(data.get("trust", {})),
        vuln_scan=_group(data, "vuln_scan", VulnScanOptions),
    )


def _group(data: dict[str, object], key: str, cls: type[GroupT]) -> GroupT:
    """Build one options group from a definition mapping, validating its keys.

    ``schema.py`` models only eight nested groups, so a typo in any other group
    reached the dataclass constructor as an unexpected keyword. That raises
    ``TypeError``, which ``cli.py`` does not catch: the user got a Python
    traceback instead of ``distroforge: error: ...``. Re-raising as ``ValueError``
    puts the group back on the friendly path while keeping the interpreter's own
    "Did you mean 'logs'?" suggestion in the message.

    Groups needing more than keyword unpacking (``qa``, ``ppa``, ``trust``,
    ``desktop_source``, ``users``, ``plugins``) keep their dedicated handlers.
    """
    value = data.get(key, {})
    if not isinstance(value, dict):
        return cls()
    try:
        return cls(**value)
    except TypeError as exc:
        raise ValueError(f"Invalid definition group {key!r}: {exc}") from exc


def _trust_options(data: object) -> TrustOptions:
    if not isinstance(data, dict):
        return TrustOptions()
    return TrustOptions(
        source_sha256=str(data["source_sha256"]) if data.get("source_sha256") else None,
        source_signature=Path(str(data["source_signature"])) if data.get("source_signature") else None,
        source_gpg_fingerprint=str(data["source_gpg_fingerprint"])
        if data.get("source_gpg_fingerprint")
        else None,
        require_source_checksum=bool(data.get("require_source_checksum", False)),
        require_source_signature=bool(data.get("require_source_signature", False)),
    )


def _ppa_options(data: object) -> PpaOptions:
    if isinstance(data, list):
        return PpaOptions([PpaSpec.parse(str(value)) for value in data])
    if isinstance(data, dict):
        values = data.get("ppas", [])
        return PpaOptions(
            ppas=[PpaSpec.parse(str(value)) for value in values],
            require_fingerprint=bool(data.get("require_fingerprint", True)),
            auto_fetch_fingerprint=bool(data.get("auto_fetch_fingerprint", True)),
            keyserver=str(data.get("keyserver", "hkps://keyserver.ubuntu.com")),
        )
    return PpaOptions()


def _desktop_source_options(data: object) -> DesktopSourceOptions:
    if not isinstance(data, dict):
        return DesktopSourceOptions()
    components: list[DesktopSourceComponent] = []
    for item in data.get("components", []):
        if isinstance(item, str):
            components.append(DesktopSourceComponent.parse(item))
        elif isinstance(item, dict):
            components.append(
                DesktopSourceComponent(
                    name=str(item["name"]),
                    version=str(item["version"]),
                    source_url=str(item["source_url"]),
                    sha256=str(item["sha256"]) if item.get("sha256") else None,
                    build_system=str(item.get("build_system", "meson")),
                    package_name=str(item["package_name"]) if item.get("package_name") else None,
                    configure_args=tuple(str(value) for value in item.get("configure_args", [])),
                )
            )
    return DesktopSourceOptions(
        enabled=bool(data.get("enabled", False)),
        desktop=str(data["desktop"]) if data.get("desktop") else None,
        version=str(data["version"]) if data.get("version") else None,
        components=components,
        install_debs=bool(data.get("install_debs", True)),
        jobs=int(data.get("jobs", 0)),
        local_suffix=str(data.get("local_suffix", "dforge")),
        build_dependencies=[str(value) for value in data.get("build_dependencies", [])],
        require_sha256=bool(data.get("require_sha256", False)),
    )


def _user_specs(data: object) -> list[UserSpec]:
    specs: list[UserSpec] = []
    if not isinstance(data, list):
        return specs
    for item in data:
        if isinstance(item, str):
            specs.append(UserSpec(name=item))
        elif isinstance(item, dict):
            specs.append(
                UserSpec(
                    name=str(item["name"]),
                    password_hash=str(item["password_hash"])
                    if item.get("password_hash")
                    else None,
                    groups=[str(group) for group in item.get("groups", ["sudo", "audio", "video"])],
                    shell=str(item.get("shell", "/bin/bash")),
                )
            )
    return specs


def _clean(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if is_dataclass(value):
        return _clean(asdict(value))
    if isinstance(value, dict):
        return _drop_none({str(key): _clean(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return [_clean(item) for item in value]
    return value


def _drop_none(data: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in data.items() if value is not None}


def _without_base(values: list[str], base: list[str]) -> list[str]:
    base_set = set(base)
    return [value for value in values if value not in base_set]


def _ppa_definition(options: PpaOptions) -> dict[str, object]:
    return {
        "ppas": [ppa.spec() for ppa in options.ppas],
        "require_fingerprint": options.require_fingerprint,
        "auto_fetch_fingerprint": options.auto_fetch_fingerprint,
        "keyserver": options.keyserver,
    }


def _desktop_source_definition(options: DesktopSourceOptions) -> dict[str, object]:
    return {
        "enabled": options.enabled,
        "desktop": options.desktop,
        "version": options.version,
        "components": [_clean(component) for component in options.components],
        "install_debs": options.install_debs,
        "jobs": options.jobs,
        "local_suffix": options.local_suffix,
        "build_dependencies": list(options.build_dependencies),
        "require_sha256": options.require_sha256,
    }


def example_definition() -> str:
    return json.dumps(
        {
            "source_mode": "iso",
            "source_iso": "ubuntu.iso",
            "packages": ["vim", "htop"],
            "snaps": ["firefox:stable", "code:stable:classic"],
            "customization": {
                "desktop": "unity",
                "autologin_user": "ubuntu",
                "hostname": "forgebox",
                "locale": "fr_FR.UTF-8",
                "timezone": "Europe/Paris",
                "keyboard_layout": "fr",
            },
            "drivers": {"auto": True},
            "ppa": {"ppas": ["ppa:graphics-drivers/ppa"], "auto_fetch_fingerprint": True},
            "apt_cache": {"enabled": False, "proxy_url": None},
            "snapshots": {"enabled": False},
            "oem": {"enabled": False},
            "systemd": {"enable": ["ssh"], "disable": [], "mask": []},
            "users": [{"name": "ubuntu", "groups": ["sudo", "audio", "video"]}],
            "network": {"netplan_dhcp": False, "dns": ["1.1.1.1"]},
            "kiosk": {"enabled": False, "browser": "firefox", "url": "about:blank"},
            "bootcheck": {"enabled": False},
            "prebuild_vm": {
                "enabled": False,
                "profile": "live",
                "firmware": "uefi",
                "secure_boot": False,
                "tpm": False,
                "memory_mb": 4096,
                "cpus": 2,
                "disk_size": "24G",
                "network": False,
                "timeout_seconds": 300,
                "success_patterns": ["login:", "Reached target"],
            },
            "qemu_screenshot": {"enabled": False},
            "policy": {"strict": False},
            "size_analysis": {"enabled": False, "top": 50},
            "reproducible": {"enabled": False, "source_date_epoch": None},
            "kernel": {
                "enabled": False,
                "build_mode": "module",
                "channel": "stable",
                "prune_obsolete_kernels": False,
                "localversion": "-dforge",
                "jobs": 0,
                "config_strategy": "current",
                "install_debs": True,
                "require_sha256": False,
                "require_gpg": False,
            },
            "desktop_source": {
                "enabled": False,
                "desktop": "ubuntu",
                "version": "50",
                "components": [
                    "gnome-shell|50.0|https://download.gnome.org/sources/gnome-shell/50/gnome-shell-50.0.tar.xz"
                ],
                "install_debs": True,
                "jobs": 0,
                "local_suffix": "dforge",
                "build_dependencies": [],
                "require_sha256": False,
            },
            "release_artifacts": {"enabled": True, "sign": False},
            "html_report": {"enabled": True, "filename": "report.html"},
            "sanitize": {"apt_lists": True, "ssh_host_keys": True},
            "autoinstall": {"enabled": True, "username": "ubuntu"},
            "branding": {
                "name": "DistroForge Remix",
                "pretty_name": "DistroForge Remix 26.04",
                "product_name": "DistroForge",
                "vendor": "DistroForge Project",
                "os_id": "distroforge",
                "id_like": "ubuntu debian",
                "home_url": "https://example.invalid",
                "support_url": "https://example.invalid/support",
                "bug_report_url": "https://example.invalid/bugs",
                "privacy_policy_url": "https://example.invalid/privacy",
                "palette": "forge",
                "palette_colors": [],
                "grub_distributor": "DistroForge",
                "grub_menu_label": "DistroForge Live",
                "plymouth_main_color": "#2e3436",
            },
            "qa": {"scenarios": ["live-bios", "live-uefi"]},
            "release_track": {"mode": "stable"},
            "system_sync": {
                "enabled": False,
                "strategy": "full",
                "fallback": True,
                "run_during_build": True,
                "post_install_tool": True,
                "hold_packages": [],
            },
            "trust": {
                "source_sha256": None,
                "source_signature": None,
                "source_gpg_fingerprint": None,
                "require_source_checksum": False,
                "require_source_signature": False,
            },
            "preview": False,
        },
        indent=2,
    )
