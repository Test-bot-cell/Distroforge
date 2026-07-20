from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator


class UserDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    groups: list[str] = Field(default_factory=lambda: ["sudo", "audio", "video"])
    password_hash: str | None = None
    shell: str = "/bin/bash"


class PpaDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ppas: list[str] = Field(default_factory=list)
    require_fingerprint: bool = True
    auto_fetch_fingerprint: bool = True
    keyserver: str = "hkps://keyserver.ubuntu.com"

    @field_validator("ppas")
    @classmethod
    def validate_ppas(cls, values: list[str]) -> list[str]:
        for value in values:
            raw = value.removeprefix("ppa:")
            if "/" not in raw:
                raise ValueError(f"Invalid PPA {value!r}, expected ppa:owner/name")
        return values


class KernelDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    build_mode: Literal["module", "full-deb"] = "module"
    channel: Literal["stable", "longterm", "mainline"] = "stable"
    version: str | None = None
    source_url: str | None = None
    pgp_url: str | None = None
    source_sha256: str | None = None
    module_source: str | None = None
    module_subdir: str | None = None
    module_name: str | None = None
    verify_pgp: bool = True
    prune_obsolete_kernels: bool = False
    integrity_check: bool = True
    localversion: str = "-dforge"
    jobs: int = 0
    config_strategy: Literal["current", "defconfig"] = "current"
    install_debs: bool = True
    gpg_keyring: str | None = None
    gpg_fingerprint: str | None = None
    require_sha256: bool = False
    require_gpg: bool = False


class DesktopSourceComponentDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    version: str
    source_url: str
    sha256: str | None = None
    build_system: Literal["meson", "cmake", "autotools", "debuild", "debian", "gnome"] = (
        "meson"
    )
    package_name: str | None = None
    configure_args: list[str] = Field(default_factory=list)


class DesktopSourceDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    desktop: str | None = None
    version: str | None = None
    components: list[DesktopSourceComponentDefinition | str] = Field(default_factory=list)
    install_debs: bool = True
    jobs: int = 0
    local_suffix: str = "dforge"
    build_dependencies: list[str] = Field(default_factory=list)
    require_sha256: bool = False


class SystemSyncDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    strategy: Literal["safe", "full"] = "full"
    fallback: bool = True
    run_during_build: bool = True
    post_install_tool: bool = True
    hold_packages: list[str] = Field(default_factory=list)


class TrustDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_sha256: str | None = None
    source_signature: str | None = None
    source_gpg_fingerprint: str | None = None
    require_source_checksum: bool = False
    require_source_signature: bool = False


class PrebuildVmDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    profile: Literal["live", "install", "rescue"] = "live"
    firmware: Literal["bios", "uefi"] = "bios"
    secure_boot: bool = False
    tpm: bool = False
    memory_mb: int = 4096
    cpus: int = 2
    disk_size: str = "24G"
    network: bool = False
    timeout_seconds: int = 300
    serial_log: str = "prebuild-vm-serial.log"
    screenshot: bool = True
    screenshot_name: str = "prebuild-vm.ppm"
    success_patterns: list[str] = Field(default_factory=lambda: ["login:", "Reached target"])
    qmp_socket: str = "qemu-lab.qmp"
    pid_file: str = "qemu-lab.pid"
    report_name: str = "qemu-lab-report.json"
    ovmf_code: str = "/usr/share/OVMF/OVMF_CODE.fd"
    ovmf_vars: str = "/usr/share/OVMF/OVMF_VARS.fd"


class BrandingDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = None
    pretty_name: str | None = None
    product_name: str | None = None
    vendor: str | None = None
    os_id: str | None = None
    id_like: str | None = None
    version_id: str | None = None
    version_codename: str | None = None
    home_url: str | None = None
    support_url: str | None = None
    bug_report_url: str | None = None
    privacy_policy_url: str | None = None
    ansi_color: str | None = None
    icon_name: str | None = None
    palette: str | None = None
    palette_colors: list[str] = Field(default_factory=list)
    palette_seed: str | None = None
    logo: str | None = None
    distributor_logo: str | None = None
    app_icon: str | None = None
    grub_background: str | None = None
    grub_theme: str | None = None
    grub_distributor: str | None = None
    grub_menu_label: str | None = None
    plymouth_theme: str | None = None
    plymouth_logo: str | None = None
    plymouth_spinner: str | None = None
    plymouth_background: str | None = None
    plymouth_main_color: str | None = None
    login_background: str | None = None
    lightdm_background: str | None = None
    installer_slideshow: str | None = None
    issue_text: str | None = None
    motd_text: str | None = None


class CustomizationDefinition(BaseModel):
    model_config = ConfigDict(extra="allow")

    desktop: str | None = None
    display_manager: str | None = None
    autologin_user: str | None = None
    wallpaper: str | None = None
    hostname: str | None = None
    locale: str | None = None
    timezone: str | None = None
    keyboard_layout: str | None = None


class ImageDefinition(BaseModel):
    model_config = ConfigDict(extra="allow")

    source_mode: Literal["iso", "bootstrap"] = "iso"
    source_iso: str | None = None
    source_starter: dict[str, object] | None = None
    packages: list[str] = Field(default_factory=list)
    remove_packages: list[str] = Field(default_factory=list)
    repositories: list[str] = Field(default_factory=list)
    snaps: list[str] = Field(default_factory=list)
    extra_install: list[str] = Field(default_factory=list)
    extra_remove: list[str] = Field(default_factory=list)
    customization: CustomizationDefinition | None = None
    branding: BrandingDefinition | None = None
    ppa: PpaDefinition | list[str] | None = None
    kernel: KernelDefinition | None = None
    desktop_source: DesktopSourceDefinition | None = None
    system_sync: SystemSyncDefinition | None = None
    trust: TrustDefinition | None = None
    prebuild_vm: PrebuildVmDefinition | None = None
    users: list[UserDefinition | str] = Field(default_factory=list)

    @field_validator("snaps")
    @classmethod
    def validate_snaps(cls, values: list[str]) -> list[str]:
        for value in values:
            if not value.strip():
                raise ValueError("Snap specs cannot be empty")
        return values


def validate_definition_data(data: dict[str, object]) -> dict[str, object]:
    try:
        model = ImageDefinition.model_validate(data)
    except ValidationError as exc:
        raise ValueError(f"Invalid DistroForge image definition:\n{exc}") from exc
    normalized = model.model_dump(exclude_none=True)
    for key, value in data.items():
        normalized.setdefault(key, value)
    return normalized


def pydantic_status() -> tuple[bool, str]:
    return True, "Pydantic v2 validation enabled"
