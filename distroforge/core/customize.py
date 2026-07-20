from __future__ import annotations

import tomllib
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from importlib.resources import files
from pathlib import Path

from .apt import PackagePlan
from .chroot import ChrootService
from .command import CommandRunner
from .fsops import FileSystemOps


@dataclass(frozen=True)
class DesktopChoice:
    key: str
    label: str
    packages: tuple[str, ...]
    display_manager: str
    session: str
    packages_by_family: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def packages_for(self, family: str = "ubuntu") -> tuple[str, ...]:
        return self.packages_by_family.get(family, self.packages)


@dataclass
class IsoCustomization:
    desktop: str | None = None
    display_manager: str | None = None
    autologin_user: str | None = None
    wallpaper: str | None = None
    hostname: str | None = None
    locale: str | None = None
    timezone: str | None = None
    keyboard_layout: str | None = None
    extra_settings: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, object] | None) -> IsoCustomization:
        data = data or {}
        return cls(
            desktop=_optional_str(data.get("desktop")),
            display_manager=_optional_str(data.get("display_manager")),
            autologin_user=_optional_str(data.get("autologin_user")),
            wallpaper=_optional_str(data.get("wallpaper")),
            hostname=_optional_str(data.get("hostname")),
            locale=_optional_str(data.get("locale")),
            timezone=_optional_str(data.get("timezone")),
            keyboard_layout=_optional_str(data.get("keyboard_layout")),
            extra_settings=dict(data.get("extra_settings", {})),
        )


@lru_cache(maxsize=1)
def load_desktops() -> dict[str, DesktopChoice]:
    path = files("distroforge.data").joinpath("desktops.toml")
    raw = tomllib.loads(path.read_text(encoding="utf-8"))
    desktops: dict[str, DesktopChoice] = {}
    for key, data in raw["desktops"].items():
        desktops[key] = DesktopChoice(
            key=key,
            label=data["label"],
            packages=tuple(data.get("packages", [])),
            display_manager=data["display_manager"],
            session=data["session"],
            packages_by_family={
                family: tuple(packages)
                for family, packages in data.get("packages_by_family", {}).items()
            },
        )
    return desktops


def selected_desktop(customization: IsoCustomization) -> DesktopChoice | None:
    if not customization.desktop:
        return None
    return load_desktops().get(customization.desktop)


def split_desktop_packages(
    customization: IsoCustomization,
    packages: list[str],
    family: str = "ubuntu",
) -> tuple[list[str], list[str]]:
    conflicts = desktop_conflicting_packages(customization, family=family)
    kept: list[str] = []
    removed: list[str] = []
    for package in packages:
        if package in conflicts:
            removed.append(package)
        else:
            kept.append(package)
    return kept, removed


def desktop_package_plan(customization: IsoCustomization, family: str = "ubuntu") -> PackagePlan:
    if not customization.desktop:
        return PackagePlan()
    desktop = selected_desktop(customization)
    if not desktop:
        return PackagePlan()
    packages = list(desktop.packages_for(family))
    dm = customization.display_manager or desktop.display_manager
    if dm and dm not in packages:
        packages.append(dm)
    return PackagePlan(install=packages)


def desktop_conflicting_packages(customization: IsoCustomization, family: str = "ubuntu") -> set[str]:
    if not customization.desktop:
        return set()
    selected = selected_desktop(customization)
    if not selected:
        return set()
    kept = set(selected.packages_for(family))
    desktops = load_desktops()
    kept.update(desktop.display_manager for desktop in desktops.values())
    all_packages: set[str] = set()
    for desktop in desktops.values():
        all_packages.update(desktop.packages)
        for packages in desktop.packages_by_family.values():
            all_packages.update(packages)
    return all_packages - kept


class CustomizationService:
    def __init__(
        self,
        runner: CommandRunner,
        root: Path,
        customization: IsoCustomization,
        use_sudo: bool = True,
    ) -> None:
        self.runner = runner
        self.root = root
        self.customization = customization
        self.use_sudo = use_sudo
        self.fs = FileSystemOps(runner, use_sudo)

    def apply(self) -> None:
        self.configure_hostname()
        self.configure_locale_timezone_keyboard()
        self.configure_autologin()
        self.configure_wallpaper()

    def configure_hostname(self) -> None:
        if not self.customization.hostname:
            return
        self._write_text("etc/hostname", self.customization.hostname + "\n")
        hosts = (
            "127.0.0.1 localhost\n"
            f"127.0.1.1 {self.customization.hostname}\n"
            "::1 localhost ip6-localhost ip6-loopback\n"
        )
        self._write_text("etc/hosts", hosts)

    def configure_locale_timezone_keyboard(self) -> None:
        chroot = ChrootService(self.runner, self.root, self.use_sudo)
        if self.customization.locale:
            self._write_text("etc/default/locale", f"LANG={self.customization.locale}\n")
            chroot.run("locale-gen", self.customization.locale)
            chroot.run("update-locale", f"LANG={self.customization.locale}")
        if self.customization.timezone:
            self._write_text("etc/timezone", self.customization.timezone + "\n")
            chroot.run("ln", "-sf", f"/usr/share/zoneinfo/{self.customization.timezone}", "/etc/localtime")
        if self.customization.keyboard_layout:
            layout = self.customization.keyboard_layout
            self._write_text(
                "etc/default/keyboard",
                f'XKBMODEL="pc105"\nXKBLAYOUT="{layout}"\nXKBVARIANT=""\nXKBOPTIONS=""\n',
            )

    def configure_autologin(self) -> None:
        user = self.customization.autologin_user
        if not user:
            return
        dm = self._display_manager()
        if dm == "lightdm":
            self._write_text(
                "etc/lightdm/lightdm.conf.d/50-distroforge-autologin.conf",
                "[Seat:*]\n"
                f"autologin-user={user}\n"
                "autologin-user-timeout=0\n"
                f"user-session={self._session()}\n",
            )
        elif dm == "gdm3":
            self._write_text(
                "etc/gdm3/custom.conf",
                "[daemon]\n"
                "AutomaticLoginEnable=True\n"
                f"AutomaticLogin={user}\n",
            )
        elif dm == "sddm":
            self._write_text(
                "etc/sddm.conf.d/50-distroforge-autologin.conf",
                "[Autologin]\n"
                f"User={user}\n"
                f"Session={self._session()}.desktop\n",
            )
        else:
            self._write_text(
                "etc/distroforge/autologin.todo",
                f"Autologin requested for {user}, unsupported display manager: {dm}\n",
            )

    def configure_wallpaper(self) -> None:
        if not self.customization.wallpaper:
            return
        source = Path(self.customization.wallpaper)
        target_rel = "usr/share/backgrounds/distroforge/wallpaper" + source.suffix.lower()
        target = self.root / target_rel
        self.fs.copy_file(source, target, "Install custom wallpaper")
        uri = "file:///" + target_rel
        self._write_text(
            "usr/share/glib-2.0/schemas/99_distroforge-wallpaper.gschema.override",
            "[org.gnome.desktop.background]\n"
            f"picture-uri='{uri}'\n"
            f"picture-uri-dark='{uri}'\n"
            "picture-options='zoom'\n",
        )
        ChrootService(self.runner, self.root, self.use_sudo).run(
            "glib-compile-schemas", "/usr/share/glib-2.0/schemas"
        )

    def _display_manager(self) -> str:
        if self.customization.display_manager:
            return self.customization.display_manager
        if self.customization.desktop:
            return load_desktops()[self.customization.desktop].display_manager
        return "gdm3"

    def _session(self) -> str:
        if self.customization.desktop:
            return load_desktops()[self.customization.desktop].session
        return "ubuntu"

    def _write_text(self, relative: str, content: str) -> None:
        path = self.root / relative
        self.fs.write_text(path, content, f"Write {relative}")


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
