from __future__ import annotations

from dataclasses import dataclass, fields
from pathlib import Path

from .branding_palettes import generate_palette, load_branding_palettes
from .chroot import ChrootService
from .command import CommandRunner, CommandSpec
from .fsops import FileSystemOps
from .project import Project


@dataclass
class BrandingOptions:
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
    palette_colors: tuple[str, ...] = ()
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


class BrandingService:
    def __init__(
        self,
        runner: CommandRunner,
        project: Project,
        options: BrandingOptions,
        use_sudo: bool = True,
    ) -> None:
        self.runner = runner
        self.project = project
        self.options = options
        self.use_sudo = use_sudo
        self.rootfs = FileSystemOps(runner, use_sudo)
        self.iso = FileSystemOps(runner, use_sudo)

    def apply(self) -> None:
        if not any(getattr(self.options, field.name) for field in fields(BrandingOptions)):
            return
        palette = self._palette_colors()
        if self._has_identity():
            self._write_text("etc/lsb-release", self._lsb_release())
            self._write_text("etc/os-release.d/distroforge-branding", self._os_release_override())
            self._write_text("etc/distroforge/branding.json", self._branding_manifest())
            self._write_text("etc/distroforge/palette.css", self._palette_css(palette))
            self._write_text(".disk/info", f"{self._display_name()} {self._version_id()}\n", iso=True)
            self._write_text("README.diskdefines", self._disk_defines(), iso=True)
        if self.options.issue_text:
            self._write_text("etc/issue", self.options.issue_text + "\n")
            self._write_text("etc/issue.net", self.options.issue_text + "\n")
        if self.options.motd_text:
            self._write_text("etc/motd", self.options.motd_text + "\n")
        if self.options.logo:
            self._copy(self.options.logo, "usr/share/pixmaps/distroforge-logo" + Path(self.options.logo).suffix)
        if self.options.distributor_logo:
            suffix = Path(self.options.distributor_logo).suffix
            self._copy(self.options.distributor_logo, "usr/share/pixmaps/distributor-logo" + suffix)
        if self.options.app_icon:
            suffix = Path(self.options.app_icon).suffix
            self._copy(self.options.app_icon, "usr/share/icons/hicolor/256x256/apps/distroforge" + suffix)
        if self.options.grub_background:
            background = "boot/grub/distroforge-background" + Path(
                self.options.grub_background
            ).suffix
            self._copy(self.options.grub_background, background, iso=True)
            self._write_text(
                "boot/grub/distroforge-theme.cfg",
                f"background_image /boot/grub/distroforge-background{Path(self.options.grub_background).suffix}\n",
                iso=True,
            )
        if self.options.grub_theme:
            self._copy_tree(self.options.grub_theme, "boot/grub/themes/distroforge", iso=True)
        if self.options.grub_distributor or self.options.grub_menu_label or self.options.grub_background:
            self._write_text("etc/default/grub.d/99-distroforge-branding.cfg", self._grub_defaults())
        if self.options.plymouth_theme:
            source = Path(self.options.plymouth_theme)
            if source.exists() and source.is_dir():
                self._copy_tree(str(source), f"usr/share/plymouth/themes/{source.name}")
            else:
                self.runner.run(
                    CommandSpec(
                        argv=("plymouth-theme-plan", self.options.plymouth_theme),
                        description="Plan Plymouth theme installation",
                    )
                )
            self._write_text("etc/distroforge/plymouth-theme", self.options.plymouth_theme + "\n")
        if self._has_custom_plymouth():
            self._install_custom_plymouth_theme()
        if self.options.login_background:
            suffix = Path(self.options.login_background).suffix
            self._copy(self.options.login_background, "usr/share/backgrounds/distroforge/login" + suffix)
            self._write_text(
                "usr/share/glib-2.0/schemas/99_distroforge-login.gschema.override",
                "[org.gnome.desktop.background]\n"
                f"picture-uri='file:///usr/share/backgrounds/distroforge/login{suffix}'\n"
                f"picture-uri-dark='file:///usr/share/backgrounds/distroforge/login{suffix}'\n",
            )
        if self.options.lightdm_background:
            suffix = Path(self.options.lightdm_background).suffix
            self._copy(self.options.lightdm_background, "usr/share/backgrounds/distroforge/lightdm" + suffix)
            self._write_text(
                "etc/lightdm/lightdm-gtk-greeter.conf.d/99-distroforge-branding.conf",
                "[greeter]\n"
                f"background=/usr/share/backgrounds/distroforge/lightdm{suffix}\n",
            )
        if self.options.installer_slideshow:
            self._copy_tree(self.options.installer_slideshow, "usr/share/ubiquity-slideshow/slides/distroforge")

    def _lsb_release(self) -> str:
        name = self._display_name()
        return (
            f"DISTRIB_ID={name}\n"
            f"DISTRIB_RELEASE={self._version_id()}\n"
            f"DISTRIB_CODENAME={self._version_codename()}\n"
            f'DISTRIB_DESCRIPTION="{self._pretty_name()}"\n'
        )

    def _os_release_override(self) -> str:
        values = {
            "NAME": self._display_name(),
            "PRETTY_NAME": self._pretty_name(),
            "ID": self.options.os_id,
            "ID_LIKE": self.options.id_like,
            "VERSION_ID": self._version_id(),
            "VERSION_CODENAME": self._version_codename(),
            "HOME_URL": self.options.home_url,
            "SUPPORT_URL": self.options.support_url,
            "BUG_REPORT_URL": self.options.bug_report_url,
            "PRIVACY_POLICY_URL": self.options.privacy_policy_url,
            "ANSI_COLOR": self.options.ansi_color,
            "LOGO": self.options.icon_name,
        }
        return "".join(f'{key}="{value}"\n' for key, value in values.items() if value)

    def _branding_manifest(self) -> str:
        name = self._display_name()
        vendor = self.options.vendor or name
        return (
            "{\n"
            f'  "name": "{_json_escape(name)}",\n'
            f'  "pretty_name": "{_json_escape(self._pretty_name())}",\n'
            f'  "product_name": "{_json_escape(self.options.product_name or name)}",\n'
            f'  "vendor": "{_json_escape(vendor)}"\n'
            "}\n"
        )

    def _disk_defines(self) -> str:
        label = self.options.grub_menu_label or self.options.product_name or self._display_name()
        return (
            f"#define DISKNAME  {label}\n"
            f"#define TYPE  binary\n"
            f"#define TYPEbinary  1\n"
            f"#define ARCH  amd64\n"
            f"#define DISKNUM  1\n"
            f"#define TOTALNUM  1\n"
        )

    def _grub_defaults(self) -> str:
        lines = []
        if distributor := self.options.grub_distributor or self._display_name():
            lines.append(f'GRUB_DISTRIBUTOR="{distributor}"')
        if self.options.grub_background:
            lines.append("GRUB_BACKGROUND=/boot/grub/distroforge-background" + Path(self.options.grub_background).suffix)
        if self.options.grub_theme:
            lines.append("GRUB_THEME=/boot/grub/themes/distroforge/theme.txt")
        return "\n".join(lines) + "\n"

    def _has_identity(self) -> bool:
        return any(
            (
                self.options.name,
                self.options.pretty_name,
                self.options.product_name,
                self.options.vendor,
                self.options.os_id,
                self.options.home_url,
                self.options.support_url,
                self.options.bug_report_url,
                self.options.privacy_policy_url,
            )
        )

    def _display_name(self) -> str:
        return self.options.name or self.options.product_name or self.project.name

    def _pretty_name(self) -> str:
        return self.options.pretty_name or f"{self._display_name()} {self._version_id()}"

    def _version_id(self) -> str:
        return self.options.version_id or self.project.release.version

    def _version_codename(self) -> str:
        return self.options.version_codename or self.project.release.codename

    def _has_custom_plymouth(self) -> bool:
        return any(
            (
                self.options.plymouth_logo,
                self.options.plymouth_spinner,
                self.options.plymouth_background,
                self.options.plymouth_main_color,
            )
        )

    def _install_custom_plymouth_theme(self) -> None:
        theme_dir = "usr/share/plymouth/themes/distroforge"
        logo_name = self._plymouth_asset("plymouth_logo", "logo")
        spinner_name = self._plymouth_asset("plymouth_spinner", "spinner")
        background_name = self._plymouth_asset("plymouth_background", "background")
        self._write_text(f"{theme_dir}/distroforge.plymouth", self._plymouth_descriptor())
        self._write_text(
            f"{theme_dir}/distroforge.script",
            self._plymouth_script(logo_name, spinner_name, background_name),
        )
        chroot = ChrootService(self.runner, self.project.squashfs_root, self.use_sudo)
        chroot.run("apt-get", "-y", "install", "plymouth", "plymouth-theme-spinner")
        chroot.run(
            "update-alternatives",
            "--install",
            "/usr/share/plymouth/themes/default.plymouth",
            "default.plymouth",
            "/usr/share/plymouth/themes/distroforge/distroforge.plymouth",
            "200",
        )
        chroot.run(
            "update-alternatives",
            "--set",
            "default.plymouth",
            "/usr/share/plymouth/themes/distroforge/distroforge.plymouth",
        )
        chroot.run("update-initramfs", "-u", "-k", "all")
        self._copy_latest_initrd_to_iso()

    def _plymouth_asset(self, field_name: str, target_stem: str) -> str | None:
        source = getattr(self.options, field_name)
        if not source:
            return None
        suffix = Path(source).suffix or ".png"
        filename = f"{target_stem}{suffix}"
        self._copy(source, f"usr/share/plymouth/themes/distroforge/{filename}")
        return filename

    def _plymouth_descriptor(self) -> str:
        return (
            "[Plymouth Theme]\n"
            f"Name={self._display_name()}\n"
            f"Description={self._pretty_name()} boot splash\n"
            "ModuleName=script\n"
            "\n"
            "[script]\n"
            "ImageDir=/usr/share/plymouth/themes/distroforge\n"
            "ScriptFile=/usr/share/plymouth/themes/distroforge/distroforge.script\n"
        )

    def _plymouth_script(
        self,
        logo_name: str | None,
        spinner_name: str | None,
        background_name: str | None,
    ) -> str:
        red, green, blue = _hex_to_plymouth_rgb(self._main_color())
        lines = [
            f"Window.SetBackgroundTopColor({red}, {green}, {blue});",
            f"Window.SetBackgroundBottomColor({red}, {green}, {blue});",
            "screen_width = Window.GetWidth();",
            "screen_height = Window.GetHeight();",
        ]
        if background_name:
            lines.extend(
                [
                    f'background_image = Image("{background_name}");',
                    "background_sprite = Sprite(background_image.Scale(screen_width, screen_height));",
                    "background_sprite.SetX(0);",
                    "background_sprite.SetY(0);",
                    "background_sprite.SetZ(-100);",
                ]
            )
        if logo_name:
            lines.extend(
                [
                    f'logo_image = Image("{logo_name}");',
                    "logo_sprite = Sprite(logo_image);",
                    "logo_sprite.SetX(screen_width / 2 - logo_image.GetWidth() / 2);",
                    "logo_sprite.SetY(screen_height / 2 - logo_image.GetHeight() / 2);",
                ]
            )
        if spinner_name:
            lines.extend(
                [
                    f'spinner_image = Image("{spinner_name}");',
                    "spinner_sprite = Sprite(spinner_image);",
                    "spinner_sprite.SetX(screen_width / 2 - spinner_image.GetWidth() / 2);",
                    "spinner_sprite.SetY(screen_height * 0.70);",
                    "spinner_tick = 0;",
                    "fun refresh_callback () {",
                    "  spinner_tick = spinner_tick + 1;",
                    "  spinner_sprite.SetOpacity(0.45 + 0.35 * Math.Sin(spinner_tick / 6));",
                    "}",
                    "Plymouth.SetRefreshFunction(refresh_callback);",
                ]
            )
        return "\n".join(lines) + "\n"

    def _copy_latest_initrd_to_iso(self) -> None:
        boot_dir = self.project.squashfs_root / "boot"
        live_dir = self.project.iso_root / self.project.release.livefs
        initrds = sorted(boot_dir.glob("initrd.img-*")) if boot_dir.exists() else []
        source = initrds[-1] if initrds else boot_dir / "initrd.img-dry-run"
        target = live_dir / "initrd"
        if self.runner.dry_run:
            self.runner.run(
                CommandSpec(
                    argv=("copy-file", str(source), str(target)),
                    description="Refresh live initrd after Plymouth branding",
                )
            )
            return
        if not source.exists():
            return
        self.iso.copy_file(source, target, "Refresh live initrd after Plymouth branding")

    def _palette_colors(self) -> tuple[str, ...]:
        if self.options.palette_colors:
            return self.options.palette_colors
        if self.options.palette == "generate":
            return generate_palette(self.options.palette_seed or self._display_name())
        if self.options.palette:
            palettes = load_branding_palettes()
            if self.options.palette in palettes:
                return palettes[self.options.palette].colors
        return ()

    def _main_color(self) -> str:
        if self.options.plymouth_main_color:
            return self.options.plymouth_main_color
        palette = self._palette_colors()
        return palette[0] if palette else "#2e3436"

    def _palette_css(self, colors: tuple[str, ...]) -> str:
        if not colors:
            colors = (self._main_color(),)
        lines = [":root {"]
        for index, color in enumerate(colors, start=1):
            lines.append(f"  --distroforge-color-{index}: {color};")
        lines.append(f"  --distroforge-main-color: {colors[0]};")
        lines.append("}")
        return "\n".join(lines) + "\n"

    def _write_text(self, relative: str, content: str, iso: bool = False) -> None:
        root = self.project.iso_root if iso else self.project.squashfs_root
        path = root / relative
        ops = self.iso if iso else self.rootfs
        ops.write_text(path, content, f"Write branding {relative}")

    def _copy(self, source: str, relative: str, iso: bool = False) -> None:
        root = self.project.iso_root if iso else self.project.squashfs_root
        target = root / relative
        ops = self.iso if iso else self.rootfs
        ops.copy_file(Path(source), target, "Copy branding asset")

    def _copy_tree(self, source: str, relative: str, iso: bool = False) -> None:
        root = self.project.iso_root if iso else self.project.squashfs_root
        target = root / relative
        ops = self.iso if iso else self.rootfs
        ops.copy_tree(Path(source), target, "Copy branding tree")


def _json_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _hex_to_plymouth_rgb(value: str) -> tuple[str, str, str]:
    text = value.strip()
    if text.startswith("#"):
        text = text[1:]
    if len(text) != 6:
        text = "2e3436"
    try:
        red = int(text[0:2], 16) / 255
        green = int(text[2:4], 16) / 255
        blue = int(text[4:6], 16) / 255
    except ValueError:
        red, green, blue = (0x2E / 255, 0x34 / 255, 0x36 / 255)
    return (f"{red:.4f}", f"{green:.4f}", f"{blue:.4f}")
