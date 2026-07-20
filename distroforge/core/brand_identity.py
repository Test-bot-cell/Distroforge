from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .branding import BrandingOptions
from .branding_palettes import generate_palette
from .project import Project


@dataclass(frozen=True)
class BrandIdentity:
    short_name: str
    full_name: str
    product_name: str
    vendor: str
    os_id: str
    version_id: str
    version_codename: str
    slogan: str | None = None
    colors: tuple[str, ...] = field(default_factory=tuple)
    logo: str | None = None
    icon: str | None = None
    support_url: str | None = None
    docs_url: str | None = None
    bug_report_url: str | None = None
    privacy_policy_url: str | None = None

    @classmethod
    def from_project_options(cls, project: Project, options: BrandingOptions) -> BrandIdentity:
        short_name = options.name or options.product_name or project.name
        version_id = options.version_id or project.release.version
        full_name = options.pretty_name or f"{short_name} {version_id}"
        product_name = options.product_name or short_name
        colors = options.palette_colors or generate_palette(short_name)
        return cls(
            short_name=short_name,
            full_name=full_name,
            product_name=product_name,
            vendor=options.vendor or short_name,
            os_id=options.os_id or _slug(short_name),
            version_id=version_id,
            version_codename=options.version_codename or project.release.codename,
            colors=tuple(colors),
            logo=options.logo,
            icon=options.icon_name or options.app_icon,
            support_url=options.support_url,
            docs_url=options.home_url,
            bug_report_url=options.bug_report_url,
            privacy_policy_url=options.privacy_policy_url,
        )

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> BrandIdentity:
        values = dict(data)
        if isinstance(values.get("colors"), list):
            values["colors"] = tuple(str(item) for item in values["colors"])
        return cls(**values)  # type: ignore[arg-type]

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["colors"] = list(self.colors)
        return data

    def to_branding_options(self) -> BrandingOptions:
        return BrandingOptions(
            name=self.short_name,
            pretty_name=self.full_name,
            product_name=self.product_name,
            vendor=self.vendor,
            os_id=self.os_id,
            version_id=self.version_id,
            version_codename=self.version_codename,
            home_url=self.docs_url,
            support_url=self.support_url,
            bug_report_url=self.bug_report_url,
            privacy_policy_url=self.privacy_policy_url,
            icon_name=self.icon,
            palette_colors=self.colors,
            logo=self.logo,
            app_icon=self.icon,
            grub_distributor=self.short_name,
            grub_menu_label=f"{self.product_name} {self.version_id}",
            issue_text=f"{self.full_name} \\n \\l",
            motd_text=f"Welcome to {self.full_name}",
        )

    def render_manifest(self) -> str:
        return json.dumps(self.to_dict(), indent=2) + "\n"

    def render_preview(self) -> str:
        colors = ", ".join(self.colors) if self.colors else "default"
        lines = [
            "Brand identity preview",
            f"Name: {self.short_name}",
            f"Full name: {self.full_name}",
            f"Product: {self.product_name}",
            f"Vendor: {self.vendor}",
            f"OS ID: {self.os_id}",
            f"Version: {self.version_id} ({self.version_codename})",
            f"Colors: {colors}",
            "",
            "GRUB",
            f"  distributor={self.short_name}",
            f"  menu={self.product_name} {self.version_id}",
            "",
            "Plymouth",
            f"  theme={_slug(self.short_name)}",
            f"  title={self.full_name}",
            "",
            "os-release",
            f"  NAME={self.short_name}",
            f"  PRETTY_NAME={self.full_name}",
            f"  ID={self.os_id}",
        ]
        return "\n".join(lines) + "\n"

    def write(self, target: Path) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.render_manifest(), encoding="utf-8")

    def write_preview(self, target_dir: Path) -> None:
        target_dir.mkdir(parents=True, exist_ok=True)
        (target_dir / "identity.txt").write_text(self.render_preview(), encoding="utf-8")
        (target_dir / "grub.cfg").write_text(
            f'GRUB_DISTRIBUTOR="{self.short_name}"\n'
            f'menuentry "{self.product_name} {self.version_id}" {{}}\n',
            encoding="utf-8",
        )
        (target_dir / "os-release").write_text(
            f'NAME="{self.short_name}"\n'
            f'PRETTY_NAME="{self.full_name}"\n'
            f'ID="{self.os_id}"\n'
            f'VERSION_ID="{self.version_id}"\n',
            encoding="utf-8",
        )
        (target_dir / "plymouth.txt").write_text(
            f"Theme: {_slug(self.short_name)}\n"
            f"Title: {self.full_name}\n"
            f"Main color: {self.colors[0] if self.colors else '#2e3436'}\n",
            encoding="utf-8",
        )


def load_identity(path: Path) -> BrandIdentity:
    return BrandIdentity.from_dict(json.loads(path.read_text(encoding="utf-8")))


def write_identity(project: Project, options: BrandingOptions, target: Path | None = None) -> BrandIdentity:
    identity = BrandIdentity.from_project_options(project, options)
    identity.write(target or project.output_dir / "BRANDING-MANIFEST.json")
    return identity


def write_identity_preview(project: Project, options: BrandingOptions, target_dir: Path | None = None) -> BrandIdentity:
    identity = BrandIdentity.from_project_options(project, options)
    identity.write_preview(target_dir or project.output_dir / "branding-preview")
    return identity


def _slug(value: str) -> str:
    text = "".join(ch.lower() if ch.isalnum() else "-" for ch in value.strip())
    collapsed = "-".join(part for part in text.split("-") if part)
    return collapsed or "distro"
