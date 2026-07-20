from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .customize import IsoCustomization, desktop_conflicting_packages
from .releases import UbuntuRelease, get_release


@dataclass
class Project:
    name: str
    root: Path
    release: UbuntuRelease
    source_mode: str = "iso"
    source_iso: Path | None = None
    source_starter: dict[str, object] | None = None
    packages: list[str] = field(default_factory=list)
    remove_packages: list[str] = field(default_factory=list)
    repositories: list[str] = field(default_factory=list)
    customization: IsoCustomization = field(default_factory=IsoCustomization)
    legacy_desktop_packages_removed: list[str] = field(default_factory=list, init=False, repr=False)
    legacy_desktop_packages_before: list[str] = field(default_factory=list, init=False, repr=False)

    @property
    def workdir(self) -> Path:
        return self.root / "work"

    @property
    def iso_root(self) -> Path:
        return self.workdir / "iso"

    @property
    def squashfs_root(self) -> Path:
        return self.workdir / "filesystem"

    @property
    def output_dir(self) -> Path:
        return self.root / "dist"

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "release": self.release.version,
            "source_mode": self.source_mode,
            "source_iso": str(self.source_iso) if self.source_iso else None,
            "source_starter": self.source_starter,
            "packages": self.packages,
            "remove_packages": self.remove_packages,
            "repositories": self.repositories,
            "customization": self.customization.to_dict(),
        }

    def save(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "project.json").write_text(
            json.dumps(self.to_dict(), indent=2), encoding="utf-8"
        )

    @classmethod
    def load(cls, root: Path) -> Project:
        project_file = root / "project.json"
        if not project_file.exists():
            raise FileNotFoundError(
                f"No DistroForge project found at {root}. Run `distroforge new NAME {root}` first."
            )
        data = json.loads(project_file.read_text(encoding="utf-8"))
        project = cls(
            name=data["name"],
            root=root,
            release=get_release(data["release"]),
            source_mode=data.get("source_mode", "iso"),
            source_iso=Path(data["source_iso"]) if data.get("source_iso") else None,
            source_starter=data.get("source_starter"),
            packages=list(data.get("packages", [])),
            remove_packages=list(data.get("remove_packages", [])),
            repositories=list(data.get("repositories", [])),
            customization=IsoCustomization.from_dict(data.get("customization")),
        )
        project.legacy_desktop_packages_removed = project.sanitize_legacy_desktop_packages(
            project_file=project_file
        )
        return project

    @classmethod
    def create(cls, name: str, root: Path, release_version: str) -> Project:
        project = cls(name=name, root=root, release=get_release(release_version))
        project.workdir.mkdir(parents=True, exist_ok=True)
        project.output_dir.mkdir(parents=True, exist_ok=True)
        project.save()
        return project

    def sanitize_legacy_desktop_packages(self, project_file: Path | None = None) -> list[str]:
        conflicts = desktop_conflicting_packages(self.customization, family=self.release.family)
        self.legacy_desktop_packages_before = list(self.packages)
        if not conflicts:
            self.legacy_desktop_packages_removed = []
            return []
        filtered: list[str] = []
        removed: list[str] = []
        for pkg in self.packages:
            if pkg in conflicts:
                removed.append(pkg)
            else:
                filtered.append(pkg)
        if not removed:
            return []
        self.packages = filtered
        target = project_file or (self.root / "project.json")
        try:
            target.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        except OSError:
            pass
        return removed

    def desktop_sanitization_message(self) -> str:
        if not self.legacy_desktop_packages_removed:
            return ""
        removed = ", ".join(sorted(self.legacy_desktop_packages_removed))
        kept = ", ".join(sorted(self.packages))
        return (
            "Sanitized legacy desktop packages from project metadata: "
            f"removed [{removed}], resulting install list [{kept}]"
        )
