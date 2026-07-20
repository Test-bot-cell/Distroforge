from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .customize import desktop_package_plan, split_desktop_packages
from .project import Project

if TYPE_CHECKING:
    from .build import BuildOptions


@dataclass
class DiffPreview:
    install: list[str]
    remove: list[str]
    snaps: list[str]
    services: list[str]
    estimated_flags: list[str]


class DiffPreviewService:
    def preview(self, project: Project, options: BuildOptions) -> DiffPreview:
        family = project.release.family
        desktop = desktop_package_plan(project.customization, family=family)
        project_packages, project_conflicts = split_desktop_packages(
            project.customization, list(project.packages), family=family
        )
        option_packages, option_conflicts = split_desktop_packages(
            project.customization, list(options.package_plan.install), family=family
        )
        install = sorted(
            set(
                [
                    *desktop.install,
                    *project_packages,
                    *option_packages,
                ]
            )
        )
        remove = sorted(
            set(
                [
                    *project.remove_packages,
                    *options.package_plan.remove,
                    *project_conflicts,
                    *option_conflicts,
                ]
            )
            - set(install)
        )
        snaps = [f"{snap.name}:{snap.channel}" for snap in options.snaps.specs]
        services = []
        if options.drivers.auto:
            services.append("ubuntu-drivers")
        if options.autoinstall.enabled:
            services.append("autoinstall")
        flags = []
        if options.release_track.mode != "stable":
            flags.append(f"release-track={options.release_track.mode}")
        if options.sanitize.enabled:
            flags.append("sanitize")
        return DiffPreview(install, remove, snaps, services, flags)
