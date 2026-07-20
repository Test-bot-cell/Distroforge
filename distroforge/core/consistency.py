from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from .customize import selected_desktop
from .project import Project

if TYPE_CHECKING:
    from .build import BuildOptions


@dataclass(frozen=True)
class ConsistencyIssue:
    level: str
    code: str
    message: str


class ConsistencyService:
    def check(self, project: Project, options: BuildOptions) -> list[ConsistencyIssue]:
        issues: list[ConsistencyIssue] = []
        custom = project.customization
        if custom.desktop and custom.display_manager:
            desktop = selected_desktop(custom)
            if not desktop:
                return issues
            expected = desktop.display_manager
            if custom.display_manager != expected:
                issues.append(
                    ConsistencyIssue(
                        "warning",
                        "desktop-display-manager",
                        f"{custom.desktop} usually uses {expected}, not {custom.display_manager}",
                    )
                )
        if custom.autologin_user and not custom.desktop:
            issues.append(
                ConsistencyIssue(
                    "warning",
                    "autologin-session",
                    "Autologin is set without an explicit desktop session",
                )
            )
        if custom.wallpaper and Path(custom.wallpaper).suffix.lower() not in {
            ".png",
            ".jpg",
            ".jpeg",
            ".webp",
        }:
            issues.append(
                ConsistencyIssue(
                    "warning",
                    "wallpaper-format",
                    "Wallpaper format should be png, jpg or webp",
                )
            )
        if options.release_track.mode == "rolling" and not options.qa.scenarios:
            issues.append(
                ConsistencyIssue(
                    "warning",
                    "rolling-no-qa",
                    "Rolling-like builds should enable at least one QA boot scenario",
                )
            )
        if options.system_sync.enabled and options.system_sync.strategy == "full" and not options.snapshots.enabled:
            issues.append(
                ConsistencyIssue(
                    "warning",
                    "system-sync-no-snapshot",
                    "Full system sync should enable snapshots for rollback",
                )
            )
        if options.secure_boot.enabled and options.kernel_module.enabled and not options.secure_boot.sign_modules:
            issues.append(
                ConsistencyIssue(
                    "error",
                    "unsigned-kernel-module",
                    "Secure Boot with a custom module should enable module signing",
                )
            )
        if (
            options.kernel_module.enabled
            and options.kernel_module.build_mode == "full-deb"
            and not options.snapshots.enabled
        ):
            issues.append(
                ConsistencyIssue(
                    "warning",
                    "full-kernel-no-snapshot",
                    "Full kernel .deb builds should enable snapshots for rollback",
                )
            )
        if options.desktop_source.enabled and not options.snapshots.enabled:
            issues.append(
                ConsistencyIssue(
                    "warning",
                    "desktop-source-no-snapshot",
                    "Desktop source .deb builds should enable snapshots for rollback",
                )
            )
        if options.desktop_source.enabled and options.desktop_source.desktop != custom.desktop:
            issues.append(
                ConsistencyIssue(
                    "warning",
                    "desktop-source-mismatch",
                    "Desktop source build target does not match the selected desktop",
                )
            )
        return issues
