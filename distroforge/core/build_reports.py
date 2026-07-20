from __future__ import annotations

from typing import TYPE_CHECKING

from .command import CommandRunner
from .diff_preview import DiffPreviewService
from .host_artifacts import HostArtifactWriter
from .project import Project

if TYPE_CHECKING:
    from .build import BuildOptions


class BuildReportArtifactService:
    """Host-owned build reports produced around the source-to-ISO pipeline."""

    def __init__(self, runner: CommandRunner, project: Project, options: BuildOptions) -> None:
        self.runner = runner
        self.project = project
        self.options = options

    def write_diff_preview(self) -> None:
        preview = DiffPreviewService().preview(self.project, self.options)
        target = self.project.output_dir / "distroforge-diff.txt"
        lines = [
            "DistroForge planned diff",
            "",
            "Install:",
            *[f"- {item}" for item in preview.install],
            "",
            "Remove:",
            *[f"- {item}" for item in preview.remove],
            "",
            "Snaps:",
            *[f"- {item}" for item in preview.snaps],
            "",
            "Services:",
            *[f"- {item}" for item in preview.services],
            "",
            "Flags:",
            *[f"- {item}" for item in preview.estimated_flags],
            "",
        ]
        HostArtifactWriter(self.runner).write_text(
            target,
            "\n".join(lines),
            f"Write diff preview with {len(preview.install)} install(s), "
            f"{len(preview.remove)} removal(s)",
        )

    def write_compatibility_report(self, compatibility: object) -> None:
        target = self.project.output_dir / "compatibility-report.txt"
        messages = getattr(compatibility, "messages", [])
        lines = [
            "DistroForge compatibility report",
            "",
            f"Release: {getattr(compatibility, 'release', '-')}",
            f"Codename: {getattr(compatibility, 'codename', '-')}",
            f"Status: {'supported' if getattr(compatibility, 'supported', False) else 'planned'}",
            "",
            "Messages:",
            *[f"- {message}" for message in messages],
        ]
        if not messages:
            lines.append("- Release supported by DistroForge")
        HostArtifactWriter(self.runner).write_text(
            target, "\n".join(lines) + "\n", "Write release compatibility report"
        )
