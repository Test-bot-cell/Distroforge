from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .project import Project


@dataclass(frozen=True)
class HostArtifactPaths:
    output_iso: Path
    reports_dir: Path
    livefs_work_dir: Path
    live_build_dir: Path
    screenshot: Path
    serial_log: Path

    def to_dict(self) -> dict[str, str]:
        return {
            "output_iso": str(self.output_iso),
            "reports_dir": str(self.reports_dir),
            "livefs_work_dir": str(self.livefs_work_dir),
            "live_build_dir": str(self.live_build_dir),
            "screenshot": str(self.screenshot),
            "serial_log": str(self.serial_log),
        }

    def render_text(self) -> str:
        lines = ["Host artifact paths"]
        lines.extend(f"- {key}: {value}" for key, value in self.to_dict().items())
        return "\n".join(lines)

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def default_artifact_paths(project: Project) -> HostArtifactPaths:
    output = project.output_dir
    return HostArtifactPaths(
        output_iso=output / f"{project.name}.iso",
        reports_dir=output / "reports",
        livefs_work_dir=output / "livefs-iso",
        live_build_dir=output / "live-build",
        screenshot=output / "qemu-lab" / "screenshot.ppm",
        serial_log=output / "qemu-lab" / "serial.log",
    )
