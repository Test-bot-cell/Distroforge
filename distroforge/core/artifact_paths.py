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


def default_output_iso(project: Project) -> Path:
    """Canonical default ISO path.

    The single source of truth for the name the builder produces. Consumers used
    to fall back on an unversioned {name}.iso while the builder wrote
    {name}-{version}.iso, so boot-proof, release-pipeline, iso-acceptance and
    publish-drill all reported a missing ISO for an ISO that was right there.
    """
    return project.output_dir / f"{project.name}-{project.release.version}.iso"


def package_artifact_dir(root: Path, override: Path | None = None) -> Path:
    """Canonical location of the Debian artifacts built from ``root``.

    dpkg-buildpackage writes the .deb, .changes and .buildinfo into the parent of the
    source tree, so that stays the default. What did not exist was any way to say
    otherwise: six call sites across packaging.py and evidence.py hardcoded
    ``root.resolve().parent``, so a maintainer who keeps the archive anywhere else got a
    clean report about an empty directory from debian-package, packaging-policy,
    evidence-status and the hermetic bundle alike -- the one failure mode that reads
    exactly like success.
    """
    if override is not None:
        return override.expanduser().resolve()
    return root.resolve().parent


def default_artifact_paths(project: Project) -> HostArtifactPaths:
    output = project.output_dir
    return HostArtifactPaths(
        output_iso=default_output_iso(project),
        reports_dir=output / "reports",
        livefs_work_dir=output / "livefs-iso",
        live_build_dir=output / "live-build",
        screenshot=output / "qemu-lab" / "screenshot.ppm",
        serial_log=output / "qemu-lab" / "serial.log",
    )
