from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .definition import load_definition


@dataclass(frozen=True)
class CaptureDiff:
    packages: int
    config_files: list[str]
    captured: int
    ignored: int
    dangerous: int
    not_reproducible: int

    def to_dict(self) -> dict[str, object]:
        return {
            "packages": self.packages,
            "config_files": self.config_files,
            "captured": self.captured,
            "ignored": self.ignored,
            "dangerous": self.dangerous,
            "not_reproducible": self.not_reproducible,
        }

    def render_text(self) -> str:
        lines = [
            "Captured profile diff",
            f"Packages: {self.packages}",
            f"Config files: {len(self.config_files)}",
            f"Captured findings: {self.captured}",
            f"Ignored findings: {self.ignored}",
            f"Dangerous findings: {self.dangerous}",
            f"Not reproducible findings: {self.not_reproducible}",
            "",
            "Included config files:",
        ]
        lines.extend(f"- {path}" for path in self.config_files) or lines.append("-")
        return "\n".join(lines)

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def diff_capture_profile(profile: Path) -> CaptureDiff:
    data = load_definition(profile)
    packages = data.get("packages", [])
    configs = data.get("capture_config_files", [])
    capture = data.get("capture", {})
    report = capture.get("report", {}) if isinstance(capture, dict) else {}
    counts = report.get("counts", {}) if isinstance(report, dict) else {}
    return CaptureDiff(
        packages=len(packages) if isinstance(packages, list) else 0,
        config_files=[str(item.get("path")) for item in configs if isinstance(item, dict) and item.get("path")],
        captured=int(counts.get("captured", 0)),
        ignored=int(counts.get("ignored", 0)),
        dangerous=int(counts.get("dangerous", 0)),
        not_reproducible=int(counts.get("not reproducible", 0)),
    )
