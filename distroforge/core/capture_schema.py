from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .capture_report import CaptureReport

CAPTURE_SCHEMA_VERSION = "distroforge.capture.v1"


@dataclass
class CapturedSystemProfile:
    definition: dict[str, object]
    report: CaptureReport
    target: Path
    sanitize: str = "strict"
    included_configs: list[str] = field(default_factory=list)
    included_config_globs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            **self.definition,
            "capture": {
                "schema": CAPTURE_SCHEMA_VERSION,
                "target": str(self.target),
                "sanitize": self.sanitize,
                "included_configs": self.included_configs,
                "included_config_globs": self.included_config_globs,
                "report": self.report.to_dict(),
            },
        }

    def render_yaml(self) -> str:
        return yaml.safe_dump(self.to_dict(), sort_keys=False, allow_unicode=False)

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def render_summary(self) -> str:
        metadata = self.definition.get("metadata", {})
        name = metadata.get("name", "captured-system") if isinstance(metadata, dict) else "captured-system"
        release = metadata.get("release", "-") if isinstance(metadata, dict) else "-"
        packages = self.definition.get("packages", [])
        repos = self.definition.get("repositories", [])
        lines = [
            f"Captured profile: {name}",
            f"Release: {release}",
            f"Packages: {len(packages) if isinstance(packages, list) else 0}",
            f"APT sources: {len(repos) if isinstance(repos, list) else 0}",
            "",
            self.report.render_text(),
        ]
        return "\n".join(lines)
