from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SystemdImagePlan:
    mode: str
    partition_layout: Path | None = None
    update_strategy: str = "manual"

    def to_dict(self) -> dict[str, object]:
        return {
            "mode": self.mode,
            "backend": "systemd-repart/sysupdate",
            "partition_layout": str(self.partition_layout) if self.partition_layout else None,
            "update_strategy": self.update_strategy,
            "steps": [
                "Validate repart.d partition declarations",
                "Build image offline",
                "Attach verity/UKI policy when configured",
                "Publish current/next resources for sysupdate",
                "Require explicit factory-reset policy",
            ],
            "status": "plan-only",
        }

    def render_text(self) -> str:
        data = self.to_dict()
        lines = [
            "Systemd/OEM image plan",
            f"Mode: {self.mode}",
            f"Partition layout: {data['partition_layout'] or '-'}",
            f"Update strategy: {self.update_strategy}",
            "Status: plan-only",
            "",
            "Steps:",
        ]
        lines.extend(f"- {step}" for step in data["steps"])
        return "\n".join(lines)

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)
