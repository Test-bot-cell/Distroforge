from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from .host_artifacts import write_host_artifact
from .project import Project


@dataclass(frozen=True)
class PublishDrillBaselineReport:
    project: Path
    bundle_dir: Path
    source: Path
    baseline: Path
    report: Path
    status: str
    promoted: bool
    allow_blocked: bool
    reason: str

    @property
    def blocked(self) -> bool:
        return self.status == "blocked"

    def to_dict(self) -> dict[str, object]:
        return {
            "project": str(self.project),
            "bundle_dir": str(self.bundle_dir),
            "source": str(self.source),
            "baseline": str(self.baseline),
            "report": str(self.report),
            "status": self.status,
            "blocked": self.blocked,
            "promoted": self.promoted,
            "allow_blocked": self.allow_blocked,
            "reason": self.reason,
        }

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def render_text(self) -> str:
        return "\n".join(
            [
                "Publish drill baseline",
                f"Project: {self.project}",
                f"Bundle: {self.bundle_dir}",
                f"Status: {self.status.upper()}",
                f"Promoted: {self.promoted}",
                f"Source: {self.source}",
                f"Baseline: {self.baseline}",
                f"Report: {self.report}",
                f"Reason: {self.reason}",
            ]
        )


def promote_publish_drill_baseline(project: Project, *, bundle_dir: Path | None = None, allow_blocked: bool = False) -> PublishDrillBaselineReport:
    bundle_dir = bundle_dir or project.output_dir / "publish"
    source = bundle_dir / "PUBLISH-DRILL.json"
    baseline = bundle_dir / "PUBLISH-DRILL.previous.json"
    report_path = bundle_dir / "PUBLISH-DRILL-BASELINE.json"
    bundle_dir.mkdir(parents=True, exist_ok=True)
    data = _read_json(source)
    drill_status = str(data.get("status", "missing"))
    promoted = False
    if not data:
        status, reason = "blocked", "PUBLISH-DRILL.json is missing or invalid."
    elif drill_status == "blocked" and not allow_blocked:
        status, reason = "blocked", "Refused to promote blocked drill without --allow-blocked."
    else:
        shutil.copy2(source, baseline)
        promoted = True
        status = "ready"
        reason = f"Promoted drill with status {drill_status}."
    report = PublishDrillBaselineReport(project.root, bundle_dir, source, baseline, report_path, status, promoted, allow_blocked, reason)
    write_host_artifact(report_path, report.render_json() + "\n", "Write PUBLISH-DRILL-BASELINE.json")
    return report


def _read_json(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}
