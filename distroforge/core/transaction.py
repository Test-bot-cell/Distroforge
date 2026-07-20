from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from .project import Project

if TYPE_CHECKING:
    from .build import BuildOptions


@dataclass(frozen=True)
class BuildTransaction:
    build_id: str
    run_dir: Path
    logs_dir: Path
    artifacts_dir: Path
    manifest_path: Path

    def to_dict(self) -> dict[str, str]:
        return {
            "build_id": self.build_id,
            "run_dir": str(self.run_dir),
            "logs_dir": str(self.logs_dir),
            "artifacts_dir": str(self.artifacts_dir),
            "manifest_path": str(self.manifest_path),
        }


def plan_transaction(project: Project, options: BuildOptions) -> BuildTransaction:
    payload = {
        "project": project.to_dict(),
        "output_iso": str(options.output_iso) if options.output_iso else None,
        "release_track": getattr(options.release_track, "mode", "stable"),
        "created_at": datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ"),
    }
    seed = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    build_id = hashlib.sha256(seed).hexdigest()[:12]
    run_dir = project.workdir / "runs" / build_id
    return BuildTransaction(
        build_id=build_id,
        run_dir=run_dir,
        logs_dir=run_dir / "logs",
        artifacts_dir=run_dir / "artifacts",
        manifest_path=run_dir / "build-manifest.json",
    )
