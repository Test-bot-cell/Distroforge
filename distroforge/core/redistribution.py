from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .brand_identity import BrandIdentity
from .branding import BrandingOptions
from .command import CommandRunner, CommandSpec
from .project import Project


@dataclass(frozen=True)
class RedistributionAttestation:
    project: str
    output_iso: str
    status: str
    generated_at: str
    identity: dict[str, object]
    artifacts: dict[str, str]

    def render_json(self) -> str:
        return json.dumps(
            {
                "project": self.project,
                "output_iso": self.output_iso,
                "status": self.status,
                "generated_at": self.generated_at,
                "identity": self.identity,
                "artifacts": self.artifacts,
            },
            indent=2,
        )


class RedistributionAttestationService:
    def __init__(self, runner: CommandRunner, project: Project) -> None:
        self.runner = runner
        self.project = project

    def write(self, output_iso: Path, options: BrandingOptions, strict: bool = False) -> None:
        identity = BrandIdentity.from_project_options(self.project, options)
        manifest = self.project.output_dir / "BRANDING-MANIFEST.json"
        attestation = self.project.output_dir / "REDISTRIBUTION-ATTESTATION.json"
        if self.runner.dry_run:
            self.runner.run(CommandSpec(argv=("write-file", str(manifest)), description="Write branding manifest"))
            self.runner.run(
                CommandSpec(argv=("write-file", str(attestation)), description="Write redistribution attestation")
            )
            return
        self.project.output_dir.mkdir(parents=True, exist_ok=True)
        identity.write(manifest)
        status = "redistribution-ready" if strict else "advisory"
        payload = RedistributionAttestation(
            project=self.project.name,
            output_iso=output_iso.name,
            status=status,
            generated_at=datetime.now(UTC).isoformat(),
            identity=identity.to_dict(),
            artifacts={
                "branding_manifest": "BRANDING-MANIFEST.json",
                "trademark_clearance": "TRADEMARK-CLEARANCE.json",
                "debrand_report": "DEBRAND-REPORT.json",
                "provenance": "distroforge-provenance.json",
                "integrity": "INTEGRITY",
            },
        )
        attestation.write_text(payload.render_json() + "\n", encoding="utf-8")
