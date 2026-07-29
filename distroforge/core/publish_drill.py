from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .artifact_paths import default_output_iso
from .build import BuildOptions
from .host_artifacts import write_host_artifact
from .jsonio import read_json_object
from .project import Project
from .release_explain import ReleaseExplainReport, explain_release
from .release_pipeline import ReleasePipelineReport, run_release_pipeline


@dataclass(frozen=True)
class PublishDrillReport:
    project: Path
    iso: Path
    bundle_dir: Path
    status: str
    drill: Path
    pipeline: ReleasePipelineReport
    explanation: ReleaseExplainReport
    execute_signing: bool
    evidence: dict[str, object]

    @property
    def blocked(self) -> bool:
        return self.status == "blocked"

    def to_dict(self) -> dict[str, object]:
        return {
            "project": str(self.project),
            "iso": str(self.iso),
            "bundle_dir": str(self.bundle_dir),
            "status": self.status,
            "blocked": self.blocked,
            "drill": str(self.drill),
            "execute_signing": self.execute_signing,
            "pipeline": self.pipeline.to_dict(),
            "explanation": self.explanation.to_dict(),
            "evidence": self.evidence,
        }

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def render_text(self) -> str:
        lines = [
            "Maintainer publish drill",
            f"Project: {self.project}",
            f"ISO: {self.iso}",
            f"Bundle: {self.bundle_dir}",
            f"Status: {self.status.upper()}",
            f"Signing: {'execute' if self.execute_signing else 'plan'}",
            f"Report: {self.drill}",
            "",
            "Pipeline:",
            *[f"- [{stage.status}] {stage.name}: {stage.detail}" for stage in self.pipeline.stages],
            "",
            "Explanation:",
            f"- status: {self.explanation.status}",
            f"- markdown: {self.explanation.markdown}",
            "",
            "Next commands:",
            *[f"- {command}" for command in self.explanation.next_commands],
        ]
        return "\n".join(lines)


def run_publish_drill(
    project: Project,
    options: BuildOptions | None = None,
    *,
    iso: Path | None = None,
    bundle_dir: Path | None = None,
    execute_signing: bool = False,
    gpg_key: str | None = None,
    gpg_keyring: Path | None = None,
    boot_backend: str = "auto",
) -> PublishDrillReport:
    options = options or BuildOptions()
    iso = iso or options.output_iso or default_output_iso(project)
    bundle_dir = bundle_dir or project.output_dir / "publish"
    pipeline = run_release_pipeline(
        project,
        options,
        iso=iso,
        output_dir=iso.parent,
        bundle_dir=bundle_dir,
        execute_signing=execute_signing,
        gpg_key=gpg_key,
        gpg_keyring=gpg_keyring,
        run_boot_proof=True,
        boot_proof_execute=True,
        boot_proof_backend=boot_backend,
    )
    explanation = explain_release(project, iso=iso, bundle_dir=bundle_dir)
    status = _drill_status(pipeline.status, explanation.status)
    evidence = {name: read_json_object(bundle_dir / filename) for name, filename in (("release_gate", "RELEASE-GATE.json"), ("manifest", "RELEASE-MANIFEST.json"), ("signing", "SIGNING-REPORT.json"), ("verify", "VERIFY-REPORT.json"))}
    report = PublishDrillReport(project.root, iso, bundle_dir, status, bundle_dir / "PUBLISH-DRILL.json", pipeline, explanation, execute_signing, evidence)
    write_host_artifact(report.drill, report.render_json() + "\n", "Write PUBLISH-DRILL.json")
    return report


def _drill_status(pipeline_status: str, explanation_status: str) -> str:
    if "blocked" in {pipeline_status, explanation_status}:
        return "blocked"
    if pipeline_status == "ready" and explanation_status == "ready":
        return "ready_to_publish"
    return "review_required"
