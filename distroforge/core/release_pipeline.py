from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .beginner_iso import repair_beginner_iso_release_artifacts
from .boot_proof import run_boot_proof
from .build import BuildOptions
from .host_artifacts import write_host_artifact
from .project import Project
from .publish_bundle import create_publish_bundle
from .release_notes import write_release_notes
from .release_signing import sign_release_bundle
from .release_verification import verify_release_bundle


@dataclass(frozen=True)
class ReleasePipelineStage:
    name: str
    status: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "status": self.status, "detail": self.detail}


@dataclass(frozen=True)
class ReleasePipelineReport:
    project: Path
    bundle_dir: Path
    status: str
    stages: tuple[ReleasePipelineStage, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "project": str(self.project),
            "bundle_dir": str(self.bundle_dir),
            "status": self.status,
            "stages": [stage.to_dict() for stage in self.stages],
        }

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def render_text(self) -> str:
        lines = [
            "Maintainer release pipeline",
            f"Project: {self.project}",
            f"Bundle: {self.bundle_dir}",
            f"Status: {self.status.upper()}",
            "",
        ]
        lines.extend(f"[{stage.status}] {stage.name}: {stage.detail}" for stage in self.stages)
        return "\n".join(lines)


def run_release_pipeline(
    project: Project,
    options: BuildOptions | None = None,
    *,
    iso: Path | None = None,
    output_dir: Path | None = None,
    bundle_dir: Path | None = None,
    execute_signing: bool = False,
    gpg_key: str | None = None,
    run_boot_proof: bool = False,
    boot_proof_execute: bool = True,
    boot_proof_backend: str = "auto",
) -> ReleasePipelineReport:
    options = options or BuildOptions()
    iso = iso or options.output_iso or project.output_dir / f"{project.name}.iso"
    output_dir = output_dir or iso.parent
    bundle_dir = bundle_dir or project.output_dir / "publish"
    stages: list[ReleasePipelineStage] = []
    if iso.exists():
        if run_boot_proof:
            boot = run_boot_proof_fn(project, options, iso=iso, backend=boot_proof_backend, execute=boot_proof_execute)
            stages.append(ReleasePipelineStage("boot-proof", boot.status, "; ".join(boot.notes)))
        repair = repair_beginner_iso_release_artifacts(project, options)
        stages.append(ReleasePipelineStage("repair-artifacts", "ready" if repair.repaired else "review", ", ".join(repair.repaired or repair.skipped)))
    else:
        stages.append(ReleasePipelineStage("repair-artifacts", "review", "ISO is missing; derivable release artifacts were not repaired."))
    bundle = create_publish_bundle(project, options, iso=iso, output_dir=output_dir, bundle_dir=bundle_dir)
    stages.append(ReleasePipelineStage("publish-bundle", bundle.status, f"{bundle.bundle_dir}"))
    first_sign = sign_release_bundle(project, bundle_dir=bundle.bundle_dir, execute=execute_signing, gpg_key=gpg_key)
    stages.append(ReleasePipelineStage("sign-release-initial", first_sign.status, f"{len(first_sign.planned or first_sign.signed)} signature targets."))
    notes = write_release_notes(project, bundle_dir=bundle.bundle_dir)
    stages.append(ReleasePipelineStage("release-notes", notes.status, f"{notes.notes.name}, {notes.changelog.name}"))
    final_sign = sign_release_bundle(project, bundle_dir=bundle.bundle_dir, execute=execute_signing, gpg_key=gpg_key)
    stages.append(ReleasePipelineStage("sign-release-final", final_sign.status, f"{len(final_sign.planned or final_sign.signed)} signature targets."))
    verify = verify_release_bundle(project, bundle_dir=bundle.bundle_dir)
    stages.append(ReleasePipelineStage("verify-release", verify.status, f"{len(verify.items)} verification checks."))
    status = "blocked" if any(stage.status == "blocked" for stage in stages) else "review" if any(stage.status in {"review", "planned"} for stage in stages) else "ready"
    report = ReleasePipelineReport(project.root, bundle.bundle_dir, status, tuple(stages))
    write_host_artifact(bundle.bundle_dir / "RELEASE-PIPELINE.json", report.render_json() + "\n", "Write RELEASE-PIPELINE.json")
    return report


def run_boot_proof_fn(project: Project, options: BuildOptions, *, iso: Path, backend: str, execute: bool):
    return run_boot_proof(project, options, iso=iso, backend=backend, execute=execute)
