from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from .artifact_paths import default_artifact_paths
from .build import BuildOptions
from .host_artifacts import write_host_artifact
from .project import Project
from .release_gate import ReleaseGateReport, ReleaseGateService


@dataclass(frozen=True)
class PublishBundleReport:
    project: Path
    bundle_dir: Path
    status: str
    copied: tuple[str, ...]
    missing: tuple[str, ...]
    gate: ReleaseGateReport

    @property
    def blocked(self) -> bool:
        return self.status == "blocked"

    def to_dict(self) -> dict[str, object]:
        return {
            "project": str(self.project),
            "bundle_dir": str(self.bundle_dir),
            "status": self.status,
            "blocked": self.blocked,
            "copied": list(self.copied),
            "missing": list(self.missing),
            "gate": self.gate.to_dict(),
        }

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def render_text(self) -> str:
        lines = [
            "Maintainer publish bundle",
            f"Project: {self.project}",
            f"Bundle: {self.bundle_dir}",
            f"Status: {self.status.upper()}",
            "",
            "Copied:",
            *[f"- {item}" for item in self.copied],
            "",
            "Missing:",
            *([f"- {item}" for item in self.missing] or ["- none"]),
            "",
            "Release gate:",
        ]
        lines.extend(f"- [{item.status}] {item.code}: {item.detail}" for item in self.gate.items)
        return "\n".join(lines)


def create_publish_bundle(
    project: Project,
    options: BuildOptions | None = None,
    *,
    iso: Path | None = None,
    output_dir: Path | None = None,
    bundle_dir: Path | None = None,
) -> PublishBundleReport:
    options = options or BuildOptions()
    paths = default_artifact_paths(project)
    iso = iso or options.output_iso or paths.output_iso
    output_dir = output_dir or iso.parent
    bundle_dir = bundle_dir or project.output_dir / "publish"
    gate = ReleaseGateService().check(project, options, iso=iso, output_dir=output_dir)
    bundle_dir.mkdir(parents=True, exist_ok=True)
    copied: list[str] = []
    missing: list[str] = []
    for source in _bundle_sources(iso, output_dir, options):
        if source.exists():
            shutil.copy2(source, bundle_dir / source.name)
            copied.append(source.name)
        else:
            missing.append(source.name)
    gate_path = bundle_dir / "RELEASE-GATE.json"
    write_host_artifact(gate_path, gate.render_json() + "\n", "Write RELEASE-GATE.json")
    copied.append(gate_path.name)
    readme_path = bundle_dir / "README-PUBLISH.txt"
    write_host_artifact(readme_path, _readme(project, gate, copied, missing), "Write README-PUBLISH.txt")
    copied.append(readme_path.name)
    return PublishBundleReport(project.root, bundle_dir, gate.status, tuple(copied), tuple(missing), gate)


def _bundle_sources(iso: Path, output_dir: Path, options: BuildOptions) -> tuple[Path, ...]:
    return (
        iso,
        output_dir / "SHA256SUMS",
        output_dir / "BUILDINFO",
        output_dir / "distroforge-provenance.json",
        output_dir / options.html_report.filename,
        output_dir / options.prebuild_vm.report_name,
        output_dir / "boot-proof.json",
    )


def _readme(project: Project, gate: ReleaseGateReport, copied: list[str], missing: list[str]) -> str:
    blocked = [item for item in gate.items if item.status == "blocked"]
    review = [item for item in gate.items if item.status == "review"]
    lines = [
        "DistroForge maintainer publish bundle",
        f"Project: {project.name}",
        f"Status: {gate.status.upper()}",
        "",
        "This directory is an inspection bundle, not a silent publish action.",
        "Do not upload or sign a BLOCKED bundle as a release.",
        "",
        "Included files:",
        *[f"- {name}" for name in copied],
        "",
        "Missing files:",
        *([f"- {name}" for name in missing] or ["- none"]),
    ]
    if blocked:
        lines.extend(["", "Blocking release gate items:", *[f"- {item.code}: {item.detail}" for item in blocked]])
    if review:
        lines.extend(["", "Review release gate items:", *[f"- {item.code}: {item.detail}" for item in review]])
    return "\n".join(lines) + "\n"
