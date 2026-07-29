from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from .artifact_paths import default_artifact_paths
from .build import BuildOptions
from .evidence_run import first_symlink_in_confined_tree
from .hashing import sha256_file
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
    explicit_bundle_dir = bundle_dir is not None
    bundle_dir = bundle_dir or project.output_dir / "publish"
    gate = ReleaseGateService().check(project, options, iso=iso, output_dir=output_dir)
    bundle_anchor = bundle_dir.parent if explicit_bundle_dir else project.root
    unsafe_bundle_path = first_symlink_in_confined_tree(
        bundle_anchor,
        bundle_dir,
    )
    if unsafe_bundle_path is not None:
        return PublishBundleReport(
            project.root,
            bundle_dir,
            "blocked",
            (),
            (f"bundle path contains unsafe symlink: {unsafe_bundle_path}",),
            gate,
        )
    bundle_dir.mkdir(parents=True, exist_ok=True)
    existing = [path for path in bundle_dir.rglob("*") if path.is_file() or path.is_symlink()]
    if existing:
        return PublishBundleReport(
            project.root,
            bundle_dir,
            "blocked",
            (),
            (
                "bundle directory is not empty; use a fresh directory so release "
                "evidence cannot mix across runs",
            ),
            gate,
        )
    copied: list[str] = []
    missing: list[str] = []
    _copy_immutable_runs(
        output_dir,
        bundle_dir,
        options.prebuild_vm.report_name,
        copied,
        missing,
    )
    for source in _bundle_sources(iso, output_dir, options):
        if source.exists():
            _copy_bundle_file(source, bundle_dir / source.name, copied, missing)
        else:
            missing.append(source.name)
    gate_path = bundle_dir / "RELEASE-GATE.json"
    _write_bundle_text(
        gate_path,
        gate.render_json() + "\n",
        copied,
        missing,
        "Write RELEASE-GATE.json",
    )
    status = "blocked" if gate.blocked or missing else gate.status
    readme_path = bundle_dir / "README-PUBLISH.txt"
    _write_bundle_text(
        readme_path,
        _readme(project, status, gate, copied, missing),
        copied,
        missing,
        "Write README-PUBLISH.txt",
    )
    expected = {
        Path(name)
        for name in copied
    } | {Path("RELEASE-GATE.json"), Path("README-PUBLISH.txt")}
    unexpected = [
        path.relative_to(bundle_dir)
        for path in bundle_dir.rglob("*")
        if path.is_file()
        and not path.is_symlink()
        and path.relative_to(bundle_dir) not in expected
    ]
    symlinks = [
        path.relative_to(bundle_dir)
        for path in bundle_dir.rglob("*")
        if path.is_symlink()
    ]
    missing.extend(f"unexpected existing bundle file: {path}" for path in unexpected)
    missing.extend(f"unsafe bundle symlink: {path}" for path in symlinks)
    status = "blocked" if gate.blocked or missing else gate.status
    return PublishBundleReport(
        project.root,
        bundle_dir,
        status,
        tuple(copied),
        tuple(missing),
        gate,
    )


def _bundle_sources(iso: Path, output_dir: Path, options: BuildOptions) -> tuple[Path, ...]:
    sources = [
        iso,
        output_dir / "SHA256SUMS",
        output_dir / "BUILDINFO",
        output_dir / "distroforge-provenance.json",
        output_dir / "ISO-BUILD.json",
    ]
    if options.html_report.enabled:
        sources.append(output_dir / options.html_report.filename)
    if options.provenance.sbom_format == "spdx":
        sources.append(output_dir / "distroforge-sbom.spdx.json")
    elif options.provenance.sbom_format == "cyclonedx":
        sources.append(output_dir / "distroforge-sbom.cdx.json")
    proof = output_dir / "boot-proof.json"
    qemu = output_dir / options.prebuild_vm.report_name
    if proof.is_file():
        sources.extend((proof, qemu))
    elif qemu.is_file():
        sources.append(qemu)
    else:
        sources.append(qemu)
    return tuple(sources)


def _copy_immutable_runs(
    output_dir: Path,
    bundle_dir: Path,
    qemu_report_name: str,
    copied: list[str],
    missing: list[str],
) -> None:
    run_ids: set[str] = set()
    for report in (
        output_dir / "distroforge-provenance.json",
        output_dir / "boot-proof.json",
        output_dir / qemu_report_name,
    ):
        try:
            data = json.loads(report.read_text(encoding="utf-8"))
        except FileNotFoundError:
            continue
        except (OSError, json.JSONDecodeError):
            missing.append(f"{report.name} has no readable run identity")
            continue
        run_id = data.get("run_id") if isinstance(data, dict) else None
        if not isinstance(run_id, str) or not run_id or Path(run_id).name != run_id:
            missing.append(f"{report.name} has no safe run_id")
            continue
        run_ids.add(run_id)
    if not run_ids:
        missing.append("evidence/runs/<run_id>")
        return
    for run_id in sorted(run_ids):
        source = output_dir / "evidence" / "runs" / run_id
        if source.is_symlink() or not source.is_dir():
            missing.append(f"evidence/runs/{run_id}")
            continue
        unsafe_source = first_symlink_in_confined_tree(output_dir, source)
        if unsafe_source is not None:
            missing.append(
                f"evidence/runs/{run_id} contains unsafe symlink "
                f"{unsafe_source.relative_to(output_dir.absolute())}; refused copy"
            )
            continue
        destination = bundle_dir / "evidence" / "runs" / run_id
        if destination.exists():
            mismatch = _tree_mismatch(source, destination)
            if mismatch:
                missing.append(
                    f"evidence/runs/{run_id} (existing destination differs at "
                    f"{mismatch}; refused overwrite)"
                )
                continue
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            # Preserve a link if one appears after the preflight check instead of
            # dereferencing it and copying bytes from outside the evidence run.
            shutil.copytree(source, destination, symlinks=True)
        unsafe_destination = first_symlink_in_confined_tree(
            bundle_dir,
            destination,
        )
        if unsafe_destination is not None:
            missing.append(
                f"evidence/runs/{run_id} copied an unsafe symlink "
                f"{unsafe_destination.relative_to(bundle_dir.absolute())}"
            )
            continue
        copied.extend(
            str(path.relative_to(bundle_dir))
            for path in sorted(destination.rglob("*"))
            if path.is_file() and not path.is_symlink()
        )


def _copy_bundle_file(
    source: Path,
    destination: Path,
    copied: list[str],
    missing: list[str],
) -> None:
    relative = destination.name
    if source.is_symlink():
        missing.append(f"{source.name} is an unsafe symlink")
        return
    if destination.exists():
        if (
            destination.is_symlink()
            or not destination.is_file()
            or destination.stat().st_size != source.stat().st_size
            or sha256_file(destination) != sha256_file(source)
        ):
            missing.append(f"{relative} already exists with different bytes; refused overwrite")
            return
    else:
        shutil.copy2(source, destination)
    copied.append(relative)


def _write_bundle_text(
    destination: Path,
    content: str,
    copied: list[str],
    missing: list[str],
    description: str,
) -> None:
    expected = content.encode("utf-8")
    if destination.exists():
        if destination.is_symlink() or not destination.is_file() or destination.read_bytes() != expected:
            missing.append(
                f"{destination.name} already exists with different bytes; refused overwrite"
            )
            return
    else:
        write_host_artifact(destination, content, description)
    copied.append(destination.name)


def _tree_mismatch(source: Path, destination: Path) -> str:
    """Return the first difference without ever repairing an existing evidence tree."""
    source_files = {
        path.relative_to(source): path
        for path in source.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    destination_files = {
        path.relative_to(destination): path
        for path in destination.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    if any(path.is_symlink() for path in source.rglob("*")):
        return "source symlink"
    if any(path.is_symlink() for path in destination.rglob("*")):
        return "destination symlink"
    for relative in sorted(source_files.keys() | destination_files.keys()):
        left = source_files.get(relative)
        right = destination_files.get(relative)
        if left is None or right is None:
            return relative.as_posix()
        if left.stat().st_size != right.stat().st_size:
            return relative.as_posix()
        if sha256_file(left) != sha256_file(right):
            return relative.as_posix()
    return ""


def _readme(
    project: Project,
    status: str,
    gate: ReleaseGateReport,
    copied: list[str],
    missing: list[str],
) -> str:
    blocked = [item for item in gate.items if item.status == "blocked"]
    review = [item for item in gate.items if item.status == "review"]
    lines = [
        "DistroForge maintainer publish bundle",
        f"Project: {project.name}",
        f"Status: {status.upper()}",
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
