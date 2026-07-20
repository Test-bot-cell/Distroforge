from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .command import CommandRunner, CommandSpec
from .host_artifacts import write_host_artifact
from .project import Project

SIGN_TARGETS = ("SHA256SUMS", "RELEASE-GATE.json", "RELEASE-MANIFEST.json")


@dataclass(frozen=True)
class ReleaseManifestEntry:
    name: str
    size: int
    sha256: str

    def to_dict(self) -> dict[str, object]:
        return {"name": self.name, "size": self.size, "sha256": self.sha256}


@dataclass(frozen=True)
class ReleaseSigningReport:
    project: Path
    bundle_dir: Path
    manifest: Path
    status: str
    execute: bool
    signed: tuple[str, ...]
    planned: tuple[str, ...]
    skipped: tuple[str, ...]
    manifest_entries: tuple[ReleaseManifestEntry, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "project": str(self.project),
            "bundle_dir": str(self.bundle_dir),
            "manifest": str(self.manifest),
            "status": self.status,
            "execute": self.execute,
            "signed": list(self.signed),
            "planned": list(self.planned),
            "skipped": list(self.skipped),
            "manifest_entries": [entry.to_dict() for entry in self.manifest_entries],
        }

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def render_text(self) -> str:
        lines = [
            "Maintainer release signing",
            f"Project: {self.project}",
            f"Bundle: {self.bundle_dir}",
            f"Manifest: {self.manifest}",
            f"Status: {self.status.upper()}",
            f"Mode: {'execute' if self.execute else 'plan'}",
            "",
            "Manifest entries:",
            *[f"- {entry.name}: {entry.sha256}" for entry in self.manifest_entries],
            "",
            "Signed:",
            *([f"- {item}" for item in self.signed] or ["- none"]),
            "",
            "Planned:",
            *([f"- {item}" for item in self.planned] or ["- none"]),
            "",
            "Skipped:",
            *([f"- {item}" for item in self.skipped] or ["- none"]),
        ]
        return "\n".join(lines)


def sign_release_bundle(
    project: Project,
    *,
    bundle_dir: Path | None = None,
    execute: bool = False,
    gpg_key: str | None = None,
) -> ReleaseSigningReport:
    bundle_dir = bundle_dir or project.output_dir / "publish"
    bundle_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = bundle_dir / "RELEASE-MANIFEST.json"
    entries = _write_manifest(project, bundle_dir, manifest_path)
    skipped: list[str] = []
    signed: list[str] = []
    planned: list[str] = []
    if execute and not CommandRunner.has_binary("gpg"):
        skipped.append("gpg is missing; install GnuPG or rerun without --execute for a signing plan.")
        status = "blocked"
    else:
        runner = CommandRunner(dry_run=not execute)
        for name in SIGN_TARGETS:
            target = bundle_dir / name
            if not target.exists():
                skipped.append(f"{name} is missing.")
                continue
            argv = ["gpg", "--armor", "--detach-sign"]
            if gpg_key:
                argv.extend(["--local-user", gpg_key])
            argv.append(str(target))
            runner.run(CommandSpec(argv=tuple(argv), description=f"Sign release file {name}"))
            (signed if execute else planned).append(f"{name}.asc")
        status = "signed" if execute and signed and not skipped else "planned" if planned else "blocked"
    report = ReleaseSigningReport(project.root, bundle_dir, manifest_path, status, execute, tuple(signed), tuple(planned), tuple(skipped), entries)
    write_host_artifact(bundle_dir / "SIGNING-REPORT.json", report.render_json() + "\n", "Write SIGNING-REPORT.json")
    return report


def _write_manifest(project: Project, bundle_dir: Path, manifest_path: Path) -> tuple[ReleaseManifestEntry, ...]:
    entries = tuple(
        ReleaseManifestEntry(path.name, path.stat().st_size, _sha256(path))
        for path in sorted(bundle_dir.iterdir())
        if path.is_file() and path.name not in {"RELEASE-MANIFEST.json", "SIGNING-REPORT.json"} and not path.name.endswith(".asc")
    )
    gate_status = _gate_status(bundle_dir / "RELEASE-GATE.json")
    write_host_artifact(
        manifest_path,
        json.dumps(
            {
                "generated_at": datetime.now(UTC).isoformat(),
                "project": project.name,
                "bundle_dir": str(bundle_dir),
                "gate_status": gate_status,
                "files": [entry.to_dict() for entry in entries],
            },
            indent=2,
        )
        + "\n",
        "Write RELEASE-MANIFEST.json",
    )
    return entries


def _gate_status(path: Path) -> str:
    if not path.exists():
        return "unknown"
    try:
        return str(json.loads(path.read_text(encoding="utf-8")).get("status", "unknown"))
    except json.JSONDecodeError:
        return "unknown"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
