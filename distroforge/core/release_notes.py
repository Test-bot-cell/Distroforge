from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .host_artifacts import write_host_artifact
from .project import Project


@dataclass(frozen=True)
class ReleaseNotesReport:
    project: Path
    bundle_dir: Path
    notes: Path
    changelog: Path
    status: str
    blockers: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "project": str(self.project),
            "bundle_dir": str(self.bundle_dir),
            "notes": str(self.notes),
            "changelog": str(self.changelog),
            "status": self.status,
            "blockers": list(self.blockers),
        }

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def render_text(self) -> str:
        lines = [
            "Maintainer release notes",
            f"Project: {self.project}",
            f"Bundle: {self.bundle_dir}",
            f"Status: {self.status.upper()}",
            f"Notes: {self.notes}",
            f"Changelog: {self.changelog}",
            "",
            "Blockers:",
            *([f"- {item}" for item in self.blockers] or ["- none"]),
        ]
        return "\n".join(lines)


def write_release_notes(project: Project, *, bundle_dir: Path | None = None) -> ReleaseNotesReport:
    bundle_dir = bundle_dir or project.output_dir / "publish"
    bundle_dir.mkdir(parents=True, exist_ok=True)
    manifest = _read_json(bundle_dir / "RELEASE-MANIFEST.json")
    gate = _read_json(bundle_dir / "RELEASE-GATE.json")
    signing = _read_json(bundle_dir / "SIGNING-REPORT.json")
    buildinfo = _read_text(bundle_dir / "BUILDINFO")
    provenance = _read_json(bundle_dir / "distroforge-provenance.json")
    status = str(gate.get("status") or manifest.get("gate_status") or "unknown")
    blockers = tuple(
        f"{item.get('code', 'unknown')}: {item.get('detail', '')}"
        for item in gate.get("items", [])
        if isinstance(item, dict) and item.get("status") == "blocked"
    )
    notes_path = bundle_dir / "RELEASE-NOTES.md"
    changelog_path = bundle_dir / "CHANGELOG.txt"
    write_host_artifact(notes_path, _notes(project, bundle_dir, manifest, gate, signing, buildinfo, provenance, status, blockers), "Write RELEASE-NOTES.md")
    write_host_artifact(changelog_path, _changelog(project, manifest, gate, signing, status, blockers), "Write CHANGELOG.txt")
    return ReleaseNotesReport(project.root, bundle_dir, notes_path, changelog_path, status, blockers)


def _notes(
    project: Project,
    bundle_dir: Path,
    manifest: dict[str, object],
    gate: dict[str, object],
    signing: dict[str, object],
    buildinfo: str,
    provenance: dict[str, object],
    status: str,
    blockers: tuple[str, ...],
) -> str:
    files = [item for item in manifest.get("files", []) if isinstance(item, dict)]
    iso = next((item for item in files if str(item.get("name", "")).endswith(".iso")), None)
    boot = [item for item in files if item.get("name") in {"qemu-lab-report.json", "boot-proof.json"}]
    signed = signing.get("signed", [])
    planned = signing.get("planned", [])
    lines = [
        f"# {project.name} Release Notes",
        "",
        f"- Status: **{status.upper()}**",
        f"- Bundle: `{bundle_dir}`",
        f"- Generated: {datetime.now(UTC).isoformat()}",
        "",
        "## ISO",
        f"- Image: {iso.get('name') if iso else 'missing'}",
        f"- SHA256: {iso.get('sha256') if iso else 'missing'}",
        "",
        "## Included Artifacts",
        *[f"- `{item.get('name')}` ({item.get('size')} bytes)" for item in files],
        "",
        "## Boot Proof",
        *([f"- `{item.get('name')}` present" for item in boot] or ["- missing"]),
        "",
        "## Signing",
        *([f"- signed: `{item}`" for item in signed] or []),
        *([f"- planned: `{item}`" for item in planned] or []),
        *([] if signed or planned else ["- no signing evidence"]),
        "",
        "## Release Gate",
        *[f"- [{item.get('status')}] {item.get('code')}: {item.get('detail')}" for item in gate.get("items", []) if isinstance(item, dict)],
        "",
        "## Blockers",
        *([f"- {item}" for item in blockers] or ["- none"]),
        "",
        "## Verification Commands",
        "```bash",
        "sha256sum -c SHA256SUMS",
        "gpg --verify SHA256SUMS.asc SHA256SUMS",
        "gpg --verify RELEASE-GATE.json.asc RELEASE-GATE.json",
        "gpg --verify RELEASE-MANIFEST.json.asc RELEASE-MANIFEST.json",
        "```",
        "",
        "## Build Info",
        "```text",
        buildinfo.strip() or "missing",
        "```",
        "",
        "## Provenance",
        "```json",
        json.dumps(provenance, indent=2) if provenance else "{}",
        "```",
    ]
    return "\n".join(lines) + "\n"


def _changelog(project: Project, manifest: dict[str, object], gate: dict[str, object], signing: dict[str, object], status: str, blockers: tuple[str, ...]) -> str:
    files = [item.get("name") for item in manifest.get("files", []) if isinstance(item, dict)]
    lines = [
        f"{project.name} release bundle",
        f"Status: {status.upper()}",
        f"Generated: {datetime.now(UTC).isoformat()}",
        "",
        "Included files:",
        *[f"- {name}" for name in files],
        "",
        f"Release gate items: {len(gate.get('items', []))}",
        f"Signing status: {signing.get('status', 'unknown')}",
        "",
        "Blockers:",
        *([f"- {item}" for item in blockers] or ["- none"]),
    ]
    return "\n".join(lines) + "\n"


def _read_json(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
