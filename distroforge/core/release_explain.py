from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .project import Project


@dataclass(frozen=True)
class ReleaseExplainReport:
    project: Path
    iso: Path
    bundle_dir: Path
    status: str
    markdown: Path
    ready: tuple[str, ...]
    review: tuple[str, ...]
    blocked: tuple[str, ...]
    boot_proof: dict[str, str]
    next_commands: tuple[str, ...]

    @property
    def blocked_release(self) -> bool:
        return self.status == "blocked"

    def to_dict(self) -> dict[str, object]:
        return {
            "project": str(self.project),
            "iso": str(self.iso),
            "bundle_dir": str(self.bundle_dir),
            "status": self.status,
            "blocked": self.blocked_release,
            "markdown": str(self.markdown),
            "ready": list(self.ready),
            "review": list(self.review),
            "blocked_items": list(self.blocked),
            "boot_proof": self.boot_proof,
            "next_commands": list(self.next_commands),
        }

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def render_text(self) -> str:
        lines = [
            "Release evidence explanation",
            f"Project: {self.project}",
            f"ISO: {self.iso}",
            f"Bundle: {self.bundle_dir}",
            f"Status: {self.status.upper()}",
            f"Markdown: {self.markdown}",
            "",
            "Boot proof:",
            f"- status: {self.boot_proof.get('status', 'missing')}",
            f"- selected backend: {self.boot_proof.get('selected_backend', 'unknown')}",
            f"- proof level: {self.boot_proof.get('proof_level', 'none')}",
            "",
            "Ready:",
            *([f"- {item}" for item in self.ready] or ["- none"]),
            "",
            "Review:",
            *([f"- {item}" for item in self.review] or ["- none"]),
            "",
            "Blocked:",
            *([f"- {item}" for item in self.blocked] or ["- none"]),
            "",
            "Next commands:",
            *[f"- {item}" for item in self.next_commands],
        ]
        return "\n".join(lines)


def explain_release(project: Project, *, iso: Path | None = None, bundle_dir: Path | None = None) -> ReleaseExplainReport:
    iso = iso or project.output_dir / f"{project.name}.iso"
    output_dir = iso.parent
    bundle_dir = bundle_dir or project.output_dir / "publish"
    gate = _read_json(bundle_dir / "RELEASE-GATE.json") or _read_json(output_dir / "RELEASE-GATE.json")
    boot = _read_json(bundle_dir / "boot-proof.json") or _read_json(output_dir / "boot-proof.json")
    manifest = _read_json(bundle_dir / "RELEASE-MANIFEST.json")
    verify = _read_json(bundle_dir / "VERIFY-REPORT.json")
    ready, review, blocked = _collect_items(gate, verify, manifest)
    boot_summary = _boot_summary(boot)
    if boot_summary["status"] == "missing":
        blocked.append("boot-proof: boot-proof.json is missing")
    elif boot_summary["status"] != "ready":
        blocked.append(f"boot-proof: {boot_summary['status']} via {boot_summary['selected_backend']}")
    else:
        ready.append(f"boot-proof: {boot_summary['proof_level']} proof via {boot_summary['selected_backend']}")
    status = "blocked" if blocked else "review" if review else "ready"
    commands = _next_commands(project, iso, bundle_dir, status, boot_summary, blocked, review)
    markdown = bundle_dir / "RELEASE-EXPLAIN.md"
    bundle_dir.mkdir(parents=True, exist_ok=True)
    report = ReleaseExplainReport(project.root, iso, bundle_dir, status, markdown, tuple(ready), tuple(review), tuple(blocked), boot_summary, tuple(commands))
    markdown.write_text(_markdown(report), encoding="utf-8")
    return report


def _collect_items(*reports: dict[str, object]) -> tuple[list[str], list[str], list[str]]:
    ready: list[str] = []
    review: list[str] = []
    blocked: list[str] = []
    for report in reports:
        for item in report.get("items", []) if isinstance(report, dict) else []:
            if not isinstance(item, dict):
                continue
            entry = f"{item.get('code', 'item')}: {item.get('detail', '')}".strip()
            status = str(item.get("status", "review"))
            if status == "ready":
                ready.append(entry)
            elif status == "blocked":
                blocked.append(entry)
            else:
                review.append(entry)
    return ready, review, blocked


def _boot_summary(data: dict[str, object]) -> dict[str, str]:
    if not data:
        return {"status": "missing", "selected_backend": "unknown", "proof_level": "none", "attempted_backends": ""}
    attempted = data.get("attempted_backends", [])
    return {
        "status": str(data.get("status", "unknown")),
        "selected_backend": str(data.get("selected_backend", data.get("backend", "unknown"))),
        "proof_level": str(data.get("proof_level", "none")),
        "attempted_backends": ", ".join(str(item) for item in attempted) if isinstance(attempted, list) else str(attempted),
    }


def _next_commands(project: Project, iso: Path, bundle_dir: Path, status: str, boot: dict[str, str], blocked: list[str], review: list[str]) -> list[str]:
    root = str(project.root)
    commands = []
    if boot.get("proof_level") != "runtime":
        commands.append(f"distroforge boot-proof {root} --iso {iso} --backend qemu")
    if any("sha256" in item.lower() or "release file" in item.lower() for item in blocked):
        commands.append(f"distroforge release-pipeline {root} --iso {iso} --run-boot-proof --boot-backend auto")
    if status != "ready":
        commands.append(f"distroforge release-gate {root} --iso {iso} --output-dir {iso.parent}")
    if review or any("signature" in item.lower() for item in blocked):
        commands.append(f"distroforge sign-release {root} --bundle-dir {bundle_dir} --execute")
    commands.append(f"distroforge verify-release {root} --bundle-dir {bundle_dir}")
    return commands


def _markdown(report: ReleaseExplainReport) -> str:
    lines = [
        f"# {report.project.name} Release Evidence",
        "",
        f"- Status: **{report.status.upper()}**",
        f"- ISO: `{report.iso}`",
        f"- Bundle: `{report.bundle_dir}`",
        f"- Generated: {datetime.now(UTC).isoformat()}",
        "",
        "## Boot Proof",
        f"- Status: {report.boot_proof.get('status', 'missing')}",
        f"- Selected backend: {report.boot_proof.get('selected_backend', 'unknown')}",
        f"- Proof level: {report.boot_proof.get('proof_level', 'none')}",
        f"- Attempted backends: {report.boot_proof.get('attempted_backends', '') or 'none'}",
        "",
        "## Ready",
        *([f"- {item}" for item in report.ready] or ["- none"]),
        "",
        "## Review",
        *([f"- {item}" for item in report.review] or ["- none"]),
        "",
        "## Blocked",
        *([f"- {item}" for item in report.blocked] or ["- none"]),
        "",
        "## Next Commands",
        "```bash",
        *report.next_commands,
        "```",
        "",
    ]
    return "\n".join(lines)


def _read_json(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}
