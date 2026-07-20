from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from .build import BuildOptions
from .project import Project
from .release_gate import ReleaseGateService


@dataclass(frozen=True)
class IsoAcceptanceItem:
    code: str
    status: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return self.__dict__


@dataclass(frozen=True)
class IsoAcceptanceReport:
    project: Path
    iso: Path
    report: Path
    status: str
    next_command: str
    items: tuple[IsoAcceptanceItem, ...]

    @property
    def blocked(self) -> bool:
        return self.status == "blocked"

    def to_dict(self) -> dict[str, object]:
        return {
            "project": str(self.project),
            "iso": str(self.iso),
            "report": str(self.report),
            "status": self.status,
            "blocked": self.blocked,
            "next_command": self.next_command,
            "items": [item.to_dict() for item in self.items],
        }

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def render_text(self) -> str:
        lines = [
            "ISO acceptance gate",
            f"Project: {self.project}",
            f"ISO: {self.iso}",
            f"Status: {self.status.upper()}",
            "",
        ]
        lines.extend(f"[{item.status}] {item.code}: {item.detail}" for item in self.items)
        lines.extend(["", "Next command:", self.next_command or "none"])
        return "\n".join(lines)


def accept_iso(
    project: Project,
    options: BuildOptions | None = None,
    *,
    iso: Path | None = None,
    output_dir: Path | None = None,
) -> IsoAcceptanceReport:
    options = options or BuildOptions()
    iso = iso or options.output_iso or project.output_dir / f"{project.name}.iso"
    output_dir = output_dir or iso.parent
    report_path = output_dir / "ISO-BUILD.json"
    items: list[IsoAcceptanceItem] = []
    _check_iso_contract(items, project, iso, report_path)
    gate = ReleaseGateService().check(project, options, iso=iso, output_dir=output_dir)
    items.append(IsoAcceptanceItem("release-gate", "blocked" if gate.blocked else "ready", f"Release gate is {gate.status}."))
    for gate_item in gate.items:
        if gate_item.status == "blocked":
            items.append(IsoAcceptanceItem(f"gate-{gate_item.code}", "blocked", gate_item.detail))
    status = "blocked" if any(item.status == "blocked" for item in items) else "accepted"
    acceptance = IsoAcceptanceReport(project.root, iso, report_path, status, _next_command(project, iso, items), tuple(items))
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "ISO-ACCEPTANCE.json").write_text(acceptance.render_json() + "\n", encoding="utf-8")
    return acceptance


def _check_iso_contract(items: list[IsoAcceptanceItem], project: Project, iso: Path, report_path: Path) -> None:
    if not iso.exists() or not iso.is_file():
        items.append(IsoAcceptanceItem("iso", "blocked", "Output ISO is missing."))
        return
    size = iso.stat().st_size
    if size <= 0:
        items.append(IsoAcceptanceItem("iso", "blocked", "Output ISO is empty."))
        return
    digest = _sha256(iso)
    items.append(IsoAcceptanceItem("iso", "ready", f"{size} bytes, SHA256 {digest}."))
    data = _read_report(report_path)
    if not data:
        items.append(IsoAcceptanceItem("iso-build-report", "blocked", "ISO-BUILD.json is missing or invalid."))
        return
    expected_iso = Path(str(data.get("output_iso", "")))
    if expected_iso != iso:
        items.append(IsoAcceptanceItem("iso-build-report", "blocked", f"ISO-BUILD.json points at {expected_iso}."))
    elif data.get("status") != "built":
        items.append(IsoAcceptanceItem("iso-build-report", "blocked", f"ISO-BUILD.json status is {data.get('status')}."))
    elif data.get("output_size") != size or data.get("output_sha256") != digest or data.get("output_exists") is not True:
        items.append(IsoAcceptanceItem("iso-build-report", "blocked", "ISO-BUILD.json output contract does not match the ISO."))
    elif str(data.get("project", "")) != str(project.root):
        items.append(IsoAcceptanceItem("iso-build-report", "blocked", "ISO-BUILD.json belongs to a different project."))
    else:
        items.append(IsoAcceptanceItem("iso-build-report", "ready", str(report_path)))


def _read_report(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _next_command(project: Project, iso: Path, items: list[IsoAcceptanceItem]) -> str:
    root = str(project.root)
    codes = {item.code for item in items if item.status == "blocked"}
    if {"iso", "iso-build-report"} & codes:
        return f"distroforge iso-build {root} --execute --boot-proof auto"
    if "gate-boot-proof" in codes:
        return f"distroforge boot-proof {root} --iso {iso} --backend auto"
    if codes:
        return f"distroforge release-gate {root} --iso {iso}"
    return f"distroforge publish-bundle {root} --iso {iso}"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
