from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from .qemu_smoke import QemuSmokePlanner


@dataclass(frozen=True)
class ReleaseReadinessItem:
    name: str
    status: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "status": self.status, "detail": self.detail}


@dataclass
class ReleaseReadinessReport:
    iso: Path
    output_dir: Path
    items: list[ReleaseReadinessItem] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return any(item.status == "blocked" for item in self.items)

    def to_dict(self) -> dict[str, object]:
        return {
            "iso": str(self.iso),
            "output_dir": str(self.output_dir),
            "blocked": self.blocked,
            "items": [item.to_dict() for item in self.items],
        }

    def render_text(self) -> str:
        lines = [
            "Release readiness",
            f"ISO: {self.iso}",
            f"Output: {self.output_dir}",
            f"Status: {'blocked' if self.blocked else 'review required'}",
            "",
        ]
        lines.extend(f"[{item.status}] {item.name}: {item.detail}" for item in self.items)
        return "\n".join(lines)

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class ReleaseReadinessService:
    def check(self, iso: Path, output_dir: Path) -> ReleaseReadinessReport:
        report = ReleaseReadinessReport(iso=iso, output_dir=output_dir)
        if iso.exists():
            report.items.append(ReleaseReadinessItem("iso", "captured", f"{iso.stat().st_size} bytes"))
            report.items.append(ReleaseReadinessItem("sha256", "captured", _sha256(iso)))
        else:
            report.items.append(ReleaseReadinessItem("iso", "blocked", "ISO path does not exist"))
            report.items.append(ReleaseReadinessItem("sha256", "blocked", "No ISO to checksum"))
        for name in ("SHA256SUMS", "BUILDINFO", "INTEGRITY", "PROVENANCE.json", "qemu-lab-report.json"):
            path = output_dir / name
            status = "captured" if path.exists() else "needs review"
            detail = str(path) if path.exists() else f"Missing {name}"
            report.items.append(ReleaseReadinessItem(name.lower(), status, detail))
        qemu_plan = QemuSmokePlanner().plan(iso)
        report.items.append(
            ReleaseReadinessItem("qemu-smoke", "needs review", f"{len(qemu_plan.scenarios)} planned scenarios")
        )
        report.items.append(
            ReleaseReadinessItem(
                "trademark",
                "needs review",
                "Review derivative/vendor identity, artwork, and redistribution policy before publication",
            )
        )
        report.items.append(
            ReleaseReadinessItem(
                "repo-trust",
                "needs review",
                "APT repositories should use signed-by keyrings and pinned provenance",
            )
        )
        return report


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
