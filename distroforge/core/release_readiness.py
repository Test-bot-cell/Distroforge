from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .hashing import sha256_file, sha256_from_sums
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
    def check(
        self, iso: Path, output_dir: Path, *, verify_checksum: bool = True
    ) -> ReleaseReadinessReport:
        """Capture the release evidence available for ``iso``.

        ``verify_checksum=False`` reports the digest SHA256SUMS already records
        rather than re-reading the ISO. The sha256 item is evidence, never a
        blocker (an existing ISO is always "captured"), so the light form cannot
        change ``blocked`` -- it only spares callers that just want the verdict.
        """
        report = ReleaseReadinessReport(iso=iso, output_dir=output_dir)
        if iso.exists():
            report.items.append(ReleaseReadinessItem("iso", "captured", f"{iso.stat().st_size} bytes"))
            report.items.append(ReleaseReadinessItem("sha256", "captured", _digest(iso, output_dir, verify_checksum)))
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


def _digest(iso: Path, output_dir: Path, verify_checksum: bool) -> str:
    if verify_checksum:
        return sha256_file(iso)
    sums = output_dir / "SHA256SUMS"
    recorded = sha256_from_sums(sums, iso.name) if sums.exists() else None
    return recorded or "not checksummed yet"
