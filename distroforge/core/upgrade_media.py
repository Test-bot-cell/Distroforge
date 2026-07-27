from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .releases import read_os_release


@dataclass(frozen=True)
class UpgradeCheck:
    name: str
    status: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "status": self.status, "detail": self.detail}


@dataclass
class UpgradePreflightReport:
    target: Path
    checks: list[UpgradeCheck] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return any(check.status == "blocked" for check in self.checks)

    def to_dict(self) -> dict[str, object]:
        return {
            "mode": "controlled-upgrade-media-preflight",
            "target": str(self.target),
            "blocked": self.blocked,
            "checks": [check.to_dict() for check in self.checks],
        }

    def render_text(self) -> str:
        lines = [
            "Controlled upgrade media preflight",
            f"Target: {self.target}",
            f"Status: {'blocked' if self.blocked else 'review required'}",
            "",
        ]
        lines.extend(f"[{check.status}] {check.name}: {check.detail}" for check in self.checks)
        return "\n".join(lines)

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class UpgradeMediaPreflight:
    def check(self, target: Path, from_release: str | None, to_release: str | None) -> UpgradePreflightReport:
        report = UpgradePreflightReport(target)
        os_release = read_os_release(target)
        current = os_release.get("VERSION_ID", "unknown")
        family = os_release.get("ID", "unknown")
        report.checks.append(UpgradeCheck("os-release", "captured", f"{family} {current}"))
        if from_release and current != from_release:
            report.checks.append(
                UpgradeCheck("release-match", "blocked", f"Expected {from_release}, found {current}")
            )
        else:
            report.checks.append(UpgradeCheck("release-match", "captured", current))
        if not to_release:
            report.checks.append(UpgradeCheck("target-release", "blocked", "--to is required"))
        elif family not in {"ubuntu", "debian"}:
            report.checks.append(UpgradeCheck("family", "blocked", f"Unsupported family: {family}"))
        else:
            report.checks.append(UpgradeCheck("target-release", "needs review", to_release))
        fstab = (target / "etc/fstab").read_text(encoding="utf-8", errors="replace") if (target / "etc/fstab").exists() else ""
        for token in ("crypt", "luks", "raid", "btrfs", "lvm"):
            if token in fstab.lower():
                report.checks.append(
                    UpgradeCheck("storage", "needs review", f"Detected {token}; manual review required")
                )
        report.checks.append(
            UpgradeCheck(
                "execution",
                "blocked",
                "Upgrade media execution is not implemented; preflight is read-only.",
            )
        )
        return report
