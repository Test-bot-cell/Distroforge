from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .qemu_invocation import QemuInvocation


@dataclass(frozen=True)
class QemuSmokeScenario:
    name: str
    firmware: str
    network: bool
    install_mode: str
    secure_boot: str
    status: str
    command: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "firmware": self.firmware,
            "network": self.network,
            "install_mode": self.install_mode,
            "secure_boot": self.secure_boot,
            "status": self.status,
            "command": list(self.command),
        }


@dataclass(frozen=True)
class QemuSmokePlan:
    iso: Path
    scenarios: tuple[QemuSmokeScenario, ...]
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "iso": str(self.iso),
            "scenarios": [scenario.to_dict() for scenario in self.scenarios],
            "warnings": list(self.warnings),
        }

    def render_text(self) -> str:
        lines = ["QEMU install smoke plan", f"ISO: {self.iso}", "", "Scenarios:"]
        for scenario in self.scenarios:
            net = "online" if scenario.network else "offline"
            lines.append(
                f"- {scenario.name}: {scenario.firmware}, {net}, {scenario.install_mode}, "
                f"secure-boot={scenario.secure_boot}, {scenario.status}"
            )
            lines.append("  " + " ".join(scenario.command))
        if self.warnings:
            lines.extend(["", "Warnings:", *[f"- {warning}" for warning in self.warnings]])
        return "\n".join(lines)

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class QemuSmokePlanner:
    def plan(self, iso: Path) -> QemuSmokePlan:
        scenarios = (
            self._scenario("live-bios-offline", iso, "bios", False, "live", "unsupported"),
            self._scenario("install-bios-offline", iso, "bios", False, "install", "unsupported"),
            self._scenario("install-uefi-online", iso, "uefi", True, "install", "planned"),
            self._scenario("live-uefi-secureboot", iso, "uefi", False, "live", "planned"),
        )
        warnings = (
            "Plan only; execute through the QEMU lab before release publication.",
            "Offline install must prove that /cdrom package sources and pool are sufficient.",
        )
        return QemuSmokePlan(iso=iso, scenarios=scenarios, warnings=warnings)

    def _scenario(
        self,
        name: str,
        iso: Path,
        firmware: str,
        network: bool,
        install_mode: str,
        secure_boot: str,
    ) -> QemuSmokeScenario:
        command = QemuInvocation(
            iso=iso,
            memory_mb=4096,
            firmware=firmware,
            network=None if network else "none",
        ).argv()
        return QemuSmokeScenario(
            name=name,
            firmware=firmware,
            network=network,
            install_mode=install_mode,
            secure_boot=secure_boot,
            status="planned",
            command=command,
        )
