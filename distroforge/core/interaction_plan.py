from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .qemu_smoke import QemuSmokePlanner, QemuSmokeScenario

VALID_INTERACTION_ACTIONS = (
    "wait-serial",
    "wait",
    "screendump",
    "sendkey",
    "query-status",
    "quit",
)


@dataclass(frozen=True)
class InteractionStep:
    action: str
    value: str = ""
    seconds: float = 0.0
    description: str = ""

    def __post_init__(self) -> None:
        if self.action not in VALID_INTERACTION_ACTIONS:
            raise ValueError(f"Unknown interaction action: {self.action}")

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = {"action": self.action}
        if self.value:
            data["value"] = self.value
        if self.seconds:
            data["seconds"] = self.seconds
        if self.description:
            data["description"] = self.description
        return data

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> InteractionStep:
        return cls(
            action=str(data["action"]),
            value=str(data.get("value", "")),
            seconds=float(data.get("seconds", 0.0)),
            description=str(data.get("description", "")),
        )


@dataclass(frozen=True)
class InteractionPlan:
    name: str
    description: str
    firmware: str = "bios"
    network: bool = False
    steps: tuple[InteractionStep, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "description": self.description,
            "firmware": self.firmware,
            "network": self.network,
            "steps": [step.to_dict() for step in self.steps],
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> InteractionPlan:
        raw_steps = data.get("steps", [])
        steps = tuple(InteractionStep.from_dict(step) for step in raw_steps)
        return cls(
            name=str(data["name"]),
            description=str(data.get("description", "")),
            firmware=str(data.get("firmware", "bios")),
            network=bool(data.get("network", False)),
            steps=steps,
        )

    def render_text(self) -> str:
        net = "online" if self.network else "offline"
        lines = [
            f"Interaction plan: {self.name}",
            self.description,
            f"Firmware: {self.firmware}, network: {net}",
            "",
            "Steps:",
        ]
        for index, step in enumerate(self.steps, start=1):
            detail = step.value or (f"{step.seconds}s" if step.seconds else "")
            head = f"{step.action} {detail}".strip()
            suffix = f" — {step.description}" if step.description else ""
            lines.append(f"{index:2}. {head}{suffix}")
        return "\n".join(lines)

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def _boot_capture_steps() -> tuple[InteractionStep, ...]:
    return (
        InteractionStep("wait-serial", value="login:", description="Wait for boot to reach a login prompt"),
        InteractionStep("screendump", description="Capture the booted screen"),
        InteractionStep("query-status", description="Confirm the guest is running"),
        InteractionStep("quit", description="Shut the guest down"),
    )


BUILTIN_INTERACTION_PLANS: dict[str, InteractionPlan] = {
    "boot-capture": InteractionPlan(
        name="boot-capture",
        description="Boot the ISO, prove it reaches a login prompt, capture a screenshot, and shut down.",
        firmware="bios",
        network=False,
        steps=_boot_capture_steps(),
    ),
    "headless-status": InteractionPlan(
        name="headless-status",
        description="Minimal liveness probe: query the guest run-state over QMP and quit.",
        firmware="bios",
        network=False,
        steps=(
            InteractionStep("query-status", description="Confirm the guest is running"),
            InteractionStep("quit", description="Shut the guest down"),
        ),
    ),
}


def smoke_interaction_plan(scenario: QemuSmokeScenario) -> InteractionPlan:
    net = "online" if scenario.network else "offline"
    return InteractionPlan(
        name=scenario.name,
        description=f"Smoke scenario {scenario.name}: {scenario.firmware} {scenario.install_mode} ({net}).",
        firmware=scenario.firmware,
        network=scenario.network,
        steps=_boot_capture_steps(),
    )


def available_interaction_plans(iso: Path | None = None) -> list[str]:
    placeholder = iso or Path("image.iso")
    smoke_names = [scenario.name for scenario in QemuSmokePlanner().plan(placeholder).scenarios]
    return list(BUILTIN_INTERACTION_PLANS) + smoke_names


def resolve_interaction_plan(spec: str, iso: Path) -> InteractionPlan:
    candidate = Path(spec)
    if candidate.is_file():
        return InteractionPlan.from_dict(json.loads(candidate.read_text(encoding="utf-8")))
    if spec in BUILTIN_INTERACTION_PLANS:
        return BUILTIN_INTERACTION_PLANS[spec]
    for scenario in QemuSmokePlanner().plan(iso).scenarios:
        if scenario.name == spec:
            return smoke_interaction_plan(scenario)
    available = ", ".join(available_interaction_plans(iso))
    raise ValueError(f"Unknown interaction plan '{spec}'. Available: {available}")
