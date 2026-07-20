from __future__ import annotations

import json
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from .command import CommandRunner, CommandSpec
from .integrity import IntegrityService
from .interaction_plan import InteractionPlan, InteractionStep
from .qemu_invocation import QemuInvocation
from .qmp import QmpControl, stop_by_pidfile


@dataclass
class QemuInteractionOptions:
    display: str = "none"
    memory_mb: int = 4096
    cpus: int = 2
    disk_size: str = "24G"
    secure_boot: bool = False
    enable_kvm: bool = True
    timeout_seconds: int = 300
    serial_log: str = "interaction-serial.log"
    qmp_socket: str = "interaction.qmp"
    pid_file: str = "interaction.pid"
    screenshot_name: str = "interaction.ppm"
    report_name: str = "qemu-interaction-report.json"
    ovmf_code: str = "/usr/share/OVMF/OVMF_CODE.fd"
    ovmf_vars: str = "/usr/share/OVMF/OVMF_VARS.fd"


@dataclass(frozen=True)
class QemuInteractionArtifacts:
    disk: Path
    qmp_socket: Path
    pid_file: Path
    serial_log: Path
    screenshot: Path
    report: Path
    ovmf_vars: Path


@dataclass(frozen=True)
class QemuInteractionReport:
    plan: InteractionPlan
    iso: Path
    display: str
    argv: tuple[str, ...]
    artifacts: QemuInteractionArtifacts

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": "distroforge.qemu-interaction.v1",
            "plan": self.plan.name,
            "description": self.plan.description,
            "firmware": self.plan.firmware,
            "network": self.plan.network,
            "display": self.display,
            "iso": str(self.iso),
            "steps": [step.to_dict() for step in self.plan.steps],
            "argv": list(self.argv),
            "artifacts": {
                "serial_log": str(self.artifacts.serial_log),
                "screenshot": str(self.artifacts.screenshot),
                "qmp_socket": str(self.artifacts.qmp_socket),
                "pid_file": str(self.artifacts.pid_file),
                "report": str(self.artifacts.report),
            },
        }

    def render_text(self) -> str:
        lines = [
            f"QEMU interaction: {self.plan.name}",
            f"ISO: {self.iso}",
            f"Display: {self.display}, firmware: {self.plan.firmware}",
            "",
            self.plan.render_text(),
        ]
        return "\n".join(lines)

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class QemuInteractionService:
    def __init__(
        self,
        runner: CommandRunner,
        iso_path: Path,
        workdir: Path,
        output_dir: Path,
        plan: InteractionPlan,
        options: QemuInteractionOptions,
    ) -> None:
        self.runner = runner
        self.iso_path = iso_path
        self.workdir = workdir / "interaction"
        self.output_dir = output_dir
        self.plan = plan
        self.options = options
        self._qmp = QmpControl(runner, options.timeout_seconds)

    def run(self) -> QemuInteractionReport:
        artifacts = self._artifacts()
        self.runner.run(
            CommandSpec(
                argv=("mkdir", "-p", str(self.workdir), str(self.output_dir)),
                description="Prepare QEMU interaction artifact directories",
            )
        )
        self.runner.run(
            CommandSpec(
                argv=("qemu-img", "create", "-f", "qcow2", str(artifacts.disk), self.options.disk_size),
                description="Create QEMU interaction disk",
            )
        )
        self._prepare_firmware(artifacts)
        argv = tuple(self._qemu_argv(artifacts))
        try:
            self.runner.run(
                CommandSpec(
                    argv=argv,
                    description="Run QEMU interaction boot with QMP control",
                )
            )
            for step in self.plan.steps:
                self._run_step(step, artifacts)
        finally:
            stop_by_pidfile(self.runner, artifacts.pid_file, "Stop QEMU interaction VM")
        report = QemuInteractionReport(
            plan=self.plan,
            iso=self.iso_path,
            display=self.options.display,
            argv=argv,
            artifacts=artifacts,
        )
        self._write_report(artifacts, report)
        IntegrityService(self.runner).write_manifest(
            self.output_dir / "INTERACTION-INTEGRITY",
            {
                "iso": self.iso_path.name,
                "plan": self.plan.name,
                "firmware": self.plan.firmware,
                "serial_log": self.options.serial_log,
                "qmp_socket": str(artifacts.qmp_socket),
                "report": self.options.report_name,
                "steps": str(len(self.plan.steps)),
            },
        )
        return report

    def _artifacts(self) -> QemuInteractionArtifacts:
        return QemuInteractionArtifacts(
            disk=self.workdir / "interaction.qcow2",
            qmp_socket=self.workdir / self.options.qmp_socket,
            pid_file=self.workdir / self.options.pid_file,
            serial_log=self.output_dir / self.options.serial_log,
            screenshot=self.output_dir / self.options.screenshot_name,
            report=self.output_dir / self.options.report_name,
            ovmf_vars=self.workdir / "OVMF_VARS.fd",
        )

    def _qemu_argv(self, artifacts: QemuInteractionArtifacts) -> list[str]:
        return list(
            QemuInvocation(
                iso=self.iso_path,
                memory_mb=self.options.memory_mb,
                cpus=self.options.cpus,
                disk=artifacts.disk,
                serial=f"file:{artifacts.serial_log}",
                qmp_socket=artifacts.qmp_socket,
                pid_file=artifacts.pid_file,
                display=self.options.display,
                daemonize=True,
                firmware=self.plan.firmware,
                ovmf_code=self.options.ovmf_code,
                ovmf_vars=str(artifacts.ovmf_vars),
                secure_boot=self.options.secure_boot,
                network="user" if self.plan.network else "none",
                enable_kvm=self.options.enable_kvm,
            ).argv()
        )

    def _prepare_firmware(self, artifacts: QemuInteractionArtifacts) -> None:
        if self.plan.firmware != "uefi":
            return
        self.runner.run(
            CommandSpec(
                argv=("copy-file", self.options.ovmf_vars, str(artifacts.ovmf_vars)),
                description="Prepare writable OVMF variables store",
            )
        )
        if not self.runner.dry_run:
            shutil.copy2(self.options.ovmf_vars, artifacts.ovmf_vars)

    def _run_step(self, step: InteractionStep, artifacts: QemuInteractionArtifacts) -> None:
        if step.action == "wait-serial":
            self._await_serial(step.value)
        elif step.action == "wait":
            self._wait(step.seconds)
        elif step.action == "screendump":
            filename = step.value or str(artifacts.screenshot)
            self._qmp.command("screendump", artifacts.qmp_socket, {"filename": filename})
        elif step.action == "sendkey":
            keys = [{"type": "qcode", "data": code} for code in step.value.split("-") if code]
            self._qmp.command("send-key", artifacts.qmp_socket, {"keys": keys})
        elif step.action == "query-status":
            self._qmp.command("query-status", artifacts.qmp_socket)
        elif step.action == "quit":
            self._qmp.command("quit", artifacts.qmp_socket)

    def _await_serial(self, pattern: str) -> None:
        serial = self.output_dir / self.options.serial_log
        self.runner.run(
            CommandSpec(
                argv=("interaction-await-serial", str(serial), pattern),
                description=f"Await serial marker: {pattern}",
            )
        )
        if self.runner.dry_run:
            return
        deadline = time.monotonic() + self.options.timeout_seconds
        while time.monotonic() <= deadline:
            if serial.exists() and pattern in serial.read_text(encoding="utf-8", errors="replace"):
                return
            time.sleep(0.5)
        raise ValueError(f"QEMU interaction did not emit serial marker: {pattern}")

    def _wait(self, seconds: float) -> None:
        self.runner.run(
            CommandSpec(
                argv=("interaction-wait", str(seconds)),
                description=f"Wait {seconds}s",
            )
        )
        if self.runner.dry_run:
            return
        time.sleep(seconds)

    def _write_report(self, artifacts: QemuInteractionArtifacts, report: QemuInteractionReport) -> None:
        self.runner.run(
            CommandSpec(
                argv=("write-file", str(artifacts.report)),
                description="Write QEMU interaction JSON report",
            )
        )
        if not self.runner.dry_run:
            artifacts.report.parent.mkdir(parents=True, exist_ok=True)
            artifacts.report.write_text(report.render_json(), encoding="utf-8")
