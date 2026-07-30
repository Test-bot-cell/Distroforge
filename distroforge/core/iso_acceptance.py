from __future__ import annotations

import json
import os
import shlex
from dataclasses import dataclass
from pathlib import Path

from .artifact_paths import default_output_iso
from .artifact_verification import (
    ArtifactVerificationError,
    ArtifactVerificationSession,
)
from .build import BuildOptions
from .project import Project
from .release_gate import ReleaseGateService
from .release_run import ExecutedReleaseRun, select_executed_release_run

_SAFE_ARTIFACT_ERRORS = (
    ArtifactVerificationError,
    OSError,
    UnicodeError,
    TypeError,
    ValueError,
    OverflowError,
    RecursionError,
)


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
    report: Path | None
    status: str
    next_command: str
    items: tuple[IsoAcceptanceItem, ...]
    build_run_id: str | None = None
    boot_run_id: str | None = None

    @property
    def blocked(self) -> bool:
        return self.status == "blocked"

    def to_dict(self) -> dict[str, object]:
        return {
            "project": str(self.project),
            "iso": str(self.iso),
            "report": str(self.report) if self.report else None,
            "immutable_iso_build": str(self.report) if self.report else None,
            "build_run_id": self.build_run_id,
            "boot_run_id": self.boot_run_id,
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
            f"Build run: {self.build_run_id or 'not selected'}",
            f"Boot run: {self.boot_run_id or 'not selected'}",
            f"Immutable ISO build: {self.report or 'not selected'}",
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
    build_run_id: str | None = None,
    boot_run_id: str | None = None,
) -> IsoAcceptanceReport:
    options = options or BuildOptions()
    iso = Path(
        os.path.abspath(iso or options.output_iso or default_output_iso(project))
    )
    output_dir = Path(os.path.abspath(output_dir or iso.parent))
    items: list[IsoAcceptanceItem] = []
    session: ArtifactVerificationSession | None = None
    selected: ExecutedReleaseRun | None = None
    selection_error: str | None = None
    selected_boot_run_id: str | None = None
    try:
        session = ArtifactVerificationSession(
            Path("/"),
            label="ISO acceptance immutable build session",
        )
        selected = select_executed_release_run(
            project,
            iso,
            output_dir,
            session,
            build_run_id=build_run_id,
        )
        _check_iso_contract(items, iso, selected, session)
    except _SAFE_ARTIFACT_ERRORS as exc:
        selection_error = str(exc)
        items.append(
            IsoAcceptanceItem(
                "iso-build-report",
                "blocked",
                "Immutable executed build run selection failed safely: "
                f"{selection_error}",
            )
        )

    if selected is not None:
        try:
            gate = ReleaseGateService().check(
                project,
                options,
                iso=iso,
                output_dir=output_dir,
                build_run_id=selected.run_id,
                boot_run_id=boot_run_id,
            )
        except _SAFE_ARTIFACT_ERRORS as exc:
            items.append(
                IsoAcceptanceItem(
                    "release-gate",
                    "blocked",
                    f"Release gate stopped safely: {exc}",
                )
            )
        else:
            selected_boot_run_id = getattr(gate, "boot_run_id", None)
            items.append(
                IsoAcceptanceItem(
                    "release-gate",
                    "blocked" if gate.blocked else "ready",
                    f"Release gate is {gate.status} for immutable build run "
                    f"{selected.run_id}.",
                )
            )
            for gate_item in gate.items:
                if gate_item.status == "blocked":
                    items.append(
                        IsoAcceptanceItem(
                            f"gate-{gate_item.code}",
                            "blocked",
                            gate_item.detail,
                        )
                    )

    if session is not None:
        try:
            if selected is None:
                session.close()
            else:
                session.seal()
        except ArtifactVerificationError as exc:
            items.append(
                IsoAcceptanceItem(
                    "artifact-session",
                    "blocked",
                    f"Immutable build selection did not close safely: {exc}",
                )
            )

    status = "blocked" if any(item.status == "blocked" for item in items) else "accepted"
    selected_run_id = selected.run_id if selected is not None else None
    selected_report = selected.iso_build_path if selected is not None else None
    acceptance = IsoAcceptanceReport(
        project.root,
        iso,
        selected_report,
        status,
        _next_command(
            project,
            iso,
            output_dir,
            items,
            selected_run_id,
            selected_boot_run_id,
            selection_error,
        ),
        tuple(items),
        selected_run_id,
        selected_boot_run_id,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "ISO-ACCEPTANCE.json").write_text(acceptance.render_json() + "\n", encoding="utf-8")
    return acceptance


def _check_iso_contract(
    items: list[IsoAcceptanceItem],
    iso: Path,
    selected: ExecutedReleaseRun,
    session: ArtifactVerificationSession,
) -> None:
    iso_handle = session.file_path(
        iso,
        label="accepted ISO",
        max_bytes=session.limits.max_file_bytes,
    )
    digest = iso_handle.digest()
    items.append(
        IsoAcceptanceItem(
            "iso",
            "ready",
            f"{iso_handle.identity.size} bytes, SHA256 {digest}.",
        )
    )
    items.append(
        IsoAcceptanceItem(
            "iso-build-report",
            "ready",
            f"{selected.iso_build_path} (immutable build run {selected.run_id})",
        )
    )


def _next_command(
    project: Project,
    iso: Path,
    output_dir: Path,
    items: list[IsoAcceptanceItem],
    build_run_id: str | None,
    boot_run_id: str | None,
    selection_error: str | None,
) -> str:
    codes = {item.code for item in items if item.status == "blocked"}
    if build_run_id is None:
        if selection_error and "multiple immutable executed build runs" in selection_error:
            return shlex.join(
                [
                    "distroforge",
                    "iso-accept",
                    str(project.root),
                    "--iso",
                    str(iso),
                    "--output-dir",
                    str(output_dir),
                    "--build-run-id",
                    "RUN_ID",
                ]
            )
        return shlex.join(
            [
                "distroforge",
                "iso-build",
                str(project.root),
                "--execute",
                "--output-iso",
                str(iso),
                "--boot-proof",
                "auto",
            ]
        )
    if "gate-boot-proof" in codes:
        # Boot creation and consumption must share one process so the newly
        # generated boot_run_id cannot be replaced with a shell placeholder or
        # lost between two independent verdicts.
        return shlex.join(
            [
                "distroforge",
                "release-pipeline",
                str(project.root),
                "--iso",
                str(iso),
                "--output-dir",
                str(output_dir),
                "--bundle-dir",
                str(project.output_dir / "publish"),
                "--build-run-id",
                build_run_id,
                "--run-boot-proof",
                "--boot-backend",
                "auto",
            ]
        )
    if codes:
        command = [
            "distroforge",
            "release-gate",
            str(project.root),
            "--iso",
            str(iso),
            "--output-dir",
            str(output_dir),
            "--build-run-id",
            build_run_id,
        ]
        if boot_run_id is not None:
            command.extend(["--boot-run-id", boot_run_id])
        return shlex.join(command)
    command = [
        "distroforge",
        "publish-bundle",
        str(project.root),
        "--iso",
        str(iso),
        "--output-dir",
        str(output_dir),
        "--build-run-id",
        build_run_id,
    ]
    if boot_run_id is not None:
        command.extend(["--boot-run-id", boot_run_id])
    return shlex.join(command)
