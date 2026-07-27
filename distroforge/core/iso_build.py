from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .artifact_paths import default_command_log, default_output_iso
from .boot_proof import BootProofReport, run_boot_proof
from .build import BuildOptions, BuildOrchestrator
from .command import CommandError, CommandRunner
from .hashing import sha256_file
from .iso_doctor import IsoDoctorReport, diagnose_iso_build
from .project import Project

# The tail of the failing command's output kept in the report. Enough for apt, dpkg or
# mmdebstrap to have said what went wrong -- their diagnosis is always at the end --
# without letting one verbose command turn ISO-BUILD.json into a log file.
_FAILURE_OUTPUT_TAIL = 8000


@dataclass(frozen=True)
class BuildFailure:
    """What broke, as a field of the report instead of a traceback on stderr.

    The first real run of the weekly golden path died inside the chroot, and the
    workflow reported it as ``jq: Could not open file .../ISO-BUILD.json`` -- because
    ``run_iso_build`` let ``CommandError`` out, so the command wrote no report at all
    and the assertion downstream failed on the absence rather than on the cause. The
    traceback did name the failing command, but it went to stderr, past ``--json``,
    and nothing downstream could read it.

    ``output`` is the failing command's own words. ``CommandRunner`` captures stdout
    and stderr (core/command.py:123) and only the raised error carries them, so if
    they are not copied here they are gone.
    """

    command: tuple[str, ...]
    description: str
    returncode: int
    output: str

    def to_dict(self) -> dict[str, object]:
        return {
            "command": list(self.command),
            "description": self.description,
            "returncode": self.returncode,
            "output": self.output,
        }


def _failure_from(exc: CommandError) -> BuildFailure:
    result = exc.result
    output = f"{result.stdout}\n{result.stderr}".strip()
    return BuildFailure(
        command=tuple(result.spec.argv),
        description=result.spec.description,
        returncode=result.returncode,
        output=output[-_FAILURE_OUTPUT_TAIL:],
    )


@dataclass(frozen=True)
class IsoBuildReport:
    project: Path
    output_iso: Path
    status: str
    execute: bool
    report: Path
    doctor: IsoDoctorReport
    build_steps: tuple[str, ...]
    output_exists: bool = False
    output_size: int = 0
    output_sha256: str = ""
    boot_proof: BootProofReport | None = None
    failure: BuildFailure | None = None
    command_log: Path | None = None
    """Where every command this build ran was recorded, named so a reader can find it.

    The report is what callers are told to read, and for one release cycle it described a
    failure without ever mentioning that a line-by-line log of the run existed -- because
    it did not: log_path arrived as None from both callers.
    """

    @property
    def blocked(self) -> bool:
        return self.status == "blocked"

    @property
    def failed(self) -> bool:
        """A build that ran and broke, as opposed to one that was refused before it ran.

        Kept apart from ``blocked`` on purpose: blocked answers "this project cannot
        build and here is the doctor's reason", which a dry run may say correctly and
        usefully. ``failed`` only ever comes from a command that exited non-zero.
        """
        return self.status == "failed"

    def to_dict(self) -> dict[str, object]:
        return {
            "project": str(self.project),
            "output_iso": str(self.output_iso),
            "status": self.status,
            "blocked": self.blocked,
            "failed": self.failed,
            "failure": self.failure.to_dict() if self.failure else None,
            "execute": self.execute,
            "report": str(self.report),
            "command_log": str(self.command_log) if self.command_log else None,
            "doctor": self.doctor.to_dict(),
            "build_steps": list(self.build_steps),
            "output_exists": self.output_exists,
            "output_size": self.output_size,
            "output_sha256": self.output_sha256,
            "boot_proof": self.boot_proof.to_dict() if self.boot_proof else None,
        }

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def render_text(self) -> str:
        lines = [
            "ISO build",
            f"Project: {self.project}",
            f"Output ISO: {self.output_iso}",
            f"Status: {self.status.upper()}",
            f"Mode: {'execute' if self.execute else 'dry-run'}",
            f"Output exists: {self.output_exists}",
            f"Output size: {self.output_size}",
            f"Output SHA256: {self.output_sha256 or 'missing'}",
            f"Report: {self.report}",
            f"Command log: {self.command_log or 'not recorded'}",
            "",
            "Doctor:",
            f"- {self.doctor.status}: {self.doctor.next_command}",
            "",
            "Build steps:",
            *([f"- {step}" for step in self.build_steps] or ["- not run"]),
        ]
        if self.boot_proof:
            lines.extend(["", "Boot proof:", f"- {self.boot_proof.status} via {self.boot_proof.selected_backend or self.boot_proof.backend}"])
        if self.failure:
            lines.extend(
                [
                    "",
                    "Failed:",
                    f"- {self.failure.description or 'command'} (exit {self.failure.returncode})",
                    f"- {' '.join(self.failure.command)}",
                    *([f"  {line}" for line in self.failure.output.splitlines()[-12:]] or ["  no output"]),
                ]
            )
        return "\n".join(lines)


def run_iso_build(
    project: Project,
    options: BuildOptions | None = None,
    *,
    execute: bool = False,
    boot_proof_backend: str = "none",
    definition: Path | None = None,
    log_path: Path | None = None,
) -> IsoBuildReport:
    options = options or BuildOptions()
    options.output_iso = options.output_iso or default_output_iso(project)
    # Default the log here rather than trust each caller to remember it. Both production
    # callers had forgotten: commands/iso_build.py passed nothing and core/demo_iso.py
    # passed nothing, so log_path stayed None, so _write_event returned before writing a
    # line (core/command.py:224) and `distroforge iso-build --execute` -- the command the
    # golden path runs -- produced no command log at all. The one caller that does pass a
    # path, commands/build.py:77, spells the same default for the other entry point.
    log_path = log_path or default_command_log(project, "iso-build")
    doctor = diagnose_iso_build(project, options, definition=definition)
    boot_report = None
    steps: tuple[str, ...] = ()
    status = "blocked" if doctor.blocked else "planned"
    failure: BuildFailure | None = None
    # Named on the report only once a runner exists to write it. A blocked project never
    # gets one, and a report pointing at a log file that was never opened is worse than a
    # report that admits there is none.
    command_log: Path | None = None
    if not doctor.blocked:
        command_log = log_path
        runner = CommandRunner(dry_run=not execute, log_path=log_path)
        try:
            build = BuildOrchestrator(project, runner, options).run()
        except CommandError as exc:
            # A build that breaks halfway is still something to report on. Letting this
            # out produced a traceback on stderr and no ISO-BUILD.json, which is the
            # worst of both: the cause was printed where --json consumers cannot see it,
            # and the report the caller was told to read did not exist. The commands run
            # so far are not lost either -- runner.history has them, and the phase is
            # named in the failing command's own description.
            failure = _failure_from(exc)
            status = "failed"
            exists, size, sha256 = _output_contract(options.output_iso)
        else:
            steps = tuple(step.phase.value for step in build.steps)
            exists, size, sha256 = _output_contract(options.output_iso)
            status = "built" if execute and exists and size > 0 else "blocked" if execute else "planned"
            if boot_proof_backend != "none" and (execute or options.output_iso.exists()):
                boot_report = run_boot_proof(
                    project,
                    options,
                    iso=options.output_iso,
                    backend=boot_proof_backend,
                    execute=execute,
                )
                if boot_report.blocked:
                    status = "blocked"
    else:
        exists, size, sha256 = _output_contract(options.output_iso)
    report = IsoBuildReport(
        project.root,
        options.output_iso,
        status,
        execute,
        project.output_dir / "ISO-BUILD.json",
        doctor,
        steps,
        exists,
        size,
        sha256,
        boot_report,
        failure,
        command_log,
    )
    project.output_dir.mkdir(parents=True, exist_ok=True)
    report.report.write_text(report.render_json() + "\n", encoding="utf-8")
    return report


def _output_contract(path: Path) -> tuple[bool, int, str]:
    if not path.exists() or not path.is_file():
        return False, 0, ""
    size = path.stat().st_size
    return True, size, sha256_file(path) if size > 0 else ""

