from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .artifact_paths import default_output_iso
from .boot_proof import BootProofReport, run_boot_proof
from .build import BuildOptions, BuildOrchestrator
from .command import CommandError, CommandRunner
from .evidence_run import (
    artifact_identity,
    critical_artifact_identity,
    evidence_run_path,
    make_run_context,
    reserve_evidence_run,
    write_immutable_text,
    write_text_alias,
)
from .hashing import sha256_file
from .iso_doctor import IsoDoctorReport, diagnose_iso_build
from .project import Project

# The tail of the failing command's output kept in the report. Enough for apt, dpkg or
# mmdebstrap to have said what went wrong -- their diagnosis is always at the end --
# without letting one verbose command turn ISO-BUILD.json into a log file.
_FAILURE_OUTPUT_TAIL = 8000
ISO_BUILD_SCHEMA = "distroforge.iso-build.v2"
RUN_MANIFEST_SCHEMA = "distroforge.build-run-manifest.v1"


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
    run_id: str = ""
    created_at: str = ""
    alias_report: Path | None = None
    evidence_context: dict[str, object] | None = None
    artifacts: tuple[dict[str, object], ...] = ()
    provenance: dict[str, object] | None = None
    run_manifest: Path | None = None
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
            "schema": ISO_BUILD_SCHEMA,
            "run_id": self.run_id,
            "created_at": self.created_at,
            "project": str(self.project),
            "output_iso": str(self.output_iso),
            "status": self.status,
            "blocked": self.blocked,
            "failed": self.failed,
            "failure": self.failure.to_dict() if self.failure else None,
            "execute": self.execute,
            "report": str(self.report),
            "alias_report": str(self.alias_report) if self.alias_report else None,
            "command_log": str(self.command_log) if self.command_log else None,
            "doctor": self.doctor.to_dict(),
            "build_steps": list(self.build_steps),
            "output_exists": self.output_exists,
            "output_size": self.output_size,
            "output_sha256": self.output_sha256,
            "boot_proof": self.boot_proof.to_dict() if self.boot_proof else None,
            "evidence_context": self.evidence_context or {},
            "artifacts": list(self.artifacts),
            "provenance": self.provenance or {},
            "run_manifest": str(self.run_manifest) if self.run_manifest else None,
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
    options._evidence_context = None
    options._evidence_reserved = False
    options._evidence_injected = False
    options._sealed_run = execute
    evidence_context = make_run_context(
        project,
        options,
        definition=definition,
        mode="execute" if execute else "plan",
    )
    run_id = str(evidence_context["run_id"])
    reserve_evidence_run(project.output_dir, run_id, executed=execute)
    options._evidence_context = evidence_context
    options._evidence_reserved = True
    options._evidence_injected = True
    immutable_report = evidence_run_path(
        project.output_dir,
        run_id,
        "ISO-BUILD.json",
        executed=execute,
    )
    alias_report = project.output_dir / (
        "ISO-BUILD.json" if execute else "ISO-BUILD.plan.json"
    )
    log_path = log_path or evidence_run_path(
        project.output_dir,
        run_id,
        "commands.jsonl",
        executed=execute,
    )
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
        except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
            failure = BuildFailure(
                command=(),
                description=type(exc).__name__,
                returncode=1,
                output=str(exc)[-_FAILURE_OUTPUT_TAIL:],
            )
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
    # Diagnosed a second time, on purpose. The call above is the gate: it decides whether a
    # build is attempted at all, and it has to run before one. This one describes the tree
    # the rest of this report describes. One call served both, so every finished build
    # shipped its own pre-build verdict -- ISO-BUILD.json from a green local run carried
    # `output_exists: true, output_size: 1348337664` beside a doctor block reading "No output
    # ISO has been produced yet. Run an executing build, not only a dry-run", and
    # render_text printed exactly that under "Doctor:". It is the file the golden path
    # publishes as evidence, and it contradicted itself eight lines apart.
    #
    # Cheap, because every finding that moves during a build is keyed on the output ISO
    # existing: a stat and a few has_binary lookups, no command run and nothing written.
    artifacts = critical_artifact_identity(project, options.output_iso)
    if command_log and command_log.is_file():
        artifacts.append(artifact_identity(command_log, role="command-log"))
    output_artifacts: list[tuple[Path, str]] = [
        (project.output_dir / "SHA256SUMS", "checksum-list"),
        (project.output_dir / "BUILDINFO", "build-info"),
        (
            project.output_dir / "distroforge-provenance.json",
            "provenance-alias",
        ),
        (
            project.output_dir / options.prebuild_vm.report_name,
            "qemu-report-alias",
        ),
        (project.output_dir / "boot-proof.json", "boot-proof-alias"),
    ]
    if options.html_report.enabled:
        output_artifacts.append(
            (project.output_dir / options.html_report.filename, "html-report")
        )
    if options.provenance.sbom_format == "spdx":
        output_artifacts.append(
            (project.output_dir / "distroforge-sbom.spdx.json", "sbom-alias")
        )
    elif options.provenance.sbom_format == "cyclonedx":
        output_artifacts.append(
            (project.output_dir / "distroforge-sbom.cdx.json", "sbom-alias")
        )
    for path, role in output_artifacts:
        if path.is_file():
            artifacts.append(artifact_identity(path, role=role))
    optional_artifacts: list[tuple[Path | None, str]] = [
        (
            evidence_run_path(
                project.output_dir,
                run_id,
                options.prebuild_vm.report_name,
                executed=execute,
            ),
            "qemu-report",
        ),
        (project.output_dir / options.prebuild_vm.serial_log, "qemu-serial"),
        (project.output_dir / options.prebuild_vm.screenshot_name, "qemu-screenshot"),
        (
            boot_report.immutable_proof
            if boot_report and boot_report.immutable_proof
            else None,
            "boot-proof",
        ),
        (
            boot_report.qemu_report
            if boot_report and boot_report.qemu_report_sha256
            else None,
            "boot-proof-qemu-report",
        ),
    ]
    for optional_path, role in optional_artifacts:
        if optional_path is not None and optional_path.is_file():
            artifacts.append(artifact_identity(optional_path, role=role))
    provenance_path = evidence_run_path(
        project.output_dir,
        run_id,
        "distroforge-provenance.json",
        executed=execute,
    )
    provenance_identity = (
        artifact_identity(provenance_path, role="provenance")
        if provenance_path.is_file()
        else {}
    )
    evidence_dir = immutable_report.parent
    recorded_paths = {
        str(item.get("path"))
        for item in artifacts
        if isinstance(item.get("path"), str)
    }
    for evidence_path in sorted(evidence_dir.rglob("*")):
        if (
            not evidence_path.is_file()
            or evidence_path == provenance_path
            or str(evidence_path) in recorded_paths
        ):
            continue
        artifacts.append(artifact_identity(evidence_path, role="run-evidence"))
        recorded_paths.add(str(evidence_path))
    run_manifest = evidence_run_path(
        project.output_dir,
        run_id,
        "RUN-MANIFEST.json",
        executed=execute,
    )
    report = IsoBuildReport(
        project=project.root,
        output_iso=options.output_iso,
        status=status,
        execute=execute,
        report=immutable_report,
        doctor=diagnose_iso_build(project, options, definition=definition),
        build_steps=steps,
        output_exists=exists,
        output_size=size,
        output_sha256=sha256,
        boot_proof=boot_report,
        failure=failure,
        command_log=command_log,
        run_id=run_id,
        created_at=str(evidence_context["created_at"]),
        alias_report=alias_report,
        evidence_context=evidence_context,
        artifacts=tuple(artifacts),
        provenance=provenance_identity,
        run_manifest=run_manifest,
    )
    content = report.render_json() + "\n"
    write_immutable_text(immutable_report, content)
    manifest_files = [
        artifact_identity(immutable_report, role="iso-build-report"),
        *artifacts,
    ]
    if provenance_identity:
        manifest_files.append(provenance_identity)
    manifest_payload = {
        "schema": RUN_MANIFEST_SCHEMA,
        "run_id": run_id,
        "mode": "execute" if execute else "plan",
        "status": status,
        "created_at": evidence_context["created_at"],
        "files": manifest_files,
    }
    manifest_content = json.dumps(manifest_payload, indent=2) + "\n"
    write_immutable_text(run_manifest, manifest_content)
    manifest_sha = sha256_file(run_manifest)
    write_immutable_text(
        run_manifest.with_name(f"{run_manifest.name}.sha256"),
        f"{manifest_sha}  {run_manifest.name}\n",
    )
    write_text_alias(alias_report, content)
    return report


def _output_contract(path: Path) -> tuple[bool, int, str]:
    if not path.exists() or not path.is_file():
        return False, 0, ""
    size = path.stat().st_size
    return True, size, sha256_file(path) if size > 0 else ""
