from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .artifact_paths import default_artifact_paths
from .build import BuildOptions
from .command import VIRTUAL_COMMANDS
from .diff_preview import DiffPreviewService
from .evidence_run import (
    canonical_sha256,
    first_symlink_in_confined_tree,
    observed_executable_counts,
)
from .hashing import sha256_file, sha256_from_sums
from .packaging import packaging_policy_report
from .prebuild_vm import validate_qemu_report
from .project import Project
from .provenance import CYCLONEDX_FILENAME, SPDX_FILENAME
from .release_readiness import ReleaseReadinessService
from .trust import TrustService
from .vulnscan import VulnScanService


@dataclass(frozen=True)
class ReleaseGateItem:
    code: str
    status: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "status": self.status, "detail": self.detail}


@dataclass
class ReleaseGateReport:
    project: Path
    iso: Path
    output_dir: Path
    items: list[ReleaseGateItem] = field(default_factory=list)

    @property
    def status(self) -> str:
        if any(item.status == "blocked" for item in self.items):
            return "blocked"
        if any(item.status == "review" for item in self.items):
            return "review"
        return "ready"

    @property
    def blocked(self) -> bool:
        return self.status == "blocked"

    def to_dict(self) -> dict[str, object]:
        return {
            "project": str(self.project),
            "iso": str(self.iso),
            "output_dir": str(self.output_dir),
            "status": self.status,
            "blocked": self.blocked,
            "items": [item.to_dict() for item in self.items],
        }

    def render_text(self) -> str:
        lines = [
            "Release gate",
            f"Project: {self.project}",
            f"ISO: {self.iso}",
            f"Output: {self.output_dir}",
            f"Status: {self.status.upper()}",
            "",
        ]
        lines.extend(f"[{item.status}] {item.code}: {item.detail}" for item in self.items)
        return "\n".join(lines)

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class ReleaseGateService:
    def check(
        self,
        project: Project,
        options: BuildOptions,
        *,
        iso: Path | None = None,
        output_dir: Path | None = None,
        verify_checksums: bool = True,
    ) -> ReleaseGateReport:
        """Report the maintainer publish gate for ``project``.

        ``verify_checksums=False`` answers the SHA256 items from the SHA256SUMS
        sidecar instead of re-reading the ISO, which is what the guided journey
        status needs: it is recomputed on every refresh and must not hash a
        multi-gigabyte artifact on the Qt thread. The verifying default stays on
        every authoritative path (``distroforge release-gate``, the Artifacts
        page, ``check_journey_step``), so the gate is never self-confirming
        where its verdict is the answer.
        """
        paths = default_artifact_paths(project)
        iso = iso or options.output_iso or paths.output_iso
        output_dir = output_dir or iso.parent
        report = ReleaseGateReport(project.root, iso, output_dir)
        _check_source_trust(report, project, options)
        _check_vuln_policy(report, project, options)
        _check_iso_and_checksums(report, iso, output_dir, verify_checksums)
        _check_release_files(report, iso, output_dir, options)
        _check_boot_proof(report, iso, output_dir, options)
        _check_release_readiness(report, iso, output_dir, verify_checksums)
        _check_packaging_policy(report, project.root)
        _check_publish_signing(report, project.root, options)
        return report


def _check_source_trust(report: ReleaseGateReport, project: Project, options: BuildOptions) -> None:
    if project.source_iso:
        trust = TrustService().check_source_iso(project.source_iso, options.trust, strict=options.policy.strict)
        if not trust.ok:
            report.items.append(ReleaseGateItem("source-trust", "blocked", trust.render_text().splitlines()[-1]))
            return
        if not options.trust.source_sha256 and not options.trust.require_source_checksum:
            report.items.append(ReleaseGateItem("source-trust", "review", "Source ISO has no SHA256 requirement."))
            return
        report.items.append(ReleaseGateItem("source-trust", "ready", "Source ISO trust checks are configured."))
        return
    if project.source_mode == "bootstrap" or project.source_starter:
        report.items.append(
            ReleaseGateItem(
                "source-trust",
                "review",
                "Bootstrap path is explicit, but repository indexes and downloaded "
                "package bytes are not yet snapshot-bound in the run evidence.",
            )
        )
    else:
        report.items.append(ReleaseGateItem("source-trust", "blocked", "No source ISO, starter or bootstrap path."))


def _check_vuln_policy(report: ReleaseGateReport, project: Project, options: BuildOptions) -> None:
    if not options.vuln_scan.enabled:
        report.items.append(ReleaseGateItem("vuln-scan", "review", "CVE scanning is not enabled."))
        return
    packages = DiffPreviewService().preview(project, options).install
    scan = VulnScanService(options.vuln_scan).scan(packages)
    counts = scan.counts
    summary = f"policy={scan.policy} db={scan.database} critical={counts['critical']} high={counts['high']}"
    if not scan.ok:
        report.items.append(ReleaseGateItem("vuln-scan", "blocked", f"CVE policy violated: {summary}"))
    elif scan.findings:
        report.items.append(ReleaseGateItem("vuln-scan", "review", f"Known advisories present (non-blocking): {summary}"))
    else:
        report.items.append(ReleaseGateItem("vuln-scan", "ready", f"No known advisories matched: {summary}"))


def _check_iso_and_checksums(
    report: ReleaseGateReport, iso: Path, output_dir: Path, verify_checksums: bool = True
) -> None:
    if not iso.exists():
        report.items.append(ReleaseGateItem("iso", "blocked", "Final ISO is missing."))
        report.items.append(ReleaseGateItem("sha256", "blocked", "Cannot verify SHA256 without an ISO."))
        return
    report.items.append(ReleaseGateItem("iso", "ready", f"{iso.stat().st_size} bytes"))
    sums = output_dir / "SHA256SUMS"
    if not sums.exists():
        report.items.append(ReleaseGateItem("sha256", "blocked", "SHA256SUMS is missing."))
        return
    expected = sha256_from_sums(sums, iso.name)
    if not verify_checksums:
        # Status-only pass: SHA256SUMS must cover the ISO, but the bytes are not
        # re-read. Whoever needs the verdict itself asks with the default.
        if expected is None:
            report.items.append(ReleaseGateItem("sha256", "blocked", "SHA256SUMS does not list the ISO."))
            return
        report.items.append(ReleaseGateItem("sha256", "ready", expected))
        return
    actual = sha256_file(iso)
    if expected != actual:
        report.items.append(ReleaseGateItem("sha256", "blocked", "SHA256SUMS does not match the ISO."))
        return
    report.items.append(ReleaseGateItem("sha256", "ready", actual))


def _check_release_files(
    report: ReleaseGateReport,
    iso: Path,
    output_dir: Path,
    options: BuildOptions,
) -> None:
    sbom_format = options.provenance.sbom_format
    sbom_filename = (
        SPDX_FILENAME if sbom_format == "spdx" else CYCLONEDX_FILENAME if sbom_format == "cyclonedx" else None
    )
    for code, filename, enabled in (
        ("buildinfo", "BUILDINFO", options.release_artifacts.enabled),
        ("provenance", "distroforge-provenance.json", options.provenance.enabled),
        ("sbom", sbom_filename, options.provenance.enabled and sbom_filename is not None),
        ("html-report", options.html_report.filename, options.html_report.enabled),
    ):
        if filename is None:
            report.items.append(ReleaseGateItem(code, "review", "Standard-format SBOM export is not enabled."))
            continue
        path = output_dir / filename
        if code == "provenance" and path.exists():
            report.items.append(_validate_build_provenance(path, iso, output_dir))
            continue
        if path.exists():
            if code in {"buildinfo", "sbom", "html-report"} and not _build_manifest_binds(
                output_dir,
                path,
            ):
                report.items.append(
                    ReleaseGateItem(
                        code,
                        "blocked" if enabled else "review",
                        f"{filename} exists but is not bound to the current build run.",
                    )
                )
            else:
                report.items.append(ReleaseGateItem(code, "ready", str(path)))
        elif enabled:
            report.items.append(ReleaseGateItem(code, "blocked", f"Expected release file is missing: {filename}"))
        else:
            report.items.append(ReleaseGateItem(code, "review", f"{filename} is not enabled."))


def _build_manifest_binds(output_dir: Path, artifact: Path) -> bool:
    provenance = output_dir / "distroforge-provenance.json"
    try:
        data = json.loads(provenance.read_text(encoding="utf-8"))
        run_id = data.get("run_id")
        if not isinstance(run_id, str) or Path(run_id).name != run_id:
            return False
        manifest = json.loads(
            (
                output_dir
                / "evidence"
                / "runs"
                / run_id
                / "RUN-MANIFEST.json"
            ).read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError):
        return False
    files = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(files, list) or not artifact.is_file():
        return False
    return any(
        isinstance(item, dict)
        and item.get("path") == str(artifact)
        and item.get("size") == artifact.stat().st_size
        and item.get("sha256") == sha256_file(artifact)
        for item in files
    )


def _validate_build_provenance(
    path: Path,
    iso: Path,
    output_dir: Path,
) -> ReleaseGateItem:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return ReleaseGateItem("provenance", "blocked", f"Provenance is unreadable: {exc}")
    if not isinstance(data, dict) or data.get("schema") != "distroforge.provenance.v2":
        return ReleaseGateItem("provenance", "blocked", "Provenance schema is absent or unsupported.")
    if data.get("attestation_kind") != "build":
        return ReleaseGateItem("provenance", "blocked", "Reconstructed provenance is not build evidence.")
    if not iso.is_file() or data.get("output_iso_sha256") != sha256_file(iso):
        return ReleaseGateItem("provenance", "blocked", "Provenance belongs to different ISO bytes.")
    run_id = data.get("run_id")
    run = data.get("run")
    if (
        not isinstance(run_id, str)
        or not run_id
        or not isinstance(run, dict)
        or run.get("run_id") != run_id
        or run.get("mode") != "execute"
    ):
        return ReleaseGateItem("provenance", "blocked", "Provenance run identity is incomplete.")
    builder = run.get("builder_source")
    definition = run.get("definition")
    toolchain = run.get("toolchain")
    observed_toolchain = data.get("observed_toolchain")
    command_records = data.get("command_records")
    executed_entrypoints = data.get("executed_host_entrypoints")
    if (
        not isinstance(builder, dict)
        or not (builder.get("worktree_sha256") or builder.get("source_tree_sha256"))
        or not isinstance(definition, dict)
        or not definition.get("effective_sha256")
        or not isinstance(toolchain, dict)
        or not isinstance(observed_toolchain, dict)
        or not isinstance(observed_toolchain.get("command_count"), int)
        or int(observed_toolchain["command_count"]) < 1
        or not isinstance(observed_toolchain.get("tools"), dict)
        or not observed_toolchain["tools"]
        or observed_toolchain.get("resolution_scope")
        != "post-run-path-snapshot"
        or not isinstance(command_records, list)
        or not command_records
        or not isinstance(executed_entrypoints, list)
        or not executed_entrypoints
    ):
        return ReleaseGateItem(
            "provenance",
            "blocked",
            "Provenance lacks source, definition or observed toolchain identity.",
        )
    if data.get("commands_sha256") != canonical_sha256(command_records):
        return ReleaseGateItem(
            "provenance",
            "blocked",
            "Provenance command-record digest does not match its command records.",
        )
    command_argv: list[tuple[str, ...]] = []
    for record in command_records:
        if not isinstance(record, dict):
            return ReleaseGateItem(
                "provenance",
                "blocked",
                "Provenance contains an invalid command record.",
            )
        argv = record.get("argv")
        if (
            not isinstance(argv, list)
            or not argv
            or not all(isinstance(token, str) and token for token in argv)
            or not isinstance(record.get("has_stdin"), bool)
            or not isinstance(record.get("env_keys"), list)
            or not all(
                isinstance(key, str) for key in record.get("env_keys", [])
            )
            or not _is_sha256(record.get("env_sha256"))
        ):
            return ReleaseGateItem(
                "provenance",
                "blocked",
                "Provenance contains a command record without a valid argv.",
            )
        command_argv.append(tuple(argv))
    expected_counts = observed_executable_counts(command_argv)
    observed_tools = observed_toolchain["tools"]
    if (
        observed_toolchain["command_count"] != len(command_records)
        or set(observed_tools) != set(expected_counts)
        or any(
            not isinstance(observed_tools[name], dict)
            or observed_tools[name].get("observed_count") != count
            for name, count in expected_counts.items()
        )
    ):
        return ReleaseGateItem(
            "provenance",
            "blocked",
            "Observed toolchain does not match the recorded command history.",
        )
    observed_leafs = {Path(name).name for name in expected_counts}
    required_tools = {"mksquashfs", "xorriso"}
    project_data = data.get("project")
    bootstrap_build = isinstance(project_data, dict) and (
        project_data.get("source_mode") == "bootstrap"
        or project_data.get("source_starter")
    )
    if bootstrap_build:
        required_tools.update({"grub-mkimage", "mformat", "mcopy"})
        if not observed_leafs & {"mmdebstrap", "debootstrap"}:
            return ReleaseGateItem(
                "provenance",
                "blocked",
                "Bootstrap build provenance has no observed mmdebstrap/debootstrap command.",
            )
    missing_tools = sorted(required_tools - observed_leafs)
    if missing_tools:
        return ReleaseGateItem(
            "provenance",
            "blocked",
            "Build provenance lacks required real tool roles: "
            + ", ".join(missing_tools),
        )
    if data.get("executed_host_entrypoints_sha256") != canonical_sha256(
        executed_entrypoints
    ):
        return ReleaseGateItem(
            "provenance",
            "blocked",
            "Executed host-entrypoint digest does not match its records.",
        )
    expected_real_indices = {
        index
        for index, argv in enumerate(command_argv)
        if Path(argv[0]).name not in VIRTUAL_COMMANDS
    }
    captured_indices: set[int] = set()
    captured_executable_leafs: set[str] = set()
    for entry in executed_entrypoints:
        if not isinstance(entry, dict):
            return ReleaseGateItem(
                "provenance",
                "blocked",
                "Executed host-entrypoint record is malformed.",
            )
        index = entry.get("history_index")
        if (
            not isinstance(index, int)
            or index not in expected_real_indices
            or index in captured_indices
            or entry.get("argv") != list(command_argv[index])
            or entry.get("scope") != "host-entrypoint-pre-dispatch"
            or entry.get("available") is not True
            or entry.get("stable_while_hashed") is not True
            or not isinstance(entry.get("size"), int)
            or int(entry["size"]) <= 0
            or not _is_sha256(entry.get("sha256"))
        ):
            return ReleaseGateItem(
                "provenance",
                "blocked",
                "Executed host-entrypoint record does not bind a real recorded command.",
            )
        chain = entry.get("execution_chain")
        if not isinstance(chain, list) or not chain:
            return ReleaseGateItem(
                "provenance",
                "blocked",
                "Executed command has no wrapper/target-root executable chain.",
            )
        for executable in chain:
            if (
                not isinstance(executable, dict)
                or executable.get("available") is not True
                or executable.get("stable_while_hashed") is not True
                or not _is_sha256(executable.get("sha256"))
                or not isinstance(executable.get("path"), str)
                or not executable.get("path")
            ):
                return ReleaseGateItem(
                    "provenance",
                    "blocked",
                    "Wrapper or target-root executable identity is incomplete.",
                )
            captured_executable_leafs.add(
                Path(str(executable.get("command", ""))).name
            )
        captured_indices.add(index)
    if captured_indices != expected_real_indices:
        return ReleaseGateItem(
            "provenance",
            "blocked",
            "Not every real command has a pre-dispatch executable identity.",
        )
    if bootstrap_build and not captured_executable_leafs & {
        "mmdebstrap",
        "debootstrap",
    }:
        return ReleaseGateItem(
            "provenance",
            "blocked",
            "Bootstrap executable bytes were not captured before dispatch.",
        )
    uncaptured_roles = sorted(required_tools - captured_executable_leafs)
    if uncaptured_roles:
        return ReleaseGateItem(
            "provenance",
            "blocked",
            "Required build executable bytes were not captured before dispatch: "
            + ", ".join(uncaptured_roles),
        )
    immutable_dir = output_dir / "evidence" / "runs" / run_id
    unsafe_symlink = first_symlink_in_confined_tree(output_dir, immutable_dir)
    if unsafe_symlink is not None:
        return ReleaseGateItem(
            "provenance",
            "blocked",
            f"Immutable run contains unsafe symlink: {unsafe_symlink}.",
        )
    immutable = immutable_dir / "distroforge-provenance.json"
    iso_report = immutable_dir / "ISO-BUILD.json"
    manifest = immutable_dir / "RUN-MANIFEST.json"
    manifest_sum = immutable_dir / "RUN-MANIFEST.json.sha256"
    required = (immutable, iso_report, manifest, manifest_sum)
    missing = [item.name for item in required if not item.is_file()]
    if missing:
        return ReleaseGateItem(
            "provenance",
            "blocked",
            f"Immutable run evidence is incomplete: {', '.join(missing)}",
        )
    if sha256_file(immutable) != sha256_file(path):
        return ReleaseGateItem("provenance", "blocked", "Provenance alias differs from immutable evidence.")
    try:
        build = json.loads(iso_report.read_text(encoding="utf-8"))
        run_manifest = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return ReleaseGateItem("provenance", "blocked", f"Run evidence is unreadable: {exc}")
    if (
        not isinstance(build, dict)
        or build.get("schema") != "distroforge.iso-build.v2"
        or build.get("run_id") != run_id
        or build.get("status") != "built"
        or build.get("execute") is not True
        or build.get("output_exists") is not True
        or build.get("output_sha256") != sha256_file(iso)
    ):
        return ReleaseGateItem("provenance", "blocked", "ISO build report does not bind this run and ISO.")
    if (
        not isinstance(run_manifest, dict)
        or run_manifest.get("schema")
        != "distroforge.build-run-manifest.v1"
        or run_manifest.get("run_id") != run_id
        or run_manifest.get("mode") != "execute"
        or run_manifest.get("status") != "built"
    ):
        return ReleaseGateItem("provenance", "blocked", "Run manifest identity does not match provenance.")
    expected_manifest_line = f"{sha256_file(manifest)}  {manifest.name}"
    if manifest_sum.read_text(encoding="utf-8").strip() != expected_manifest_line:
        return ReleaseGateItem("provenance", "blocked", "Run manifest SHA256 sidecar does not match.")
    files = run_manifest.get("files")
    if not isinstance(files, list):
        return ReleaseGateItem("provenance", "blocked", "Run manifest has no file identities.")
    recorded: dict[str, str] = {}
    for item in files:
        if not isinstance(item, dict):
            return ReleaseGateItem("provenance", "blocked", "Run manifest contains an invalid file entry.")
        artifact_path = Path(str(item.get("path", "")))
        artifact_key = str(artifact_path)
        if not artifact_key or artifact_key in recorded:
            return ReleaseGateItem(
                "provenance",
                "blocked",
                "Run manifest contains an empty or duplicate artifact path.",
            )
        if (
            artifact_path.is_symlink()
            or
            not artifact_path.is_file()
            or item.get("size") != artifact_path.stat().st_size
            or item.get("sha256") != sha256_file(artifact_path)
        ):
            return ReleaseGateItem(
                "provenance",
                "blocked",
                f"Run artifact changed or disappeared: {artifact_path}",
            )
        recorded[artifact_key] = str(item.get("sha256"))
    unrecorded_run_files = [
        path
        for path in immutable_dir.rglob("*")
        if path.is_file()
        and path not in {manifest, manifest_sum}
        and str(path) not in recorded
    ]
    if unrecorded_run_files:
        return ReleaseGateItem(
            "provenance",
            "blocked",
            "Immutable run contains unmanifested files: "
            + ", ".join(path.name for path in unrecorded_run_files),
        )
    alias_report = output_dir / "ISO-BUILD.json"
    if (
        not alias_report.is_file()
        or sha256_file(alias_report) != sha256_file(iso_report)
    ):
        return ReleaseGateItem(
            "provenance",
            "blocked",
            "ISO-BUILD.json alias differs from immutable build evidence.",
        )
    for artifact in (
        immutable,
        iso_report,
        iso,
        path,
        output_dir / "SHA256SUMS",
        output_dir / "BUILDINFO",
    ):
        if not artifact.is_file():
            return ReleaseGateItem(
                "provenance",
                "blocked",
                f"Required build artifact is missing: {artifact.name}.",
            )
        if recorded.get(str(artifact)) != sha256_file(artifact):
            return ReleaseGateItem(
                "provenance",
                "blocked",
                f"Run manifest does not bind {artifact.name}.",
            )
    command_log_error = _command_log_error(
        immutable_dir / "commands.jsonl",
        command_records,
    )
    if command_log_error:
        return ReleaseGateItem(
            "provenance",
            "blocked",
            command_log_error,
        )
    return ReleaseGateItem(
        "provenance",
        "ready",
        f"immutable build run {run_id} matches ISO SHA256 {sha256_file(iso)}",
    )


def _is_sha256(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _command_log_error(
    path: Path,
    command_records: list[object],
) -> str | None:
    try:
        events = [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except (OSError, json.JSONDecodeError) as exc:
        return f"Command log is unreadable: {exc}"
    starts = [
        event
        for event in events
        if isinstance(event, dict) and event.get("event") == "start"
    ]
    if len(starts) < len(command_records):
        return "Command log has fewer start events than provenance command records."
    keys = (
        "argv",
        "cwd",
        "needs_root",
        "description",
        "has_stdin",
        "env_keys",
        "env_sha256",
    )
    for index, record in enumerate(command_records):
        if not isinstance(record, dict) or any(
            starts[index].get(key) != record.get(key) for key in keys
        ):
            return f"Command log diverges from provenance at command index {index}."
    return None


def _check_boot_proof(
    report: ReleaseGateReport,
    iso: Path,
    output_dir: Path,
    options: BuildOptions,
) -> None:
    qemu_report = output_dir / options.prebuild_vm.report_name
    proof = output_dir / "boot-proof.json"
    if proof.exists():
        report.items.append(_validate_boot_proof(proof, iso))
    elif qemu_report.exists():
        validation = validate_qemu_report(qemu_report, iso)
        binding_error = (
            _qemu_run_binding_error(
                output_dir,
                iso,
                qemu_report.name,
                validation.payload,
            )
            if validation.ok
            else None
        )
        report.items.append(
            ReleaseGateItem(
                "boot-proof",
                "ready" if validation.ok and binding_error is None else "blocked",
                binding_error or validation.detail,
            )
        )
    elif options.prebuild_vm.enabled or options.bootcheck.enabled or options.qa.scenarios:
        report.items.append(ReleaseGateItem("boot-proof", "blocked", "Boot proof is configured but no executed proof report exists."))
    else:
        report.items.append(ReleaseGateItem("boot-proof", "blocked", "No QEMU, bootcheck or QA proof configured."))


def _qemu_run_binding_error(
    output_dir: Path,
    iso: Path,
    report_name: str,
    payload: dict[str, object] | None,
) -> str | None:
    if not isinstance(payload, dict):
        return "QEMU report payload is missing."
    run_id = payload.get("run_id")
    if not isinstance(run_id, str) or Path(run_id).name != run_id:
        return "QEMU report has no safe run identity."
    run_dir = output_dir / "evidence" / "runs" / run_id
    unsafe_symlink = first_symlink_in_confined_tree(output_dir, run_dir)
    if unsafe_symlink is not None:
        return f"QEMU run contains unsafe symlink: {unsafe_symlink}."
    manifest_path = run_dir / "RUN-MANIFEST.json"
    sidecar = run_dir / "RUN-MANIFEST.json.sha256"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        sidecar_text = sidecar.read_text(encoding="utf-8").strip()
    except (OSError, json.JSONDecodeError) as exc:
        return f"QEMU run manifest is missing or unreadable: {exc}"
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema")
        not in {
            "distroforge.build-run-manifest.v1",
            "distroforge.boot-proof-run-manifest.v1",
            "distroforge.qemu-run-manifest.v1",
        }
        or manifest.get("run_id") != run_id
        or manifest.get("mode") != "execute"
    ):
        return "QEMU run manifest identity is inconsistent."
    if sidecar_text != f"{sha256_file(manifest_path)}  {manifest_path.name}":
        return "QEMU run manifest sidecar does not match."
    files = manifest.get("files")
    if not isinstance(files, list):
        return "QEMU run manifest has no files."
    recorded: dict[str, str] = {}
    for item in files:
        if not isinstance(item, dict):
            return "QEMU run manifest contains a malformed entry."
        path = Path(str(item.get("path", "")))
        key = str(path)
        if (
            not key
            or key in recorded
            or path.is_symlink()
            or not path.is_file()
            or item.get("size") != path.stat().st_size
            or item.get("sha256") != sha256_file(path)
        ):
            return f"QEMU run artifact changed or disappeared: {path}"
        recorded[key] = str(item.get("sha256"))
    immutable_report = run_dir / report_name
    command_log = run_dir / "commands.jsonl"
    for required in (immutable_report, command_log, iso):
        if not required.is_file() or recorded.get(str(required)) != sha256_file(required):
            return f"QEMU run manifest does not bind {required.name}."
    unrecorded = [
        path
        for path in run_dir.rglob("*")
        if path.is_file()
        and path not in {manifest_path, sidecar}
        and str(path) not in recorded
    ]
    if unrecorded:
        return "QEMU run contains unmanifested files: " + ", ".join(
            path.name for path in unrecorded
        )
    return None


def _validate_boot_proof(path: Path, iso: Path) -> ReleaseGateItem:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return ReleaseGateItem("boot-proof", "blocked", f"Boot proof is unreadable: {exc}")
    if not isinstance(data, dict) or data.get("schema") != "distroforge.boot-proof.v2":
        return ReleaseGateItem("boot-proof", "blocked", "Boot proof schema is absent or unsupported.")
    status = str(data.get("status", "unknown"))
    backend = str(data.get("selected_backend", data.get("backend", "unknown")))
    proof_level = str(data.get("proof_level", "none"))
    if status != "ready":
        return ReleaseGateItem(
            "boot-proof",
            "blocked",
            f"Boot proof report is not ready: {status} via {backend}.",
        )
    if not iso.is_file() or data.get("iso_sha256") != sha256_file(iso):
        return ReleaseGateItem("boot-proof", "blocked", "Boot proof belongs to different ISO bytes.")
    run_id = data.get("run_id")
    if (
        not isinstance(run_id, str)
        or not run_id
        or Path(run_id).name != run_id
    ):
        return ReleaseGateItem("boot-proof", "blocked", "Boot proof has no immutable run_id.")
    immutable_dir = path.parent / "evidence" / "runs" / run_id
    unsafe_symlink = first_symlink_in_confined_tree(path.parent, immutable_dir)
    if unsafe_symlink is not None:
        return ReleaseGateItem(
            "boot-proof",
            "blocked",
            f"Boot run contains unsafe symlink: {unsafe_symlink}.",
        )
    immutable_proof = immutable_dir / "boot-proof.json"
    run_manifest_path = immutable_dir / "RUN-MANIFEST.json"
    run_manifest_sum = immutable_dir / "RUN-MANIFEST.json.sha256"
    for required in (immutable_proof, run_manifest_path, run_manifest_sum):
        if not required.is_file():
            return ReleaseGateItem(
                "boot-proof",
                "blocked",
                f"Immutable boot run evidence is missing: {required.name}.",
            )
    if sha256_file(immutable_proof) != sha256_file(path):
        return ReleaseGateItem(
            "boot-proof",
            "blocked",
            "Boot-proof alias differs from immutable evidence.",
        )
    if data.get("immutable_proof") != immutable_proof.name:
        return ReleaseGateItem(
            "boot-proof",
            "blocked",
            "Boot proof does not identify its immutable report.",
        )
    try:
        run_manifest = json.loads(run_manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return ReleaseGateItem(
            "boot-proof",
            "blocked",
            f"Boot run manifest is unreadable: {exc}",
        )
    if (
        not isinstance(run_manifest, dict)
        or run_manifest.get("schema")
        != "distroforge.boot-proof-run-manifest.v1"
        or run_manifest.get("run_id") != run_id
        or run_manifest.get("mode") != "execute"
        or run_manifest.get("status") != status
    ):
        return ReleaseGateItem(
            "boot-proof",
            "blocked",
            "Boot run manifest identity or status is inconsistent.",
        )
    expected_manifest_line = (
        f"{sha256_file(run_manifest_path)}  {run_manifest_path.name}"
    )
    if run_manifest_sum.read_text(encoding="utf-8").strip() != expected_manifest_line:
        return ReleaseGateItem(
            "boot-proof",
            "blocked",
            "Boot run manifest SHA256 sidecar does not match.",
        )
    files = run_manifest.get("files")
    if not isinstance(files, list):
        return ReleaseGateItem(
            "boot-proof",
            "blocked",
            "Boot run manifest has no file identities.",
        )
    recorded: dict[str, str] = {}
    for item in files:
        if not isinstance(item, dict):
            return ReleaseGateItem(
                "boot-proof",
                "blocked",
                "Boot run manifest contains an invalid file entry.",
            )
        artifact = Path(str(item.get("path", "")))
        artifact_key = str(artifact)
        if (
            not artifact_key
            or artifact_key in recorded
            or artifact.is_symlink()
            or not artifact.is_file()
            or item.get("size") != artifact.stat().st_size
            or item.get("sha256") != sha256_file(artifact)
        ):
            return ReleaseGateItem(
                "boot-proof",
                "blocked",
                f"Boot run artifact changed, disappeared or is duplicated: {artifact}.",
            )
        recorded[artifact_key] = str(item.get("sha256"))
    unrecorded = [
        item
        for item in immutable_dir.rglob("*")
        if item.is_file()
        and item not in {run_manifest_path, run_manifest_sum}
        and str(item) not in recorded
    ]
    if unrecorded:
        return ReleaseGateItem(
            "boot-proof",
            "blocked",
            "Boot run contains unmanifested files: "
            + ", ".join(item.name for item in unrecorded),
        )
    for required in (immutable_proof, iso):
        if recorded.get(str(required)) != sha256_file(required):
            return ReleaseGateItem(
                "boot-proof",
                "blocked",
                f"Boot run manifest does not bind {required.name}.",
            )
    if proof_level != "runtime" or backend != "qemu":
        return ReleaseGateItem(
            "boot-proof",
            "blocked",
            f"{proof_level} proof via {backend} does not satisfy the runtime release gate.",
        )
    qemu_path_value = data.get("qemu_report")
    if (
        not isinstance(qemu_path_value, str)
        or not qemu_path_value
        or Path(qemu_path_value).name != qemu_path_value
    ):
        return ReleaseGateItem("boot-proof", "blocked", "Boot proof does not name its QEMU report.")
    qemu_path = immutable_dir / qemu_path_value
    if not qemu_path.is_file():
        return ReleaseGateItem("boot-proof", "blocked", f"QEMU report is missing: {qemu_path}")
    if data.get("qemu_report_sha256") != sha256_file(qemu_path):
        return ReleaseGateItem("boot-proof", "blocked", "Boot proof does not match its QEMU report SHA256.")
    validation = validate_qemu_report(qemu_path, iso)
    if not validation.ok:
        return ReleaseGateItem("boot-proof", "blocked", validation.detail)
    if validation.payload and validation.payload.get("run_id") != run_id:
        return ReleaseGateItem("boot-proof", "blocked", "Boot proof and QEMU report use different run IDs.")
    command_log = immutable_dir / "commands.jsonl"
    if (
        data.get("command_log") != command_log.name
        or not command_log.is_file()
        or recorded.get(str(command_log)) != sha256_file(command_log)
    ):
        return ReleaseGateItem(
            "boot-proof",
            "blocked",
            "Boot proof has no sealed command log for the QEMU invocation.",
        )
    return ReleaseGateItem("boot-proof", "ready", validation.detail)


def _check_release_readiness(
    report: ReleaseGateReport, iso: Path, output_dir: Path, verify_checksums: bool = True
) -> None:
    readiness = ReleaseReadinessService().check(iso, output_dir, verify_checksum=verify_checksums)
    report.items.append(
        ReleaseGateItem(
            "release-readiness",
            "blocked" if readiness.blocked else "review",
            "Release readiness report is available; review non-blocking evidence items.",
        )
    )


def _check_packaging_policy(report: ReleaseGateReport, root: Path) -> None:
    if not (root / "debian/control").exists():
        report.items.append(ReleaseGateItem("packaging-policy", "review", "No Debian source package metadata in project root."))
        return
    policy = packaging_policy_report(root)
    if policy.blocked:
        report.items.append(ReleaseGateItem("packaging-policy", "blocked", "Packaging policy is blocked."))
        return
    autopkgtest_status = policy.autopkgtest_policy.status if policy.autopkgtest_policy else "undeclared"
    status = "ready" if autopkgtest_status == "declared and meaningful" else "review"
    report.items.append(ReleaseGateItem("packaging-policy", status, f"Autopkgtest: {autopkgtest_status}."))


def _check_publish_signing(report: ReleaseGateReport, root: Path, options: BuildOptions) -> None:
    if not options.release_artifacts.sign:
        return
    bundle = root / "dist" / "publish"
    required = ("RELEASE-MANIFEST.json", "SIGNING-REPORT.json", "SHA256SUMS.asc", "RELEASE-GATE.json.asc", "RELEASE-MANIFEST.json.asc")
    missing = [name for name in required if not (bundle / name).exists()]
    if missing:
        report.items.append(ReleaseGateItem("publish-signing", "review", f"Missing publish signing evidence: {', '.join(missing)}"))
    else:
        report.items.append(ReleaseGateItem("publish-signing", "ready", str(bundle)))



def _boot_proof_summary(path: Path) -> dict[str, str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"status": "invalid", "selected_backend": "unknown", "proof_level": "none"}
    if not isinstance(data, dict):
        return {"status": "invalid", "selected_backend": "unknown", "proof_level": "none"}
    return {
        "status": str(data.get("status", "unknown")),
        "selected_backend": str(data.get("selected_backend", data.get("backend", "unknown"))),
        "proof_level": str(data.get("proof_level", "none")),
    }
