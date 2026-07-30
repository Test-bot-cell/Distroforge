from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from .artifact_paths import default_artifact_paths
from .artifact_verification import (
    ArtifactIdentity,
    ArtifactLimits,
    ArtifactTreeInventory,
    ArtifactVerificationError,
    ArtifactVerificationSession,
)
from .build import BuildOptions
from .evidence_run import (
    StableParentIdentity,
    cleanup_owned_tree,
    copy_immutable_file,
    copy_immutable_tree,
    ensure_directory_nofollow,
    entry_exists_nofollow,
    full_filesystem_identity,
    is_safe_run_id,
    owned_temporary_directory,
    publish_immutable_tree,
    stable_identity_from_full,
    write_immutable_text,
)
from .project import Project
from .release_gate import ReleaseGateReport, ReleaseGateService

_PUBLISH_JSON_BYTES = 16 * 1024 * 1024
_PUBLISH_JSON_LIMITS = ArtifactLimits(
    max_open_files=8,
    max_file_bytes=_PUBLISH_JSON_BYTES,
    max_buffered_bytes=3 * _PUBLISH_JSON_BYTES,
    max_hashed_bytes=6 * _PUBLISH_JSON_BYTES,
    max_json_nodes=250_000,
    max_closing_fds=64,
)


@dataclass(frozen=True)
class PublishBundleReport:
    project: Path
    bundle_dir: Path
    status: str
    copied: tuple[str, ...]
    missing: tuple[str, ...]
    publication_identity: StableParentIdentity | None
    gate: ReleaseGateReport

    @property
    def blocked(self) -> bool:
        return self.status == "blocked"

    @property
    def published(self) -> bool:
        return self.publication_identity is not None

    def to_dict(self) -> dict[str, object]:
        return {
            "project": str(self.project),
            "bundle_dir": str(self.bundle_dir),
            "status": self.status,
            "blocked": self.blocked,
            "copied": list(self.copied),
            "missing": list(self.missing),
            "published": self.published,
            "publication_identity": (
                list(self.publication_identity) if self.publication_identity is not None else None
            ),
            "gate": self.gate.to_dict(),
        }

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def render_text(self) -> str:
        lines = [
            "Maintainer publish bundle",
            f"Project: {self.project}",
            f"Bundle: {self.bundle_dir}",
            f"Status: {self.status.upper()}",
            "",
            "Copied:",
            *[f"- {item}" for item in self.copied],
            "",
            "Missing:",
            *([f"- {item}" for item in self.missing] or ["- none"]),
            "",
            "Release gate:",
        ]
        lines.extend(f"- [{item.status}] {item.code}: {item.detail}" for item in self.gate.items)
        return "\n".join(lines)


def create_publish_bundle(
    project: Project,
    options: BuildOptions | None = None,
    *,
    iso: Path | None = None,
    output_dir: Path | None = None,
    bundle_dir: Path | None = None,
    build_run_id: str | None = None,
    boot_run_id: str | None = None,
) -> PublishBundleReport:
    options = options or BuildOptions()
    paths = default_artifact_paths(project)
    iso = Path(os.path.abspath(iso or options.output_iso or paths.output_iso))
    output_dir = Path(os.path.abspath(output_dir or iso.parent))
    bundle_dir = Path(os.path.abspath(bundle_dir or project.output_dir / "publish"))
    gate = ReleaseGateService().check(
        project,
        options,
        iso=iso,
        output_dir=output_dir,
        bundle_dir=bundle_dir,
        capture_artifact_receipt=True,
        build_run_id=build_run_id,
        boot_run_id=boot_run_id,
    )
    try:
        bundle_parent_identity = ensure_directory_nofollow(bundle_dir.parent)
        bundle_exists = entry_exists_nofollow(
            bundle_dir,
            expected_parent_identity=bundle_parent_identity,
        )
    except (OSError, ValueError) as exc:
        return PublishBundleReport(
            project.root,
            bundle_dir,
            "blocked",
            (),
            (f"bundle parent/path could not be anchored safely: {exc}",),
            None,
            gate,
        )
    if bundle_exists:
        return PublishBundleReport(
            project.root,
            bundle_dir,
            "blocked",
            (),
            (
                "bundle directory is not empty or is already reserved; use a fresh "
                "path so release evidence cannot mix across runs",
            ),
            None,
            gate,
        )
    copied: list[str] = []
    expected_digests: dict[str, str] = {}
    missing: list[str] = []
    gate_file_identities, identity_problems = _gate_bundle_file_identities(
        gate,
        iso=iso,
        output_dir=output_dir,
    )
    missing.extend(identity_problems)
    publication_identity: StableParentIdentity | None = None
    try:
        temporary = owned_temporary_directory(
            prefix=f".{bundle_dir.name}.staging-",
            directory=bundle_dir.parent,
            mode=0o755,
            expected_parent_identity=bundle_parent_identity,
        )
    except (OSError, ValueError) as exc:
        return PublishBundleReport(
            project.root,
            bundle_dir,
            "blocked",
            (),
            (f"bundle staging reservation failed closed: {exc}",),
            None,
            gate,
        )
    staging = temporary.path
    staging_identity: StableParentIdentity | None = temporary.identity
    staging_fd = -1
    publication_succeeded = False
    try:
        staging_fd = os.open(
            staging,
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        held_staging_identity = _held_directory_identity(staging_fd)
        if held_staging_identity != staging_identity:
            raise ValueError("staging directory changed before mode hardening")
        os.fchmod(staging_fd, 0o755)
        _copy_immutable_runs(
            output_dir,
            staging,
            staging_fd,
            gate,
            copied,
            expected_digests,
            missing,
        )
        selected_boot_sources = _gate_selected_boot_sources(
            gate,
        )
        if not selected_boot_sources and (
            options.prebuild_vm.enabled or options.bootcheck.enabled or options.qa.scenarios
        ):
            missing.append(options.prebuild_vm.report_name)
        sources = (
            *_bundle_sources(iso, output_dir, options),
            gate.immutable_provenance
            or output_dir / "evidence" / "runs" / "<unselected>" / "distroforge-provenance.json",
            gate.immutable_iso_build
            or output_dir / "evidence" / "runs" / "<unselected>" / "ISO-BUILD.json",
            *((gate.immutable_sbom,) if gate.immutable_sbom is not None else ()),
            *selected_boot_sources,
        )
        for source in dict.fromkeys(sources):
            try:
                source.lstat()
            except FileNotFoundError:
                missing.append(source.name)
            else:
                _copy_bundle_file(
                    source,
                    staging / source.name,
                    copied,
                    expected_digests,
                    missing,
                    expected_parent_identity=_held_directory_identity(staging_fd),
                    expected_source_identity=gate_file_identities.get(source.name),
                )
        missing.extend(
            _gate_bundle_binding_problems(
                gate,
                iso=iso,
                output_dir=output_dir,
                copied_digests=expected_digests,
            )
        )
        gate_path = staging / "RELEASE-GATE.json"
        _write_bundle_text(
            gate_path,
            gate.render_json() + "\n",
            copied,
            expected_digests,
            missing,
            expected_parent_identity=_held_directory_identity(staging_fd),
        )
        status = "blocked" if gate.blocked or missing else gate.status
        readme_path = staging / "README-PUBLISH.txt"
        _write_bundle_text(
            readme_path,
            _readme(project, status, gate, copied, missing),
            copied,
            expected_digests,
            missing,
            expected_parent_identity=_held_directory_identity(staging_fd),
        )
        assert staging_identity is not None
        current_staging_identity = _held_directory_identity(staging_fd)
        if (
            current_staging_identity[:5] != staging_identity[:5]
            or current_staging_identity[6] != staging_identity[6]
        ):
            missing.append("staging directory identity changed while assembling the bundle")
        if len(copied) != len(expected_digests) or set(copied) != set(expected_digests):
            missing.append("bundle digest receipts do not cover the exact staged file set")
        if missing:
            copied = []
        else:
            try:
                publication = publish_immutable_tree(
                    staging,
                    bundle_dir,
                    expected_files=copied,
                    expected_digests=expected_digests,
                    expected_staging_identity=current_staging_identity,
                )
                publication_identity = publication.target_stable_identity
                publication_succeeded = True
            except (OSError, ValueError) as exc:
                missing.append(f"atomic bundle publication failed: {exc}")
                copied = []
    except (OSError, ValueError) as exc:
        missing.append(f"held bundle staging assembly failed closed: {exc}")
        copied = []
    finally:
        if staging_fd >= 0:
            os.close(staging_fd)
        if not publication_succeeded and staging_identity is not None:
            try:
                detached = cleanup_owned_tree(staging, staging_identity)
            except (OSError, RuntimeError, ValueError) as exc:
                missing.append(f"staging cleanup failed closed: {exc}")
            else:
                if not detached.durably_detached:
                    missing.append(
                        "staging cleanup refused because the owned directory "
                        "was missing or replaced"
                    )
                elif not detached.scrub_complete:
                    missing.append(
                        "staging was durably detached but its bounded scrub "
                        "remains incomplete "
                        f"(residual_entries={detached.residual_entries}, "
                        f"residual_bytes={detached.residual_bytes}, "
                        f"errors={list(detached.errors)})"
                    )
    status = "blocked" if gate.blocked or missing else gate.status
    return PublishBundleReport(
        project.root,
        bundle_dir,
        status,
        tuple(copied),
        tuple(missing),
        publication_identity,
        gate,
    )


def _gate_bundle_binding_problems(
    gate: ReleaseGateReport,
    *,
    iso: Path,
    output_dir: Path,
    copied_digests: dict[str, str],
) -> list[str]:
    """Match every gate-consumed product byte to the immutable copy receipt."""
    receipt = gate.artifact_receipt
    if receipt is None:
        return [
            "release gate has no sealed artifact receipt; bundle publication "
            "cannot bind copied bytes to its verdict"
        ]

    absolute_iso = Path(os.path.abspath(iso))
    absolute_output = Path(os.path.abspath(output_dir))
    problems: list[str] = []
    required: dict[str, tuple[str, int]] = {}
    for item in receipt.files:
        if item.absolute_path == absolute_iso:
            bundle_relative = absolute_iso.name
        elif item.absolute_path == gate.immutable_iso_build:
            bundle_relative = "ISO-BUILD.json"
        elif item.absolute_path == gate.immutable_provenance:
            bundle_relative = "distroforge-provenance.json"
        elif item.absolute_path == gate.immutable_boot_proof:
            bundle_relative = "boot-proof.json"
        elif item.absolute_path == gate.immutable_qemu_report:
            bundle_relative = item.absolute_path.name
        elif item.absolute_path == gate.immutable_sbom:
            bundle_relative = item.absolute_path.name
        else:
            try:
                bundle_relative = item.absolute_path.relative_to(absolute_output).as_posix()
            except ValueError:
                continue
        existing = required.get(bundle_relative)
        binding = (item.sha256, item.identity.size)
        if existing is not None and existing != binding:
            problems.append(
                f"gate-bound bundle path {bundle_relative} has conflicting source receipts"
            )
            continue
        required[bundle_relative] = binding

    for relative, (expected_sha256, expected_size) in sorted(required.items()):
        copied_sha256 = copied_digests.get(relative)
        if copied_sha256 is None:
            problems.append(
                f"gate-bound artifact {relative} ({expected_size} bytes) was not "
                "copied into the bundle"
            )
        elif copied_sha256 != expected_sha256:
            problems.append(
                f"gate-bound artifact {relative} changed after the release verdict "
                f"(expected size={expected_size}, sha256={expected_sha256}; "
                f"copied sha256={copied_sha256})"
            )
    unreceipted_copies = sorted(
        name
        for name in set(copied_digests) - set(required)
        if not name.startswith("evidence/runs/")
    )
    if unreceipted_copies:
        problems.append(
            "bundle source copies are absent from the sealed gate receipt: "
            + ", ".join(unreceipted_copies)
        )

    runs_root = absolute_output / "evidence" / "runs"
    expected_run_files: set[str] = set()
    for tree in receipt.trees:
        if not tree.absolute_path.is_relative_to(runs_root):
            continue
        bundle_prefix = tree.absolute_path.relative_to(absolute_output).as_posix()
        expected_files = {
            f"{bundle_prefix}/{name}"
            for name, identity in tree.inventory.entries
            if stat.S_ISREG(identity.mode)
        }
        expected_run_files.update(expected_files)
        copied_files = {name for name in copied_digests if name.startswith(f"{bundle_prefix}/")}
        if copied_files != expected_files:
            unexpected = sorted(copied_files - expected_files)
            absent = sorted(expected_files - copied_files)
            problems.append(
                f"gate-bound evidence tree {bundle_prefix} differs from its "
                f"sealed inventory (unexpected={unexpected}, missing={absent})"
            )
    copied_run_files = {name for name in copied_digests if name.startswith("evidence/runs/")}
    if copied_run_files != expected_run_files:
        unexpected = sorted(copied_run_files - expected_run_files)
        absent = sorted(expected_run_files - copied_run_files)
        problems.append(
            "copied evidence/runs files differ from the complete sealed gate "
            f"inventory union (unexpected={unexpected}, missing={absent})"
        )
    return problems


def _gate_bundle_file_identities(
    gate: ReleaseGateReport,
    *,
    iso: Path,
    output_dir: Path,
) -> tuple[dict[str, ArtifactIdentity], list[str]]:
    """Project the sealed gate receipt to exact top-level copy identities."""

    receipt = gate.artifact_receipt
    if receipt is None:
        return {}, []
    absolute_iso = Path(os.path.abspath(iso))
    absolute_output = Path(os.path.abspath(output_dir))
    identities: dict[str, ArtifactIdentity] = {}
    problems: list[str] = []
    for item in receipt.files:
        if item.absolute_path == absolute_iso:
            relative = absolute_iso.name
        elif item.absolute_path == gate.immutable_iso_build:
            relative = "ISO-BUILD.json"
        elif item.absolute_path == gate.immutable_provenance:
            relative = "distroforge-provenance.json"
        elif item.absolute_path == gate.immutable_boot_proof:
            relative = "boot-proof.json"
        elif item.absolute_path == gate.immutable_qemu_report:
            relative = item.absolute_path.name
        elif item.absolute_path == gate.immutable_sbom:
            relative = item.absolute_path.name
        else:
            try:
                relative = item.absolute_path.relative_to(absolute_output).as_posix()
            except ValueError:
                continue
        if "/" in relative:
            continue
        existing = identities.get(relative)
        if existing is not None and existing != item.identity:
            problems.append(f"gate-bound bundle path {relative} has conflicting source identities")
            continue
        identities[relative] = item.identity
    return identities, problems


def _gate_selected_boot_sources(
    gate: ReleaseGateReport,
) -> tuple[Path, ...]:
    """Select only immutable boot evidence consumed by the sealed verdict."""

    receipt = gate.artifact_receipt
    if receipt is None:
        return ()
    candidates = tuple(
        candidate
        for candidate in (
            gate.immutable_boot_proof,
            gate.immutable_qemu_report,
        )
        if candidate is not None
    )
    consumed = {item.absolute_path for item in receipt.files}
    return tuple(candidate for candidate in candidates if candidate in consumed)


def _gate_run_identity_sources(
    gate: ReleaseGateReport,
) -> dict[Path, ArtifactIdentity]:
    """Return immutable run reports and their exact sealed gate identities."""

    receipt = gate.artifact_receipt
    if receipt is None:
        return {}
    candidates = tuple(
        candidate
        for candidate in (
            gate.immutable_iso_build,
            gate.immutable_provenance,
            gate.immutable_boot_proof,
            gate.immutable_qemu_report,
        )
        if candidate is not None
    )
    consumed = {item.absolute_path: item.identity for item in receipt.files}
    return {candidate: consumed[candidate] for candidate in candidates if candidate in consumed}


def _bundle_sources(
    iso: Path,
    output_dir: Path,
    options: BuildOptions,
) -> tuple[Path, ...]:
    sources = [
        iso,
        output_dir / "SHA256SUMS",
        output_dir / "BUILDINFO",
    ]
    if options.html_report.enabled:
        sources.append(output_dir / options.html_report.filename)
    return tuple(sources)


def _gate_run_tree_inventories(
    gate: ReleaseGateReport,
    *,
    output_dir: Path,
) -> tuple[dict[Path, ArtifactTreeInventory], list[str]]:
    receipt = gate.artifact_receipt
    if receipt is None:
        return {}, []
    runs_root = Path(os.path.abspath(output_dir)) / "evidence" / "runs"
    inventories: dict[Path, ArtifactTreeInventory] = {}
    problems: list[str] = []
    for tree in receipt.trees:
        if not tree.absolute_path.is_relative_to(runs_root):
            continue
        existing = inventories.get(tree.absolute_path)
        if existing is not None and existing != tree.inventory:
            problems.append(
                "sealed release verdict contains conflicting evidence tree "
                f"inventories for {tree.absolute_path}"
            )
            continue
        inventories[tree.absolute_path] = tree.inventory
    return inventories, problems


def _copy_immutable_runs(
    output_dir: Path,
    bundle_dir: Path,
    staging_fd: int,
    gate: ReleaseGateReport,
    copied: list[str],
    expected_digests: dict[str, str],
    missing: list[str],
) -> None:
    run_ids: set[str] = set()
    if gate.artifact_receipt is None:
        missing.append(
            "publish run identities are not stable bounded JSON because the "
            "sealed gate receipt is unavailable; an unsafe symlink, special "
            "file, or gate mutation may have been refused"
        )
        return
    absolute_output = Path(os.path.abspath(output_dir))
    session: ArtifactVerificationSession | None = None
    try:
        session = ArtifactVerificationSession(
            absolute_output,
            label="publish bundle run identities",
            limits=_PUBLISH_JSON_LIMITS,
        )
        for report, expected_identity in _gate_run_identity_sources(
            gate,
        ).items():
            handle = session.file_path(
                Path(os.path.abspath(report)),
                label=f"publish run identity {report.name}",
                max_bytes=_PUBLISH_JSON_BYTES,
            )
            if handle.identity != expected_identity:
                raise ArtifactVerificationError(
                    f"{report.name} differs from its sealed gate identity"
                )
            data = handle.json_object()
            run_id = data.get("run_id")
            if not is_safe_run_id(run_id):
                raise ArtifactVerificationError(f"{report.name} has no safe run_id")
            assert isinstance(run_id, str)
            run_ids.add(run_id)
        session.seal()
    except (ArtifactVerificationError, OSError, UnicodeError, ValueError) as exc:
        missing.append(
            "publish run identities are not stable bounded JSON; an unsafe "
            f"symlink, special file, or mutation was refused: {exc}"
        )
        return
    finally:
        if session is not None:
            session.close()
    if not run_ids:
        missing.append("evidence/runs/<run_id>")
        return
    expected_trees, tree_contract_problems = _gate_run_tree_inventories(
        gate,
        output_dir=output_dir,
    )
    missing.extend(tree_contract_problems)
    evidence_fd = -1
    runs_fd = -1
    try:
        os.mkdir("evidence", 0o755, dir_fd=staging_fd)
        os.fsync(staging_fd)
        evidence_fd = os.open(
            "evidence",
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=staging_fd,
        )
        os.mkdir("runs", 0o755, dir_fd=evidence_fd)
        os.fsync(evidence_fd)
        runs_fd = os.open(
            "runs",
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=evidence_fd,
        )
        for run_id in sorted(run_ids):
            source = output_dir / "evidence" / "runs" / run_id
            destination = bundle_dir / "evidence" / "runs" / run_id
            expected_tree = expected_trees.get(Path(os.path.abspath(source)))
            if expected_tree is None:
                missing.append(
                    f"evidence/runs/{run_id} has no exact source identity "
                    "inventory in the sealed release verdict"
                )
                continue
            try:
                receipt = copy_immutable_tree(
                    source,
                    destination,
                    expected_parent_identity=_held_directory_identity(runs_fd),
                    expected_source_identity=expected_tree.anchor_identity,
                    expected_source_inventory=dict(expected_tree.entries),
                )
            except (OSError, ValueError) as exc:
                missing.append(
                    f"gate-bound evidence tree evidence/runs/{run_id} differs "
                    "from its sealed source identity inventory; unsafe symlink, "
                    f"special file, or unstable immutable copy refused: {exc}"
                )
                continue
            receipt_digests = dict(receipt.digests)
            if set(receipt.files) != set(receipt_digests):
                missing.append(f"evidence/runs/{run_id} copy receipt has an incomplete digest map")
                continue
            for relative in receipt.files:
                bundle_relative = f"evidence/runs/{run_id}/{relative}"
                _record_bundle_digest(
                    bundle_relative,
                    receipt_digests[relative],
                    copied,
                    expected_digests,
                    missing,
                )
        os.fsync(runs_fd)
        os.fsync(evidence_fd)
        os.fsync(staging_fd)
    except (OSError, ValueError) as exc:
        missing.append(
            "evidence/runs staging parents could not be created through the "
            f"held bundle root: {exc}"
        )
    finally:
        if runs_fd >= 0:
            os.close(runs_fd)
        if evidence_fd >= 0:
            os.close(evidence_fd)


def _copy_bundle_file(
    source: Path,
    destination: Path,
    copied: list[str],
    expected_digests: dict[str, str],
    missing: list[str],
    *,
    expected_parent_identity: StableParentIdentity,
    expected_source_identity: ArtifactIdentity | None,
) -> None:
    relative = destination.name
    if source.is_symlink():
        missing.append(f"{source.name} is an unsafe symlink")
        return
    try:
        receipt = copy_immutable_file(
            source,
            destination,
            expected_parent_identity=expected_parent_identity,
            expected_source_identity=expected_source_identity,
        )
    except FileExistsError:
        missing.append(f"{relative} already exists; refused immutable overwrite")
        return
    except (OSError, ValueError) as exc:
        if (
            expected_source_identity is not None
            and "identity differs from the expected verdict" in str(exc)
        ):
            missing.append(
                f"gate-bound artifact {relative} changed after the release verdict: {exc}"
            )
        else:
            missing.append(f"{relative} immutable copy failed: {exc}")
        return
    _record_bundle_digest(
        relative,
        receipt.sha256,
        copied,
        expected_digests,
        missing,
    )


def _write_bundle_text(
    destination: Path,
    content: str,
    copied: list[str],
    expected_digests: dict[str, str],
    missing: list[str],
    *,
    expected_parent_identity: StableParentIdentity,
) -> None:
    try:
        receipt = write_immutable_text(
            destination,
            content,
            expected_parent_identity=expected_parent_identity,
        )
    except (OSError, ValueError) as exc:
        missing.append(f"{destination.name} immutable publication failed: {exc}")
    else:
        _record_bundle_digest(
            destination.name,
            receipt.sha256,
            copied,
            expected_digests,
            missing,
        )


def _record_bundle_digest(
    relative: str,
    digest: str,
    copied: list[str],
    expected_digests: dict[str, str],
    missing: list[str],
) -> None:
    if relative in expected_digests or relative in copied:
        missing.append(f"{relative} was assembled more than once; refused ambiguous digest receipt")
        return
    expected_digests[relative] = digest
    copied.append(relative)


def _held_directory_identity(descriptor: int) -> StableParentIdentity:
    return stable_identity_from_full(full_filesystem_identity(os.fstat(descriptor)))


def _readme(
    project: Project,
    status: str,
    gate: ReleaseGateReport,
    copied: list[str],
    missing: list[str],
) -> str:
    blocked = [item for item in gate.items if item.status == "blocked"]
    review = [item for item in gate.items if item.status == "review"]
    lines = [
        "DistroForge maintainer publish bundle",
        f"Project: {project.name}",
        f"Status: {status.upper()}",
        "",
        "This directory is an inspection bundle, not a silent publish action.",
        "Do not upload or sign a BLOCKED bundle as a release.",
        "",
        "Included files:",
        *[f"- {name}" for name in copied],
        "",
        "Missing files:",
        *([f"- {name}" for name in missing] or ["- none"]),
    ]
    if blocked:
        lines.extend(
            [
                "",
                "Blocking release gate items:",
                *[f"- {item.code}: {item.detail}" for item in blocked],
            ]
        )
    if review:
        lines.extend(
            [
                "",
                "Review release gate items:",
                *[f"- {item.code}: {item.detail}" for item in review],
            ]
        )
    return "\n".join(lines) + "\n"
