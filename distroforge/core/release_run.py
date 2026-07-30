"""Select one immutable executed build run for release publication.

The top-level ``ISO-BUILD.json`` and ``distroforge-provenance.json`` files are
convenience aliases.  They are deliberately not inputs to this selector: a
release verdict is anchored in ``evidence/runs/<run_id>`` and keeps the selected
files open in the caller's :class:`ArtifactVerificationSession`.
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from .artifact_verification import (
    ArtifactHandle,
    ArtifactLimits,
    ArtifactVerificationError,
    ArtifactVerificationSession,
)
from .evidence_run import is_safe_run_id
from .hashing import parse_sha256_sums
from .project import Project

_RUN_JSON_BYTES = 128 * 1024 * 1024
_RUN_SIDECAR_BYTES = 4096
_DISCOVERY_LIMITS = ArtifactLimits(
    max_open_files=32,
    max_file_bytes=64 * 1024 * 1024 * 1024,
    max_buffered_bytes=512 * 1024 * 1024,
    max_hashed_bytes=256 * 1024 * 1024 * 1024,
    max_json_depth=256,
    max_json_nodes=2_000_000,
    max_path_components=256,
    max_closing_fds=256,
    max_inventory_entries=100_000,
)


@dataclass(frozen=True)
class ExecutedReleaseRun:
    """Descriptor-bound immutable inputs selected for one release verdict."""

    run_id: str
    run_dir: Path
    iso_build_path: Path
    provenance_path: Path
    manifest_path: Path
    manifest_sidecar_path: Path
    iso_handle: ArtifactHandle
    iso_build: ArtifactHandle
    provenance: ArtifactHandle
    manifest: ArtifactHandle
    manifest_sidecar: ArtifactHandle
    iso_build_payload: dict[str, object]
    provenance_payload: dict[str, object]
    manifest_payload: dict[str, object]


def select_executed_release_run(
    project: Project,
    iso: Path,
    output_dir: Path,
    session: ArtifactVerificationSession,
    *,
    build_run_id: str | None = None,
    verify_iso: bool = True,
) -> ExecutedReleaseRun:
    """Select and bind exactly one immutable executed run.

    An explicit ``build_run_id`` addresses a single run and is still checked
    against the exact project and ISO bytes.  Without it, discovery accepts only
    one matching immutable run and fails closed on ambiguity.

    ``verify_iso=False`` is reserved for non-authoritative status views: it
    binds the candidate to the strict product ``SHA256SUMS`` entry without
    re-reading a multi-gigabyte ISO.  Publication keeps the verifying default.
    """

    absolute_iso = Path(os.path.abspath(iso))
    absolute_output = Path(os.path.abspath(output_dir))
    release_iso = session.file_path(
        absolute_iso,
        label="selected release ISO",
        max_bytes=session.limits.max_file_bytes,
    )
    if verify_iso:
        expected_iso_digest = release_iso.digest()
    else:
        product_sums = session.file_path(
            absolute_output / "SHA256SUMS",
            label="selected release SHA256SUMS",
            max_bytes=_RUN_SIDECAR_BYTES,
        )
        product_entries = parse_sha256_sums(product_sums.read_bytes())
        sidecar_digest = product_entries.get(absolute_iso.name)
        if sidecar_digest is None:
            raise ArtifactVerificationError(
                "SHA256SUMS does not bind selected release ISO "
                f"{absolute_iso.name}"
            )
        expected_iso_digest = sidecar_digest
    expected_iso_size = release_iso.identity.size
    if build_run_id is not None:
        if not is_safe_run_id(build_run_id):
            raise ArtifactVerificationError(
                "build run id is unsafe; pass the exact canonical run id"
            )
        return _bind_candidate(
            project,
            absolute_iso,
            absolute_output,
            build_run_id,
            session,
            expected_iso_digest=expected_iso_digest,
            expected_iso_size=expected_iso_size,
        )

    candidate_names = _discover_candidate_names(absolute_output)
    matching: list[str] = []
    rejected: list[str] = []
    for candidate in candidate_names:
        candidate_session: ArtifactVerificationSession | None = None
        try:
            candidate_session = ArtifactVerificationSession(
                Path("/"),
                label=f"release run discovery {candidate}",
                limits=_DISCOVERY_LIMITS,
            )
            _bind_candidate(
                project,
                absolute_iso,
                absolute_output,
                candidate,
                candidate_session,
                expected_iso_digest=expected_iso_digest,
                expected_iso_size=expected_iso_size,
            )
            candidate_session.seal()
        except (ArtifactVerificationError, OSError, UnicodeError, ValueError) as exc:
            rejected.append(f"{candidate}: {exc}")
        else:
            matching.append(candidate)
        finally:
            if candidate_session is not None:
                candidate_session.close()

    if not matching:
        suffix = ""
        if rejected:
            suffix = " Rejected candidates: " + "; ".join(rejected[:8])
        raise ArtifactVerificationError(
            "no immutable executed build run matches this project and ISO; "
            "pass --build-run-id RUN_ID after auditing evidence/runs."
            + suffix
        )
    if len(matching) != 1:
        raise ArtifactVerificationError(
            "multiple immutable executed build runs match this project and ISO "
            f"({', '.join(sorted(matching))}); pass --build-run-id RUN_ID "
            "to select one explicitly."
        )
    return _bind_candidate(
        project,
        absolute_iso,
        absolute_output,
        matching[0],
        session,
        expected_iso_digest=expected_iso_digest,
        expected_iso_size=expected_iso_size,
    )

def _discover_candidate_names(output_dir: Path) -> tuple[str, ...]:
    runs_root = output_dir / "evidence" / "runs"
    try:
        with ArtifactVerificationSession(
            Path("/"),
            label="release run directory discovery",
            limits=_DISCOVERY_LIMITS,
        ) as session:
            inventory = session.tree_inventory_path(
                runs_root,
                label="immutable release runs",
            )
            names = {
                name
                for name, identity in inventory.entries
                if "/" not in name
                and stat.S_ISDIR(identity.mode)
                and is_safe_run_id(name)
            }
    except (ArtifactVerificationError, OSError, ValueError) as exc:
        raise ArtifactVerificationError(
            "immutable release run discovery refused an unsafe symlink, "
            f"special file, or unstable directory: {exc}"
        ) from exc
    return tuple(sorted(names))


def _bind_candidate(
    project: Project,
    iso: Path,
    output_dir: Path,
    run_id: str,
    session: ArtifactVerificationSession,
    *,
    expected_iso_digest: str,
    expected_iso_size: int,
) -> ExecutedReleaseRun:
    if not is_safe_run_id(run_id):
        raise ArtifactVerificationError(f"immutable build run id is unsafe: {run_id!r}")
    run_dir = output_dir / "evidence" / "runs" / run_id
    iso_build_path = run_dir / "ISO-BUILD.json"
    provenance_path = run_dir / "distroforge-provenance.json"
    manifest_path = run_dir / "RUN-MANIFEST.json"
    manifest_sidecar_path = run_dir / "RUN-MANIFEST.json.sha256"

    iso_handle = session.file_path(
        iso,
        label="selected release ISO",
        max_bytes=session.limits.max_file_bytes,
    )
    iso_build = session.file_path(
        iso_build_path,
        label=f"immutable ISO-BUILD for {run_id}",
        max_bytes=_RUN_JSON_BYTES,
    )
    provenance = session.file_path(
        provenance_path,
        label=f"immutable provenance for {run_id}",
        max_bytes=_RUN_JSON_BYTES,
    )
    manifest = session.file_path(
        manifest_path,
        label=f"immutable run manifest for {run_id}",
        max_bytes=_RUN_JSON_BYTES,
    )
    manifest_sidecar = session.file_path(
        manifest_sidecar_path,
        label=f"immutable run manifest sidecar for {run_id}",
        max_bytes=_RUN_SIDECAR_BYTES,
    )

    build_payload = iso_build.json_object()
    provenance_payload = provenance.json_object()
    manifest_payload = manifest.json_object()
    declared_iso_digest = build_payload.get("output_sha256")
    if (
        not isinstance(declared_iso_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", declared_iso_digest) is None
    ):
        raise ArtifactVerificationError(
            f"immutable ISO-BUILD for {run_id} has no canonical ISO SHA-256"
        )
    if (
        build_payload.get("schema") != "distroforge.iso-build.v2"
        or build_payload.get("run_id") != run_id
        or build_payload.get("project") != str(project.root)
        or build_payload.get("status") != "built"
        or build_payload.get("execute") is not True
        or build_payload.get("output_iso") != str(iso)
        or build_payload.get("output_exists") is not True
        or build_payload.get("output_size") != expected_iso_size
        or build_payload.get("output_sha256") != expected_iso_digest
    ):
        raise ArtifactVerificationError(
            f"immutable ISO-BUILD for {run_id} does not bind the exact "
            "project, executed status, output path, size, and SHA-256"
        )
    provenance_run = provenance_payload.get("run")
    if (
        provenance_payload.get("schema") != "distroforge.provenance.v2"
        or provenance_payload.get("attestation_kind") != "build"
        or provenance_payload.get("run_id") != run_id
        or provenance_payload.get("output_iso") != str(iso)
        or provenance_payload.get("output_iso_sha256") != expected_iso_digest
        or not isinstance(provenance_run, dict)
        or provenance_run.get("run_id") != run_id
        or provenance_run.get("mode") != "execute"
    ):
        raise ArtifactVerificationError(
            f"immutable provenance for {run_id} does not bind the exact "
            "executed run and ISO"
        )
    if (
        manifest_payload.get("schema")
        != "distroforge.build-run-manifest.v1"
        or manifest_payload.get("run_id") != run_id
        or manifest_payload.get("mode") != "execute"
        or manifest_payload.get("status") != "built"
    ):
        raise ArtifactVerificationError(
            f"immutable run manifest for {run_id} has the wrong identity"
        )
    sidecar_entries = parse_sha256_sums(manifest_sidecar.read_bytes())
    if sidecar_entries != {"RUN-MANIFEST.json": manifest.digest()}:
        raise ArtifactVerificationError(
            f"immutable run manifest sidecar for {run_id} is not exact"
        )
    _require_manifest_bindings(
        manifest_payload,
        (
            (iso_build_path, iso_build),
            (provenance_path, provenance),
            (iso, iso_handle),
        ),
        run_id=run_id,
        digest_overrides={str(iso): expected_iso_digest},
    )
    return ExecutedReleaseRun(
        run_id=run_id,
        run_dir=run_dir,
        iso_build_path=iso_build_path,
        provenance_path=provenance_path,
        manifest_path=manifest_path,
        manifest_sidecar_path=manifest_sidecar_path,
        iso_handle=iso_handle,
        iso_build=iso_build,
        provenance=provenance,
        manifest=manifest,
        manifest_sidecar=manifest_sidecar,
        iso_build_payload=build_payload,
        provenance_payload=provenance_payload,
        manifest_payload=manifest_payload,
    )


def embedded_boot_run_id(selected: ExecutedReleaseRun) -> str | None:
    """Return the exact boot run embedded by one verified immutable build.

    ``None`` means that the build deliberately carries no boot proof.  Any
    other malformed value is a causal contract violation rather than an
    invitation to discover a convenient global alias.
    """

    embedded = selected.iso_build_payload.get("boot_proof")
    if embedded is None:
        return None
    if not isinstance(embedded, dict):
        raise ArtifactVerificationError(
            f"immutable ISO-BUILD for {selected.run_id} has a malformed boot proof"
        )
    candidate = embedded.get("run_id")
    if not is_safe_run_id(candidate):
        raise ArtifactVerificationError(
            f"immutable ISO-BUILD for {selected.run_id} embeds no safe boot run id"
        )
    assert isinstance(candidate, str)
    return candidate


def _require_manifest_bindings(
    manifest: dict[str, object],
    required: tuple[tuple[Path, ArtifactHandle], ...],
    *,
    run_id: str,
    digest_overrides: dict[str, str],
) -> None:
    files = manifest.get("files")
    if not isinstance(files, list):
        raise ArtifactVerificationError(
            f"immutable run manifest for {run_id} has no file identities"
        )
    recorded: dict[str, tuple[object, object]] = {}
    for item in files:
        if not isinstance(item, dict):
            raise ArtifactVerificationError(
                f"immutable run manifest for {run_id} has a malformed entry"
            )
        path = item.get("path")
        if not isinstance(path, str) or not path or path in recorded:
            raise ArtifactVerificationError(
                f"immutable run manifest for {run_id} has an empty or "
                "duplicate path"
            )
        recorded[path] = (item.get("size"), item.get("sha256"))
    for path, handle in required:
        expected_digest = digest_overrides.get(str(path))
        if expected_digest is None:
            expected_digest = handle.digest()
        expected = (handle.identity.size, expected_digest)
        if recorded.get(str(path)) != expected:
            raise ArtifactVerificationError(
                f"immutable run manifest for {run_id} does not bind {path.name}"
            )


__all__ = [
    "ExecutedReleaseRun",
    "embedded_boot_run_id",
    "select_executed_release_run",
]
