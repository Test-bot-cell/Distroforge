"""Close the identity chain between staged SquashFS bytes and the final ISO."""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import cast

from .artifact_verification import (
    ArtifactHandle,
    ArtifactIdentity,
    ArtifactLimits,
    ArtifactVerificationError,
    ArtifactVerificationSession,
)
from .command import CommandRunner, CommandSpec, sudo
from .evidence_run import (
    cleanup_owned_tree,
    is_safe_run_id,
    owned_temporary_directory,
    write_immutable_text,
)
from .rootfs_evidence import (
    MAX_ROOTFS_MANIFEST_BYTES,
    MAX_ROOTFS_MANIFEST_JSON_NODES,
    MAX_ROOTFS_PACKING_VERIFICATION_BYTES,
    ROOTFS_DESCRIPTOR_WRITE_SCHEMA,
    ROOTFS_PACKING_VERIFICATION_SCHEMA,
    RootfsEvidenceError,
    StableFileWitness,
    load_rootfs_manifest,
    rootfs_capture_command,
    rootfs_unpack_command,
    validate_replayed_rootfs_payloads,
    validate_rootfs_manifest_payload,
)

ISO_ASSEMBLY_SCHEMA = "distroforge.iso-assembly.v1"
ISO_ASSEMBLY_FILENAME = "ISO-ASSEMBLY.json"
MAX_ISO_ASSEMBLY_BYTES = 1024 * 1024
MAX_ISO_ARTIFACT_BYTES = 64 * 1024 * 1024 * 1024


class IsoAssemblyEvidenceError(RuntimeError):
    """The final ISO cannot be bound to its staged SquashFS."""


@dataclass(frozen=True)
class IsoAssemblyEvidenceValidation:
    ok: bool
    detail: str


def iso_extract_member_command(
    witness: StableFileWitness | ArtifactHandle,
    member: str,
    destination: Path,
    *,
    use_sudo: bool = True,
    destination_descriptor: int | None = None,
) -> CommandSpec:
    """Extract one ISO member from a pinned final-ISO descriptor."""
    _validate_iso_member(member)
    if destination_descriptor is None:
        pass_fds = witness.pass_fds
        return CommandSpec(
            argv=sudo(
                (
                    "xorriso",
                    "-osirrox",
                    "on",
                    "-indev",
                    str(witness.proc_fd_path),
                    "-extract",
                    member,
                    str(destination),
                ),
                use_sudo,
                preserve_fds=pass_fds,
            ),
            needs_root=use_sudo,
            description="Extract staged SquashFS from witnessed final ISO",
            pass_fds=pass_fds,
        )
    try:
        destination_identity = os.fstat(destination_descriptor)
    except OSError as exc:
        raise IsoAssemblyEvidenceError(
            f"ISO replay destination descriptor is unavailable: {exc}"
        ) from exc
    if not stat.S_ISREG(destination_identity.st_mode):
        raise IsoAssemblyEvidenceError(
            "ISO replay destination descriptor does not name a regular file"
        )
    if destination_identity.st_size != 0:
        raise IsoAssemblyEvidenceError(
            "ISO replay destination descriptor must name a fresh empty file"
        )
    pass_fds = (*witness.pass_fds, destination_descriptor)
    if len(set(pass_fds)) != len(pass_fds):
        raise IsoAssemblyEvidenceError(
            "ISO input and replay destination descriptors must be distinct"
        )
    return CommandSpec(
        argv=sudo(
            (
                "xorriso",
                "-osirrox",
                "on",
                "-follow",
                "concat",
                "-indev",
                str(witness.proc_fd_path),
                "-concat",
                "overwrite",
                f"/proc/self/fd/{destination_descriptor}",
                member,
            ),
            use_sudo,
            preserve_fds=pass_fds,
        ),
        needs_root=use_sudo,
        description="Extract staged SquashFS into a held replay inode",
        pass_fds=pass_fds,
    )


def iso_extract_member_path_command(
    iso: Path,
    member: str,
    destination: Path,
    *,
    use_sudo: bool = True,
) -> CommandSpec:
    """Dry-run-only shape of :func:`iso_extract_member_command`."""
    _validate_iso_member(member)
    return CommandSpec(
        argv=sudo(
            (
                "xorriso",
                "-osirrox",
                "on",
                "-indev",
                str(iso),
                "-extract",
                member,
                str(destination),
            ),
            use_sudo,
        ),
        needs_root=use_sudo,
        description="Plan extraction of staged SquashFS from final ISO",
    )


def write_iso_assembly_evidence(
    path: Path,
    *,
    run_id: str,
    iso_member: str,
    output_iso: dict[str, object],
    staged_squashfs: dict[str, object],
    embedded_squashfs: dict[str, object],
) -> dict[str, object]:
    """Write an immutable, exact-byte link from packing witness to final ISO."""
    _validate_run_id(run_id)
    _validate_iso_member(iso_member)
    _validate_file_identity(output_iso, "output ISO")
    _validate_file_identity(staged_squashfs, "staged SquashFS")
    _validate_file_identity(embedded_squashfs, "embedded SquashFS")
    matches = staged_squashfs == embedded_squashfs
    payload: dict[str, object] = {
        "schema": ISO_ASSEMBLY_SCHEMA,
        "run_id": run_id,
        "status": "verified" if matches else "mismatch",
        "iso_member": iso_member,
        "output_iso": dict(output_iso),
        "staged_squashfs": dict(staged_squashfs),
        "embedded_squashfs": dict(embedded_squashfs),
        "matches_staged": matches,
    }
    if not matches:
        raise IsoAssemblyEvidenceError(
            "Final ISO embeds SquashFS bytes different from the packing witness"
        )
    write_immutable_text(
        path,
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
    )
    return payload


def validate_iso_assembly_evidence(
    run_dir: Path,
    *,
    expected_run_id: str,
    output_iso_path: Path | None = None,
    staged_squashfs_path: Path | None = None,
    authoritative_replay: bool | None = None,
    replay_runner: CommandRunner | None = None,
    replay_use_sudo: bool = True,
    session: ArtifactVerificationSession | None = None,
) -> IsoAssemblyEvidenceValidation:
    """Validate the packing-witness → staged image → final ISO byte chain.

    The authoritative form independently re-extracts the SquashFS from a pinned
    final-ISO descriptor, unpacks that exact member through another pinned
    descriptor, and compares the resulting tree with ``ROOTFS-MANIFEST.json``.
    ``authoritative_replay=None`` enables that expensive refresh when a final ISO
    is supplied without a staged-tree path.  This makes the publication-provenance
    gate authoritative while avoiding duplicate multi-gigabyte replays in its
    cheaper staged-artifact item.  Callers may explicitly force or suppress it.
    """
    try:
        _validate_run_id(expected_run_id)
    except IsoAssemblyEvidenceError as exc:
        return IsoAssemblyEvidenceValidation(False, str(exc))
    absolute_run_dir = Path(os.path.abspath(run_dir))
    absolute_output_iso = (
        Path(os.path.abspath(output_iso_path)) if output_iso_path is not None else None
    )
    absolute_staged_squashfs = (
        Path(os.path.abspath(staged_squashfs_path)) if staged_squashfs_path is not None else None
    )
    if session is None:
        anchor_candidates = [absolute_run_dir]
        for candidate in (absolute_output_iso, absolute_staged_squashfs):
            if candidate is not None:
                anchor_candidates.append(candidate.parent)
        local_anchor = Path(os.path.commonpath([str(candidate) for candidate in anchor_candidates]))
        try:
            with ArtifactVerificationSession(
                local_anchor,
                label="ISO assembly evidence verification",
            ) as local_session:
                return validate_iso_assembly_evidence(
                    absolute_run_dir,
                    expected_run_id=expected_run_id,
                    output_iso_path=absolute_output_iso,
                    staged_squashfs_path=absolute_staged_squashfs,
                    authoritative_replay=authoritative_replay,
                    replay_runner=replay_runner,
                    replay_use_sudo=replay_use_sudo,
                    session=local_session,
                )
        except ArtifactVerificationError as exc:
            return IsoAssemblyEvidenceValidation(
                False,
                f"ISO assembly evidence is unreadable: {exc}",
            )

    report_path = absolute_run_dir / ISO_ASSEMBLY_FILENAME
    packing_path = absolute_run_dir / "ROOTFS-PACKING-VERIFICATION.json"
    try:
        report = session.file_path(
            report_path,
            label="ISO assembly report",
            max_bytes=MAX_ISO_ASSEMBLY_BYTES,
        ).json_object()
        packing = session.file_path(
            packing_path,
            label="rootfs packing verification",
            max_bytes=MAX_ROOTFS_PACKING_VERIFICATION_BYTES,
        ).json_object()
    except ArtifactVerificationError as exc:
        return IsoAssemblyEvidenceValidation(
            False,
            f"ISO assembly evidence is unreadable: {exc}",
        )
    expected_fields = {
        "schema",
        "run_id",
        "status",
        "iso_member",
        "output_iso",
        "staged_squashfs",
        "embedded_squashfs",
        "matches_staged",
    }
    if (
        set(report) != expected_fields
        or report.get("schema") != ISO_ASSEMBLY_SCHEMA
        or report.get("run_id") != expected_run_id
        or report.get("status") != "verified"
        or report.get("matches_staged") is not True
    ):
        return IsoAssemblyEvidenceValidation(False, "ISO assembly proof is not closed")
    try:
        member = report.get("iso_member")
        if not isinstance(member, str):
            raise IsoAssemblyEvidenceError("ISO member path is malformed")
        _validate_iso_member(member)
        for field, label in (
            ("output_iso", "output ISO"),
            ("staged_squashfs", "staged SquashFS"),
            ("embedded_squashfs", "embedded SquashFS"),
        ):
            identity = report.get(field)
            if not isinstance(identity, dict):
                raise IsoAssemblyEvidenceError(f"{label} identity is malformed")
            _validate_file_identity(cast(dict[str, object], identity), label)
    except IsoAssemblyEvidenceError as exc:
        return IsoAssemblyEvidenceValidation(False, str(exc))
    staged = cast(dict[str, object], report["staged_squashfs"])
    embedded = cast(dict[str, object], report["embedded_squashfs"])
    if staged != embedded:
        return IsoAssemblyEvidenceValidation(
            False,
            "Final ISO SquashFS identity differs from the staged packing witness",
        )
    if (
        packing.get("schema") != ROOTFS_PACKING_VERIFICATION_SCHEMA
        or packing.get("run_id") != expected_run_id
        or packing.get("status") != "verified"
    ):
        return IsoAssemblyEvidenceValidation(
            False,
            "Rootfs packing proof cannot anchor ISO assembly evidence",
        )
    packed_image = packing.get("packed_image")
    witness = packed_image.get("witness") if isinstance(packed_image, dict) else None
    if witness != staged:
        return IsoAssemblyEvidenceValidation(
            False,
            "ISO assembly staged identity differs from the rootfs FD witness",
        )
    replay = (
        output_iso_path is not None and staged_squashfs_path is None
        if authoritative_replay is None
        else authoritative_replay
    )
    if replay and output_iso_path is None:
        return IsoAssemblyEvidenceValidation(
            False,
            "Authoritative ISO assembly replay requires the published ISO path",
        )
    replay_detail: str | None = None
    if absolute_output_iso is not None:
        try:
            output_iso_handle = session.file_path(
                absolute_output_iso,
                label="published ISO",
                max_bytes=MAX_ISO_ARTIFACT_BYTES,
            )
            current_output = _artifact_identity(
                output_iso_handle,
                absolute_output_iso.name,
            )
        except ArtifactVerificationError as exc:
            return IsoAssemblyEvidenceValidation(
                False,
                f"Published ISO identity cannot be verified: {exc}",
            )
        if current_output != report.get("output_iso"):
            return IsoAssemblyEvidenceValidation(
                False,
                "Published ISO bytes differ from the witnessed assembled ISO",
            )
        if replay:
            active_runner = replay_runner or CommandRunner(dry_run=False)
            replay_validation = session.replay_once(
                (
                    "authoritative-iso-product-replay",
                    str(absolute_run_dir),
                    expected_run_id,
                    output_iso_handle.identity,
                    report.get("iso_member"),
                    replay_use_sudo,
                    id(active_runner),
                ),
                lambda: _authoritative_product_replay(
                    absolute_run_dir,
                    expected_run_id=expected_run_id,
                    output_iso_handle=output_iso_handle,
                    report=report,
                    runner=active_runner,
                    use_sudo=replay_use_sudo,
                    session=session,
                ),
            )
            if not replay_validation.ok:
                return replay_validation
            replay_detail = replay_validation.detail
    if absolute_staged_squashfs is not None:
        try:
            staged_handle = session.file_path(
                absolute_staged_squashfs,
                label="staged SquashFS",
                max_bytes=MAX_ISO_ARTIFACT_BYTES,
            )
            current_staged = _artifact_identity(
                staged_handle,
                absolute_staged_squashfs.name,
            )
        except ArtifactVerificationError as exc:
            return IsoAssemblyEvidenceValidation(
                False,
                f"Staged SquashFS identity cannot be verified: {exc}",
            )
        if current_staged != staged:
            return IsoAssemblyEvidenceValidation(
                False,
                "Staged SquashFS bytes differ from the packing FD witness",
            )
    return IsoAssemblyEvidenceValidation(
        True,
        (
            replay_detail
            or f"authoritative final-ISO/SquashFS/rootfs replay closed for run {expected_run_id}"
            if replay
            else f"recorded ISO assembly identities closed for run {expected_run_id}"
        ),
    )


def _authoritative_product_replay(
    run_dir: Path,
    *,
    expected_run_id: str,
    output_iso_handle: ArtifactHandle,
    report: dict[str, object],
    runner: CommandRunner,
    use_sudo: bool,
    session: ArtifactVerificationSession,
) -> IsoAssemblyEvidenceValidation:
    """Replay the actual final product instead of trusting self-consistent JSON."""
    if runner.dry_run:
        return IsoAssemblyEvidenceValidation(
            False,
            "Authoritative ISO assembly replay cannot use a dry-run command runner",
        )
    member = report.get("iso_member")
    output_identity = report.get("output_iso")
    embedded_identity = report.get("embedded_squashfs")
    if (
        not isinstance(member, str)
        or not isinstance(output_identity, dict)
        or not isinstance(embedded_identity, dict)
    ):
        return IsoAssemblyEvidenceValidation(False, "ISO assembly replay inputs are malformed")
    manifest_path = run_dir / "ROOTFS-MANIFEST.json"
    try:
        manifest = load_rootfs_manifest(manifest_path, session=session)
    except RootfsEvidenceError as exc:
        return IsoAssemblyEvidenceValidation(
            False,
            f"Authoritative rootfs replay lacks a valid manifest: {exc}",
        )
    if manifest.get("run_id") != expected_run_id:
        return IsoAssemblyEvidenceValidation(
            False,
            "Authoritative rootfs replay manifest belongs to another run",
        )
    raw_exclusions = manifest.get("excluded_descendants")
    if not isinstance(raw_exclusions, list) or not all(
        isinstance(value, str) for value in raw_exclusions
    ):
        return IsoAssemblyEvidenceValidation(
            False,
            "Authoritative rootfs replay exclusions are malformed",
        )
    exclusions = cast(list[str], raw_exclusions)

    try:
        temporary = owned_temporary_directory(prefix="distroforge-iso-replay-")
    except (OSError, RuntimeError, ValueError) as exc:
        return IsoAssemblyEvidenceValidation(
            False,
            "Authoritative final-product replay workspace reservation failed "
            f"closed: {exc}",
        )
    temporary_root = temporary.path
    artifact_root = temporary_root / "artifacts"
    embedded_path = artifact_root / "filesystem.squashfs"
    replay_root = temporary_root / "rootfs"
    replay_manifest = temporary_root / "ROOTFS-REPLAY.json"
    temporary_fd = -1
    artifact_fd = -1
    embedded_fd = -1
    replay_root_fd = -1
    replay_manifest_fd = -1
    result: IsoAssemblyEvidenceValidation
    try:
        temporary_fd = _open_directory_nofollow(temporary_root)
        artifact_fd = _create_held_directory(
            temporary_fd,
            artifact_root.name,
        )
        embedded_fd = _create_held_regular_file(
            artifact_fd,
            embedded_path.name,
        )
        replay_root_fd = _create_held_directory(
            temporary_fd,
            replay_root.name,
        )
        replay_manifest_fd = _create_held_regular_file(
            temporary_fd,
            replay_manifest.name,
        )
        runner.run(
            iso_extract_member_command(
                output_iso_handle,
                member,
                embedded_path,
                use_sudo=use_sudo,
                destination_descriptor=embedded_fd,
            )
        )
        _assert_held_entry(
            artifact_fd,
            embedded_path.name,
            embedded_fd,
            expected="regular file",
        )
        with ArtifactVerificationSession(
            artifact_root,
            label="authoritative extracted SquashFS verification",
        ) as replay_session:
            squashfs_handle = replay_session.file_path(
                embedded_path,
                label="embedded SquashFS",
                max_bytes=MAX_ISO_ARTIFACT_BYTES,
            )
            if squashfs_handle.identity != ArtifactIdentity.from_stat(
                os.fstat(embedded_fd)
            ):
                raise ArtifactVerificationError(
                    "Extracted SquashFS path differs from its held output inode"
                )
            current_embedded = _artifact_identity(
                squashfs_handle,
                embedded_path.name,
            )
            if current_embedded != embedded_identity:
                result = IsoAssemblyEvidenceValidation(
                    False,
                    "Final ISO member bytes differ from ISO-ASSEMBLY.json",
                )
            else:
                runner.run(
                    rootfs_unpack_command(
                        squashfs_handle,
                        replay_root,
                        use_sudo=use_sudo,
                        destination_descriptor=replay_root_fd,
                    )
                )
                _assert_held_entry(
                    temporary_fd,
                    replay_root.name,
                    replay_root_fd,
                    expected="directory",
                )
                capture_result = runner.run(
                    rootfs_capture_command(
                        replay_root,
                        replay_manifest,
                        run_id=expected_run_id,
                        excluded_descendants=exclusions,
                        use_sudo=use_sudo,
                        root_descriptor=replay_root_fd,
                        manifest_descriptor=replay_manifest_fd,
                    )
                )
                manifest_receipt = _parse_descriptor_write_receipt(
                    capture_result.stdout
                )
                _assert_held_entry(
                    temporary_fd,
                    replay_root.name,
                    replay_root_fd,
                    expected="directory",
                )
                _assert_held_entry(
                    temporary_fd,
                    replay_manifest.name,
                    replay_manifest_fd,
                    expected="regular file",
                )
                with ArtifactVerificationSession(
                    temporary_root,
                    label="authoritative rootfs replay manifest",
                    limits=ArtifactLimits(
                        max_json_nodes=MAX_ROOTFS_MANIFEST_JSON_NODES,
                    ),
                ) as manifest_session:
                    replay_manifest_handle = manifest_session.file_path(
                        replay_manifest,
                        label="authoritative rootfs replay manifest",
                        max_bytes=MAX_ROOTFS_MANIFEST_BYTES,
                    )
                    if (
                        replay_manifest_handle.identity
                        != ArtifactIdentity.from_stat(
                            os.fstat(replay_manifest_fd)
                        )
                    ):
                        raise ArtifactVerificationError(
                            "Rootfs replay manifest path differs from its held "
                            "output inode"
                        )
                    replayed_manifest = validate_rootfs_manifest_payload(
                        replay_manifest_handle.json_object()
                    )
                    if (
                        replay_manifest_handle.identity.size
                        != manifest_receipt["size"]
                        or replay_manifest_handle.digest()
                        != manifest_receipt["sha256"]
                    ):
                        raise ArtifactVerificationError(
                            "Rootfs replay manifest differs from the descriptor "
                            "writer receipt"
                        )
                rootfs_validation = validate_replayed_rootfs_payloads(
                    manifest,
                    replayed_manifest,
                    expected_run_id=expected_run_id,
                )
                result = IsoAssemblyEvidenceValidation(
                    rootfs_validation.ok,
                    rootfs_validation.detail,
                )
    except (OSError, RuntimeError, ValueError) as exc:
        result = IsoAssemblyEvidenceValidation(
            False,
            f"Authoritative final-product replay failed closed: {exc}",
        )
    finally:
        for descriptor in (
            replay_manifest_fd,
            replay_root_fd,
            embedded_fd,
            artifact_fd,
            temporary_fd,
        ):
            if descriptor >= 0:
                os.close(descriptor)

    try:
        cleanup_outcome = cleanup_owned_tree(
            temporary_root,
            temporary.identity,
            scrub=False,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        return IsoAssemblyEvidenceValidation(
            False,
            f"Authoritative final-product replay cleanup failed closed: {exc}",
        )
    if not cleanup_outcome.durably_detached:
        cleanup_errors = "; ".join(cleanup_outcome.errors) or "unspecified detach failure"
        return IsoAssemblyEvidenceValidation(
            False,
            f"{result.detail}; authoritative final-product replay cleanup "
            "could not durably detach the exact workspace; a missing or "
            f"substituted pathname was left untouched: {cleanup_errors}",
        )
    cleanup_note = (
        "authoritative replay workspace was durably detached; detach-only "
        "policy intentionally did not claim a complete scrub and retained "
        f"{cleanup_outcome.residual_entries} entries / "
        f"{cleanup_outcome.residual_bytes} regular-file bytes in quarantine"
    )
    if cleanup_outcome.errors:
        cleanup_note += "; bounded terminal inventory notes: " + "; ".join(
            cleanup_outcome.errors
        )
    return IsoAssemblyEvidenceValidation(
        result.ok,
        f"{result.detail}; {cleanup_note}",
    )


def _artifact_identity(handle: ArtifactHandle, name: str) -> dict[str, object]:
    return {
        "name": name,
        "size": handle.identity.size,
        "sha256": handle.digest(),
    }


def _open_directory_nofollow(path: Path) -> int:
    absolute = Path(os.path.abspath(path))
    descriptor = os.open(
        os.sep,
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        for component in absolute.parts[1:]:
            child = os.open(
                component,
                os.O_RDONLY
                | os.O_CLOEXEC
                | os.O_DIRECTORY
                | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
        result = descriptor
        descriptor = -1
        return result
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _create_held_directory(parent_fd: int, name: str) -> int:
    _validate_replay_leaf(name)
    os.mkdir(name, 0o700, dir_fd=parent_fd)
    os.fsync(parent_fd)
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
        dir_fd=parent_fd,
    )
    try:
        _assert_held_entry(
            parent_fd,
            name,
            descriptor,
            expected="directory",
        )
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _create_held_regular_file(parent_fd: int, name: str) -> int:
    _validate_replay_leaf(name)
    descriptor = os.open(
        name,
        os.O_RDWR
        | os.O_CLOEXEC
        | os.O_CREAT
        | os.O_EXCL
        | os.O_NOFOLLOW
        | os.O_NONBLOCK,
        0o600,
        dir_fd=parent_fd,
    )
    try:
        os.fsync(parent_fd)
        _assert_held_entry(
            parent_fd,
            name,
            descriptor,
            expected="regular file",
        )
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _assert_held_entry(
    parent_fd: int,
    name: str,
    held_fd: int,
    *,
    expected: str,
) -> None:
    _validate_replay_leaf(name)
    held = os.fstat(held_fd)
    current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if expected == "directory":
        expected_type = stat.S_IFDIR
    elif expected == "regular file":
        expected_type = stat.S_IFREG
    else:
        raise ValueError(f"unsupported replay entry type: {expected}")
    if (
        stat.S_IFMT(held.st_mode) != expected_type
        or stat.S_IFMT(current.st_mode) != expected_type
        or _stable_object_identity(held) != _stable_object_identity(current)
    ):
        raise ArtifactVerificationError(
            f"Authoritative replay {expected} path changed after reservation: "
            f"{name}"
        )


def _stable_object_identity(value: os.stat_result) -> tuple[int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        stat.S_IFMT(value.st_mode),
        value.st_rdev,
    )


def _validate_replay_leaf(name: str) -> None:
    if name in {"", ".", ".."} or "/" in name or "\\" in name or "\x00" in name:
        raise ArtifactVerificationError(
            f"Authoritative replay has an unsafe output name: {name!r}"
        )


def _parse_descriptor_write_receipt(value: str) -> dict[str, object]:
    try:
        payload = json.loads(value)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise ArtifactVerificationError(
            f"Rootfs replay descriptor receipt is malformed: {exc}"
        ) from exc
    if not isinstance(payload, dict) or set(payload) != {
        "schema",
        "size",
        "sha256",
    }:
        raise ArtifactVerificationError(
            "Rootfs replay descriptor receipt fields are malformed"
        )
    size = payload.get("size")
    digest = payload.get("sha256")
    if (
        payload.get("schema") != ROOTFS_DESCRIPTOR_WRITE_SCHEMA
        or type(size) is not int
        or size < 0
        or size > MAX_ROOTFS_MANIFEST_BYTES
        or not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise ArtifactVerificationError(
            "Rootfs replay descriptor receipt is invalid"
        )
    return payload


def _validate_file_identity(value: dict[str, object], label: str) -> None:
    if set(value) != {"name", "size", "sha256"}:
        raise IsoAssemblyEvidenceError(f"{label} identity fields are malformed")
    name = value.get("name")
    size = value.get("size")
    digest = value.get("sha256")
    if (
        not isinstance(name, str)
        or not name
        or Path(name).name != name
        or not isinstance(size, int)
        or isinstance(size, bool)
        or size <= 0
        or not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise IsoAssemblyEvidenceError(f"{label} identity is malformed")


def _validate_iso_member(value: str) -> None:
    path = PurePosixPath(value)
    if (
        not value.startswith("/")
        or path.as_posix() != value
        or value == "/"
        or any(part in {"", ".", ".."} for part in path.parts[1:])
        or path.name != "filesystem.squashfs"
    ):
        raise IsoAssemblyEvidenceError(f"Unsafe final ISO SquashFS member: {value!r}")


def _validate_run_id(value: str) -> None:
    if not is_safe_run_id(value):
        raise IsoAssemblyEvidenceError(f"Unsafe ISO assembly run_id: {value!r}")
