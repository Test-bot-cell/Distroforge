"""Close the identity chain between staged SquashFS bytes and the final ISO."""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import cast

from .command import CommandRunner, CommandSpec, sudo
from .evidence_run import write_immutable_text
from .fsops import FileSystemOps
from .rootfs_evidence import (
    ROOTFS_PACKING_VERIFICATION_SCHEMA,
    PackedImageWitness,
    RootfsEvidenceError,
    StableFileWitness,
    load_rootfs_manifest,
    rootfs_capture_command,
    rootfs_unpack_command,
    validate_replayed_rootfs_manifest,
)

ISO_ASSEMBLY_SCHEMA = "distroforge.iso-assembly.v1"
ISO_ASSEMBLY_FILENAME = "ISO-ASSEMBLY.json"


class IsoAssemblyEvidenceError(RuntimeError):
    """The final ISO cannot be bound to its staged SquashFS."""


@dataclass(frozen=True)
class IsoAssemblyEvidenceValidation:
    ok: bool
    detail: str


def iso_extract_member_command(
    witness: StableFileWitness,
    member: str,
    destination: Path,
    *,
    use_sudo: bool = True,
) -> CommandSpec:
    """Extract one ISO member from a pinned final-ISO descriptor."""
    _validate_iso_member(member)
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
        ),
        needs_root=use_sudo,
        description="Extract staged SquashFS from witnessed final ISO",
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
    report_path = run_dir / ISO_ASSEMBLY_FILENAME
    packing_path = run_dir / "ROOTFS-PACKING-VERIFICATION.json"
    if report_path.is_symlink() or packing_path.is_symlink():
        return IsoAssemblyEvidenceValidation(False, "ISO assembly evidence uses a symlink")
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
        packing = json.loads(packing_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
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
        not isinstance(report, dict)
        or set(report) != expected_fields
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
        not isinstance(packing, dict)
        or packing.get("schema") != ROOTFS_PACKING_VERIFICATION_SCHEMA
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
    if output_iso_path is not None:
        if output_iso_path.is_symlink():
            return IsoAssemblyEvidenceValidation(False, "Published ISO is a symlink")
        if replay:
            replay_validation = _authoritative_product_replay(
                run_dir,
                expected_run_id=expected_run_id,
                output_iso_path=output_iso_path,
                report=report,
                runner=replay_runner or CommandRunner(dry_run=False),
                use_sudo=replay_use_sudo,
            )
            if not replay_validation.ok:
                return replay_validation
        else:
            try:
                current_witness = StableFileWitness(output_iso_path)
                with current_witness:
                    pass
                current = current_witness.sealed_identity
            except (OSError, RootfsEvidenceError) as exc:
                return IsoAssemblyEvidenceValidation(
                    False,
                    f"Published ISO identity cannot be verified: {exc}",
                )
            if current != report.get("output_iso"):
                return IsoAssemblyEvidenceValidation(
                    False,
                    "Published ISO bytes differ from the witnessed assembled ISO",
                )
    if staged_squashfs_path is not None:
        if staged_squashfs_path.is_symlink():
            return IsoAssemblyEvidenceValidation(False, "Staged SquashFS is a symlink")
        try:
            current_witness = StableFileWitness(staged_squashfs_path)
            with current_witness:
                pass
            current_staged = current_witness.sealed_identity
        except (OSError, RootfsEvidenceError) as exc:
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
            f"authoritative final-ISO/SquashFS/rootfs replay closed for run {expected_run_id}"
            if replay
            else f"recorded ISO assembly identities closed for run {expected_run_id}"
        ),
    )


def _authoritative_product_replay(
    run_dir: Path,
    *,
    expected_run_id: str,
    output_iso_path: Path,
    report: dict[str, object],
    runner: CommandRunner,
    use_sudo: bool,
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
        manifest = load_rootfs_manifest(manifest_path)
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

    temporary_root = Path(tempfile.mkdtemp(prefix="distroforge-iso-replay-"))
    embedded_path = temporary_root / "filesystem.squashfs"
    replay_root = temporary_root / "rootfs"
    replay_manifest = temporary_root / "ROOTFS-REPLAY.json"
    result: IsoAssemblyEvidenceValidation
    try:
        iso_witness = StableFileWitness(output_iso_path)
        if iso_witness.initial_identity != output_identity:
            iso_witness.close()
            result = IsoAssemblyEvidenceValidation(
                False,
                "Published ISO bytes differ from the witnessed assembled ISO",
            )
        else:
            with iso_witness:
                runner.run(
                    iso_extract_member_command(
                        iso_witness,
                        member,
                        embedded_path,
                        use_sudo=use_sudo,
                    )
                )
            if iso_witness.sealed_identity != output_identity:
                result = IsoAssemblyEvidenceValidation(
                    False,
                    "Published ISO changed during authoritative member extraction",
                )
            else:
                squashfs_witness = PackedImageWitness(embedded_path)
                if squashfs_witness.initial_identity != embedded_identity:
                    squashfs_witness.close()
                    result = IsoAssemblyEvidenceValidation(
                        False,
                        "Final ISO member bytes differ from ISO-ASSEMBLY.json",
                    )
                else:
                    with squashfs_witness:
                        runner.run(
                            rootfs_unpack_command(
                                squashfs_witness,
                                replay_root,
                                use_sudo=use_sudo,
                            )
                        )
                    if squashfs_witness.sealed_identity != embedded_identity:
                        result = IsoAssemblyEvidenceValidation(
                            False,
                            "Embedded SquashFS changed during authoritative extraction",
                        )
                    else:
                        runner.run(
                            rootfs_capture_command(
                                replay_root,
                                replay_manifest,
                                run_id=expected_run_id,
                                excluded_descendants=exclusions,
                                use_sudo=use_sudo,
                            )
                        )
                        rootfs_validation = validate_replayed_rootfs_manifest(
                            manifest_path,
                            replay_manifest,
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

    try:
        FileSystemOps(runner, use_sudo).remove_tree(
            temporary_root,
            "Remove authoritative ISO replay workspace",
        )
    except (OSError, RuntimeError, ValueError) as exc:
        return IsoAssemblyEvidenceValidation(
            False,
            f"Authoritative final-product replay cleanup failed closed: {exc}",
        )
    return result


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
    if not value or Path(value).name != value:
        raise IsoAssemblyEvidenceError(f"Unsafe ISO assembly run_id: {value!r}")
