from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from distroforge.core.command import CommandResult, CommandRunner, CommandSpec
from distroforge.core.iso import IsoService
from distroforge.core.iso_evidence import (
    ISO_ASSEMBLY_FILENAME,
    iso_extract_member_command,
    validate_iso_assembly_evidence,
    write_iso_assembly_evidence,
)
from distroforge.core.project import Project
from distroforge.core.rootfs_evidence import (
    RootfsChangedError,
    RootfsEvidenceService,
    StableFileWitness,
    validate_rootfs_evidence,
)
from distroforge.core.squashfs import SquashfsService


def _identity(path: Path) -> dict[str, object]:
    witness = StableFileWitness(path)
    with witness:
        pass
    return witness.sealed_identity


product_replay_tools = pytest.mark.skipif(
    any(shutil.which(tool) is None for tool in ("mksquashfs", "unsquashfs", "xorriso")),
    reason="SquashFS and xorriso tools are required for authoritative product replay",
)


def _run(*argv: str) -> None:
    subprocess.run(argv, check=True, capture_output=True, text=True)


def _closed_fixture(
    tmp_path: Path,
) -> tuple[Path, Path, str, dict[str, object]]:
    run_id = "run-iso-assembly"
    run_dir = tmp_path / "evidence" / "runs" / run_id
    run_dir.mkdir(parents=True)

    rootfs = tmp_path / "rootfs"
    (rootfs / "etc").mkdir(parents=True)
    (rootfs / "etc" / "identity").write_bytes(b"authoritative rootfs bytes\n")
    rootfs_service = RootfsEvidenceService(rootfs, run_id=run_id)
    rootfs_manifest = run_dir / "ROOTFS-MANIFEST.json"
    rootfs_service.capture_before_packing(rootfs_manifest)

    staged_file = tmp_path / "filesystem.squashfs"
    _run(
        "mksquashfs",
        str(rootfs),
        str(staged_file),
        "-noappend",
        "-comp",
        "gzip",
        "-processors",
        "1",
        "-no-progress",
    )
    staged = _identity(staged_file)
    unpacked = tmp_path / "packing-replay"
    _run(
        "unsquashfs",
        "-no-progress",
        "-d",
        str(unpacked),
        str(staged_file),
    )
    rootfs_service.verify_after_packing(
        rootfs_manifest,
        staged_file,
        unpacked,
        staged,
        run_dir / "ROOTFS-PACKING-VERIFICATION.json",
    )

    iso_tree = tmp_path / "iso-tree"
    iso_member = iso_tree / "casper" / "filesystem.squashfs"
    iso_member.parent.mkdir(parents=True)
    shutil.copyfile(staged_file, iso_member)
    output_iso = tmp_path / "final.iso"
    _run(
        "xorriso",
        "-as",
        "mkisofs",
        "-quiet",
        "-o",
        str(output_iso),
        str(iso_tree),
    )
    write_iso_assembly_evidence(
        run_dir / ISO_ASSEMBLY_FILENAME,
        run_id=run_id,
        iso_member="/casper/filesystem.squashfs",
        output_iso=_identity(output_iso),
        staged_squashfs=staged,
        embedded_squashfs=staged,
    )
    return run_dir, output_iso, run_id, staged


@product_replay_tools
def test_iso_assembly_closes_packing_witness_to_published_iso(tmp_path) -> None:
    run_dir, output_iso, run_id, _staged = _closed_fixture(tmp_path)
    runner = CommandRunner(dry_run=False)

    validation = validate_iso_assembly_evidence(
        run_dir,
        expected_run_id=run_id,
        output_iso_path=output_iso,
        replay_runner=runner,
        replay_use_sudo=False,
    )

    assert validation.ok, validation.detail
    executed = {
        Path(str(identity["argv0"])).name for identity in runner.execution_identities
    }
    assert {"xorriso", "unsquashfs"}.issubset(executed)


@product_replay_tools
def test_replacing_final_iso_after_proof_is_blocked(tmp_path) -> None:
    run_dir, output_iso, run_id, _staged = _closed_fixture(tmp_path)
    replacement = tmp_path / "replacement.iso"
    replacement.write_bytes(b"different ISO bytes")
    replacement.replace(output_iso)

    validation = validate_iso_assembly_evidence(
        run_dir,
        expected_run_id=run_id,
        output_iso_path=output_iso,
        replay_use_sudo=False,
    )

    assert not validation.ok
    assert "differ" in validation.detail


@product_replay_tools
def test_replacing_staged_squashfs_after_proof_is_blocked(tmp_path) -> None:
    run_dir, output_iso, run_id, _staged = _closed_fixture(tmp_path)
    staged_path = tmp_path / "filesystem.squashfs"
    replacement = tmp_path / "replacement.squashfs"
    replacement.write_bytes(b"different staged bytes")
    replacement.replace(staged_path)

    validation = validate_iso_assembly_evidence(
        run_dir,
        expected_run_id=run_id,
        output_iso_path=output_iso,
        staged_squashfs_path=staged_path,
        authoritative_replay=True,
        replay_use_sudo=False,
    )

    assert not validation.ok
    assert "packing FD witness" in validation.detail


@product_replay_tools
def test_iso_assembly_cannot_substitute_an_unwitnessed_staged_squashfs(tmp_path) -> None:
    run_dir, output_iso, run_id, _staged = _closed_fixture(tmp_path)
    report_path = run_dir / ISO_ASSEMBLY_FILENAME
    report = json.loads(report_path.read_text(encoding="utf-8"))
    substituted = {
        "name": "filesystem.squashfs",
        "size": 8192,
        "sha256": "a" * 64,
    }
    report["staged_squashfs"] = substituted
    report["embedded_squashfs"] = substituted
    report_path.write_text(json.dumps(report), encoding="utf-8")

    validation = validate_iso_assembly_evidence(
        run_dir,
        expected_run_id=run_id,
        output_iso_path=output_iso,
        replay_use_sudo=False,
    )

    assert not validation.ok
    assert "FD witness" in validation.detail


@product_replay_tools
def test_authoritative_replay_rejects_forged_json_for_a_different_iso_member(
    tmp_path: Path,
) -> None:
    run_dir, output_iso, run_id, _staged = _closed_fixture(tmp_path)
    forged_tree = tmp_path / "forged-iso-tree"
    forged_member = forged_tree / "casper" / "filesystem.squashfs"
    forged_member.parent.mkdir(parents=True)
    forged_member.write_bytes(b"not the witnessed SquashFS")
    _run(
        "xorriso",
        "-as",
        "mkisofs",
        "-quiet",
        "-o",
        str(tmp_path / "forged.iso"),
        str(forged_tree),
    )
    (tmp_path / "forged.iso").replace(output_iso)

    report_path = run_dir / ISO_ASSEMBLY_FILENAME
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["output_iso"] = _identity(output_iso)
    report_path.write_text(json.dumps(report), encoding="utf-8")

    validation = validate_iso_assembly_evidence(
        run_dir,
        expected_run_id=run_id,
        output_iso_path=output_iso,
        replay_use_sudo=False,
    )

    assert not validation.ok
    assert "member bytes differ" in validation.detail


@product_replay_tools
def test_authoritative_replay_rejects_self_consistent_forged_rootfs_json(
    tmp_path: Path,
) -> None:
    run_dir, output_iso, run_id, _staged = _closed_fixture(tmp_path)
    claimed_root = tmp_path / "claimed-rootfs"
    (claimed_root / "etc").mkdir(parents=True)
    (claimed_root / "etc" / "identity").write_bytes(b"fabricated claimed bytes\n")
    claimed = RootfsEvidenceService(claimed_root, run_id=run_id).snapshot()
    manifest_path = run_dir / "ROOTFS-MANIFEST.json"
    manifest_path.write_text(
        json.dumps(claimed, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    packing_path = run_dir / "ROOTFS-PACKING-VERIFICATION.json"
    packing = json.loads(packing_path.read_text(encoding="utf-8"))
    packing["manifest"].update(
        {
            "tree_sha256": claimed["tree_sha256"],
            "host_scan_guard_sha256": claimed["host_scan_guard_sha256"],
            "object_count": claimed["object_count"],
        }
    )
    packing["after_packing"].update(
        {
            "tree_sha256": claimed["tree_sha256"],
            "host_scan_guard_sha256": claimed["host_scan_guard_sha256"],
        }
    )
    packing["packed_rootfs"]["tree_sha256"] = claimed["tree_sha256"]
    packing_path.write_text(json.dumps(packing), encoding="utf-8")
    assert validate_rootfs_evidence(run_dir, expected_run_id=run_id).ok

    validation = validate_iso_assembly_evidence(
        run_dir,
        expected_run_id=run_id,
        output_iso_path=output_iso,
        replay_use_sudo=False,
    )

    assert not validation.ok
    assert "replay differs" in validation.detail


class _NoopIsoRunner:
    dry_run = False

    def __init__(self, *, produce: bytes | None = None) -> None:
        self.produce = produce
        self.history: list[CommandSpec] = []

    def run(self, spec: CommandSpec, check: bool = True) -> CommandResult:
        self.history.append(spec)
        if "-report_el_torito" in spec.argv:
            stdout = "-b /boot/grub/i386-pc/eltorito.img\n"
        else:
            stdout = ""
        if self.produce is not None and "mkisofs" in spec.argv:
            staged = Path(spec.argv[spec.argv.index("-o") + 1])
            staged.write_bytes(self.produce)
        return CommandResult(spec=spec, returncode=0, stdout=stdout, stderr="")


def _source_project(tmp_path: Path) -> Project:
    project = Project.create("Atomic", tmp_path / "project", "26.04")
    project.source_mode = "iso"
    project.source_iso = tmp_path / "source.iso"
    project.source_iso.write_bytes(b"source")
    return project


def test_xorriso_noop_cannot_bless_a_stale_output_iso(tmp_path) -> None:
    project = _source_project(tmp_path)
    output = tmp_path / "output.iso"
    output.write_bytes(b"stale ISO must survive as stale")
    runner = _NoopIsoRunner()

    with pytest.raises(ValueError, match="was not produced"):
        IsoService(runner, use_sudo=False).rebuild(
            project,
            output,
            staging_output=tmp_path / ".output.iso.run-1",
        )

    assert output.read_bytes() == b"stale ISO must survive as stale"


def test_fresh_iso_is_validated_then_atomically_promoted(tmp_path) -> None:
    project = _source_project(tmp_path)
    output = tmp_path / "output.iso"
    output.write_bytes(b"old")
    staging = tmp_path / ".output.iso.run-2"
    runner = _NoopIsoRunner(produce=b"fresh and non-empty")

    identity = IsoService(runner, use_sudo=False).rebuild(
        project,
        output,
        staging_output=staging,
    )

    assert output.read_bytes() == b"fresh and non-empty"
    assert not staging.exists()
    assert identity == _identity(output)


def test_sealed_source_unpack_refuses_preseeded_ghost(tmp_path) -> None:
    destination = tmp_path / "work" / "filesystem"
    ghost = destination / "usr/bin/ghost"
    ghost.parent.mkdir(parents=True)
    ghost.write_text("old run", encoding="utf-8")
    runner = _NoopIsoRunner()

    with pytest.raises(ValueError, match="not fresh"):
        SquashfsService(
            runner,
            use_sudo=False,
            require_fresh_unpack=True,
        ).unpack(tmp_path / "source.squashfs", destination)

    assert ghost.read_text(encoding="utf-8") == "old run"
    assert runner.history == []


def test_sealed_source_iso_extract_refuses_preseeded_tree(tmp_path) -> None:
    destination = tmp_path / "work" / "iso"
    ghost = destination / "casper/ghost"
    ghost.parent.mkdir(parents=True)
    ghost.write_text("old run", encoding="utf-8")
    runner = _NoopIsoRunner()

    with pytest.raises(ValueError, match="not fresh"):
        IsoService(
            runner,
            use_sudo=False,
            require_fresh_extract=True,
        ).extract(tmp_path / "source.iso", destination)

    assert ghost.read_text(encoding="utf-8") == "old run"
    assert runner.history == []


def test_witnessed_source_extract_refuses_wrong_trusted_digest(tmp_path) -> None:
    source = tmp_path / "source.iso"
    source.write_bytes(b"trusted source bytes")
    runner = _NoopIsoRunner()

    with pytest.raises(ValueError, match="trusted opening identity"):
        IsoService(
            runner,
            use_sudo=False,
            require_fresh_extract=True,
        ).extract_witnessed(
            source,
            tmp_path / "work/iso",
            expected_sha256="0" * 64,
        )

    assert runner.history == []
    assert not (tmp_path / "work/iso").exists()


def test_witnessed_source_extract_blocks_path_swap_after_dispatch(tmp_path) -> None:
    source = tmp_path / "source.iso"
    source.write_bytes(b"trusted source bytes")
    replacement = tmp_path / "replacement.iso"
    replacement.write_bytes(b"attacker replacement")

    class _SwapRunner(_NoopIsoRunner):
        def run(self, spec: CommandSpec, check: bool = True) -> CommandResult:
            result = super().run(spec, check)
            if "-extract" in spec.argv:
                replacement.replace(source)
            return result

    runner = _SwapRunner()
    expected = hashlib.sha256(b"trusted source bytes").hexdigest()

    with pytest.raises(RootfsChangedError, match="changed during extraction|another inode"):
        IsoService(
            runner,
            use_sudo=False,
            require_fresh_extract=True,
        ).extract_witnessed(
            source,
            tmp_path / "work/iso",
            expected_sha256=expected,
        )

    extraction = next(spec for spec in runner.history if "-extract" in spec.argv)
    indev = extraction.argv[extraction.argv.index("-indev") + 1]
    assert indev.startswith(f"/proc/{os.getpid()}/fd/")


def test_unsquashfs_never_uses_force_merge_flag(tmp_path) -> None:
    runner = CommandRunner(dry_run=True)
    SquashfsService(
        runner,
        use_sudo=False,
        require_fresh_unpack=True,
    ).unpack(tmp_path / "source.squashfs", tmp_path / "fresh")

    assert "-f" not in runner.history[-1].argv


@pytest.mark.skipif(shutil.which("xorriso") is None, reason="xorriso is not installed")
def test_real_iso_member_is_extracted_through_fd_witness(tmp_path) -> None:
    source = tmp_path / "tree"
    member = source / "casper/filesystem.squashfs"
    member.parent.mkdir(parents=True)
    member.write_bytes(b"exact staged bytes")
    iso = tmp_path / "fixture.iso"
    runner = CommandRunner(dry_run=False)
    runner.run(
        CommandSpec(
            argv=(
                "xorriso",
                "-as",
                "mkisofs",
                "-o",
                str(iso),
                str(source),
            )
        )
    )
    extracted = tmp_path / "extracted" / "filesystem.squashfs"
    extracted.parent.mkdir()

    witness = StableFileWitness(iso)
    with witness:
        runner.run(
            iso_extract_member_command(
                witness,
                "/casper/filesystem.squashfs",
                extracted,
                use_sudo=False,
            )
        )

    assert extracted.read_bytes() == member.read_bytes()
    assert witness.sealed_identity == _identity(iso)
