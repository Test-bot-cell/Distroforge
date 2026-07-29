from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from distroforge.core import rootfs_evidence
from distroforge.core.evidence_run import canonical_sha256
from distroforge.core.rootfs_evidence import (
    ROOTFS_MANIFEST_SCHEMA,
    ROOTFS_PACKING_VERIFICATION_SCHEMA,
    PackedImageWitness,
    RootfsChangedError,
    RootfsEvidenceError,
    RootfsEvidenceService,
    load_rootfs_manifest,
    main,
    rootfs_capture_command,
    rootfs_unpack_command,
    rootfs_verify_command,
    validate_rootfs_evidence,
)

squashfs_tools = pytest.mark.skipif(
    shutil.which("mksquashfs") is None or shutil.which("unsquashfs") is None,
    reason="squashfs-tools is not installed",
)


def _rootfs(tmp_path: Path) -> Path:
    root = tmp_path / "rootfs"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "config").write_bytes(b"sealed-rootfs\n")
    return root


def _entries(payload: dict[str, object]) -> dict[str, dict[str, object]]:
    raw = payload["entries"]
    assert isinstance(raw, list)
    return {str(item["path"]): item for item in raw if isinstance(item, dict)}


def _seal_image(path: Path) -> dict[str, object]:
    witness = PackedImageWitness(path)
    with witness:
        pass
    return witness.sealed_identity


def test_snapshot_records_filesystem_semantics_and_special_objects(tmp_path: Path) -> None:
    root = _rootfs(tmp_path)
    config = root / "etc" / "config"
    config.chmod(0o640)
    os.link(config, root / "etc" / "config.link")
    (root / "absolute-link").symlink_to("/etc/config")
    os.mkfifo(root / "event.pipe", 0o620)

    payload = RootfsEvidenceService(root, excluded_descendants=()).snapshot()
    entries = _entries(payload)

    assert payload["schema"] == ROOTFS_MANIFEST_SCHEMA
    assert payload["object_count"] == len(entries)
    assert payload["tree_sha256"] == canonical_sha256(payload["entries"])
    assert list(entries) == sorted(entries, key=os.fsencode)
    assert entries["."]["type"] == "directory"
    assert entries["etc/config"] == {
        "path": "etc/config",
        "type": "regular",
        "mode": "0640",
        "uid": os.getuid(),
        "gid": os.getgid(),
        "link_count": 2,
        "xattrs": [],
        "size": len(b"sealed-rootfs\n"),
        "sha256": hashlib.sha256(b"sealed-rootfs\n").hexdigest(),
        "hardlink_master": "etc/config",
    }
    assert entries["etc/config.link"]["hardlink_master"] == "etc/config"
    assert entries["absolute-link"]["type"] == "symlink"
    assert entries["absolute-link"]["target"] == "/etc/config"
    assert entries["event.pipe"]["type"] == "fifo"
    assert entries["event.pipe"]["mode"] == "0620"
    assert rootfs_evidence._file_type(stat.S_IFSOCK | 0o600) == "socket"


def test_snapshot_records_extended_attribute_bytes(tmp_path: Path) -> None:
    root = _rootfs(tmp_path)
    target = root / "etc" / "config"
    try:
        os.setxattr(target, "user.distroforge-test", b"\x00proof\xff")
    except OSError as exc:
        pytest.skip(f"test filesystem does not support user xattrs: {exc}")

    entry = _entries(RootfsEvidenceService(root, excluded_descendants=()).snapshot())["etc/config"]

    assert entry["xattrs"] == [
        {
            "name": "user.distroforge-test",
            "value_base64": "AHByb29m/w==",
        }
    ]


def test_snapshot_declares_and_omits_only_packer_excluded_descendants(
    tmp_path: Path,
) -> None:
    root = _rootfs(tmp_path)
    for name in ("dev", "proc", "run", "sys"):
        directory = root / name
        directory.mkdir()
        (directory / "runtime-state").write_text(name, encoding="utf-8")
    (root / "usr").mkdir()
    (root / "usr" / "kept").write_text("kept", encoding="utf-8")

    payload = RootfsEvidenceService(root).snapshot()
    entries = _entries(payload)

    assert payload["excluded_descendants"] == ["dev", "proc", "run", "sys"]
    assert all(name in entries for name in ("dev", "proc", "run", "sys"))
    assert not any(path.endswith("/runtime-state") for path in entries)
    assert "usr/kept" in entries


def test_snapshot_rejects_a_hardlink_escaping_the_packing_scope(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.write_text("same inode", encoding="utf-8")
    root = tmp_path / "rootfs"
    root.mkdir()
    os.link(outside, root / "inside")

    with pytest.raises(RootfsEvidenceError, match="hardlink group escapes"):
        RootfsEvidenceService(root, excluded_descendants=()).snapshot()


def test_snapshot_rejects_change_between_its_two_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _rootfs(tmp_path)
    original_scan = rootfs_evidence._scan_once
    calls = 0

    def change_after_first_scan(scanned_root: Path, exclusions: tuple[str, ...]) -> object:
        nonlocal calls
        result = original_scan(scanned_root, exclusions)
        calls += 1
        if calls == 1:
            (root / "etc" / "config").write_text("changed\n", encoding="utf-8")
        return result

    monkeypatch.setattr(rootfs_evidence, "_scan_once", change_after_first_scan)

    with pytest.raises(RootfsChangedError, match="between the two"):
        RootfsEvidenceService(root, excluded_descendants=()).snapshot()


def test_capture_is_immutable_and_cannot_be_written_inside_rootfs(tmp_path: Path) -> None:
    root = _rootfs(tmp_path)
    service = RootfsEvidenceService(root, excluded_descendants=())
    manifest = tmp_path / "ROOTFS-MANIFEST.json"

    service.capture_before_packing(manifest)
    with pytest.raises(FileExistsError):
        service.capture_before_packing(manifest)
    with pytest.raises(RootfsEvidenceError, match="outside the rootfs"):
        service.capture_before_packing(root / "proof.json")
    alias = tmp_path / "rootfs-alias"
    alias.symlink_to(root, target_is_directory=True)
    with pytest.raises(RootfsEvidenceError, match="outside the rootfs"):
        service.capture_before_packing(alias / "proof-via-alias.json")


def test_snapshot_rejects_a_symlinked_root_boundary(tmp_path: Path) -> None:
    root = _rootfs(tmp_path)
    alias = tmp_path / "rootfs-alias"
    alias.symlink_to(root, target_is_directory=True)

    with pytest.raises(RootfsEvidenceError, match="symlink component"):
        RootfsEvidenceService(alias, excluded_descendants=()).snapshot()


def test_load_manifest_rejects_tampered_digest_and_unsafe_paths(tmp_path: Path) -> None:
    root = _rootfs(tmp_path)
    manifest = tmp_path / "ROOTFS-MANIFEST.json"
    RootfsEvidenceService(root, excluded_descendants=()).capture_before_packing(manifest)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["entries"][1]["path"] = "../escape"
    payload["tree_sha256"] = canonical_sha256(payload["entries"])
    tampered = tmp_path / "tampered.json"
    tampered.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(RootfsEvidenceError, match="path"):
        load_rootfs_manifest(tampered)

    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["tree_sha256"] = "0" * 64
    bad_digest = tmp_path / "bad-digest.json"
    bad_digest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(RootfsEvidenceError, match="semantic digest"):
        load_rootfs_manifest(bad_digest)


def test_verify_packing_binds_an_unchanged_rootfs_and_image(tmp_path: Path) -> None:
    root = _rootfs(tmp_path)
    manifest = tmp_path / "ROOTFS-MANIFEST.json"
    packed = tmp_path / "filesystem.squashfs"
    unpacked = tmp_path / "unpacked-image"
    verification = tmp_path / "ROOTFS-PACKING-VERIFICATION.json"
    service = RootfsEvidenceService(root, excluded_descendants=())

    service.capture_before_packing(manifest)
    result = packed.write_bytes(b"squashfs fixture")
    shutil.copytree(root, unpacked, symlinks=True)
    image_witness = _seal_image(packed)
    service.verify_after_packing(
        manifest,
        packed,
        unpacked,
        image_witness,
        verification,
    )

    report = json.loads(verification.read_text(encoding="utf-8"))
    assert result == len(b"squashfs fixture")
    assert report["schema"] == ROOTFS_PACKING_VERIFICATION_SCHEMA
    assert report["status"] == "verified"
    assert report["drift"] == {
        "added": [],
        "removed": [],
        "changed": [],
        "host_identity_changed": False,
    }
    assert report["packed_rootfs"]["matches_manifest"] is True
    expected_identity = {
        "name": "filesystem.squashfs",
        "size": len(b"squashfs fixture"),
        "sha256": hashlib.sha256(b"squashfs fixture").hexdigest(),
    }
    assert report["packed_image"] == {
        "witness": expected_identity,
        "after_extraction": expected_identity,
        "matches_witness": True,
    }


def test_verify_packing_reports_semantic_drift_and_fails_closed(tmp_path: Path) -> None:
    root = _rootfs(tmp_path)
    manifest = tmp_path / "ROOTFS-MANIFEST.json"
    packed = tmp_path / "filesystem.squashfs"
    unpacked = tmp_path / "unpacked-image"
    verification = tmp_path / "ROOTFS-PACKING-VERIFICATION.json"
    service = RootfsEvidenceService(root, excluded_descendants=())

    service.capture_before_packing(manifest)
    packed.write_bytes(b"image")
    shutil.copytree(root, unpacked, symlinks=True)
    image_witness = _seal_image(packed)
    (root / "etc" / "config").chmod(0o600)
    with pytest.raises(RootfsChangedError) as raised:
        service.verify_after_packing(
            manifest,
            packed,
            unpacked,
            image_witness,
            verification,
        )

    assert raised.value.report is not None
    assert raised.value.report.changed == ("etc/config",)
    report = json.loads(verification.read_text(encoding="utf-8"))
    assert report["status"] == "drifted"
    assert report["drift"]["changed"] == ["etc/config"]


def test_host_guard_detects_modify_then_restore_across_packing(tmp_path: Path) -> None:
    root = _rootfs(tmp_path)
    target = root / "etc" / "config"
    original_mode = target.stat().st_mode & 0o7777
    manifest = tmp_path / "ROOTFS-MANIFEST.json"
    packed = tmp_path / "filesystem.squashfs"
    unpacked = tmp_path / "unpacked-image"
    service = RootfsEvidenceService(root, excluded_descendants=())

    service.capture_before_packing(manifest)
    packed.write_bytes(b"image")
    shutil.copytree(root, unpacked, symlinks=True)
    image_witness = _seal_image(packed)
    target.chmod(0o600)
    target.chmod(original_mode)
    with pytest.raises(RootfsChangedError) as raised:
        service.verify_after_packing(
            manifest,
            packed,
            unpacked,
            image_witness,
        )

    report = raised.value.report
    assert report is not None
    assert report.before_tree_sha256 == report.after_tree_sha256
    assert report.changed == ()
    assert report.before_host_guard_sha256 != report.after_host_guard_sha256


def test_packed_tree_comparison_catches_transient_input_substitution(
    tmp_path: Path,
) -> None:
    root = _rootfs(tmp_path)
    manifest = tmp_path / "ROOTFS-MANIFEST.json"
    packed = tmp_path / "filesystem.squashfs"
    unpacked = tmp_path / "unpacked-image"
    verification = tmp_path / "ROOTFS-PACKING-VERIFICATION.json"
    service = RootfsEvidenceService(root, excluded_descendants=())

    service.capture_before_packing(manifest)
    packed.write_bytes(b"image with substituted bytes")
    shutil.copytree(root, unpacked, symlinks=True)
    image_witness = _seal_image(packed)
    (unpacked / "etc" / "config").write_text(
        "substituted during pack\n",
        encoding="utf-8",
    )
    with pytest.raises(RootfsChangedError) as raised:
        service.verify_after_packing(
            manifest,
            packed,
            unpacked,
            image_witness,
            verification,
        )

    report = raised.value.report
    assert report is not None
    assert report.before_tree_sha256 == report.after_tree_sha256
    assert report.before_host_guard_sha256 == report.after_host_guard_sha256
    assert report.packed_changed == ("etc/config",)
    written = json.loads(verification.read_text(encoding="utf-8"))
    assert written["packed_rootfs"]["matches_manifest"] is False
    assert written["packed_rootfs"]["changed"] == ["etc/config"]


def test_verify_rejects_image_path_swapped_after_extraction(tmp_path: Path) -> None:
    root = _rootfs(tmp_path)
    manifest = tmp_path / "ROOTFS-MANIFEST.json"
    packed = tmp_path / "filesystem.squashfs"
    unpacked = tmp_path / "unpacked-image"
    verification = tmp_path / "ROOTFS-PACKING-VERIFICATION.json"
    service = RootfsEvidenceService(root, excluded_descendants=())
    service.capture_before_packing(manifest)
    packed.write_bytes(b"image A consumed by extraction")
    with PackedImageWitness(packed) as witness:
        shutil.copytree(root, unpacked, symlinks=True)
    image_witness = witness.sealed_identity
    replacement = tmp_path / "replacement.squashfs"
    replacement.write_bytes(b"image C swapped onto the reported path")
    replacement.replace(packed)

    with pytest.raises(RootfsChangedError) as raised:
        service.verify_after_packing(
            manifest,
            packed,
            unpacked,
            image_witness,
            verification,
        )

    report = raised.value.report
    assert report is not None
    assert report.packed_image_matches_witness is False
    written = json.loads(verification.read_text(encoding="utf-8"))
    assert written["packed_image"]["matches_witness"] is False
    assert written["packed_rootfs"]["matches_manifest"] is True


def test_image_witness_refuses_a_path_swap_while_it_is_open(tmp_path: Path) -> None:
    packed = tmp_path / "filesystem.squashfs"
    packed.write_bytes(b"original")
    replacement = tmp_path / "replacement.squashfs"
    replacement.write_bytes(b"replacement")

    with pytest.raises(RootfsChangedError, match="inode changed"):
        with PackedImageWitness(packed):
            replacement.replace(packed)


@squashfs_tools
def test_real_squashfs_round_trip_matches_the_prepacking_manifest(
    tmp_path: Path,
) -> None:
    root = _rootfs(tmp_path)
    for name in ("dev", "proc", "run", "sys"):
        (root / name).mkdir()
    os.link(root / "etc" / "config", root / "etc" / "config.link")
    (root / "config-link").symlink_to("/etc/config")
    os.mkfifo(root / "event.pipe", 0o620)
    manifest = tmp_path / "ROOTFS-MANIFEST.json"
    packed = tmp_path / "filesystem.squashfs"
    unpacked = tmp_path / "unpacked-image"
    verification = tmp_path / "ROOTFS-PACKING-VERIFICATION.json"
    service = RootfsEvidenceService(root, run_id="real-roundtrip")
    service.capture_before_packing(manifest)

    subprocess.run(
        (
            "mksquashfs",
            str(root),
            str(packed),
            "-noappend",
            "-comp",
            "gzip",
            "-processors",
            "1",
            "-no-progress",
            "-wildcards",
            "-e",
            "proc/*",
            "sys/*",
            "run/*",
            "dev/*",
        ),
        check=True,
        capture_output=True,
        text=True,
    )
    witness = PackedImageWitness(packed)
    with witness:
        unpack = rootfs_unpack_command(witness, unpacked, use_sudo=False)
        assert str(unpack.argv[-1]).startswith(f"/proc/{os.getpid()}/fd/")
        subprocess.run(
            unpack.argv,
            check=True,
            capture_output=True,
            text=True,
        )

    report = service.verify_after_packing(
        manifest,
        packed,
        unpacked,
        witness.sealed_identity,
        verification,
    )

    assert report.ok is True
    assert report.packed_tree_sha256 == report.before_tree_sha256
    validation = validate_rootfs_evidence(
        tmp_path,
        expected_run_id="real-roundtrip",
    )
    assert validation.ok, validation.detail


def test_snapshot_refuses_any_mount_below_rootfs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _rootfs(tmp_path)
    monkeypatch.setattr(
        rootfs_evidence,
        "_mounts_under_strict",
        lambda _root: [str(root / "proc")],
    )

    with pytest.raises(RootfsEvidenceError, match="mounted filesystems"):
        RootfsEvidenceService(root).snapshot()


def test_privileged_helper_commands_preserve_the_exact_exclusion_scope(
    tmp_path: Path,
) -> None:
    root = tmp_path / "protected-rootfs"
    manifest = tmp_path / "ROOTFS-MANIFEST.json"
    packed = tmp_path / "filesystem.squashfs"
    unpacked = tmp_path / "unpacked-image"
    verification = tmp_path / "ROOTFS-PACKING-VERIFICATION.json"
    python = Path("/opt/distroforge/python")

    capture = rootfs_capture_command(
        root,
        manifest,
        excluded_descendants=(),
        use_sudo=False,
        python=python,
    )
    packed.write_bytes(b"packed")
    witness = PackedImageWitness(packed)
    with witness:
        unpack = rootfs_unpack_command(witness, unpacked, use_sudo=False)
        assert unpack.argv == (
            "unsquashfs",
            "-no-progress",
            "-d",
            str(unpacked),
            str(witness.proc_fd_path),
        )
        assert str(unpack.argv[-1]) != str(packed)
    verify = rootfs_verify_command(
        root,
        manifest,
        packed,
        unpacked,
        witness.sealed_identity,
        verification,
        excluded_descendants=("run", "dev"),
        use_sudo=False,
        python=python,
    )

    assert capture.argv[:3] == (
        "/opt/distroforge/python",
        "-m",
        "distroforge.core.rootfs_evidence",
    )
    assert capture.argv[-1] == "--no-default-exclusions"
    assert capture.needs_root is False
    assert verify.argv[-4:] == ("--exclude", "dev", "--exclude", "run")
    assert verify.needs_root is False
    assert "-f" not in unpack.argv


def test_module_helper_captures_and_verifies_without_a_shell(tmp_path: Path) -> None:
    root = _rootfs(tmp_path)
    manifest = tmp_path / "ROOTFS-MANIFEST.json"
    packed = tmp_path / "filesystem.squashfs"
    unpacked = tmp_path / "unpacked-image"
    verification = tmp_path / "ROOTFS-PACKING-VERIFICATION.json"

    assert (
        main(
            [
                "capture",
                "--root",
                str(root),
                "--manifest",
                str(manifest),
                "--no-default-exclusions",
            ]
        )
        == 0
    )
    packed.write_bytes(b"packed")
    shutil.copytree(root, unpacked, symlinks=True)
    image_witness = _seal_image(packed)
    assert (
        main(
            [
                "verify",
                "--root",
                str(root),
                "--manifest",
                str(manifest),
                "--packed-image",
                str(packed),
                "--unpacked-image-root",
                str(unpacked),
                "--packed-image-sha256",
                str(image_witness["sha256"]),
                "--packed-image-size",
                str(image_witness["size"]),
                "--packed-image-name",
                str(image_witness["name"]),
                "--verification",
                str(verification),
                "--no-default-exclusions",
            ]
        )
        == 0
    )
    assert json.loads(verification.read_text(encoding="utf-8"))["status"] == "verified"
