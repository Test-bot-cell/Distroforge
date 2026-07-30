from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path

import pytest
from conftest import (
    package_fixture_options,
    write_valid_boot_proof,
    write_valid_build_evidence,
)

from distroforge.core import release_verification
from distroforge.core.artifact_paths import default_output_iso
from distroforge.core.artifact_verification import (
    ArtifactVerificationError,
    ArtifactVerificationSession,
)
from distroforge.core.command import CommandRunner
from distroforge.core.evidence_run import stable_parent_identity
from distroforge.core.project import Project
from distroforge.core.publish_bundle import create_publish_bundle
from distroforge.core.release_signing import SIGN_TARGETS, SIGNING_KEYRING
from distroforge.core.release_verification import (
    ReleaseVerifyItem,
    _BundleInventory,
    _verify_runtime_evidence,
    _verify_signatures,
    verify_release_bundle,
)

_FINGERPRINT = "4248DCA20A9407BBFA31818518BC560A874C3C7F"


def _bundle_fixture(tmp_path: Path, name: str) -> tuple[Project, Path]:
    project = Project.create(name, tmp_path / name.lower(), "26.04")
    bundle = project.output_dir / "publish"
    bundle.mkdir(parents=True)
    iso = bundle / f"{name}-26.04.iso"
    iso.write_bytes(b"verified iso bytes")
    digest = hashlib.sha256(iso.read_bytes()).hexdigest()
    (bundle / "SHA256SUMS").write_text(
        f"{digest}  {iso.name}\n",
        encoding="utf-8",
    )
    (bundle / "RELEASE-GATE.json").write_text(
        json.dumps(
            {
                "iso": str(iso),
                "status": "ready",
                "blocked": False,
                "items": [
                    {
                        "code": "iso",
                        "status": "ready",
                        "detail": f"{iso.stat().st_size} bytes",
                    },
                    {
                        "code": "sha256",
                        "status": "ready",
                        "detail": digest,
                    },
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (bundle / "SIGNING-REPORT.json").write_text(
        '{"status":"planned","planned":[]}\n',
        encoding="utf-8",
    )
    (bundle / "RELEASE-MANIFEST.json").write_text(
        json.dumps(
            {
                "gate_status": "ready",
                "files": [
                    {
                        "name": iso.name,
                        "size": iso.stat().st_size,
                        "sha256": digest,
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return project, bundle


def _runtime_bundle_fixture(
    tmp_path: Path,
    name: str,
) -> tuple[Path, dict[str, object]]:
    project = Project.create(name, tmp_path / name.lower(), "26.04")
    project.source_mode = "bootstrap"
    iso = default_output_iso(project)
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso, run_id="build-run")
    write_valid_boot_proof(
        project,
        iso,
        run_id="boot-run",
        build_run_id="build-run",
    )
    bundle = tmp_path / f"{name.lower()}-bundle"
    published = create_publish_bundle(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
        bundle_dir=bundle,
        build_run_id="build-run",
        boot_run_id="boot-run",
    )
    assert published.published, published.missing
    return bundle, published.gate.to_dict()


def _runtime_evidence_items(
    bundle: Path,
    gate: dict[str, object],
) -> list[ReleaseVerifyItem]:
    inventory = release_verification._descriptor_tree_inventory(bundle)
    session = ArtifactVerificationSession(
        bundle,
        label="runtime B/C binding test",
    )
    items: list[ReleaseVerifyItem] = []
    try:
        _verify_runtime_evidence(
            bundle,
            items,
            session=session,
            inventory=inventory,
            gate=gate,
        )
    finally:
        session.close()
    return items


def test_runtime_verification_rejects_boot_proof_gate_run_mismatch(
    tmp_path: Path,
) -> None:
    bundle, gate = _runtime_bundle_fixture(tmp_path, "ProofRunMismatch")
    proof_path = bundle / "boot-proof.json"
    proof = json.loads(proof_path.read_text(encoding="utf-8"))
    proof["build_run_id"] = "forged-build-run"
    proof_path.write_text(json.dumps(proof) + "\n", encoding="utf-8")

    items = _runtime_evidence_items(bundle, gate)

    assert items[-1].status == "blocked"
    assert "bind a ready QEMU run" in items[-1].detail


def test_runtime_verification_rejects_manifest_gate_run_mismatch(
    tmp_path: Path,
) -> None:
    bundle, gate = _runtime_bundle_fixture(tmp_path, "ManifestRunMismatch")
    manifest_path = (
        bundle / "evidence" / "runs" / "boot-run" / "RUN-MANIFEST.json"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["build_run_id"] = "forged-build-run"
    manifest_path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")
    (manifest_path.parent / "RUN-MANIFEST.json.sha256").write_text(
        f"{hashlib.sha256(manifest_path.read_bytes()).hexdigest()}  "
        "RUN-MANIFEST.json\n",
        encoding="utf-8",
    )

    items = _runtime_evidence_items(bundle, gate)

    assert items[-1].status == "blocked"
    assert "manifest identity" in items[-1].detail


def test_release_verification_blocks_invalid_utf8_without_raw_exception(
    tmp_path: Path,
) -> None:
    project, bundle = _bundle_fixture(tmp_path, "InvalidUtf8")
    (bundle / "SIGNING-REPORT.json").write_bytes(b'{"status":"planned"}\xff\n')

    report = verify_release_bundle(project, bundle_dir=bundle)

    assert report.blocked
    assert any(item.code == "signing-report" and item.status == "blocked" for item in report.items)
    assert not (bundle / "VERIFY-REPORT.json").exists()
    assert report.bundle_identity is None


def test_release_verification_rejects_duplicate_sha256sums_entries(
    tmp_path: Path,
) -> None:
    project, bundle = _bundle_fixture(tmp_path, "DuplicateSums")
    iso = bundle / "DuplicateSums-26.04.iso"
    line = f"{hashlib.sha256(iso.read_bytes()).hexdigest()}  {iso.name}\n"
    (bundle / "SHA256SUMS").write_text(line + line, encoding="utf-8")

    report = verify_release_bundle(project, bundle_dir=bundle)

    assert report.blocked
    sha_item = next(item for item in report.items if item.code == "sha256sums")
    assert sha_item.status == "blocked"
    assert "duplicates" in sha_item.detail


def test_release_verification_rejects_fifo_without_waiting(tmp_path: Path) -> None:
    project, bundle = _bundle_fixture(tmp_path, "FifoArtifact")
    fifo = bundle / "payload.bin"
    os.mkfifo(fifo)
    manifest_path = bundle / "RELEASE-MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"].append({"name": fifo.name, "size": 0, "sha256": "0" * 64})
    manifest_path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")

    report = verify_release_bundle(project, bundle_dir=bundle)

    assert report.blocked
    assert any(
        item.code == "manifest-file"
        and item.status == "blocked"
        and "not a regular file" in item.detail
        for item in report.items
    )


def test_release_inventory_applies_its_budget_during_scandir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    for index in range(3):
        (bundle / f"entry-{index}").write_bytes(b"x")
    inspected: list[str] = []
    original = release_verification._strict_filesystem_name

    def record_name(value: str) -> str:
        inspected.append(value)
        return original(value)

    monkeypatch.setattr(release_verification, "_INVENTORY_MAX_ENTRIES", 2)
    monkeypatch.setattr(
        release_verification,
        "_strict_filesystem_name",
        record_name,
    )

    with pytest.raises(ArtifactVerificationError, match="inventory entry limit"):
        release_verification._descriptor_tree_inventory(bundle)

    assert len(inspected) == 2


def test_release_verification_detects_same_size_same_mtime_atomic_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, bundle = _bundle_fixture(tmp_path, "AtomicSwap")
    gate_path = bundle / "RELEASE-GATE.json"
    opening_identity = gate_path.stat()
    opening_bytes = gate_path.read_bytes()
    replacement_bytes = opening_bytes.replace(b'"ready"', b'"reedy"')
    assert len(replacement_bytes) == len(opening_bytes)
    original = release_verification._verify_manifest_files

    def swap_after_manifest(
        bundle_dir: Path,
        manifest: dict[str, object],
        items: list[ReleaseVerifyItem],
        *,
        session: ArtifactVerificationSession,
        inventory: _BundleInventory,
    ) -> None:
        original(
            bundle_dir,
            manifest,
            items,
            session=session,
            inventory=inventory,
        )
        replacement = bundle_dir / ".release-gate.swap"
        replacement.write_bytes(replacement_bytes)
        os.utime(
            replacement,
            ns=(opening_identity.st_atime_ns, opening_identity.st_mtime_ns),
        )
        os.replace(replacement, gate_path)
        assert gate_path.stat().st_size == opening_identity.st_size
        assert gate_path.stat().st_mtime_ns == opening_identity.st_mtime_ns

    monkeypatch.setattr(
        release_verification,
        "_verify_manifest_files",
        swap_after_manifest,
    )

    report = verify_release_bundle(project, bundle_dir=bundle)

    assert report.blocked
    assert any(
        item.code == "artifact-session"
        and item.status == "blocked"
        and ("another inode" in item.detail or "identity changed" in item.detail)
        for item in report.items
    )


def test_release_verification_never_publishes_into_a_post_anchor_clone(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, bundle = _bundle_fixture(tmp_path, "BundleClone")
    expected = stable_parent_identity(bundle)
    moved = bundle.with_name("publish-original")
    real_inventory = release_verification._descriptor_tree_inventory
    swapped = False

    def swap_before_inventory(path: Path) -> _BundleInventory:
        nonlocal swapped
        if not swapped:
            swapped = True
            path.rename(moved)
            shutil.copytree(moved, path)
        return real_inventory(path)

    monkeypatch.setattr(
        release_verification,
        "_descriptor_tree_inventory",
        swap_before_inventory,
    )

    report = verify_release_bundle(
        project,
        bundle_dir=bundle,
        expected_bundle_identity=expected,
    )

    assert report.blocked
    assert not (bundle / "VERIFY-REPORT.json").exists()
    assert not (moved / "VERIFY-REPORT.json").exists()
    assert any(
        item.code == "artifact-session"
        and "primary descriptor-session anchor" in item.detail
        for item in report.items
    )


def test_verify_report_symlink_never_writes_its_external_target(
    tmp_path: Path,
) -> None:
    project, bundle = _bundle_fixture(tmp_path, "ReportSymlink")
    external = tmp_path / "external-report.json"
    sentinel = b'{"external":"must stay unchanged"}\n'
    external.write_bytes(sentinel)
    report_path = bundle / "VERIFY-REPORT.json"
    report_path.symlink_to(external)

    report = verify_release_bundle(project, bundle_dir=bundle)

    assert report.blocked
    assert external.read_bytes() == sentinel
    assert report_path.is_symlink()
    assert not list(bundle.glob(".VERIFY-REPORT.json.tmp-*"))
    assert any(
        item.code == "verify-report"
        and item.status == "blocked"
        and "not a regular file" in item.detail
        for item in report.items
    )


def test_existing_regular_verify_report_is_replaced_without_following_links(
    tmp_path: Path,
) -> None:
    project, bundle = _bundle_fixture(tmp_path, "ReplaceReport")

    first = verify_release_bundle(project, bundle_dir=bundle)
    first_bytes = (bundle / "VERIFY-REPORT.json").read_bytes()
    (bundle / "SIGNING-REPORT.json").write_bytes(b'{"status":"planned"}\xff\n')
    second = verify_release_bundle(project, bundle_dir=bundle)

    assert first_bytes == (bundle / "VERIFY-REPORT.json").read_bytes()
    assert second.blocked
    assert second.bundle_identity is None
    assert first.status in {"blocked", "review", "ready"}


def test_release_signature_verification_passes_only_held_descriptors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = tmp_path / "signed-bundle"
    bundle.mkdir()
    keyring = bundle / SIGNING_KEYRING
    keyring.write_bytes(b"pinned public keyring")
    required = sorted(f"{name}.asc" for name in SIGN_TARGETS)
    for asc_name in required:
        (bundle / asc_name).write_bytes(b"detached signature")
        (bundle / asc_name.removesuffix(".asc")).write_bytes(b"signed payload")
    calls: list[tuple[int, int, int]] = []

    def verify_with_descriptors(
        runner: CommandRunner,
        signature: Path,
        payload: Path,
        keyring_path: Path,
        expected_fingerprint: str,
        *,
        signature_fd: int | None = None,
        payload_fd: int | None = None,
        keyring_fd: int | None = None,
    ) -> tuple[str, ...]:
        del runner, signature, payload, keyring_path
        assert expected_fingerprint == _FINGERPRINT
        assert signature_fd is not None
        assert payload_fd is not None
        assert keyring_fd is not None
        assert all(
            os.path.exists(f"/proc/{os.getpid()}/fd/{descriptor}")
            for descriptor in (signature_fd, payload_fd, keyring_fd)
        )
        calls.append((signature_fd, payload_fd, keyring_fd))
        return (_FINGERPRINT,)

    monkeypatch.setattr(
        CommandRunner,
        "has_binary",
        staticmethod(lambda name: name == "gpg"),
    )
    monkeypatch.setattr(
        release_verification,
        "verify_detached_signature",
        verify_with_descriptors,
    )
    items: list[ReleaseVerifyItem] = []

    _verify_signatures(
        bundle,
        {
            "status": "signed",
            "execute": True,
            "signed": required,
            "planned": [],
            "skipped": [],
            "signer_fingerprint": _FINGERPRINT,
            "verification_keyring": SIGNING_KEYRING,
            "verification_keyring_sha256": hashlib.sha256(keyring.read_bytes()).hexdigest(),
        },
        items,
        _FINGERPRINT,
    )

    assert len(calls) == len(required)
    assert all(
        item.status == "ready"
        for item in items
        if item.code in {"signature", "signature-fingerprint", "signature-keyring"}
    )
