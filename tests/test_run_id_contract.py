from __future__ import annotations

import json
from pathlib import Path

import pytest

from distroforge.core import release_verification
from distroforge.core.command import CommandRunner
from distroforge.core.iso_evidence import (
    IsoAssemblyEvidenceError,
    write_iso_assembly_evidence,
)
from distroforge.core.package_apt_actions import (
    PackageAptActionsError,
    build_package_apt_actions_report,
)
from distroforge.core.package_causality import (
    PackageFilesystemCausalityError,
    validate_package_filesystem_causality,
    write_package_filesystem_causality,
)
from distroforge.core.package_evidence import (
    validate_package_apt_actions_evidence,
    validate_package_evidence,
)
from distroforge.core.prebuild_vm import (
    PrebuildVmOptions,
    QemuLabService,
)
from distroforge.core.release_gate import _qemu_run_binding_error
from distroforge.core.release_verification import (
    _descriptor_tree_inventory,
    _verify_runtime_evidence,
)
from distroforge.core.rootfs_evidence import (
    RootfsEvidenceError,
    RootfsEvidenceService,
    validate_replayed_rootfs_payloads,
    validate_rootfs_evidence,
)

_UNSAFE_RUN_IDS = (
    "",
    ".",
    "..",
    "parent/child",
    "parent\\child",
    "line\nbreak",
    "nul\x00byte",
    "delete\x7fbyte",
    "\ud800",
    "é" * 128,  # 256 UTF-8 bytes, over the portable component bound.
)


@pytest.mark.parametrize("run_id", _UNSAFE_RUN_IDS)
def test_run_id_producers_reject_noncanonical_components_before_io(
    tmp_path: Path,
    run_id: str,
) -> None:
    with pytest.raises(IsoAssemblyEvidenceError, match="Unsafe ISO assembly run_id"):
        write_iso_assembly_evidence(
            tmp_path / "ISO-ASSEMBLY.json",
            run_id=run_id,
            iso_member="/casper/filesystem.squashfs",
            output_iso={},
            staged_squashfs={},
            embedded_squashfs={},
        )

    with pytest.raises(RootfsEvidenceError, match="Unsafe rootfs evidence run_id"):
        RootfsEvidenceService(tmp_path / "rootfs", run_id=run_id)

    with pytest.raises(ValueError, match="QEMU lab requires a safe run_id"):
        QemuLabService(
            CommandRunner(dry_run=True),
            tmp_path / "product.iso",
            tmp_path / "work",
            tmp_path / "output",
            PrebuildVmOptions(),
            run_id=run_id,
        )

    with pytest.raises(PackageFilesystemCausalityError, match="run_id is unsafe"):
        write_package_filesystem_causality(
            tmp_path / "run",
            run_id,
            CommandRunner(dry_run=False),
        )

    with pytest.raises(PackageAptActionsError, match="run_id is unsafe"):
        build_package_apt_actions_report(
            run_id=run_id,
            package_inputs={},
            package_inputs_identity={},
            journal_identity={},
            transactions=(),
            captures=(),
        )


@pytest.mark.parametrize("run_id", _UNSAFE_RUN_IDS)
def test_run_id_readers_block_noncanonical_components_before_path_lookup(
    tmp_path: Path,
    run_id: str,
) -> None:
    rootfs = validate_rootfs_evidence(tmp_path / "missing", expected_run_id=run_id)
    assert not rootfs.ok
    assert "unsafe" in rootfs.detail

    replay = validate_replayed_rootfs_payloads(
        {},
        {},
        expected_run_id=run_id,
    )
    assert not replay.ok
    assert "unsafe" in replay.detail

    package = validate_package_evidence(
        tmp_path / "missing",
        expected_run_id=run_id,
        expected_source_mode="bootstrap",
        expected_signer_fingerprints=(),
        expected_keyring_sha256=None,
    )
    assert not package.ok
    assert "unsafe" in package.detail

    apt_actions = validate_package_apt_actions_evidence(
        tmp_path / "missing",
        expected_run_id=run_id,
    )
    assert not apt_actions.ok
    assert "unsafe" in apt_actions.detail

    causality = validate_package_filesystem_causality(
        tmp_path / "missing",
        run_id,
        CommandRunner(dry_run=False),
    )
    assert not causality.ok
    assert "unsafe" in causality.detail

    qemu_binding = _qemu_run_binding_error(
        tmp_path / "output",
        tmp_path / "product.iso",
        "qemu.json",
        {"run_id": run_id},
    )
    assert qemu_binding == "QEMU report has no safe run identity."


@pytest.mark.parametrize("run_id", _UNSAFE_RUN_IDS)
def test_release_verifier_blocks_unsafe_runtime_run_id_without_raw_oserror(
    tmp_path: Path,
    run_id: str,
) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "product.iso").write_bytes(b"ISO")
    (bundle / "boot-proof.json").write_text(
        json.dumps(
            {
                "schema": "distroforge.boot-proof.v2",
                "status": "ready",
                "proof_level": "runtime",
                "selected_backend": "qemu",
                "run_id": run_id,
                "qemu_report": "qemu.json",
                "iso_sha256": "0" * 64,
            },
            ensure_ascii=True,
        )
        + "\n",
        encoding="utf-8",
    )
    inventory = _descriptor_tree_inventory(bundle)
    items: list[release_verification.ReleaseVerifyItem] = []
    session = release_verification.ArtifactVerificationSession(
        bundle,
        label="unsafe runtime run-id test",
    )
    try:
        _verify_runtime_evidence(
            bundle,
            items,
            session=session,
            inventory=inventory,
            gate={
                "build_run_id": "build-run",
                "boot_run_id": "boot-run",
            },
        )
    finally:
        session.close()

    assert items
    assert items[-1].status == "blocked"
    assert "OSError" not in items[-1].detail
