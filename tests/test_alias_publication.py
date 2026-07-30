from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest

import distroforge.core.evidence_run as evidence_run_module
from distroforge.cli import main
from distroforge.core.boot_proof import run_boot_proof
from distroforge.core.build import BuildOptions
from distroforge.core.command import CommandRunner
from distroforge.core.evidence_run import (
    ImmutableCopyReceipt,
    copy_immutable_file_descriptor,
    evidence_run_path,
    reserve_evidence_run,
    write_text_alias,
)
from distroforge.core.iso_build import run_iso_build
from distroforge.core.project import Project
from distroforge.core.provenance import ProvenanceOptions, ProvenanceService

ROOT = Path(__file__).resolve().parents[1]


def _alias_receipt(report: Any) -> dict[str, Any]:
    assert report.alias_publication_receipt is not None
    return json.loads(
        report.alias_publication_receipt.read_text(encoding="utf-8")
    )


def _ready_plan_project(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    name: str,
) -> Project:
    monkeypatch.setattr(
        "distroforge.core.iso_doctor.CommandRunner.has_binary",
        lambda *args: True,
    )
    project = Project.create(name, tmp_path / name.lower(), "26.04")
    project.source_mode = "bootstrap"
    project.save()
    return project


def test_text_alias_is_no_replace_and_idempotent(tmp_path: Path) -> None:
    parent = tmp_path / "aliases"
    parent.mkdir()
    target = parent / "latest.json"

    first = write_text_alias(target, '{"status":"ready"}\n')
    second = write_text_alias(target, '{"status":"ready"}\n')

    assert second == first
    assert target.read_text(encoding="utf-8") == '{"status":"ready"}\n'
    with pytest.raises(FileExistsError):
        write_text_alias(target, '{"status":"blocked"}\n')
    assert target.read_text(encoding="utf-8") == '{"status":"ready"}\n'


def test_text_alias_refuses_a_symlink_without_touching_its_victim(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "aliases"
    parent.mkdir()
    victim = tmp_path / "victim.json"
    victim_bytes = b'{"external":true}\n'
    victim.write_bytes(victim_bytes)
    target = parent / "latest.json"
    target.symlink_to(victim)

    with pytest.raises(ValueError, match="regular file"):
        write_text_alias(target, '{"status":"ready"}\n')

    assert target.is_symlink()
    assert victim.read_bytes() == victim_bytes


def test_text_alias_parent_swap_blocks_without_writing_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "aliases"
    parent.mkdir()
    moved = tmp_path / "aliases-held"
    target = parent / "latest.json"
    victim_bytes = b"foreign parent\n"
    real_publish = evidence_run_module.publish_regular_text
    swapped = False

    def publish_after_parent_swap(
        path: Path,
        content: str,
        *,
        max_bytes: int,
        expected_parent_identity: Any,
    ) -> ImmutableCopyReceipt:
        nonlocal swapped
        if not swapped:
            swapped = True
            parent.rename(moved)
            parent.mkdir()
            (parent / "victim.txt").write_bytes(victim_bytes)
        return real_publish(
            path,
            content,
            max_bytes=max_bytes,
            expected_parent_identity=expected_parent_identity,
        )

    monkeypatch.setattr(
        evidence_run_module,
        "publish_regular_text",
        publish_after_parent_swap,
    )

    with pytest.raises(ValueError, match="parent identity changed"):
        write_text_alias(target, '{"status":"ready"}\n')

    assert swapped
    assert {entry.name for entry in parent.iterdir()} == {"victim.txt"}
    assert (parent / "victim.txt").read_bytes() == victim_bytes
    assert not (moved / target.name).exists()


def test_iso_build_two_plans_seal_exact_alias_receipts_in_their_manifests(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _ready_plan_project(monkeypatch, tmp_path, "AliasTransactions")
    alias = project.output_dir / "ISO-BUILD.plan.json"

    first = run_iso_build(project, BuildOptions(), execute=False)
    first_alias = alias.read_bytes()
    second = run_iso_build(project, BuildOptions(), execute=False)

    first_receipt = _alias_receipt(first)
    second_receipt = _alias_receipt(second)
    assert first_receipt["status"] == "matched"
    assert second_receipt["status"] == "collision-preserved"
    assert first_receipt["target"] == second_receipt["target"] == str(alias)
    assert alias.read_bytes() == first_alias

    for report, receipt in ((first, first_receipt), (second, second_receipt)):
        assert report.alias_target == alias
        assert report.alias_report == alias
        assert report.alias_publication_receipt is not None
        report_bytes = report.report.read_bytes()
        assert receipt["schema"] == "distroforge.iso-build-alias-publication.v1"
        assert receipt["run_id"] == report.run_id
        assert receipt["authoritative_report"] == {
            "path": str(report.report),
            "size": len(report_bytes),
            "sha256": hashlib.sha256(report_bytes).hexdigest(),
        }
        immutable_payload = json.loads(report_bytes)
        assert immutable_payload["alias_target"] == str(alias)
        assert immutable_payload["alias_report"] == str(alias)
        assert immutable_payload["alias_publication_receipt"] == str(
            report.alias_publication_receipt
        )

        assert report.run_manifest is not None
        manifest_bytes = report.run_manifest.read_bytes()
        manifest = json.loads(manifest_bytes)
        receipt_entries = [
            item
            for item in manifest["files"]
            if item["path"] == str(report.alias_publication_receipt)
        ]
        assert len(receipt_entries) == 1
        receipt_bytes = report.alias_publication_receipt.read_bytes()
        assert receipt_entries[0]["role"] == "iso-build-alias-publication"
        assert receipt_entries[0]["size"] == len(receipt_bytes)
        assert receipt_entries[0]["sha256"] == hashlib.sha256(
            receipt_bytes
        ).hexdigest()
        sidecar = report.run_manifest.with_name(
            f"{report.run_manifest.name}.sha256"
        )
        assert sidecar.read_text(encoding="utf-8") == (
            f"{hashlib.sha256(manifest_bytes).hexdigest()}  "
            f"{report.run_manifest.name}\n"
        )


def test_iso_build_alias_concurrent_link_collision_is_preserved_and_receipted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _ready_plan_project(monkeypatch, tmp_path, "AliasConcurrent")
    alias = project.output_dir / "ISO-BUILD.plan.json"
    competitor = b'{"competitor":true}\n'
    real_link = evidence_run_module.os.link
    alias_attempts = 0

    def inject_before_alias_link(
        source_name: str,
        target_name: str,
        **kwargs: Any,
    ) -> None:
        nonlocal alias_attempts
        destination_fd = kwargs.get("dst_dir_fd")
        destination_parent = (
            Path(os.readlink(f"/proc/self/fd/{destination_fd}"))
            if isinstance(destination_fd, int)
            else None
        )
        if target_name == alias.name and destination_parent == alias.parent:
            alias_attempts += 1
            if alias_attempts == 1:
                alias.write_bytes(competitor)
        real_link(source_name, target_name, **kwargs)

    monkeypatch.setattr(evidence_run_module.os, "link", inject_before_alias_link)

    report = run_iso_build(project, BuildOptions(), execute=False)

    assert alias_attempts == 1
    assert alias.read_bytes() == competitor
    assert _alias_receipt(report)["status"] == "collision-preserved"


@pytest.mark.parametrize("target_kind", ("symlink", "fifo"))
def test_iso_build_alias_special_collision_never_opens_or_mutates_the_target(
    target_kind: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _ready_plan_project(monkeypatch, tmp_path, f"Alias{target_kind}")
    alias = project.output_dir / "ISO-BUILD.plan.json"
    victim = tmp_path / "victim.json"
    victim_bytes = b'{"victim":true}\n'
    victim.write_bytes(victim_bytes)
    if target_kind == "symlink":
        alias.symlink_to(victim)
    else:
        os.mkfifo(alias)

    report = run_iso_build(project, BuildOptions(), execute=False)

    assert _alias_receipt(report)["status"] == "collision-preserved"
    assert victim.read_bytes() == victim_bytes
    if target_kind == "symlink":
        assert alias.is_symlink()
    else:
        assert stat.S_ISFIFO(alias.lstat().st_mode)


def test_iso_build_alias_post_link_fsync_failure_is_unconfirmed_not_removed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _ready_plan_project(monkeypatch, tmp_path, "AliasPostLink")
    alias = project.output_dir / "ISO-BUILD.plan.json"
    real_link = evidence_run_module.os.link
    real_fsync = evidence_run_module.os.fsync
    alias_linked = False
    injected = False

    def observe_alias_link(
        source_name: str,
        target_name: str,
        **kwargs: Any,
    ) -> None:
        nonlocal alias_linked
        real_link(source_name, target_name, **kwargs)
        destination_fd = kwargs.get("dst_dir_fd")
        destination_parent = (
            Path(os.readlink(f"/proc/self/fd/{destination_fd}"))
            if isinstance(destination_fd, int)
            else None
        )
        if target_name == alias.name and destination_parent == alias.parent:
            alias_linked = True

    def fail_first_post_alias_directory_fsync(file_descriptor: int) -> None:
        nonlocal injected
        if (
            alias_linked
            and not injected
            and stat.S_ISDIR(os.fstat(file_descriptor).st_mode)
        ):
            injected = True
            raise OSError("simulated post-link alias fsync failure")
        real_fsync(file_descriptor)

    monkeypatch.setattr(evidence_run_module.os, "link", observe_alias_link)
    monkeypatch.setattr(evidence_run_module.os, "fsync", fail_first_post_alias_directory_fsync)

    report = run_iso_build(project, BuildOptions(), execute=False)

    receipt = _alias_receipt(report)
    assert alias_linked and injected
    assert receipt["status"] == "unconfirmed"
    assert "may have been linked" in receipt["detail"]
    assert alias.read_bytes() == report.report.read_bytes()


def test_iso_build_alias_collisions_do_not_leak_file_descriptors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _ready_plan_project(monkeypatch, tmp_path, "AliasDescriptors")
    run_iso_build(project, BuildOptions(), execute=False)
    descriptors_before = len(tuple(Path("/proc/self/fd").iterdir()))

    for _ in range(4):
        report = run_iso_build(project, BuildOptions(), execute=False)
        assert _alias_receipt(report)["status"] == "collision-preserved"

    descriptors_after = len(tuple(Path("/proc/self/fd").iterdir()))
    assert descriptors_after == descriptors_before


def test_iso_build_cli_reports_optional_alias_target_and_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = _ready_plan_project(monkeypatch, tmp_path, "AliasCli")

    main(["iso-build", str(project.root), "--json"])

    payload = json.loads(capsys.readouterr().out)
    alias = project.output_dir / "ISO-BUILD.plan.json"
    receipt_path = Path(payload["alias_publication_receipt"])
    assert payload["alias_report"] == payload["alias_target"] == str(alias)
    assert receipt_path.name == "ISO-BUILD-ALIAS-PUBLICATION.json"
    assert receipt_path.parent == Path(payload["report"]).parent
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["run_id"] == payload["run_id"]
    assert receipt["target"] == str(alias)
    assert receipt["status"] == "matched"


def test_iso_build_canonicalises_a_relative_custom_output_before_sealing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _ready_plan_project(monkeypatch, tmp_path, "RelativeOutput")
    monkeypatch.chdir(tmp_path)

    report = run_iso_build(
        project,
        BuildOptions(output_iso=Path("custom/RelativeOutput.iso")),
        execute=False,
    )

    assert report.output_iso == tmp_path / "custom" / "RelativeOutput.iso"
    immutable = json.loads(report.report.read_text(encoding="utf-8"))
    assert immutable["output_iso"] == str(report.output_iso)


def test_provenance_alias_collision_preserves_first_alias_and_receipts_each_run(
    tmp_path: Path,
) -> None:
    project = Project.create("ProvenanceAlias", tmp_path / "provenance-alias", "26.04")
    alias = project.output_dir / "distroforge-provenance.json"
    receipts: list[dict[str, Any]] = []

    for run_id in ("provenance-run-one", "provenance-run-two"):
        reserve_evidence_run(project.output_dir, run_id, executed=False)
        context: dict[str, object] = {"run_id": run_id, "mode": "plan"}
        ProvenanceService(
            CommandRunner(dry_run=False),
            project,
            ProvenanceOptions(),
            evidence_context=context,
        ).write()
        receipt_path = evidence_run_path(
            project.output_dir,
            run_id,
            "distroforge-provenance.json.alias-publication.json",
            executed=False,
        )
        receipts.append(json.loads(receipt_path.read_text(encoding="utf-8")))

    first_immutable = evidence_run_path(
        project.output_dir,
        "provenance-run-one",
        "distroforge-provenance.json",
        executed=False,
    )
    second_immutable = evidence_run_path(
        project.output_dir,
        "provenance-run-two",
        "distroforge-provenance.json",
        executed=False,
    )
    assert alias.read_bytes() == first_immutable.read_bytes()
    assert alias.read_bytes() != second_immutable.read_bytes()
    assert [receipt["status"] for receipt in receipts] == [
        "matched",
        "collision-preserved",
    ]
    assert receipts[1]["authoritative_document"] == {
        "path": str(second_immutable),
        "size": second_immutable.stat().st_size,
        "sha256": hashlib.sha256(second_immutable.read_bytes()).hexdigest(),
    }


def test_descriptor_copy_idempotence_accepts_only_identical_bytes(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.json"
    source.write_bytes(b'{"status":"ready"}\n')
    different = tmp_path / "different.json"
    different.write_bytes(b'{"status":"other"}\n')
    target = tmp_path / "alias.json"
    source_fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC)
    different_fd = os.open(different, os.O_RDONLY | os.O_CLOEXEC)
    try:
        first = copy_immutable_file_descriptor(
            source_fd,
            target,
            idempotent=True,
        )
        second = copy_immutable_file_descriptor(
            source_fd,
            target,
            idempotent=True,
        )
        with pytest.raises(FileExistsError):
            copy_immutable_file_descriptor(
                different_fd,
                target,
                idempotent=True,
            )
    finally:
        os.close(different_fd)
        os.close(source_fd)

    assert second == first
    assert target.read_bytes() == source.read_bytes()


@pytest.mark.parametrize("kind", ("directory", "fifo"))
def test_descriptor_copy_idempotence_refuses_special_targets_without_waiting(
    kind: str,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.json"
    source.write_bytes(b'{"status":"ready"}\n')
    target = tmp_path / "alias.json"
    if kind == "directory":
        target.mkdir()
    else:
        os.mkfifo(target)
    source_fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC)
    try:
        with pytest.raises(ValueError, match="regular file"):
            copy_immutable_file_descriptor(
                source_fd,
                target,
                idempotent=True,
            )
    finally:
        os.close(source_fd)


def test_descriptor_copy_idempotent_name_swap_blocks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.json"
    content = b'{"status":"ready"}\n'
    source.write_bytes(content)
    target = tmp_path / "alias.json"
    target.write_bytes(content)
    displaced = tmp_path / "displaced.json"
    real_rehash = evidence_run_module._rehash_held_regular_fd
    attacked = False

    def rehash_then_swap(
        file_descriptor: int,
        *,
        max_bytes: int,
        label: str,
    ) -> ImmutableCopyReceipt:
        nonlocal attacked
        receipt = real_rehash(
            file_descriptor,
            max_bytes=max_bytes,
            label=label,
        )
        if label == "existing immutable copy target" and not attacked:
            attacked = True
            target.rename(displaced)
            target.write_bytes(content)
        return receipt

    monkeypatch.setattr(
        evidence_run_module,
        "_rehash_held_regular_fd",
        rehash_then_swap,
    )
    source_fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC)
    try:
        with pytest.raises(ValueError, match="path no longer names its held inode"):
            copy_immutable_file_descriptor(
                source_fd,
                target,
                idempotent=True,
            )
    finally:
        os.close(source_fd)

    assert attacked
    assert displaced.read_bytes() == content
    assert target.read_bytes() == content


def test_descriptor_copy_idempotent_collisions_do_not_leak_descriptors(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.json"
    source.write_bytes(b'{"status":"ready"}\n')
    target = tmp_path / "alias.json"
    source_fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC)
    try:
        copy_immutable_file_descriptor(source_fd, target, idempotent=True)
        descriptors_before = len(tuple(Path("/proc/self/fd").iterdir()))
        for _ in range(32):
            copy_immutable_file_descriptor(source_fd, target, idempotent=True)
        descriptors_after = len(tuple(Path("/proc/self/fd").iterdir()))
    finally:
        os.close(source_fd)

    assert descriptors_after == descriptors_before


def test_descriptor_copy_target_swap_blocks_and_never_unlinks_victim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.json"
    source.write_bytes(b'{"status":"ready"}\n')
    target = tmp_path / "alias.json"
    victim = tmp_path / "victim.json"
    victim_bytes = b'{"external":true}\n'
    victim.write_bytes(victim_bytes)
    real_link = evidence_run_module.os.link
    attacked = False

    def link_after_target_swap(
        source_name: str,
        target_name: str,
        **kwargs: Any,
    ) -> None:
        nonlocal attacked
        if target_name == target.name and not attacked:
            attacked = True
            target.symlink_to(victim)
        real_link(source_name, target_name, **kwargs)

    monkeypatch.setattr(
        evidence_run_module.os,
        "link",
        link_after_target_swap,
    )
    source_fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC)
    try:
        with pytest.raises(ValueError, match="regular file"):
            copy_immutable_file_descriptor(
                source_fd,
                target,
                idempotent=True,
            )
    finally:
        os.close(source_fd)

    assert attacked
    assert target.is_symlink()
    assert victim.read_bytes() == victim_bytes


def test_boot_proof_alias_swap_is_non_authoritative_without_unlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = Project.create("AliasProof", tmp_path / "alias-proof", "26.04")
    iso = project.output_dir / "AliasProof.iso"
    iso.write_bytes(b"iso")
    target = project.output_dir / "boot-proof.plan.json"
    victim = tmp_path / "boot-proof-victim.json"
    victim_bytes = b'{"external":true}\n'
    victim.write_bytes(victim_bytes)
    real_link = evidence_run_module.os.link
    attacked = False

    def link_after_alias_swap(
        source_name: str,
        target_name: str,
        **kwargs: Any,
    ) -> None:
        nonlocal attacked
        destination_fd = kwargs.get("dst_dir_fd")
        destination_parent = (
            Path(os.readlink(f"/proc/self/fd/{destination_fd}"))
            if isinstance(destination_fd, int)
            else None
        )
        if target_name == target.name and destination_parent == target.parent and not attacked:
            attacked = True
            target.symlink_to(victim)
        real_link(source_name, target_name, **kwargs)

    monkeypatch.setattr(
        evidence_run_module.os,
        "link",
        link_after_alias_swap,
    )

    report = run_boot_proof(
        project,
        iso=iso,
        backend="qemu",
        execute=False,
        timeout=120,
    )

    assert attacked, report.notes
    assert report.status == "planned"
    receipt = _alias_receipt(report)
    assert receipt["status"] == "collision-preserved"
    assert receipt["target"] == str(target)
    assert receipt["authoritative_report"]["path"] == str(
        report.immutable_proof
    )
    assert target.is_symlink()
    assert victim.read_bytes() == victim_bytes
    assert not tuple(project.output_dir.glob(".boot-proof.json.staged-*"))


def test_boot_proof_different_alias_bytes_preserve_first_without_downgrade(
    tmp_path: Path,
) -> None:
    project = Project.create("AliasProof", tmp_path / "alias-proof", "26.04")
    iso = project.output_dir / "AliasProof.iso"
    iso.write_bytes(b"iso")
    target = project.output_dir / "boot-proof.plan.json"

    first = run_boot_proof(
        project,
        iso=iso,
        backend="qemu",
        execute=False,
        timeout=120,
    )
    sealed_alias = target.read_bytes()
    second = run_boot_proof(
        project,
        iso=iso,
        backend="qemu",
        execute=False,
        timeout=120,
    )

    assert first.status == "planned"
    assert second.status == "planned"
    assert _alias_receipt(first)["status"] == "matched"
    assert _alias_receipt(second)["status"] == "collision-preserved"
    assert target.read_bytes() == sealed_alias
    assert second.alias_publication_receipt is not None
    manifest = json.loads(second.run_manifest.read_text(encoding="utf-8"))
    receipt_identity = next(
        item
        for item in manifest["files"]
        if item["path"] == str(second.alias_publication_receipt)
    )
    receipt_bytes = second.alias_publication_receipt.read_bytes()
    assert receipt_identity["size"] == len(receipt_bytes)
    assert receipt_identity["sha256"] == hashlib.sha256(receipt_bytes).hexdigest()


def test_alias_writers_contain_no_replace_or_unlink_by_name() -> None:
    boot_source = (ROOT / "distroforge/core/boot_proof.py").read_text(encoding="utf-8")
    evidence_source = (ROOT / "distroforge/core/evidence_run.py").read_text(encoding="utf-8")

    assert "os.replace(" not in boot_source
    assert "os.unlink(" not in boot_source
    assert "os.replace(" not in evidence_source
    assert "os.unlink(" not in evidence_source
