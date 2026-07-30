from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.util
import json
import os
import py_compile
import stat
from pathlib import Path

import pytest
from conftest import (
    package_fixture_options,
    write_valid_boot_proof,
    write_valid_build_evidence,
)

import distroforge.core.evidence_run as evidence_run_module
import distroforge.core.release_gate as release_gate_module
import distroforge.core.release_run as release_run_module
from distroforge.core.beginner_iso import repair_beginner_iso_release_artifacts
from distroforge.core.build import BuildOptions
from distroforge.core.command import CommandRunner, CommandSpec, _execution_chain
from distroforge.core.evidence_run import (
    TOOLCHAIN_BINARIES,
    builder_source_identity,
    canonical_sha256,
    close_run_identity,
    copy_immutable_file,
    copy_immutable_file_descriptor,
    copy_immutable_tree,
    first_symlink_in_confined_tree,
    make_run_context,
    observed_executable_counts,
    owned_temporary_directory,
    publish_immutable_tree,
    publish_regular_text,
    reserve_evidence_run,
    toolchain_identity,
    write_immutable_text,
)
from distroforge.core.iso_build import run_iso_build
from distroforge.core.project import Project
from distroforge.core.release_gate import (
    ReleaseGateService,
    _git_builder_publication_problem,
    _identity_closure_problem,
    _provenance_is_bootstrap,
)


def test_evidence_run_id_is_bounded_by_portable_component_bytes() -> None:
    assert evidence_run_module.is_safe_run_id("r" * 255)
    assert not evidence_run_module.is_safe_run_id("r" * 256)
    assert not evidence_run_module.is_safe_run_id("é" * 128)


def test_iso_starter_does_not_invent_bootstrap_tool_roles() -> None:
    assert _provenance_is_bootstrap(
        {
            "source_mode": "bootstrap",
            "source_starter": {"kind": "skeleton"},
        }
    )
    assert not _provenance_is_bootstrap(
        {
            "source_mode": "iso",
            "source_starter": {"kind": "official-iso"},
        }
    )


def test_a_plan_cannot_replace_the_last_executed_build_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        "distroforge.core.iso_doctor.CommandRunner.has_binary",
        lambda *args: True,
    )
    project = Project.create("Immutable", tmp_path / "immutable", "26.04")
    project.source_mode = "bootstrap"
    options = BuildOptions()

    class _Built:
        steps: tuple[object, ...] = ()

    def _build(self) -> _Built:
        self.runner.run(
            CommandSpec(
                ("python3", "-c", "pass"),
                description="record one real build command",
            )
        )
        if not self.runner.dry_run:
            self.options.output_iso.write_bytes(b"sealed ISO")
        return _Built()

    monkeypatch.setattr("distroforge.core.iso_build.BuildOrchestrator.run", _build)

    executed = run_iso_build(project, options, execute=True)
    executed_alias = project.output_dir / "ISO-BUILD.json"
    sealed_alias = executed_alias.read_bytes()
    planned = run_iso_build(project, options, execute=False)

    assert executed.run_id != planned.run_id
    assert executed.report != planned.report
    assert executed.command_log != planned.command_log
    assert executed_alias.read_bytes() == sealed_alias
    assert (project.output_dir / "ISO-BUILD.plan.json").read_bytes() == planned.report.read_bytes()
    assert json.loads(executed.report.read_text(encoding="utf-8"))["execute"] is True
    assert json.loads(planned.report.read_text(encoding="utf-8"))["execute"] is False


def test_repeated_plans_keep_the_first_alias_and_return_fresh_typed_evidence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        "distroforge.core.iso_doctor.CommandRunner.has_binary",
        lambda *args: True,
    )
    project = Project.create("RepeatedPlan", tmp_path / "repeated-plan", "26.04")
    project.source_mode = "bootstrap"

    first = run_iso_build(project, BuildOptions(), execute=False)
    alias = project.output_dir / "ISO-BUILD.plan.json"
    first_alias_bytes = alias.read_bytes()
    second = run_iso_build(project, BuildOptions(), execute=False)

    assert first.run_id != second.run_id
    assert first.alias_report == alias
    assert first.alias_target == alias
    assert first.alias_publication_receipt is not None
    assert first.alias_problem is not None
    assert second.alias_report == alias
    assert second.alias_target == alias
    assert second.alias_publication_receipt is not None
    assert second.alias_problem is not None
    assert "non-authoritative target" in second.alias_problem
    assert alias.read_bytes() == first_alias_bytes
    assert second.report.is_file()
    assert second.run_manifest is not None
    assert second.run_manifest.is_file()
    written = json.loads(second.report.read_text(encoding="utf-8"))
    assert written["alias_report"] == str(alias)
    assert written["alias_target"] == str(alias)
    assert written["alias_publication_receipt"] == str(
        second.alias_publication_receipt
    )
    assert written["alias_problem"] == second.alias_problem
    first_receipt = json.loads(
        first.alias_publication_receipt.read_text(encoding="utf-8")
    )
    second_receipt = json.loads(
        second.alias_publication_receipt.read_text(encoding="utf-8")
    )
    assert first_receipt["status"] == "matched"
    assert second_receipt["status"] == "collision-preserved"


def test_a_run_id_collision_is_refused_before_evidence_can_mix(tmp_path: Path) -> None:
    output = tmp_path / "dist"
    reserve_evidence_run(output, "same-run", executed=True)

    with pytest.raises(FileExistsError):
        reserve_evidence_run(output, "same-run", executed=True)


@pytest.mark.parametrize(
    "run_id",
    ("", ".", "..", "a/b", "a\\b", "a\nb", "a\x7fb", "\ud800"),
)
def test_evidence_run_paths_refuse_noncanonical_run_ids(
    tmp_path: Path,
    run_id: str,
) -> None:
    with pytest.raises(ValueError, match="invalid evidence run_id"):
        evidence_run_module.evidence_run_path(
            tmp_path,
            run_id,
            "proof.json",
            executed=True,
        )


def test_immutable_text_is_synced_before_atomic_no_replace_publication(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "run" / "proof.json"
    events: list[str] = []
    real_fsync = os.fsync
    real_link = os.link

    def recording_fsync(file_descriptor: int) -> None:
        kind = "directory" if stat.S_ISDIR(os.fstat(file_descriptor).st_mode) else "file"
        events.append(f"fsync-{kind}")
        real_fsync(file_descriptor)

    def recording_link(
        source: str,
        destination: str,
        **kwargs: object,
    ) -> None:
        events.append("link")
        real_link(source, destination, **kwargs)

    monkeypatch.setattr(evidence_run_module.os, "fsync", recording_fsync)
    monkeypatch.setattr(evidence_run_module.os, "link", recording_link)

    write_immutable_text(target, '{"sealed": true}\n')

    assert target.read_bytes() == b'{"sealed": true}\n'
    assert target.stat().st_nlink == 1
    assert events == [
        "fsync-directory",
        "fsync-file",
        "link",
        "fsync-directory",
    ]
    assert list(target.parent.glob(f".{target.name}.tmp-*")) == []


def test_immutable_text_refuses_existing_file_and_symlink_destinations(
    tmp_path: Path,
) -> None:
    existing = tmp_path / "existing.json"
    existing.write_text("original\n", encoding="utf-8")

    with pytest.raises(FileExistsError):
        write_immutable_text(existing, "replacement\n")

    assert existing.read_text(encoding="utf-8") == "original\n"
    assert list(tmp_path.glob(f".{existing.name}.tmp-*")) == []

    external = tmp_path / "external.json"
    external.write_text("external\n", encoding="utf-8")
    linked = tmp_path / "linked.json"
    linked.symlink_to(external)

    with pytest.raises(FileExistsError):
        write_immutable_text(linked, "replacement\n")

    assert linked.is_symlink()
    assert external.read_text(encoding="utf-8") == "external\n"
    assert list(tmp_path.glob(f".{linked.name}.tmp-*")) == []


def test_immutable_text_fsync_failure_cannot_publish_partial_evidence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "proof.json"
    publication_attempted = False
    real_fsync = os.fsync

    def failing_file_fsync(file_descriptor: int) -> None:
        if stat.S_ISREG(os.fstat(file_descriptor).st_mode):
            raise OSError("simulated file fsync failure")
        real_fsync(file_descriptor)

    def unexpected_link(*args: object, **kwargs: object) -> None:
        nonlocal publication_attempted
        publication_attempted = True

    monkeypatch.setattr(evidence_run_module.os, "fsync", failing_file_fsync)
    monkeypatch.setattr(evidence_run_module.os, "link", unexpected_link)

    with pytest.raises(OSError, match="simulated file fsync failure"):
        write_immutable_text(target, "must not become partial\n")

    assert publication_attempted is False
    assert not target.exists()
    assert list(tmp_path.glob(f".{target.name}.tmp-*")) == []


def test_immutable_text_directory_fsync_failure_leaves_only_complete_evidence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "proof.json"
    real_fsync = os.fsync

    def failing_directory_fsync(file_descriptor: int) -> None:
        if stat.S_ISDIR(os.fstat(file_descriptor).st_mode):
            raise OSError("simulated directory fsync failure")
        real_fsync(file_descriptor)

    monkeypatch.setattr(
        evidence_run_module.os,
        "fsync",
        failing_directory_fsync,
    )

    with pytest.raises(OSError, match="simulated directory fsync failure"):
        write_immutable_text(target, "complete before publication\n")

    assert target.read_text(encoding="utf-8") == "complete before publication\n"
    assert list(tmp_path.glob(f".{target.name}.tmp-*")) == []


def test_immutable_binary_copy_is_hashed_and_durably_published_no_replace(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"binary evidence bytes")
    target = tmp_path / "sealed" / "target.bin"
    events: list[str] = []
    real_fsync = os.fsync
    real_link = os.link

    def recording_fsync(file_descriptor: int) -> None:
        kind = "directory" if stat.S_ISDIR(os.fstat(file_descriptor).st_mode) else "file"
        events.append(f"fsync-{kind}")
        real_fsync(file_descriptor)

    def recording_link(source_name: str, target_name: str, **kwargs: object) -> None:
        events.append("link")
        real_link(source_name, target_name, **kwargs)

    monkeypatch.setattr(evidence_run_module.os, "fsync", recording_fsync)
    monkeypatch.setattr(evidence_run_module.os, "link", recording_link)

    receipt = copy_immutable_file(source, target)

    assert receipt.size == len(b"binary evidence bytes")
    assert receipt.sha256 == hashlib.sha256(b"binary evidence bytes").hexdigest()
    assert target.read_bytes() == b"binary evidence bytes"
    assert target.stat().st_nlink == 1
    assert events == [
        "fsync-directory",
        "fsync-file",
        "link",
        "fsync-directory",
    ]
    assert list(target.parent.glob(f".{target.name}.tmp-*")) == []


def test_immutable_binary_copy_from_held_fd_preserves_the_callers_offset(
    tmp_path: Path,
) -> None:
    source = tmp_path / "held.bin"
    source.write_bytes(b"held descriptor bytes")
    target = tmp_path / "sealed.bin"
    source_fd = os.open(source, os.O_RDONLY)
    try:
        os.lseek(source_fd, 5, os.SEEK_SET)
        receipt = copy_immutable_file_descriptor(source_fd, target)

        assert os.lseek(source_fd, 0, os.SEEK_CUR) == 5
    finally:
        os.close(source_fd)

    assert target.read_bytes() == source.read_bytes()
    assert receipt.sha256 == hashlib.sha256(source.read_bytes()).hexdigest()


@pytest.mark.parametrize("kind", ("symlink", "directory", "fifo"))
def test_immutable_binary_copy_refuses_every_non_regular_source_without_waiting(
    kind: str,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    if kind == "symlink":
        external = tmp_path / "external"
        external.write_bytes(b"external bytes")
        source.symlink_to(external)
    elif kind == "directory":
        source.mkdir()
    else:
        os.mkfifo(source)
    target = tmp_path / "target"

    with pytest.raises((OSError, ValueError)):
        copy_immutable_file(source, target)

    assert not target.exists()
    assert list(tmp_path.glob(f".{target.name}.tmp-*")) == []


def test_immutable_binary_copy_never_creates_through_a_symlinked_target_parent(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"sealed bytes")
    outside = tmp_path / "outside"
    outside.mkdir()
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(outside, target_is_directory=True)

    with pytest.raises(OSError):
        copy_immutable_file(source, linked_parent / "target.bin")

    assert not (outside / "target.bin").exists()
    assert list(outside.iterdir()) == []


def test_immutable_binary_copy_write_failure_cannot_publish_partial_bytes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"must remain complete")
    target = tmp_path / "target.bin"
    real_write = os.write
    calls = 0

    def failing_write(file_descriptor: int, content: bytes) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            return real_write(file_descriptor, content[:3])
        raise OSError("simulated write failure")

    monkeypatch.setattr(evidence_run_module.os, "write", failing_write)

    with pytest.raises(OSError, match="simulated write failure"):
        copy_immutable_file(source, target)

    assert not target.exists()
    assert list(tmp_path.glob(f".{target.name}.tmp-*")) == []


def test_immutable_binary_copy_fsync_failure_prevents_publication(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"must be synced")
    target = tmp_path / "target.bin"
    publication_attempted = False
    real_fsync = os.fsync

    def failing_file_fsync(file_descriptor: int) -> None:
        if stat.S_ISREG(os.fstat(file_descriptor).st_mode):
            raise OSError("simulated binary fsync failure")
        real_fsync(file_descriptor)

    def unexpected_link(*args: object, **kwargs: object) -> None:
        nonlocal publication_attempted
        publication_attempted = True

    monkeypatch.setattr(evidence_run_module.os, "fsync", failing_file_fsync)
    monkeypatch.setattr(evidence_run_module.os, "link", unexpected_link)

    with pytest.raises(OSError, match="simulated binary fsync failure"):
        copy_immutable_file(source, target)

    assert publication_attempted is False
    assert not target.exists()
    assert list(tmp_path.glob(f".{target.name}.tmp-*")) == []


def test_immutable_binary_copy_collision_preserves_existing_target(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"new bytes")
    target = tmp_path / "target.bin"
    target.write_bytes(b"existing bytes")

    with pytest.raises(FileExistsError):
        copy_immutable_file(source, target)

    assert target.read_bytes() == b"existing bytes"
    assert list(tmp_path.glob(f".{target.name}.tmp-*")) == []


def test_immutable_binary_copy_link_failure_leaves_no_publication_or_temporary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"complete source")
    target = tmp_path / "target.bin"

    def failing_link(*args: object, **kwargs: object) -> None:
        raise OSError("simulated link failure")

    monkeypatch.setattr(evidence_run_module.os, "link", failing_link)

    with pytest.raises(OSError, match="simulated link failure"):
        copy_immutable_file(source, target)

    assert not target.exists()
    assert list(tmp_path.glob(f".{target.name}.tmp-*")) == []


def test_immutable_binary_copy_directory_fsync_failure_leaves_complete_target(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"complete before directory sync")
    target = tmp_path / "target.bin"
    real_fsync = os.fsync

    def failing_directory_fsync(file_descriptor: int) -> None:
        if stat.S_ISDIR(os.fstat(file_descriptor).st_mode):
            raise OSError("simulated binary directory fsync failure")
        real_fsync(file_descriptor)

    monkeypatch.setattr(evidence_run_module.os, "fsync", failing_directory_fsync)

    with pytest.raises(OSError, match="simulated binary directory fsync failure"):
        copy_immutable_file(source, target)

    assert target.read_bytes() == b"complete before directory sync"
    assert target.stat().st_nlink == 1
    assert list(tmp_path.glob(f".{target.name}.tmp-*")) == []


def test_immutable_binary_copy_never_requires_pathname_unlink(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"fully published bytes")
    target = tmp_path / "target.bin"
    def forbidden_unlink(path: str, **kwargs: object) -> None:
        raise AssertionError(f"unexpected unlink of {path}")

    monkeypatch.setattr(evidence_run_module.os, "unlink", forbidden_unlink)

    copy_immutable_file(source, target)

    assert target.read_bytes() == b"fully published bytes"
    assert target.stat().st_nlink == 1
    assert list(tmp_path.glob(f".{target.name}.tmp-*")) == []


def test_immutable_binary_copy_detects_source_mutation_before_publication(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"opening source bytes")
    target = tmp_path / "target.bin"
    real_read = os.read
    mutated = False

    def mutating_read(file_descriptor: int, size: int) -> bytes:
        nonlocal mutated
        content = real_read(file_descriptor, size)
        if content and not mutated:
            mutated = True
            source.write_bytes(b"changed source bytes")
        return content

    monkeypatch.setattr(evidence_run_module.os, "read", mutating_read)

    with pytest.raises(ValueError, match="source changed"):
        copy_immutable_file(source, target)

    assert not target.exists()
    assert list(tmp_path.glob(f".{target.name}.tmp-*")) == []


def test_immutable_binary_copy_bounds_growth_before_writing_extra_bytes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"x")
    target = tmp_path / "target.bin"
    real_read = os.read
    real_write = os.write
    written = 0
    grown = False

    def growing_read(file_descriptor: int, size: int) -> bytes:
        nonlocal grown
        content = real_read(file_descriptor, size)
        if content and not grown:
            grown = True
            with source.open("ab") as handle:
                handle.write(b"y" * (4 * 1024 * 1024))
        return content

    def counting_write(file_descriptor: int, content: bytes) -> int:
        nonlocal written
        written += len(content)
        return real_write(file_descriptor, content)

    monkeypatch.setattr(evidence_run_module.os, "read", growing_read)
    monkeypatch.setattr(evidence_run_module.os, "write", counting_write)

    with pytest.raises(ValueError, match="grew while it was read"):
        copy_immutable_file(source, target)

    assert written == 1
    assert not target.exists()
    assert list(tmp_path.glob(f".{target.name}.tmp-*")) == []


def test_immutable_binary_copy_has_no_swappable_temporary_name(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"verified source")
    target = tmp_path / "target.bin"
    real_link = os.link
    observed_named_temporary = False

    def swap_before_link(
        source_name: str,
        target_name: str,
        **kwargs: object,
    ) -> None:
        nonlocal observed_named_temporary
        if target_name == target.name:
            observed_named_temporary = bool(
                list(tmp_path.glob(f".{target.name}.tmp-*"))
            )
        real_link(source_name, target_name, **kwargs)

    monkeypatch.setattr(evidence_run_module.os, "link", swap_before_link)

    copy_immutable_file(source, target)

    assert observed_named_temporary is False
    assert target.read_bytes() == b"verified source"


def test_immutable_binary_copy_blocks_a_permission_change_during_link(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"verified source")
    source.chmod(0o600)
    target = tmp_path / "target.bin"
    real_link = os.link

    def chmod_before_link(
        source_name: str,
        target_name: str,
        **kwargs: object,
    ) -> None:
        if target_name == target.name:
            os.chmod(source_name, 0o777)
        real_link(source_name, target_name, **kwargs)

    monkeypatch.setattr(evidence_run_module.os, "link", chmod_before_link)

    with pytest.raises(ValueError, match="permissions changed"):
        copy_immutable_file(source, target)

    assert stat.S_IMODE(target.stat().st_mode) == 0o777


def test_idempotent_descriptor_copy_refuses_different_permissions(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"verified source")
    source.chmod(0o600)
    target = tmp_path / "target.bin"
    target.write_bytes(source.read_bytes())
    target.chmod(0o777)

    source_fd = os.open(source, os.O_RDONLY)
    try:
        with pytest.raises(FileExistsError, match="different permissions"):
            copy_immutable_file_descriptor(
                source_fd,
                target,
                idempotent=True,
            )
    finally:
        os.close(source_fd)

    assert stat.S_IMODE(target.stat().st_mode) == 0o777


@pytest.mark.parametrize("operation", ("binary", "text"))
def test_idempotent_publication_syncs_existing_inode_and_parent(
    operation: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"verified source")
    target = tmp_path / "target.bin"
    target.write_bytes(source.read_bytes())
    target_identity = (target.stat().st_dev, target.stat().st_ino)
    parent_identity = (tmp_path.stat().st_dev, tmp_path.stat().st_ino)
    real_fsync = os.fsync
    synced: set[str] = set()

    def recording_fsync(file_descriptor: int) -> None:
        info = os.fstat(file_descriptor)
        identity = (info.st_dev, info.st_ino)
        if identity == target_identity:
            synced.add("target")
        if identity == parent_identity:
            synced.add("parent")
        real_fsync(file_descriptor)

    monkeypatch.setattr(evidence_run_module.os, "fsync", recording_fsync)

    if operation == "binary":
        source_fd = os.open(source, os.O_RDONLY)
        try:
            copy_immutable_file_descriptor(
                source_fd,
                target,
                idempotent=True,
            )
        finally:
            os.close(source_fd)
    else:
        publish_regular_text(target, "verified source")

    assert synced == {"target", "parent"}


def test_immutable_binary_copy_retains_a_final_target_swap_without_deletion(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"verified source")
    target = tmp_path / "target.bin"
    real_require = evidence_run_module._require_named_held_identity
    attacked = False

    def swap_before_final_identity_check(
        parent_fd: int,
        name: str,
        held_file_fd: int,
        *,
        label: str,
    ) -> None:
        nonlocal attacked
        if not attacked and label == "immutable copy published target":
            attacked = True
            os.rename(
                target.name,
                "moved-held-target",
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
            victim_fd = os.open(
                target.name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=parent_fd,
            )
            try:
                os.write(victim_fd, b"attacker target")
            finally:
                os.close(victim_fd)
        real_require(
            parent_fd,
            name,
            held_file_fd,
            label=label,
        )

    monkeypatch.setattr(
        evidence_run_module,
        "_require_named_held_identity",
        swap_before_final_identity_check,
    )

    with pytest.raises(ValueError, match="path no longer names"):
        copy_immutable_file(source, target)

    assert target.read_bytes() == b"attacker target"
    assert (tmp_path / "moved-held-target").read_bytes() == b"verified source"


def test_immutable_binary_copy_checks_the_target_name_after_its_parent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"verified source")
    target = tmp_path / "target.bin"
    moved = tmp_path / "moved-held-target"
    real_require_parent = evidence_run_module._require_parent_path_identity
    attacked = False

    def swap_after_terminal_parent_check(path: Path, expected) -> None:
        nonlocal attacked
        real_require_parent(path, expected)
        if not attacked and path == target.parent and target.exists():
            attacked = True
            target.rename(moved)
            target.write_bytes(b"attacker target")

    monkeypatch.setattr(
        evidence_run_module,
        "_require_parent_path_identity",
        swap_after_terminal_parent_check,
    )

    with pytest.raises(ValueError, match="path no longer names"):
        copy_immutable_file(source, target)

    assert target.read_bytes() == b"attacker target"
    assert moved.read_bytes() == b"verified source"


def test_idempotent_descriptor_copy_checks_the_target_name_after_its_parent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"verified source")
    target = tmp_path / "target.bin"
    target.write_bytes(source.read_bytes())
    moved = tmp_path / "moved-held-target"
    real_require_parent = evidence_run_module._require_parent_path_identity
    parent_checks = 0

    def swap_after_terminal_parent_check(path: Path, expected) -> None:
        nonlocal parent_checks
        real_require_parent(path, expected)
        if path != target.parent:
            return
        parent_checks += 1
        if parent_checks == 2:
            target.rename(moved)
            target.write_bytes(b"attacker target")

    monkeypatch.setattr(
        evidence_run_module,
        "_require_parent_path_identity",
        swap_after_terminal_parent_check,
    )

    source_fd = os.open(source, os.O_RDONLY)
    try:
        with pytest.raises(ValueError, match="path no longer names"):
            copy_immutable_file_descriptor(
                source_fd,
                target,
                idempotent=True,
            )
    finally:
        os.close(source_fd)

    assert target.read_bytes() == b"attacker target"
    assert moved.read_bytes() == b"verified source"


def test_regular_text_publication_creates_reuses_and_refuses_replacement(
    tmp_path: Path,
) -> None:
    target = tmp_path / "status.json"
    parent_identity = evidence_run_module.stable_parent_identity(tmp_path)

    created = publish_regular_text(
        target,
        '{"status":"created"}\n',
        expected_parent_identity=parent_identity,
    )
    reused = publish_regular_text(
        target,
        '{"status":"created"}\n',
        expected_parent_identity=parent_identity,
    )
    with pytest.raises(FileExistsError, match="different bytes"):
        publish_regular_text(
            target,
            '{"status":"replaced"}\n',
            expected_parent_identity=parent_identity,
        )

    assert created.sha256 == hashlib.sha256(b'{"status":"created"}\n').hexdigest()
    assert reused == created
    assert target.read_text(encoding="utf-8") == '{"status":"created"}\n'
    assert list(tmp_path.glob(f".{target.name}.tmp-*")) == []


def test_regular_text_publication_checks_the_target_name_after_its_parent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "status"
    moved = tmp_path / "moved-held-status"
    real_require_parent = evidence_run_module._require_parent_path_identity
    attacked = False

    def swap_after_terminal_parent_check(path: Path, expected) -> None:
        nonlocal attacked
        real_require_parent(path, expected)
        if not attacked and path == target.parent and target.exists():
            attacked = True
            target.rename(moved)
            target.write_text("attacker\n", encoding="utf-8")

    monkeypatch.setattr(
        evidence_run_module,
        "_require_parent_path_identity",
        swap_after_terminal_parent_check,
    )

    with pytest.raises(ValueError, match="path no longer names"):
        publish_regular_text(target, "verified\n")

    assert target.read_text(encoding="utf-8") == "attacker\n"
    assert moved.read_text(encoding="utf-8") == "verified\n"


def test_regular_text_reuse_checks_the_target_name_after_its_parent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "status"
    target.write_text("verified\n", encoding="utf-8")
    moved = tmp_path / "moved-held-status"
    real_require_parent = evidence_run_module._require_parent_path_identity
    parent_checks = 0

    def swap_after_terminal_parent_check(path: Path, expected) -> None:
        nonlocal parent_checks
        real_require_parent(path, expected)
        if path != target.parent:
            return
        parent_checks += 1
        if parent_checks == 2:
            target.rename(moved)
            target.write_text("attacker\n", encoding="utf-8")

    monkeypatch.setattr(
        evidence_run_module,
        "_require_parent_path_identity",
        swap_after_terminal_parent_check,
    )

    with pytest.raises(ValueError, match="path no longer names"):
        publish_regular_text(target, "verified\n")

    assert target.read_text(encoding="utf-8") == "attacker\n"
    assert moved.read_text(encoding="utf-8") == "verified\n"


def test_regular_text_publication_refuses_a_changed_parent_anchor(
    tmp_path: Path,
) -> None:
    target = tmp_path / "status"
    expected = list(evidence_run_module.stable_parent_identity(tmp_path))
    expected[1] += 1

    with pytest.raises(ValueError, match="parent identity changed before writing"):
        publish_regular_text(
            target,
            "blocked\n",
            expected_parent_identity=tuple(expected),
        )

    assert not target.exists()


def test_regular_text_publication_blocks_a_parent_path_swap(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    parent = tmp_path / "published-parent"
    parent.mkdir()
    target = parent / "status"
    expected_parent = evidence_run_module.stable_parent_identity(parent)
    real_link = os.link
    attacked = False

    def swap_parent_before_link(
        source_name: str,
        target_name: str,
        **kwargs: object,
    ) -> None:
        nonlocal attacked
        if not attacked and target_name == target.name:
            attacked = True
            parent.rename(tmp_path / "moved-held-parent")
            parent.mkdir()
        real_link(source_name, target_name, **kwargs)

    monkeypatch.setattr(evidence_run_module.os, "link", swap_parent_before_link)

    with pytest.raises(ValueError, match="parent path no longer names"):
        publish_regular_text(
            target,
            "held bytes\n",
            expected_parent_identity=expected_parent,
        )

    assert not target.exists()
    assert (tmp_path / "moved-held-parent" / "status").read_text(
        encoding="utf-8"
    ) == "held bytes\n"


def test_regular_text_publication_refuses_symlink_and_preserves_referent(
    tmp_path: Path,
) -> None:
    external = tmp_path / "external"
    external.write_text("external\n", encoding="utf-8")
    target = tmp_path / "status"
    target.symlink_to(external)

    with pytest.raises(ValueError, match="regular file"):
        publish_regular_text(target, "replacement\n")

    assert target.is_symlink()
    assert external.read_text(encoding="utf-8") == "external\n"


def test_regular_text_publication_exposes_no_temporary_path_to_swap(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "status"
    real_link = os.link
    observed_named_temporary = False

    def swap_before_link(
        source_name: str,
        target_name: str,
        **kwargs: object,
    ) -> None:
        nonlocal observed_named_temporary
        if target_name == target.name:
            observed_named_temporary = bool(
                list(tmp_path.glob(f".{target.name}.tmp-*"))
            )
        real_link(source_name, target_name, **kwargs)

    monkeypatch.setattr(evidence_run_module.os, "link", swap_before_link)

    publish_regular_text(target, "verified text\n")

    assert observed_named_temporary is False
    assert target.read_text(encoding="utf-8") == "verified text\n"


def test_regular_text_publication_blocks_metadata_change_during_link(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "status"
    real_link = os.link

    def chmod_before_link(
        source_name: str,
        target_name: str,
        **kwargs: object,
    ) -> None:
        if target_name == target.name:
            os.chmod(source_name, 0o777)
        real_link(source_name, target_name, **kwargs)

    monkeypatch.setattr(evidence_run_module.os, "link", chmod_before_link)

    with pytest.raises(ValueError, match="metadata changed"):
        publish_regular_text(target, "verified text\n")

    assert stat.S_IMODE(target.stat().st_mode) == 0o777


def test_regular_text_refuses_different_existing_bytes_without_exchange(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "status"
    target.write_text("opening target\n", encoding="utf-8")
    def forbidden_exchange(
        parent_fd: int,
        first_name: str,
        second_name: str,
    ) -> None:
        raise AssertionError(
            f"unexpected exchange {first_name!r} -> {second_name!r} in fd {parent_fd}"
        )

    monkeypatch.setattr(
        evidence_run_module,
        "_exchange_entries",
        forbidden_exchange,
    )

    with pytest.raises(FileExistsError, match="different bytes"):
        publish_regular_text(target, "replacement\n")

    assert target.read_text(encoding="utf-8") == "opening target\n"


def test_immutable_tree_copy_is_bounded_and_never_follows_links(
    tmp_path: Path,
) -> None:
    source = tmp_path / "run"
    (source / "nested").mkdir(parents=True)
    (source / "proof.json").write_bytes(b"proof")
    (source / "nested" / "serial.log").write_bytes(b"serial")
    external = tmp_path / "external"
    external.write_bytes(b"must not be copied")
    (source / "nested" / "unsafe").symlink_to(external)
    target = tmp_path / "sealed-run"

    with pytest.raises(ValueError, match="non-regular entry"):
        copy_immutable_tree(source, target, max_files=10, max_bytes=100)

    assert not target.exists()


def test_immutable_tree_copy_reports_exact_files_and_enforces_its_budget(
    tmp_path: Path,
) -> None:
    source = tmp_path / "run"
    (source / "nested").mkdir(parents=True)
    (source / "proof.json").write_bytes(b"proof")
    (source / "nested" / "serial.log").write_bytes(b"serial")
    target = tmp_path / "sealed-run"

    receipt = copy_immutable_tree(source, target, max_files=2, max_bytes=11)

    assert receipt.files == ("nested/serial.log", "proof.json")
    assert receipt.bytes_copied == 11
    assert dict(receipt.digests) == {
        "nested/serial.log": hashlib.sha256(b"serial").hexdigest(),
        "proof.json": hashlib.sha256(b"proof").hexdigest(),
    }
    assert receipt.target_identity == evidence_run_module.full_filesystem_identity(target.stat())
    assert receipt.target_stable_identity == evidence_run_module.stable_identity_from_full(
        receipt.target_identity
    )
    assert (target / "proof.json").read_bytes() == b"proof"
    assert (target / "nested" / "serial.log").read_bytes() == b"serial"

    with pytest.raises(ValueError, match="copy budget"):
        too_small = tmp_path / "too-small"
        copy_immutable_tree(source, too_small, max_files=1)
    assert not too_small.exists()


def test_immutable_tree_copy_bounds_directory_entries_before_staging(
    tmp_path: Path,
) -> None:
    source = tmp_path / "run"
    source.mkdir()
    for index in range(3):
        (source / f"empty-{index}").mkdir()
    target = tmp_path / "sealed-run"

    with pytest.raises(ValueError, match="entry budget"):
        copy_immutable_tree(source, target, max_entries=2)

    assert not target.exists()
    assert list(tmp_path.glob(f".{target.name}.tmp-*")) == []


@pytest.mark.parametrize("operation", ("copy", "publish"))
def test_immutable_tree_depth_is_bounded_before_python_recursion_limit(
    operation: str,
    tmp_path: Path,
) -> None:
    source = tmp_path / "deep-tree"
    source.mkdir()
    current = source
    for _index in range(evidence_run_module._TREE_MAX_DEPTH + 1):
        current /= "d"
        current.mkdir()
    (current / "proof").write_bytes(b"proof")
    target = tmp_path / "published"

    with pytest.raises(ValueError, match="depth budget"):
        if operation == "copy":
            copy_immutable_tree(source, target)
        else:
            publish_immutable_tree(source, target)

    assert not target.exists()


def test_immutable_tree_copy_checks_expected_root_before_inventory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "run"
    source.mkdir()
    (source / "proof").write_bytes(b"proof")
    expected = evidence_run_module.ArtifactIdentity.from_stat(source.stat())
    expected = evidence_run_module.ArtifactIdentity(
        **{**vars(expected), "ino": expected.ino + 1}
    )

    monkeypatch.setattr(
        evidence_run_module,
        "_inspect_immutable_tree",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("inventory must not run")
        ),
    )

    with pytest.raises(ValueError, match="expected verdict"):
        copy_immutable_tree(
            source,
            tmp_path / "sealed-run",
            expected_source_identity=expected,
        )


def test_immutable_tree_copy_refuses_a_swap_between_preflight_and_copy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "run"
    source.mkdir()
    payload = source / "proof"
    payload.write_bytes(b"opening")
    opening = payload.stat()
    target = tmp_path / "sealed-run"
    real_mkdir = os.mkdir
    swapped = False

    def swapping_mkdir(path: str, mode: int = 0o777, **kwargs: object) -> None:
        nonlocal swapped
        real_mkdir(path, mode, **kwargs)
        if not swapped and str(path).startswith(f".{target.name}.tmp-"):
            swapped = True
            replacement = source / "replacement"
            replacement.write_bytes(b"changed")
            os.utime(
                replacement,
                ns=(opening.st_atime_ns, opening.st_mtime_ns),
            )
            replacement.replace(payload)

    monkeypatch.setattr(evidence_run_module.os, "mkdir", swapping_mkdir)

    with pytest.raises(ValueError, match="changed after preflight"):
        copy_immutable_tree(source, target)

    assert not target.exists()
    assert list(tmp_path.glob(f".{target.name}.tmp-*")) == []


def test_immutable_tree_publication_refuses_an_unexpected_empty_directory(
    tmp_path: Path,
) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "proof").write_bytes(b"proof")
    (staging / "unexpected-empty").mkdir()
    target = tmp_path / "published"

    with pytest.raises(ValueError, match="publication contract"):
        publish_immutable_tree(staging, target, expected_files=("proof",))

    assert staging.is_dir()
    assert not target.exists()


def test_immutable_tree_publication_receipt_binds_the_renamed_directory(
    tmp_path: Path,
) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "proof").write_bytes(b"proof")
    target = tmp_path / "published"

    receipt = publish_immutable_tree(
        staging,
        target,
        expected_files=("proof",),
    )

    assert not staging.exists()
    assert receipt.files == ("proof",)
    assert receipt.bytes_copied == len(b"proof")
    assert dict(receipt.digests) == {"proof": hashlib.sha256(b"proof").hexdigest()}
    assert receipt.target_identity == evidence_run_module.full_filesystem_identity(os.lstat(target))
    assert receipt.target_stable_identity == evidence_run_module.stable_identity_from_full(
        receipt.target_identity
    )


def test_immutable_tree_publication_rejects_a_pre_snapshot_digest_rewrite(
    tmp_path: Path,
) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    proof = staging / "proof"
    opening_bytes = b"opening"
    proof.write_bytes(opening_bytes)
    opening = proof.stat()
    expected = {"proof": hashlib.sha256(opening_bytes).hexdigest()}
    proof.write_bytes(b"forged!")
    os.utime(
        proof,
        ns=(opening.st_atime_ns, opening.st_mtime_ns),
    )
    target = tmp_path / "published"

    with pytest.raises(ValueError, match="digest contract"):
        publish_immutable_tree(
            staging,
            target,
            expected_files=("proof",),
            expected_digests=expected,
        )

    closing = proof.stat()
    assert closing.st_size == opening.st_size
    assert closing.st_mtime_ns == opening.st_mtime_ns
    assert proof.read_bytes() == b"forged!"
    assert staging.is_dir()
    assert not target.exists()


@pytest.mark.parametrize("operation", ("copy", "publish"))
def test_immutable_tree_rehash_blocks_a_rewrite_immediately_before_rename(
    operation: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "proof").write_bytes(b"opening")
    target = tmp_path / "published"
    real_rename = evidence_run_module._rename_directory_noreplace
    attacked = False

    def rewrite_before_rename(
        parent_fd: int,
        source_name: str,
        target_name: str,
    ) -> None:
        nonlocal attacked
        if not attacked and target_name == target.name:
            attacked = True
            source_fd = os.open(source_name, os.O_RDONLY, dir_fd=parent_fd)
            try:
                proof_fd = os.open(
                    "proof",
                    os.O_WRONLY | os.O_TRUNC,
                    dir_fd=source_fd,
                )
                try:
                    os.write(proof_fd, b"forged!")
                    os.fsync(proof_fd)
                finally:
                    os.close(proof_fd)
            finally:
                os.close(source_fd)
        real_rename(parent_fd, source_name, target_name)

    monkeypatch.setattr(
        evidence_run_module,
        "_rename_directory_noreplace",
        rewrite_before_rename,
    )

    with pytest.raises(ValueError, match="content changed"):
        if operation == "copy":
            source = tmp_path / "source"
            source.mkdir()
            (source / "proof").write_bytes(b"opening")
            copy_immutable_tree(source, target)
        else:
            publish_immutable_tree(staging, target, expected_files=("proof",))

    assert not target.exists()


@pytest.mark.parametrize("operation", ("copy", "publish"))
def test_immutable_tree_publication_blocks_a_root_mode_change_during_rename(
    operation: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "proof").write_bytes(b"opening")
    target = tmp_path / "published"
    real_rename = evidence_run_module._rename_directory_noreplace
    attacked = False

    def chmod_before_rename(
        parent_fd: int,
        source_name: str,
        target_name: str,
    ) -> None:
        nonlocal attacked
        if not attacked and target_name == target.name:
            attacked = True
            source_fd = os.open(
                source_name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
            try:
                os.fchmod(source_fd, 0o777)
            finally:
                os.close(source_fd)
        real_rename(parent_fd, source_name, target_name)

    monkeypatch.setattr(
        evidence_run_module,
        "_rename_directory_noreplace",
        chmod_before_rename,
    )

    with pytest.raises(ValueError, match="metadata"):
        if operation == "copy":
            source = tmp_path / "source"
            source.mkdir()
            (source / "proof").write_bytes(b"opening")
            copy_immutable_tree(source, target)
        else:
            publish_immutable_tree(staging, target, expected_files=("proof",))

    assert not target.exists()


def test_immutable_tree_copy_receipt_rejects_a_same_size_staging_rewrite(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "proof").write_bytes(b"opening")
    target = tmp_path / "published"
    real_snapshot = evidence_run_module._capture_immutable_tree_snapshot
    attacked = False

    def rewrite_before_first_snapshot(
        directory_fd: int,
        *args: object,
        **kwargs: object,
    ):
        nonlocal attacked
        if not attacked:
            attacked = True
            proof_fd = os.open(
                "proof",
                os.O_WRONLY | os.O_TRUNC,
                dir_fd=directory_fd,
            )
            try:
                os.write(proof_fd, b"forged!")
                os.fsync(proof_fd)
            finally:
                os.close(proof_fd)
        return real_snapshot(directory_fd, *args, **kwargs)

    monkeypatch.setattr(
        evidence_run_module,
        "_capture_immutable_tree_snapshot",
        rewrite_before_first_snapshot,
    )

    with pytest.raises(ValueError, match="completed copy receipt"):
        copy_immutable_tree(source, target)

    assert not target.exists()


def test_owned_temporary_directory_never_cleans_a_recycled_name(
    tmp_path: Path,
) -> None:
    temporary = owned_temporary_directory(
        prefix="owned-temp-",
        directory=tmp_path,
    )
    moved = tmp_path / "moved-owned-temp"

    with pytest.raises(
        OSError,
        match="cleanup refused a missing or substituted workspace",
    ):
        with temporary as path:
            path.rename(moved)
            path.mkdir()
            (path / "foreign-victim.txt").write_text(
                "must survive\n",
                encoding="utf-8",
            )

    assert temporary.cleanup_succeeded is False
    assert temporary.retained_quarantine is False
    assert (temporary.path / "foreign-victim.txt").read_text(encoding="utf-8") == "must survive\n"
    assert moved.is_dir()


def test_owned_temporary_directory_refuses_a_symlinked_parent_before_creation(
    tmp_path: Path,
) -> None:
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(OSError):
        owned_temporary_directory(
            prefix="must-not-exist-",
            directory=linked_parent / "nested",
        )

    assert list(real_parent.iterdir()) == []


def test_owned_temporary_directory_quarantines_a_hardening_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        evidence_run_module.os,
        "fchmod",
        lambda *_args: (_ for _ in ()).throw(
            OSError("simulated temporary fchmod failure")
        ),
    )

    with pytest.raises(OSError, match="simulated temporary fchmod failure"):
        owned_temporary_directory(
            prefix="failed-hardening-",
            directory=tmp_path,
        )

    assert list(tmp_path.glob("failed-hardening-*")) == []
    retained = list(tmp_path.glob(".failed-hardening-*.cleanup-*"))
    assert len(retained) == 1


def test_owned_temporary_directory_scrubs_and_reports_retained_quarantine(
    tmp_path: Path,
) -> None:
    temporary = owned_temporary_directory(
        prefix="private-",
        directory=tmp_path,
    )
    with temporary as path:
        (path / "secret.bin").write_bytes(b"sensitive bytes")

    assert temporary.cleanup_succeeded is True
    assert temporary.retained_quarantine is True
    assert temporary.cleanup_outcome is not None
    assert temporary.cleanup_outcome.durably_detached
    assert temporary.cleanup_outcome.scrub_complete
    assert temporary.cleanup_outcome.residual_entries == 1
    assert temporary.cleanup_outcome.residual_bytes == 0
    assert temporary.cleanup_outcome.errors == ()
    assert not temporary.path.exists()
    quarantines = list(tmp_path.glob(f".{temporary.path.name}.cleanup-*"))
    assert len(quarantines) == 1
    assert (quarantines[0] / "secret.bin").read_bytes() == b""


def test_detach_only_cleanup_accepts_rootfs_links_without_traversal(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    staging = tmp_path / "rootfs-replay"
    staging.mkdir()
    first = staging / "usr-a"
    first.write_bytes(b"package bytes")
    os.link(first, staging / "usr-b")
    (staging / "usr-link").symlink_to("usr-a")
    identity = evidence_run_module.stable_parent_identity(staging)
    monkeypatch.setattr(evidence_run_module, "_TREE_MAX_ENTRIES", 0)
    monkeypatch.setattr(
        evidence_run_module,
        "_scrub_owned_tree_contents",
        lambda *_args: (_ for _ in ()).throw(
            AssertionError("detach-only cleanup must not traverse")
        ),
    )

    outcome = evidence_run_module.cleanup_owned_tree(
        staging,
        identity,
        scrub=False,
    )
    assert outcome.durably_detached
    assert not outcome.scrub_complete
    assert outcome.residual_entries == 3
    assert outcome.residual_bytes == len(b"package bytes")
    assert outcome.errors == ()
    assert not staging.exists()
    quarantine = next(tmp_path.glob(".rootfs-replay.cleanup-*"))
    assert (quarantine / "usr-a").read_bytes() == b"package bytes"
    assert (quarantine / "usr-b").stat().st_ino == (quarantine / "usr-a").stat().st_ino
    assert (quarantine / "usr-link").is_symlink()


def test_cleanup_owned_tree_refuses_success_after_a_parent_path_swap(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    parent = tmp_path / "parent"
    staging = parent / "staging"
    staging.mkdir(parents=True)
    (staging / "secret").write_bytes(b"owned")
    identity = evidence_run_module.stable_parent_identity(staging)
    moved_parent = tmp_path / "moved-parent"
    real_rename = evidence_run_module._rename_directory_noreplace
    attacked = False

    def swap_parent_after_detach(
        parent_fd: int,
        source_name: str,
        target_name: str,
    ) -> None:
        nonlocal attacked
        real_rename(parent_fd, source_name, target_name)
        if not attacked:
            attacked = True
            parent.rename(moved_parent)
            staging.mkdir(parents=True)
            (staging / "victim").write_bytes(b"must survive")

    monkeypatch.setattr(
        evidence_run_module,
        "_rename_directory_noreplace",
        swap_parent_after_detach,
    )

    outcome = evidence_run_module.cleanup_owned_tree(staging, identity)
    assert not outcome.durably_detached
    assert not outcome.scrub_complete
    assert any("anchored parent" in error for error in outcome.errors)
    assert (staging / "victim").read_bytes() == b"must survive"
    assert not (moved_parent / "staging").exists()


def test_cleanup_owned_tree_never_follows_a_symlink_while_scrubbing(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside-secret"
    outside.write_bytes(b"must remain")
    staging = tmp_path / "symlink-staging"
    staging.mkdir()
    (staging / "owned").write_bytes(b"owned bytes")
    (staging / "outside-link").symlink_to(outside)
    identity = evidence_run_module.stable_parent_identity(staging)

    outcome = evidence_run_module.cleanup_owned_tree(staging, identity)

    assert outcome.durably_detached
    assert outcome.scrub_complete
    assert outcome.residual_entries == 2
    assert outcome.residual_bytes == 0
    assert outside.read_bytes() == b"must remain"
    quarantine = next(tmp_path.glob(".symlink-staging.cleanup-*"))
    assert (quarantine / "owned").read_bytes() == b""
    assert (quarantine / "outside-link").is_symlink()


def test_cleanup_owned_tree_never_truncates_an_externally_hardlinked_inode(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside-hardlink"
    outside.write_bytes(b"shared bytes")
    staging = tmp_path / "hardlink-staging"
    staging.mkdir()
    os.link(outside, staging / "shared")
    identity = evidence_run_module.stable_parent_identity(staging)

    outcome = evidence_run_module.cleanup_owned_tree(staging, identity)

    assert outcome.durably_detached
    assert not outcome.scrub_complete
    assert outcome.residual_entries == 1
    assert outcome.residual_bytes == len(b"shared bytes")
    assert any("hardlinks" in error for error in outcome.errors)
    assert outside.read_bytes() == b"shared bytes"


def test_cleanup_owned_tree_reports_byte_budget_residuals(
    tmp_path: Path,
) -> None:
    staging = tmp_path / "budget-staging"
    staging.mkdir()
    (staging / "oversized").write_bytes(b"five!")
    identity = evidence_run_module.stable_parent_identity(staging)

    outcome = evidence_run_module.cleanup_owned_tree(
        staging,
        identity,
        max_bytes=4,
    )

    assert outcome.durably_detached
    assert not outcome.scrub_complete
    assert outcome.residual_entries == 1
    assert outcome.residual_bytes == 5
    assert any("4-byte budget" in error for error in outcome.errors)
    quarantine = next(tmp_path.glob(".budget-staging.cleanup-*"))
    assert (quarantine / "oversized").read_bytes() == b"five!"


def test_cleanup_owned_tree_reports_entry_budget_without_unbounded_walk(
    tmp_path: Path,
) -> None:
    staging = tmp_path / "entry-budget-staging"
    staging.mkdir()
    (staging / "a").write_bytes(b"a")
    (staging / "b").write_bytes(b"b")
    identity = evidence_run_module.stable_parent_identity(staging)

    outcome = evidence_run_module.cleanup_owned_tree(
        staging,
        identity,
        max_entries=1,
    )

    assert outcome.durably_detached
    assert not outcome.scrub_complete
    assert any("1-entry budget" in error for error in outcome.errors)
    quarantine = next(tmp_path.glob(".entry-budget-staging.cleanup-*"))
    residual_sizes = sorted(
        len((quarantine / name).read_bytes())
        for name in ("a", "b")
    )
    assert residual_sizes == [0, 1]


def test_cleanup_owned_tree_reports_depth_budget_without_descending(
    tmp_path: Path,
) -> None:
    staging = tmp_path / "deep-staging"
    (staging / "nested").mkdir(parents=True)
    (staging / "nested" / "secret").write_bytes(b"deep secret")
    identity = evidence_run_module.stable_parent_identity(staging)

    outcome = evidence_run_module.cleanup_owned_tree(
        staging,
        identity,
        max_depth=0,
    )

    assert outcome.durably_detached
    assert not outcome.scrub_complete
    assert any("depth budget" in error for error in outcome.errors)
    quarantine = next(tmp_path.glob(".deep-staging.cleanup-*"))
    assert (quarantine / "nested" / "secret").read_bytes() == b"deep secret"


def test_cleanup_owned_tree_does_not_claim_durability_when_parent_fsync_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    staging = tmp_path / "fsync-staging"
    staging.mkdir()
    identity = evidence_run_module.stable_parent_identity(staging)
    real_fsync = evidence_run_module.os.fsync
    failed = False

    def fail_first_sync(descriptor: int) -> None:
        nonlocal failed
        if not failed:
            failed = True
            raise OSError("simulated parent fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(evidence_run_module.os, "fsync", fail_first_sync)

    outcome = evidence_run_module.cleanup_owned_tree(staging, identity)

    assert not outcome.durably_detached
    assert not outcome.scrub_complete
    assert any("simulated parent fsync failure" in error for error in outcome.errors)
    assert not staging.exists()
    assert len(list(tmp_path.glob(".fsync-staging.cleanup-*"))) == 1


def test_cleanup_owned_tree_scrub_failure_continues_with_safe_siblings(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    staging = tmp_path / "best-effort-staging"
    staging.mkdir()
    (staging / "a").write_bytes(b"first")
    (staging / "b").write_bytes(b"second")
    identity = evidence_run_module.stable_parent_identity(staging)
    real_ftruncate = evidence_run_module.os.ftruncate
    failed = False

    def fail_first_truncate(descriptor: int, length: int) -> None:
        nonlocal failed
        if not failed:
            failed = True
            raise OSError("simulated first scrub failure")
        real_ftruncate(descriptor, length)

    monkeypatch.setattr(evidence_run_module.os, "ftruncate", fail_first_truncate)

    outcome = evidence_run_module.cleanup_owned_tree(staging, identity)

    assert outcome.durably_detached
    assert not outcome.scrub_complete
    assert outcome.residual_entries == 2
    assert outcome.residual_bytes == len(b"first")
    assert any("simulated first scrub failure" in error for error in outcome.errors)
    quarantine = next(tmp_path.glob(".best-effort-staging.cleanup-*"))
    assert (quarantine / "a").read_bytes() == b"first"
    assert (quarantine / "b").read_bytes() == b""


def test_regular_rollback_leaves_a_substituted_foreign_name_intact(
    tmp_path: Path,
) -> None:
    target = tmp_path / "published"
    target.write_bytes(b"owned")
    held_fd = os.open(target, os.O_RDONLY)
    parent_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    moved_owned = tmp_path / "moved-owned"
    target.rename(moved_owned)
    target.write_bytes(b"foreign")
    try:
        with pytest.raises(ValueError, match="foreign pathname left intact"):
            evidence_run_module._rollback_owned_regular_publication(
                parent_fd,
                target.name,
                held_fd,
                preserve_as=".published.tmp-owned",
            )
    finally:
        os.close(held_fd)
        os.close(parent_fd)

    assert target.read_bytes() == b"foreign"
    assert moved_owned.read_bytes() == b"owned"


def test_immutable_tree_publication_never_moves_a_swapped_foreign_target(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "proof").write_bytes(b"owned")
    target = tmp_path / "published"
    real_rename = evidence_run_module._rename_directory_noreplace
    attacked = False

    def swap_after_rename(
        parent_fd: int,
        source_name: str,
        target_name: str,
    ) -> None:
        nonlocal attacked
        real_rename(parent_fd, source_name, target_name)
        if not attacked and target_name == target.name:
            attacked = True
            os.rename(
                target_name,
                "moved-owned-publication",
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
            os.mkdir(target_name, dir_fd=parent_fd)
            victim_directory_fd = os.open(
                target_name,
                os.O_RDONLY,
                dir_fd=parent_fd,
            )
            try:
                victim_fd = os.open(
                    "victim",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=victim_directory_fd,
                )
                try:
                    os.write(victim_fd, b"victim survives")
                finally:
                    os.close(victim_fd)
            finally:
                os.close(victim_directory_fd)

    monkeypatch.setattr(
        evidence_run_module,
        "_rename_directory_noreplace",
        swap_after_rename,
    )

    with pytest.raises(OSError, match="foreign pathname left intact"):
        copy_immutable_tree(source, target)

    assert (target / "victim").read_bytes() == b"victim survives"
    assert (tmp_path / "moved-owned-publication" / "proof").read_bytes() == b"owned"


def test_immutable_tree_copy_checks_the_target_name_after_its_parent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "proof").write_bytes(b"owned")
    target = tmp_path / "published"
    moved = tmp_path / "moved-owned-publication"
    real_require_parent = evidence_run_module._require_parent_path_identity
    attacked = False

    def swap_after_terminal_parent_check(path: Path, expected) -> None:
        nonlocal attacked
        real_require_parent(path, expected)
        if not attacked and path == target.parent and target.exists():
            attacked = True
            target.rename(moved)
            target.mkdir()
            (target / "victim").write_bytes(b"must survive")

    monkeypatch.setattr(
        evidence_run_module,
        "_require_parent_path_identity",
        swap_after_terminal_parent_check,
    )

    with pytest.raises(OSError, match="foreign pathname left intact"):
        copy_immutable_tree(source, target)

    assert moved.joinpath("proof").read_bytes() == b"owned"
    assert target.joinpath("victim").read_bytes() == b"must survive"


def test_immutable_tree_publication_blocks_an_ancestor_parent_swap(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    parent = tmp_path / "parent"
    staging = parent / "staging"
    staging.mkdir(parents=True)
    (staging / "proof").write_bytes(b"owned")
    target = parent / "published"
    moved_parent = tmp_path / "moved-parent"
    real_snapshot = evidence_run_module._capture_immutable_tree_snapshot
    attacked = False

    def swap_parent_after_snapshot(*args: object, **kwargs: object):
        nonlocal attacked
        snapshot = real_snapshot(*args, **kwargs)
        if not attacked:
            attacked = True
            parent.rename(moved_parent)
            parent.mkdir()
            (parent / "victim").write_bytes(b"must survive")
        return snapshot

    monkeypatch.setattr(
        evidence_run_module,
        "_capture_immutable_tree_snapshot",
        swap_parent_after_snapshot,
    )

    with pytest.raises(ValueError, match="parent path no longer names"):
        publish_immutable_tree(staging, target, expected_files=("proof",))

    assert (parent / "victim").read_bytes() == b"must survive"
    assert not target.exists()
    retained = next(moved_parent.glob(".published.cleanup-*"))
    assert (retained / "proof").read_bytes() == b""


def test_immutable_tree_copy_failure_cleans_staging_and_never_publishes_final(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "run"
    source.mkdir()
    (source / "a").write_bytes(b"a")
    (source / "b").write_bytes(b"b")
    target = tmp_path / "sealed-run"
    real_copy = evidence_run_module._copy_immutable_from_path_fd
    calls = 0

    def fail_second_copy(
        source_path_fd: int,
        directory_fd: int,
        target_name: str,
        *,
        max_bytes: int,
        expected_source_identity=None,
    ):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated staged tree copy failure")
        return real_copy(
            source_path_fd,
            directory_fd,
            target_name,
            max_bytes=max_bytes,
            expected_source_identity=expected_source_identity,
        )

    monkeypatch.setattr(
        evidence_run_module,
        "_copy_immutable_from_path_fd",
        fail_second_copy,
    )

    with pytest.raises(OSError, match="simulated staged tree copy failure"):
        copy_immutable_tree(source, target)

    assert not target.exists()
    assert list(tmp_path.glob(f".{target.name}.tmp-*")) == []


def test_recursive_tree_cleanup_quarantines_the_whole_tree_without_unlink(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "proof").write_bytes(b"owned")
    target = tmp_path / "published"
    real_snapshot = evidence_run_module._capture_immutable_tree_snapshot
    force_failure = True
    destructive_calls: list[str] = []

    def fail_first_snapshot(*args: object, **kwargs: object):
        nonlocal force_failure
        if force_failure:
            force_failure = False
            raise OSError("force cleanup")
        return real_snapshot(*args, **kwargs)

    def forbidden_unlink(path: str, **kwargs: object) -> None:
        destructive_calls.append(f"unlink:{path}")

    def forbidden_rmdir(path: str, **kwargs: object) -> None:
        destructive_calls.append(f"rmdir:{path}")

    monkeypatch.setattr(
        evidence_run_module,
        "_capture_immutable_tree_snapshot",
        fail_first_snapshot,
    )
    monkeypatch.setattr(
        evidence_run_module.os,
        "unlink",
        forbidden_unlink,
    )
    monkeypatch.setattr(evidence_run_module.os, "rmdir", forbidden_rmdir)

    with pytest.raises(OSError, match="force cleanup"):
        copy_immutable_tree(source, target)

    quarantines = list(tmp_path.glob(f"..{target.name}.tmp-*.cleanup-*"))
    assert len(quarantines) == 1
    assert (quarantines[0] / "proof").read_bytes() == b""
    assert destructive_calls == []
    assert not target.exists()


def test_immutable_tree_cleanup_never_deletes_a_swapped_replacement(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "run"
    source.mkdir()
    (source / "a").write_bytes(b"a")
    (source / "b").write_bytes(b"b")
    target = tmp_path / "sealed-run"
    real_copy = evidence_run_module._copy_immutable_from_path_fd
    calls = 0

    def swap_staging_then_fail(
        source_path_fd: int,
        directory_fd: int,
        target_name: str,
        *,
        max_bytes: int,
        expected_source_identity=None,
    ):
        nonlocal calls
        calls += 1
        if calls == 2:
            staging = next(tmp_path.glob(f".{target.name}.tmp-*"))
            staging.rename(tmp_path / "moved-owned-staging")
            staging.mkdir()
            (staging / "unrelated-victim").write_bytes(b"must survive")
            raise OSError("simulated copy failure after staging swap")
        return real_copy(
            source_path_fd,
            directory_fd,
            target_name,
            max_bytes=max_bytes,
            expected_source_identity=expected_source_identity,
        )

    monkeypatch.setattr(
        evidence_run_module,
        "_copy_immutable_from_path_fd",
        swap_staging_then_fail,
    )

    with pytest.raises(OSError, match="staging cleanup failed"):
        copy_immutable_tree(source, target)

    replacement = next(tmp_path.glob(f".{target.name}.tmp-*"))
    assert (replacement / "unrelated-victim").read_bytes() == b"must survive"
    assert (tmp_path / "moved-owned-staging").is_dir()
    assert not target.exists()


def test_immutable_tree_copy_collision_preserves_existing_tree_and_cleans_staging(
    tmp_path: Path,
) -> None:
    source = tmp_path / "run"
    source.mkdir()
    (source / "proof").write_bytes(b"new")
    target = tmp_path / "sealed-run"
    target.mkdir()
    (target / "proof").write_bytes(b"existing")

    with pytest.raises(FileExistsError):
        copy_immutable_tree(source, target)

    assert (target / "proof").read_bytes() == b"existing"
    assert list(tmp_path.glob(f".{target.name}.tmp-*")) == []


def test_immutable_tree_copy_fails_closed_when_renameat2_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "run"
    source.mkdir()
    (source / "proof").write_bytes(b"proof")
    target = tmp_path / "sealed-run"

    monkeypatch.setattr(
        evidence_run_module.ctypes,
        "CDLL",
        lambda *args, **kwargs: object(),
    )

    with pytest.raises(OSError, match="no-replace"):
        copy_immutable_tree(source, target)

    assert not target.exists()
    staging = list(tmp_path.glob(f".{target.name}.tmp-*"))
    assert len(staging) == 1
    assert (staging[0] / "proof").read_bytes() == b"proof"


def test_immutable_tree_copy_rolls_back_after_final_parent_fsync_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "run"
    source.mkdir()
    (source / "proof").write_bytes(b"proof")
    target = tmp_path / "sealed-run"
    real_fsync = os.fsync
    failed = False

    def fail_final_parent_fsync(descriptor: int) -> None:
        nonlocal failed
        if not failed and stat.S_ISDIR(os.fstat(descriptor).st_mode) and target.exists():
            failed = True
            raise OSError("simulated final tree fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(evidence_run_module.os, "fsync", fail_final_parent_fsync)

    with pytest.raises(OSError, match="simulated final tree fsync failure"):
        copy_immutable_tree(source, target)

    assert not target.exists()
    assert list(tmp_path.glob(f".{target.name}.tmp-*")) == []


def test_symlink_detection_includes_every_ancestor_below_the_anchor(
    tmp_path: Path,
) -> None:
    output = tmp_path / "dist"
    evidence = output / "evidence"
    evidence.mkdir(parents=True)
    external_runs = tmp_path / "external-runs"
    run = external_runs / "run-1"
    run.mkdir(parents=True)
    linked_runs = evidence / "runs"
    linked_runs.symlink_to(external_runs, target_is_directory=True)

    detected = first_symlink_in_confined_tree(output, linked_runs / "run-1")

    assert detected == linked_runs


def test_definition_bytes_and_effective_options_are_bound_to_the_run(tmp_path: Path) -> None:
    project = Project.create("Context", tmp_path / "context", "26.04")
    definition = project.root / "build.yaml"
    definition.write_text("source_mode: bootstrap\n", encoding="utf-8")
    first = make_run_context(project, BuildOptions(), definition=definition, mode="plan")

    definition.write_text("source_mode: bootstrap\npackages: [curl]\n", encoding="utf-8")
    second = make_run_context(project, BuildOptions(), definition=definition, mode="plan")

    assert first["definition"]["sha256"] != second["definition"]["sha256"]
    assert first["definition"]["effective_sha256"] == second["definition"]["effective_sha256"]
    builder = first["builder_source"]
    assert builder.get("worktree_sha256") or builder.get("source_tree_sha256")


def test_closing_identity_detects_definition_mutation_even_after_bytes_and_mtime_are_restored(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _patch_stable_builder_identity(monkeypatch)
    project = Project.create("DefinitionClose", tmp_path / "definition-close", "26.04")
    project.source_mode = "bootstrap"
    definition = project.root / "build.yaml"
    original = b"source_mode: bootstrap\n"
    definition.write_bytes(original)
    before = definition.stat()
    options = BuildOptions()
    context = make_run_context(
        project,
        options,
        definition=definition,
        mode="execute",
    )

    definition.write_bytes(b"x" * len(original))
    definition.write_bytes(original)
    os.utime(definition, ns=(before.st_atime_ns, before.st_mtime_ns))

    with pytest.raises(RuntimeError, match="definition"):
        close_run_identity(project, options, context)

    closure = context["identity_closure"]
    assert closure["status"] == "blocked"
    check = next(item for item in closure["checks"] if item["name"] == "definition")
    assert check["final"]["file"]["sha256"] == context["definition"]["sha256"]
    assert check["initial_sha256"] != check["final_sha256"]


def test_closing_identity_detects_same_byte_atomic_source_iso_replacement(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _patch_stable_builder_identity(monkeypatch)
    project = Project.create("SourceClose", tmp_path / "source-close", "26.04")
    source_iso = tmp_path / "source.iso"
    source_iso.write_bytes(b"same source ISO bytes")
    before = source_iso.stat()
    project.source_iso = source_iso
    options = BuildOptions()
    context = make_run_context(project, options, mode="execute")

    replacement = tmp_path / "replacement.iso"
    replacement.write_bytes(source_iso.read_bytes())
    os.utime(replacement, ns=(before.st_atime_ns, before.st_mtime_ns))
    os.replace(replacement, source_iso)

    with pytest.raises(RuntimeError, match="source_iso"):
        close_run_identity(project, options, context)

    closure = context["identity_closure"]
    check = next(item for item in closure["checks"] if item["name"] == "source_iso")
    assert check["final"]["file"]["sha256"] == context["source_iso"]["sha256"]
    assert (
        check["final"]["file"]["descriptor_stat"]["inode"]
        != context["source_iso"]["file"]["descriptor_stat"]["inode"]
    )


def test_closing_identity_detects_worktree_mutation_and_restoration(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    worktree = tmp_path / "builder"
    worktree.mkdir()
    builder_file = worktree / "builder.py"
    original = b"print('sealed')\n"
    builder_file.write_bytes(original)
    before = builder_file.stat()
    _patch_fake_git_worktree(monkeypatch, worktree, ("builder.py",))
    monkeypatch.setattr(
        "distroforge.core.evidence_run.toolchain_identity",
        lambda *args, **kwargs: {},
    )
    project = Project.create("BuilderClose", tmp_path / "project", "26.04")
    project.source_mode = "bootstrap"
    options = BuildOptions()
    context = make_run_context(project, options, mode="execute")

    builder_file.write_bytes(b"x" * len(original))
    builder_file.write_bytes(original)
    os.utime(builder_file, ns=(before.st_atime_ns, before.st_mtime_ns))

    with pytest.raises(RuntimeError, match="builder_source"):
        close_run_identity(project, options, context)

    check = next(
        item for item in context["identity_closure"]["checks"] if item["name"] == "builder_source"
    )
    assert (
        check["final"]["filesystem_guard"]["content_sha256"]
        == context["builder_source"]["filesystem_guard"]["content_sha256"]
    )
    assert (
        check["final"]["filesystem_guard"]["metadata_sha256"]
        != context["builder_source"]["filesystem_guard"]["metadata_sha256"]
    )


def test_a_stably_deleted_tracked_file_can_close_as_dirty_build_evidence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    worktree = tmp_path / "builder-deleted"
    worktree.mkdir()
    _patch_fake_git_worktree(
        monkeypatch,
        worktree,
        ("deleted.py",),
        diff=b"deleted tracked file",
    )
    monkeypatch.setattr(
        "distroforge.core.evidence_run.toolchain_identity",
        lambda *args, **kwargs: {},
    )
    project = Project.create("DeletedClose", tmp_path / "deleted-project", "26.04")
    project.source_mode = "bootstrap"
    options = BuildOptions()
    context = make_run_context(project, options, mode="execute")

    closure = close_run_identity(project, options, context)

    assert context["builder_source"]["dirty"] is True
    assert context["builder_source"]["filesystem_guard"]["stable"] is True
    assert closure["status"] == "closed"


def test_builder_double_measurement_marks_a_mid_capture_change_unstable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import distroforge.core.evidence_run as evidence_run_module

    worktree = tmp_path / "builder-mid-capture"
    worktree.mkdir()
    builder_file = worktree / "builder.py"
    builder_file.write_text("VALUE = 1\n", encoding="utf-8")
    _patch_fake_git_worktree(monkeypatch, worktree, ("builder.py",))
    real_guard = evidence_run_module._builder_filesystem_guard
    call_count = 0
    snapshots: list[dict[str, object]] = []

    def mutating_guard(root: Path, paths: list[str]) -> dict[str, object]:
        nonlocal call_count
        call_count += 1
        result = real_guard(root, paths)
        snapshots.append(result)
        if call_count == 1:
            builder_file.write_text("VALUE = 2\n", encoding="utf-8")
        return result

    monkeypatch.setattr(
        "distroforge.core.evidence_run._builder_filesystem_guard",
        mutating_guard,
    )

    identity = builder_source_identity()

    assert call_count == 2
    assert identity["stable_while_measured"] is False
    assert snapshots[0] != snapshots[1]
    assert identity["filesystem_guard"] == snapshots[1]


def test_closing_identity_detects_transient_created_used_and_deleted_builder_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    worktree = tmp_path / "builder-transient"
    package = worktree / "distroforge"
    cache = package / "__pycache__"
    cache.mkdir(parents=True)
    (package / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
    before = cache.stat()
    _patch_fake_git_worktree(
        monkeypatch,
        worktree,
        ("distroforge/__init__.py",),
    )
    monkeypatch.setattr(
        "distroforge.core.evidence_run.toolchain_identity",
        lambda *args, **kwargs: {},
    )
    project = Project.create("TransientClose", tmp_path / "transient-project", "26.04")
    project.source_mode = "bootstrap"
    options = BuildOptions()
    context = make_run_context(project, options, mode="execute")

    transient_source = tmp_path / "transient_plugin.py"
    transient_source.write_text("RESULT = 42\n", encoding="utf-8")
    transient = cache / "transient_plugin.pyc"
    py_compile.compile(str(transient_source), cfile=str(transient), doraise=True)
    loader = importlib.machinery.SourcelessFileLoader(
        "transient_plugin",
        str(transient),
    )
    spec = importlib.util.spec_from_loader("transient_plugin", loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    assert module.RESULT == 42
    transient.unlink()
    os.utime(cache, ns=(before.st_atime_ns, before.st_mtime_ns))

    with pytest.raises(RuntimeError, match="builder_source"):
        close_run_identity(project, options, context)

    check = next(
        item for item in context["identity_closure"]["checks"] if item["name"] == "builder_source"
    )
    assert (
        check["final"]["filesystem_guard"]["content_sha256"]
        == context["builder_source"]["filesystem_guard"]["content_sha256"]
    )
    assert (
        check["final"]["filesystem_guard"]["directory_metadata_sha256"]
        != context["builder_source"]["filesystem_guard"]["directory_metadata_sha256"]
    )


def test_closing_identity_detects_same_byte_toolchain_replacement(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _patch_stable_builder_identity(monkeypatch)
    tool = tmp_path / "fixture-tool"
    tool.write_bytes(b"stable tool bytes")

    def measured_toolchain(*_args: object, **_kwargs: object) -> dict[str, object]:
        measured = tool.stat()
        return {
            "fixture-tool": {
                "available": True,
                "path": str(tool),
                "sha256": hashlib.sha256(tool.read_bytes()).hexdigest(),
                "device": measured.st_dev,
                "inode": measured.st_ino,
                "ctime_ns": measured.st_ctime_ns,
                "stable_while_hashed": True,
                "version": "fixture 1",
            }
        }

    monkeypatch.setattr(
        "distroforge.core.evidence_run.toolchain_identity",
        measured_toolchain,
    )
    project = Project.create("ToolClose", tmp_path / "tool-project", "26.04")
    project.source_mode = "bootstrap"
    options = BuildOptions()
    context = make_run_context(project, options, mode="execute")
    replacement = tmp_path / "fixture-tool.new"
    replacement.write_bytes(tool.read_bytes())
    os.replace(replacement, tool)

    with pytest.raises(RuntimeError, match="toolchain"):
        close_run_identity(project, options, context)

    check = next(
        item for item in context["identity_closure"]["checks"] if item["name"] == "toolchain"
    )
    assert (
        check["final"]["fixture-tool"]["sha256"] == context["toolchain"]["fixture-tool"]["sha256"]
    )
    assert check["final"]["fixture-tool"]["inode"] != context["toolchain"]["fixture-tool"]["inode"]


def test_closing_identity_records_a_canonical_success_proof(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _patch_stable_builder_identity(monkeypatch)
    project = Project.create("Closed", tmp_path / "closed", "26.04")
    project.source_mode = "bootstrap"
    options = BuildOptions()
    context = make_run_context(project, options, mode="execute")

    closure = close_run_identity(project, options, context)

    assert closure["status"] == "closed"
    assert closure["issues"] == []
    assert closure["checks_sha256"] == canonical_sha256(closure["checks"])
    assert all(check["initial_sha256"] == check["final_sha256"] for check in closure["checks"])
    assert _identity_closure_problem(context) is None
    context.pop("identity_closure")
    assert _identity_closure_problem(context) is not None


def test_opening_toolchain_covers_every_build_and_verification_role() -> None:
    assert {
        "git",
        "gpgv",
        "dpkg-deb",
        "unsquashfs",
        "lz4",
        "zstd",
        "chroot",
        "sudo",
    } <= set(TOOLCHAIN_BINARIES)


def test_publication_git_policy_is_clean_signed_and_reconstructible() -> None:
    builder: dict[str, object] = {
        "kind": "git",
        "head": "1" * 40,
        "tree": "2" * 40,
        "commit_signature": "G " + "3" * 40,
        "git_measurements_complete": True,
        "dirty": False,
        "tracked_diff_sha256": ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        "untracked": [],
        "ignored_runtime_paths": [],
        "worktree_sha256": "4" * 64,
        "stable_while_measured": True,
        "filesystem_guard": {"stable": True},
    }

    assert _git_builder_publication_problem(builder) is None
    builder["dirty"] = True
    assert "dirty" in str(_git_builder_publication_problem(builder))
    builder["dirty"] = False
    builder["ignored_runtime_paths"] = ["distroforge/__pycache__/injected.pyc"]
    assert "ignored runtime" in str(_git_builder_publication_problem(builder))


def _patch_stable_builder_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    identity = {
        "kind": "git",
        "worktree_sha256": "a" * 64,
        "filesystem_guard": {
            "entry_count": 1,
            "entries_sha256": "b" * 64,
            "content_sha256": "c" * 64,
            "metadata_sha256": "d" * 64,
            "stable": True,
            "problems": [],
        },
        "stable_while_measured": True,
    }
    monkeypatch.setattr(
        "distroforge.core.evidence_run.builder_source_identity",
        lambda *args, **kwargs: identity,
    )
    monkeypatch.setattr(
        "distroforge.core.evidence_run.toolchain_identity",
        lambda *args, **kwargs: {},
    )


def _patch_fake_git_worktree(
    monkeypatch: pytest.MonkeyPatch,
    worktree: Path,
    tracked: tuple[str, ...],
    *,
    diff: bytes = b"",
) -> None:
    def fake_git_text(_cwd: Path, *args: str) -> str:
        values = {
            ("rev-parse", "--show-toplevel"): str(worktree),
            ("rev-parse", "HEAD"): "1" * 40,
            ("rev-parse", "HEAD^{tree}"): "2" * 40,
            ("branch", "--show-current"): "develop",
            ("log", "-1", "--format=%G? %GF"): "G " + "3" * 40,
        }
        return values.get(args, "")

    def fake_git_bytes(_cwd: Path, *args: str) -> bytes:
        if args[:2] == ("diff", "--binary"):
            return diff
        if args[:2] == ("ls-files", "--others"):
            return b""
        if args[:2] == ("ls-files", "--cached"):
            return b"".join(os.fsencode(path) + b"\0" for path in tracked)
        return b""

    monkeypatch.setattr("distroforge.core.evidence_run._git_text", fake_git_text)
    monkeypatch.setattr("distroforge.core.evidence_run._git_bytes", fake_git_bytes)


def test_source_and_tool_identities_refresh_between_runs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    state = {"head": "1" * 40, "diff": b"first"}

    def _git_text(_cwd: Path, *args: str) -> str:
        if args == ("rev-parse", "--show-toplevel"):
            return str(tmp_path)
        if args == ("rev-parse", "HEAD"):
            return state["head"]
        if args == ("rev-parse", "HEAD^{tree}"):
            return "2" * 40
        if args == ("branch", "--show-current"):
            return "develop"
        return ""

    def _git_bytes(_cwd: Path, *args: str) -> bytes:
        if args[:2] == ("diff", "--binary"):
            return state["diff"]
        return b""

    monkeypatch.setattr("distroforge.core.evidence_run._git_text", _git_text)
    monkeypatch.setattr("distroforge.core.evidence_run._git_bytes", _git_bytes)
    first_source = builder_source_identity()
    state.update({"head": "3" * 40, "diff": b"second"})
    second_source = builder_source_identity()
    assert first_source["worktree_sha256"] != second_source["worktree_sha256"]

    executable = tmp_path / "fixture-tool"
    executable.write_bytes(b"first executable")
    executable.chmod(0o755)
    first_tool = toolchain_identity((str(executable),))[str(executable)]
    executable.write_bytes(b"second executable")
    executable.chmod(0o755)
    second_tool = toolchain_identity((str(executable),))[str(executable)]
    assert first_tool["sha256"] != second_tool["sha256"]


def test_observed_tools_expand_privilege_chroot_and_env_wrappers() -> None:
    observed = observed_executable_counts(
        [
            (
                "sudo",
                "-A",
                "chroot",
                "/target",
                "env",
                "DEBIAN_FRONTEND=noninteractive",
                "apt-get",
                "install",
                "casper",
            )
        ]
    )

    assert {"sudo", "chroot", "env", "apt-get"} <= set(observed)


def test_execution_identity_hashes_the_target_root_binary(tmp_path: Path) -> None:
    root = tmp_path / "rootfs"
    for name, body in (
        ("env", b"target env"),
        ("apt-get", b"target apt"),
    ):
        binary = root / "usr" / "bin" / name
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_bytes(body)
        binary.chmod(0o755)

    chain = _execution_chain(
        (
            "chroot",
            str(root),
            "env",
            "DEBIAN_FRONTEND=noninteractive",
            "apt-get",
            "install",
            "casper",
        )
    )
    apt = next(item for item in chain if item["command"] == "apt-get")

    assert apt["scope"] == "target-root-pre-dispatch"
    assert apt["path"] == str(root / "usr" / "bin" / "apt-get")
    assert apt["sha256"] == __import__("hashlib").sha256(b"target apt").hexdigest()


def test_runner_snapshots_the_host_entrypoint_before_dispatch(tmp_path: Path) -> None:
    executable = tmp_path / "real-tool"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    runner = CommandRunner(dry_run=False, log_path=tmp_path / "commands.jsonl")

    runner.run(CommandSpec((str(executable),), description="Run real fixture tool"))

    assert len(runner.execution_identities) == 1
    identity = runner.execution_identities[0]
    assert identity["scope"] == "host-entrypoint-pre-dispatch"
    assert identity["stable_while_hashed"] is True
    assert identity["sha256"]
    assert '"event": "execution-identity"' in (tmp_path / "commands.jsonl").read_text(
        encoding="utf-8"
    )


def test_release_gate_rejects_provenance_without_iso_tool_roles(tmp_path: Path) -> None:
    project = Project.create("ToolRoles", tmp_path / "tool-roles", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "ToolRoles.iso"
    iso.write_bytes(b"iso")
    immutable = write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    provenance = json.loads(immutable.read_text(encoding="utf-8"))
    records = [
        {
            "argv": ["/usr/bin/true"],
            "cwd": str(project.root),
            "needs_root": False,
            "description": "Not an ISO build",
            "has_stdin": False,
            "env_keys": [],
            "env_sha256": canonical_sha256({}),
        }
    ]
    entrypoints = [
        {
            "history_index": 0,
            "captured_at": "2026-07-29T00:00:00+00:00",
            "scope": "host-entrypoint-pre-dispatch",
            "argv": ["/usr/bin/true"],
            "argv0": "/usr/bin/true",
            "available": True,
            "path": "/usr/bin/true",
            "size": 1,
            "sha256": "e" * 64,
            "stable_while_hashed": True,
            "execution_chain": [
                {
                    "command": "/usr/bin/true",
                    "scope": "host-pre-dispatch",
                    "root": None,
                    "available": True,
                    "path": "/usr/bin/true",
                    "size": 1,
                    "sha256": "e" * 64,
                    "stable_while_hashed": True,
                }
            ],
        }
    ]
    provenance["command_records"] = records
    provenance["commands_sha256"] = canonical_sha256(records)
    provenance["observed_toolchain"] = {
        "command_count": 1,
        "resolution_scope": "post-run-path-snapshot",
        "tools": {
            "/usr/bin/true": {
                "available": True,
                "sha256": "e" * 64,
                "observed_count": 1,
            }
        },
    }
    provenance["executed_host_entrypoints"] = entrypoints
    provenance["executed_host_entrypoints_sha256"] = canonical_sha256(entrypoints)
    content = json.dumps(provenance, indent=2) + "\n"
    immutable.write_text(content, encoding="utf-8")
    alias = project.output_dir / "distroforge-provenance.json"
    alias.write_text(content, encoding="utf-8")
    manifest_path = immutable.parent / "RUN-MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for item in manifest["files"]:
        artifact = Path(item["path"])
        if artifact in {immutable, alias}:
            item["size"] = artifact.stat().st_size
            item["sha256"] = __import__("hashlib").sha256(artifact.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    sidecar = manifest_path.with_name("RUN-MANIFEST.json.sha256")
    sidecar.write_text(
        f"{__import__('hashlib').sha256(manifest_path.read_bytes()).hexdigest()}  "
        "RUN-MANIFEST.json\n",
        encoding="utf-8",
    )

    gate = ReleaseGateService().check(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
    )

    provenance_item = next(item for item in gate.items if item.code == "provenance")
    assert provenance_item.status == "blocked"
    assert "mmdebstrap" in provenance_item.detail


def test_release_gate_ignores_global_provenance_alias_but_blocks_immutable_tampering(
    tmp_path: Path,
) -> None:
    project = Project.create("Tamper", tmp_path / "tamper", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "Tamper.iso"
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)

    clean = ReleaseGateService().check(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
    )
    assert {item.code: item.status for item in clean.items}["provenance"] == "ready"

    provenance = project.output_dir / "distroforge-provenance.json"
    provenance.write_text(provenance.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    tampered = ReleaseGateService().check(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
    )
    item = next(item for item in tampered.items if item.code == "provenance")
    assert item.status == "ready"

    immutable = (
        project.output_dir
        / "evidence"
        / "runs"
        / "build-run"
        / "distroforge-provenance.json"
    )
    immutable.write_text(
        immutable.read_text(encoding="utf-8") + "\n",
        encoding="utf-8",
    )
    tampered = ReleaseGateService().check(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
    )
    item = next(item for item in tampered.items if item.code == "provenance")
    assert item.status == "blocked"
    assert "No immutable executed build provenance was selected" in item.detail


def test_release_gate_recomputes_each_package_receipt_once(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    project = Project.create("SingleMapPass", tmp_path / "single-map-pass", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "SingleMapPass.iso"
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    validate = release_gate_module.validate_package_filesystem_causality
    validate_actions = release_gate_module.validate_package_apt_actions_evidence
    map_calls = 0
    action_calls = 0

    def counted_validation(*args: object, **kwargs: object):
        nonlocal map_calls
        map_calls += 1
        return validate(*args, **kwargs)

    def counted_action_validation(*args: object, **kwargs: object):
        nonlocal action_calls
        action_calls += 1
        return validate_actions(*args, **kwargs)

    monkeypatch.setattr(
        release_gate_module,
        "validate_package_filesystem_causality",
        counted_validation,
    )
    monkeypatch.setattr(
        release_gate_module,
        "validate_package_apt_actions_evidence",
        counted_action_validation,
    )

    ReleaseGateService().check(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
    )

    assert action_calls == 1
    assert map_calls == 1


def test_release_gate_requires_the_apt_action_receipt(
    tmp_path: Path,
) -> None:
    project = Project.create(
        "MissingActions",
        tmp_path / "missing-actions",
        "26.04",
    )
    project.source_mode = "bootstrap"
    iso = project.output_dir / "MissingActions.iso"
    iso.write_bytes(b"iso")
    immutable = write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    (immutable.parent / "PACKAGE-APT-ACTIONS.json").unlink()

    gate = ReleaseGateService().check(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
    )

    item = next(item for item in gate.items if item.code == "package-inputs")
    assert item.status == "blocked"
    assert "no PACKAGE-APT-ACTIONS.json receipt" in item.detail


def test_release_gate_rejects_a_forged_apt_action_promotion(
    tmp_path: Path,
) -> None:
    project = Project.create(
        "ForgedActions",
        tmp_path / "forged-actions",
        "26.04",
    )
    project.source_mode = "bootstrap"
    iso = project.output_dir / "ForgedActions.iso"
    iso.write_bytes(b"iso")
    immutable = write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    action_path = immutable.parent / "PACKAGE-APT-ACTIONS.json"
    action_payload = json.loads(action_path.read_text(encoding="utf-8"))
    action_payload["release_ready"] = True
    action_path.write_text(
        json.dumps(action_payload, indent=2) + "\n",
        encoding="utf-8",
    )

    gate = ReleaseGateService().check(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
    )

    item = next(item for item in gate.items if item.code == "package-inputs")
    assert item.status == "blocked"
    assert "forbidden release promotion" in item.detail


def test_release_gate_preview_bounds_the_apt_action_receipt_before_reading(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    project = Project.create(
        "OversizedActions",
        tmp_path / "oversized-actions",
        "26.04",
    )
    project.source_mode = "bootstrap"
    iso = project.output_dir / "OversizedActions.iso"
    iso.write_bytes(b"iso")
    immutable = write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    action_path = immutable.parent / "PACKAGE-APT-ACTIONS.json"
    byte_limit = action_path.stat().st_size - 1
    monkeypatch.setattr(
        release_gate_module,
        "MAX_REPORT_JSON_BYTES",
        byte_limit,
    )

    gate = ReleaseGateService().check(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
        verify_checksums=False,
    )

    item = next(item for item in gate.items if item.code == "package-inputs")
    assert item.status == "blocked"
    assert f"APT action report exceeds its {byte_limit}-byte limit" in item.detail


@pytest.mark.parametrize(
    ("filename", "bound_name", "expected"),
    (
        (
            "PACKAGE-INPUTS.json",
            "MAX_PACKAGE_INPUTS_BYTES",
            "PACKAGE-INPUTS",
        ),
        (
            "PACKAGE-FILESYSTEM-CAUSALITY.json",
            "MAX_PACKAGE_CAUSALITY_JSON_BYTES",
            "package/filesystem causality report",
        ),
    ),
)
def test_release_gate_preview_bounds_all_package_json_before_reading(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    filename: str,
    bound_name: str,
    expected: str,
) -> None:
    project = Project.create("BoundedPackageJson", tmp_path / filename, "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "BoundedPackageJson.iso"
    iso.write_bytes(b"iso")
    immutable = write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    target = immutable.parent / filename
    byte_limit = target.stat().st_size - 1
    monkeypatch.setattr(
        release_gate_module,
        bound_name,
        byte_limit,
    )

    gate = ReleaseGateService().check(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
        verify_checksums=False,
    )

    item = next(item for item in gate.items if item.code == "package-inputs")
    assert item.status == "blocked"
    assert f"{expected} exceeds its {byte_limit}-byte limit" in item.detail


@pytest.mark.parametrize(
    "filename",
    (
        "PACKAGE-INPUTS.json",
        "PACKAGE-APT-ACTIONS.json",
        "PACKAGE-FILESYSTEM-CAUSALITY.json",
    ),
)
def test_release_gate_preview_converts_invalid_package_unicode_to_blocked(
    tmp_path: Path,
    filename: str,
) -> None:
    project = Project.create("InvalidPackageJson", tmp_path / filename, "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "InvalidPackageJson.iso"
    iso.write_bytes(b"iso")
    immutable = write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    (immutable.parent / filename).write_bytes(b"\xff")

    gate = ReleaseGateService().check(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
        verify_checksums=False,
    )

    item = next(item for item in gate.items if item.code == "package-inputs")
    assert item.status == "blocked"
    assert "Package-input evidence" in item.detail
    assert "not strict UTF-8" in item.detail
    assert "UTF-8" in item.detail


@pytest.mark.parametrize(
    ("mutation", "expected"),
    (
        ("invalid-utf8", "UTF-8"),
        ("non-object", "one JSON object"),
        ("duplicate-key", "duplicate JSON key"),
        ("non-finite", "non-finite JSON number"),
        ("oversized", "exceeds its"),
        ("fifo", "not a regular file"),
    ),
)
def test_release_gate_fails_closed_for_invalid_bounded_provenance(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mutation: str,
    expected: str,
) -> None:
    project = Project.create("InvalidProvenance", tmp_path / mutation, "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "InvalidProvenance.iso"
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    provenance = (
        project.output_dir
        / "evidence"
        / "runs"
        / "build-run"
        / "distroforge-provenance.json"
    )
    if mutation == "invalid-utf8":
        provenance.write_bytes(b"\xff")
    elif mutation == "non-object":
        provenance.write_bytes(b"[]\n")
    elif mutation == "duplicate-key":
        provenance.write_text(
            '{"run_id":"opening","run_id":"forged"}\n',
            encoding="utf-8",
        )
    elif mutation == "non-finite":
        provenance.write_text('{"value":NaN}\n', encoding="utf-8")
    elif mutation == "oversized":
        monkeypatch.setattr(
            release_run_module,
            "_RUN_JSON_BYTES",
            provenance.stat().st_size - 1,
        )
    else:
        provenance.unlink()
        os.mkfifo(provenance)

    gate = ReleaseGateService().check(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
        verify_checksums=False,
    )

    items = {item.code: item for item in gate.items}
    for code in (
        "package-inputs",
        "rootfs-identity",
        "iso-assembly",
        "provenance",
        "provenance-snapshot",
    ):
        assert items[code].status == "blocked"
    assert expected in items["package-inputs"].detail


def test_release_gate_pins_one_immutable_provenance_snapshot_and_detects_swap(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    project = Project.create("SwappedProvenance", tmp_path / "swap", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "SwappedProvenance.iso"
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    provenance = (
        project.output_dir
        / "evidence"
        / "runs"
        / "build-run"
        / "distroforge-provenance.json"
    )
    package_item = release_gate_module._package_inputs_item

    def swap_after_package_check(*args: object, **kwargs: object):
        item = package_item(*args, **kwargs)
        replacement = json.loads(provenance.read_text(encoding="utf-8"))
        replacement["run_id"] = "swapped-run"
        provenance.write_text(
            json.dumps(replacement, indent=2) + "\n",
            encoding="utf-8",
        )
        return item

    monkeypatch.setattr(
        release_gate_module,
        "_package_inputs_item",
        swap_after_package_check,
    )

    gate = ReleaseGateService().check(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
        verify_checksums=False,
    )

    items = {item.code: item for item in gate.items}
    assert items["rootfs-identity"].status == "review"
    assert items["iso-assembly"].status == "review"
    # Every consumer used the opening descriptor snapshot. The common session
    # detects the immutable file mutation at the single closing boundary.
    assert items["provenance-snapshot"].status == "ready"
    assert items["artifact-session"].status == "blocked"
    assert "provenance" in items["artifact-session"].detail


@pytest.mark.parametrize(
    ("mutation", "expected"),
    (
        ("missing-closure", "did not close"),
        ("divergent-closure", "did not close"),
        ("dirty-builder", "not publication-grade"),
        ("unsigned-builder", "not publication-grade"),
        ("ignored-runtime", "not publication-grade"),
    ),
)
def test_release_gate_requires_closed_clean_signed_builder_identity(
    tmp_path: Path,
    mutation: str,
    expected: str,
) -> None:
    project = Project.create("IdentityGate", tmp_path / mutation, "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "IdentityGate.iso"
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    provenance = (
        project.output_dir
        / "evidence"
        / "runs"
        / "build-run"
        / "distroforge-provenance.json"
    )
    payload = json.loads(provenance.read_text(encoding="utf-8"))
    run = payload["run"]
    if mutation == "missing-closure":
        run.pop("identity_closure")
    elif mutation == "divergent-closure":
        builder_check = next(
            check
            for check in run["identity_closure"]["checks"]
            if check["name"] == "builder_source"
        )
        builder_check["final"]["dirty"] = True
    elif mutation == "dirty-builder":
        run["builder_source"]["dirty"] = True
        _reclose_fixture_identity(run)
    elif mutation == "ignored-runtime":
        run["builder_source"]["ignored_runtime_paths"] = ["distroforge/__pycache__/injected.pyc"]
        _reclose_fixture_identity(run)
    else:
        run["builder_source"]["commit_signature"] = "N"
        _reclose_fixture_identity(run)
    _rewrite_manifest_bound_provenance(provenance, payload)

    gate = ReleaseGateService().check(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
    )

    item = next(item for item in gate.items if item.code == "provenance")
    assert item.status == "blocked"
    assert expected in item.detail


def _reclose_fixture_identity(run: dict[str, object]) -> None:
    opening = {
        name: run[name] for name in ("builder_source", "definition", "source_iso", "toolchain")
    }
    opening_sha256 = canonical_sha256(opening)
    checks = [
        {
            "name": name,
            "status": "closed",
            "initial_sha256": canonical_sha256(identity),
            "final_sha256": canonical_sha256(identity),
            "final": identity,
            "issues": [],
        }
        for name, identity in opening.items()
    ]
    run["opening_identity_sha256"] = opening_sha256
    run["identity_closure"] = {
        "schema": "distroforge.run-identity-closure.v1",
        "status": "closed",
        "checked_at": "2026-07-29T00:00:00+00:00",
        "opening_identity_sha256": opening_sha256,
        "checks": checks,
        "checks_sha256": canonical_sha256(checks),
        "issues": [],
    }


def _rewrite_manifest_bound_provenance(
    provenance: Path,
    payload: dict[str, object],
) -> None:
    provenance.write_text(
        json.dumps(payload, indent=2) + "\n",
        encoding="utf-8",
    )
    manifest_path = provenance.parent / "RUN-MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for item in manifest["files"]:
        if item["path"] == str(provenance):
            item["size"] = provenance.stat().st_size
            item["sha256"] = hashlib.sha256(provenance.read_bytes()).hexdigest()
            break
    else:
        raise AssertionError("fixture manifest does not bind immutable provenance")
    manifest_path.write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )
    (manifest_path.parent / "RUN-MANIFEST.json.sha256").write_text(
        f"{hashlib.sha256(manifest_path.read_bytes()).hexdigest()}  "
        "RUN-MANIFEST.json\n",
        encoding="utf-8",
    )


def test_release_gate_detects_a_command_log_changed_after_sealing(tmp_path: Path) -> None:
    project = Project.create("LogTamper", tmp_path / "log-tamper", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "LogTamper.iso"
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    command_log = project.output_dir / "evidence" / "runs" / "build-run" / "commands.jsonl"
    command_log.write_text(
        command_log.read_text(encoding="utf-8") + '{"forged": true}\n',
        encoding="utf-8",
    )

    gate = ReleaseGateService().check(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
    )

    item = next(item for item in gate.items if item.code == "provenance")
    assert item.status == "blocked"
    assert "commands.jsonl" in item.detail


def test_repair_preserves_build_provenance_and_reconstructs_only_in_fresh_output(
    tmp_path: Path,
) -> None:
    project = Project.create("Repair", tmp_path / "repair", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "Repair.iso"
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso)
    provenance = project.output_dir / "distroforge-provenance.json"
    original = provenance.read_bytes()

    report = repair_beginner_iso_release_artifacts(
        project,
        BuildOptions(output_iso=iso),
    )

    assert provenance.read_bytes() == original
    assert any("preserved" in item for item in report.skipped)

    sealed = {
        path.name: path.read_bytes()
        for path in project.output_dir.iterdir()
        if path.is_file() and path != provenance
    }
    provenance.unlink()
    dirty_retry = repair_beginner_iso_release_artifacts(
        project,
        BuildOptions(output_iso=iso),
    )

    assert dirty_retry.status == "blocked"
    assert not provenance.exists()
    assert dirty_retry.repaired == ()
    assert any("fresh output directory" in item for item in dirty_retry.skipped)
    assert sealed == {
        path.name: path.read_bytes()
        for path in project.output_dir.iterdir()
        if path.is_file()
    }

    fresh = Project.create("FreshRepair", tmp_path / "fresh-repair", "26.04")
    fresh.source_mode = "bootstrap"
    fresh_iso = fresh.output_dir / "FreshRepair.iso"
    fresh_iso.write_bytes(b"iso")

    reconstructed_report = repair_beginner_iso_release_artifacts(
        fresh,
        BuildOptions(output_iso=fresh_iso),
    )
    fresh_provenance = fresh.output_dir / "distroforge-provenance.json"
    reconstructed = json.loads(fresh_provenance.read_text(encoding="utf-8"))

    assert reconstructed_report.status == "ready"
    assert reconstructed["attestation_kind"] == "reconstructed"
