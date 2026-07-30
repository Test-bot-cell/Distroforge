from __future__ import annotations

import errno
import hashlib
import os
import socket
from pathlib import Path

import pytest

from distroforge.core import artifact_verification
from distroforge.core.artifact_verification import (
    ArtifactLimits,
    ArtifactVerificationError,
    ArtifactVerificationSession,
)


def _limits(**overrides: int) -> ArtifactLimits:
    values = {
        "max_open_files": 256,
        "max_file_bytes": 64 * 1024 * 1024,
        "max_buffered_bytes": 16 * 1024 * 1024,
        "max_hashed_bytes": 256 * 1024 * 1024,
        "max_json_depth": 256,
        "max_json_nodes": 2_000_000,
    }
    values.update(overrides)
    return ArtifactLimits(**values)


def _fd_count() -> int:
    return len(os.listdir("/proc/self/fd"))


def test_digest_is_reused_only_inside_one_session(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"AAAA")
    timestamp = artifact.stat().st_mtime_ns
    expected_first = hashlib.sha256(b"AAAA").hexdigest()

    first = ArtifactVerificationSession(tmp_path)
    first_handle = first.file(Path("artifact.bin"))
    assert first_handle.digest() == expected_first
    assert first_handle.digest() == expected_first
    assert first.metrics.files_opened == 1
    assert first.metrics.bytes_hashed == 4
    assert first.metrics.digest_reuse == 1
    first.seal()
    assert first.metrics.bytes_hashed == 8
    assert first.metrics.files_opened == 2

    replacement = tmp_path / "replacement.bin"
    replacement.write_bytes(b"BBBB")
    os.utime(replacement, ns=(timestamp, timestamp))
    replacement.replace(artifact)

    expected_second = hashlib.sha256(b"BBBB").hexdigest()
    second = ArtifactVerificationSession(tmp_path)
    second_handle = second.file(Path("artifact.bin"))
    assert second_handle.digest() == expected_second
    assert second_handle.digest() != expected_first
    assert second.metrics.bytes_hashed == 4
    assert second.metrics.digest_reuse == 1
    second.seal()
    assert second.metrics.bytes_hashed == 8


def test_seal_with_receipt_hashes_and_binds_every_opened_path(tmp_path: Path) -> None:
    first = tmp_path / "first.bin"
    second = tmp_path / "second.bin"
    first.write_bytes(b"first")
    second.write_bytes(b"second")
    session = ArtifactVerificationSession(tmp_path)
    first_handle = session.file(Path("first.bin"))
    second_handle = session.file(Path("second.bin"))
    assert first_handle.digest() == hashlib.sha256(b"first").hexdigest()
    second_identity = second_handle.identity

    receipt = session.seal_with_receipt()

    assert session.receipt is receipt
    assert receipt.anchor_path == tmp_path
    assert receipt.anchor_identity == session.anchor_identity
    assert receipt.by_absolute_path() == {
        first: receipt.files[0],
        second: receipt.files[1],
    }
    assert receipt.files[0].relative_path == Path("first.bin")
    assert receipt.files[0].absolute_path == first
    assert receipt.files[0].sha256 == hashlib.sha256(b"first").hexdigest()
    assert receipt.files[1].relative_path == Path("second.bin")
    assert receipt.files[1].absolute_path == second
    assert receipt.files[1].identity == second_identity
    assert receipt.files[1].sha256 == hashlib.sha256(b"second").hexdigest()


def test_ordinary_seal_does_not_create_or_backfill_receipt(tmp_path: Path) -> None:
    (tmp_path / "artifact.bin").write_bytes(b"artifact")
    session = ArtifactVerificationSession(tmp_path)
    session.file(Path("artifact.bin"))

    session.seal()

    assert session.receipt is None
    with pytest.raises(
        ArtifactVerificationError,
        match="already sealed without an artifact receipt",
    ):
        session.seal_with_receipt()


def test_unrelated_sibling_churn_does_not_replace_ancestor_binding(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"artifact")
    session = ArtifactVerificationSession(Path("/"))
    session.file_path(artifact).digest()

    (tmp_path / "unrelated").mkdir()

    receipt = session.seal_with_receipt()
    assert receipt.by_absolute_path()[artifact].sha256 == hashlib.sha256(
        b"artifact"
    ).hexdigest()


def test_ancestor_inode_swap_is_blocked_even_if_leaf_bytes_match(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "parent"
    parent.mkdir()
    artifact = parent / "artifact.bin"
    artifact.write_bytes(b"artifact")
    session = ArtifactVerificationSession(Path("/"))
    session.file_path(artifact).digest()

    parent.rename(tmp_path / "held-parent")
    parent.mkdir()
    (parent / artifact.name).write_bytes(b"artifact")

    with pytest.raises(
        ArtifactVerificationError,
        match="ancestor identity changed before closure",
    ):
        session.seal_with_receipt()


def test_receipt_hashes_inventory_only_regular_files(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    artifact = tree / "inventory-only.bin"
    artifact.write_bytes(b"inventory")
    session = ArtifactVerificationSession(tmp_path)
    inventory = session.tree_inventory(Path("tree"))

    receipt = session.seal_with_receipt()

    assert receipt.trees[0].inventory == inventory
    assert receipt.trees[0].absolute_path == tree
    file_receipt = receipt.by_absolute_path()[artifact]
    assert file_receipt.identity == inventory.by_name()["inventory-only.bin"]
    assert file_receipt.sha256 == hashlib.sha256(b"inventory").hexdigest()


def test_inventory_only_file_mutation_before_receipt_is_blocked(
    tmp_path: Path,
) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    artifact = tree / "inventory-only.bin"
    artifact.write_bytes(b"opening")
    session = ArtifactVerificationSession(tmp_path)
    session.tree_inventory(Path("tree"))

    artifact.write_bytes(b"changed")

    with pytest.raises(
        ArtifactVerificationError,
        match="changed after its opening tree inventory",
    ):
        session.seal_with_receipt()


def test_inventory_receipt_obeys_logical_open_file_budget(
    tmp_path: Path,
) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "a.bin").write_bytes(b"a")
    (tree / "b.bin").write_bytes(b"b")
    session = ArtifactVerificationSession(
        tmp_path,
        limits=_limits(max_open_files=1),
    )
    session.tree_inventory(Path("tree"))

    with pytest.raises(
        ArtifactVerificationError,
        match="receipt exceeds its logical open-file budget \\(1\\)",
    ):
        session.seal_with_receipt()
    assert session.receipt is None


def test_tree_root_swap_after_terminal_inventory_is_blocked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "artifact.bin").write_bytes(b"opening")
    session = ArtifactVerificationSession(Path("/"))
    session.tree_inventory_path(tree)
    real_open_anchor = session._open_absolute_anchor
    swapped = False

    def swap_before_tree_path_pins(path: Path):
        nonlocal swapped
        result = real_open_anchor(path)
        if not swapped:
            swapped = True
            tree.rename(tmp_path / "held-tree")
            tree.mkdir()
            (tree / "artifact.bin").write_bytes(b"forged!")
        return result

    monkeypatch.setattr(
        session,
        "_open_absolute_anchor",
        swap_before_tree_path_pins,
    )

    with pytest.raises(
        ArtifactVerificationError,
        match="path root identity changed before closure",
    ):
        session.seal_with_receipt()
    assert swapped


def test_inventory_file_mutation_after_terminal_inventory_is_blocked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    artifact = tree / "artifact.bin"
    artifact.write_bytes(b"opening")
    session = ArtifactVerificationSession(Path("/"))
    session.tree_inventory_path(tree)
    real_open_anchor = session._open_absolute_anchor
    mutated = False

    def mutate_before_tree_entry_pins(path: Path):
        nonlocal mutated
        result = real_open_anchor(path)
        if not mutated:
            mutated = True
            artifact.write_bytes(b"forged!")
        return result

    monkeypatch.setattr(
        session,
        "_open_absolute_anchor",
        mutate_before_tree_entry_pins,
    )

    with pytest.raises(
        ArtifactVerificationError,
        match="entry identity changed before closure: artifact.bin",
    ):
        session.seal_with_receipt()
    assert mutated


def test_anchor_tree_entry_mutation_after_terminal_inventory_is_blocked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"opening")
    session = ArtifactVerificationSession(tmp_path)
    session.tree_inventory(Path("."))
    real_open_anchor = session._open_absolute_anchor
    mutated = False

    def mutate_before_anchor_tree_entry_pins(path: Path):
        nonlocal mutated
        result = real_open_anchor(path)
        if not mutated:
            mutated = True
            artifact.write_bytes(b"forged!")
        return result

    monkeypatch.setattr(
        session,
        "_open_absolute_anchor",
        mutate_before_anchor_tree_entry_pins,
    )

    with pytest.raises(
        ArtifactVerificationError,
        match="entry identity changed before closure: artifact.bin",
    ):
        session.seal_with_receipt()
    assert mutated


def test_same_size_same_mtime_path_swap_is_blocked_at_seal(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"AAAA")
    timestamp = artifact.stat().st_mtime_ns
    session = ArtifactVerificationSession(tmp_path)
    assert session.file(Path("artifact.bin")).digest() == hashlib.sha256(b"AAAA").hexdigest()

    replacement = tmp_path / "replacement.bin"
    replacement.write_bytes(b"BBBB")
    os.utime(replacement, ns=(timestamp, timestamp))
    replacement.replace(artifact)

    with pytest.raises(
        ArtifactVerificationError,
        match="path resolves to another inode before closure",
    ):
        session.seal()


def test_mutation_during_closing_path_pinning_is_blocked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"AAAA")
    session = ArtifactVerificationSession(tmp_path)
    session.file(Path("artifact.bin")).digest()
    real_open_anchor = session._open_absolute_anchor

    def adversarial_open_anchor(path: Path):
        result = real_open_anchor(path)
        artifact.write_bytes(b"BBBB")
        return result

    monkeypatch.setattr(session, "_open_absolute_anchor", adversarial_open_anchor)
    with pytest.raises(ArtifactVerificationError, match="before closure"):
        session.seal()


def test_path_swap_after_closing_rehash_is_blocked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"AAAA")
    session = ArtifactVerificationSession(tmp_path)
    session.file(Path("artifact.bin")).digest()
    real_seal_record = session._seal_record
    swapped = False

    def swap_after_rehash(record) -> None:
        nonlocal swapped
        real_seal_record(record)
        if not swapped:
            swapped = True
            artifact.rename(tmp_path / "held.bin")
            artifact.write_bytes(b"BBBB")

    monkeypatch.setattr(session, "_seal_record", swap_after_rehash)

    with pytest.raises(
        ArtifactVerificationError,
        match="path resolves to another inode before closure",
    ):
        session.seal()


def test_anchor_swap_after_closing_rehash_is_blocked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    anchor = tmp_path / "anchor"
    anchor.mkdir()
    artifact = anchor / "artifact.bin"
    artifact.write_bytes(b"AAAA")
    session = ArtifactVerificationSession(anchor)
    session.file(Path("artifact.bin")).digest()
    real_seal_record = session._seal_record
    swapped = False

    def swap_anchor_after_rehash(record) -> None:
        nonlocal swapped
        real_seal_record(record)
        if not swapped:
            swapped = True
            anchor.rename(tmp_path / "held-anchor")
            anchor.mkdir()
            (anchor / "artifact.bin").write_bytes(b"AAAA")

    monkeypatch.setattr(session, "_seal_record", swap_anchor_after_rehash)

    with pytest.raises(
        ArtifactVerificationError,
        match="anchor path identity changed during verification",
    ):
        session.seal()


def test_leaf_swap_after_closing_pin_is_blocked_by_terminal_name_observation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"AAAA")
    session = ArtifactVerificationSession(tmp_path)
    session.file(Path("artifact.bin")).digest()
    real_pin_bindings = session._pin_bindings_for_close

    def swap_after_pinning(anchor_descriptor: int):
        pins = real_pin_bindings(anchor_descriptor)
        artifact.rename(tmp_path / "held.bin")
        artifact.write_bytes(b"BBBB")
        return pins

    monkeypatch.setattr(
        session,
        "_pin_bindings_for_close",
        swap_after_pinning,
    )

    with pytest.raises(
        ArtifactVerificationError,
        match="terminal name no longer resolves to its held inode",
    ):
        session.seal()


def test_anchor_swap_after_closing_pin_is_blocked_by_terminal_name_observation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    anchor = tmp_path / "anchor"
    anchor.mkdir()
    artifact = anchor / "artifact.bin"
    artifact.write_bytes(b"AAAA")
    session = ArtifactVerificationSession(anchor)
    session.file(Path("artifact.bin")).digest()
    real_pin_bindings = session._pin_bindings_for_close

    def swap_after_pinning(anchor_descriptor: int):
        pins = real_pin_bindings(anchor_descriptor)
        anchor.rename(tmp_path / "held-anchor")
        anchor.mkdir()
        (anchor / "artifact.bin").write_bytes(b"AAAA")
        return pins

    monkeypatch.setattr(
        session,
        "_pin_bindings_for_close",
        swap_after_pinning,
    )

    with pytest.raises(
        ArtifactVerificationError,
        match="terminal anchor name no longer resolves to its held inode",
    ):
        session.seal()


def test_mutation_during_terminal_name_observation_is_blocked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"AAAA")
    session = ArtifactVerificationSession(tmp_path)
    session.file(Path("artifact.bin")).digest()
    real_stat = os.stat
    mutated = False

    def mutate_before_named_stat(
        path: os.PathLike[str] | str | int,
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> os.stat_result:
        nonlocal mutated
        if path == "artifact.bin" and dir_fd is not None and not mutated:
            mutated = True
            artifact.write_bytes(b"BBBB")
        return real_stat(
            path,
            dir_fd=dir_fd,
            follow_symlinks=follow_symlinks,
        )

    monkeypatch.setattr(os, "stat", mutate_before_named_stat)

    with pytest.raises(
        ArtifactVerificationError,
        match="held identity changed before its terminal name observation",
    ):
        session.seal()
    assert mutated


@pytest.mark.parametrize("mutation", ["grow", "truncate"])
def test_growth_or_truncation_after_fstat_is_blocked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"A" * (2 * 1024 * 1024))
    session = ArtifactVerificationSession(tmp_path)
    handle = session.file(Path("artifact.bin"))
    real_read = os.read
    mutated = False

    def adversarial_read(descriptor: int, size: int) -> bytes:
        nonlocal mutated
        chunk = real_read(descriptor, size)
        if chunk and not mutated:
            mutated = True
            if mutation == "grow":
                with artifact.open("ab") as stream:
                    stream.write(b"B")
            else:
                artifact.write_bytes(b"")
        return chunk

    monkeypatch.setattr(os, "read", adversarial_read)
    try:
        with pytest.raises(ArtifactVerificationError, match="changed while it was read"):
            handle.digest()
    finally:
        session.close()


def test_leaf_symlink_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target.bin"
    target.write_bytes(b"payload")
    (tmp_path / "leaf-link").symlink_to(target.name)

    with pytest.raises(ArtifactVerificationError, match="without following links"):
        with ArtifactVerificationSession(tmp_path) as session:
            session.file(Path("leaf-link"))


def test_symlink_ancestor_is_rejected(tmp_path: Path) -> None:
    real_directory = tmp_path / "real"
    real_directory.mkdir()
    (real_directory / "artifact.bin").write_bytes(b"payload")
    (tmp_path / "linked").symlink_to(real_directory.name, target_is_directory=True)

    with pytest.raises(ArtifactVerificationError, match="unreadable ancestor"):
        with ArtifactVerificationSession(tmp_path) as session:
            session.file(Path("linked/artifact.bin"))


def test_fifo_is_rejected_without_waiting_for_a_writer(tmp_path: Path) -> None:
    fifo = tmp_path / "artifact.pipe"
    os.mkfifo(fifo, 0o620)

    with pytest.raises(ArtifactVerificationError, match="not a regular file"):
        with ArtifactVerificationSession(tmp_path) as session:
            session.file(Path("artifact.pipe"))


def test_unix_socket_is_rejected_without_connecting(tmp_path: Path) -> None:
    socket_path = tmp_path / "artifact.sock"

    try:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    except PermissionError:
        pytest.skip("the execution sandbox forbids creating Unix sockets")
    with listener:
        try:
            listener.bind(str(socket_path))
        except PermissionError:
            pytest.skip("the execution sandbox forbids creating Unix socket nodes")
        with pytest.raises(
            ArtifactVerificationError,
            match="cannot be opened without following links|not a regular file",
        ):
            with ArtifactVerificationSession(tmp_path) as session:
                session.file(Path("artifact.sock"))


def test_directory_is_rejected_as_an_artifact(tmp_path: Path) -> None:
    (tmp_path / "artifact-dir").mkdir()

    with pytest.raises(ArtifactVerificationError, match="not a regular file"):
        with ArtifactVerificationSession(tmp_path) as session:
            session.file(Path("artifact-dir"))


def test_descriptor_tree_inventory_records_types_and_regular_files(
    tmp_path: Path,
) -> None:
    tree = tmp_path / "tree"
    nested = tree / "nested"
    nested.mkdir(parents=True)
    (tree / "root.bin").write_bytes(b"root")
    (nested / "leaf.bin").write_bytes(b"leaf")
    (tree / "leaf-link").symlink_to("root.bin")

    with ArtifactVerificationSession(tmp_path) as session:
        inventory = session.tree_inventory(Path("tree"))
        assert inventory.regular_files() == {"root.bin", "nested/leaf.bin"}
        assert inventory.non_directory_entries() == {
            "root.bin",
            "nested/leaf.bin",
            "leaf-link",
        }


def test_descriptor_tree_inventory_can_bind_the_session_anchor(
    tmp_path: Path,
) -> None:
    (tmp_path / "artifact.bin").write_bytes(b"payload")

    with ArtifactVerificationSession(tmp_path) as session:
        inventory = session.tree_inventory_path(tmp_path)
        assert inventory.regular_files() == {"artifact.bin"}


def test_descriptor_tree_inventory_detects_same_size_same_mtime_swap(
    tmp_path: Path,
) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    artifact = tree / "artifact.bin"
    artifact.write_bytes(b"AAAA")
    timestamp = artifact.stat().st_mtime_ns
    session = ArtifactVerificationSession(tmp_path)
    session.tree_inventory(Path("tree"))

    replacement = tmp_path / "replacement.bin"
    replacement.write_bytes(b"BBBB")
    os.utime(replacement, ns=(timestamp, timestamp))
    replacement.replace(artifact)

    with pytest.raises(
        ArtifactVerificationError,
        match="inventory changed during verification",
    ):
        session.seal()


def test_descriptor_tree_inventory_detects_added_empty_directory(
    tmp_path: Path,
) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    session = ArtifactVerificationSession(tmp_path)
    session.tree_inventory(Path("tree"))
    (tree / "unmanifested").mkdir()

    with pytest.raises(
        ArtifactVerificationError,
        match="inventory changed during verification",
    ):
        session.seal()


def test_tree_inventory_is_rechecked_after_held_record_rehash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tree = tmp_path / "tree"
    nested = tree / "nested"
    nested.mkdir(parents=True)
    held = tree / "held.bin"
    unbound = nested / "unbound.bin"
    held.write_bytes(b"held")
    unbound.write_bytes(b"opening")
    session = ArtifactVerificationSession(tmp_path)
    session.tree_inventory(Path("tree"))
    session.file(Path("tree/held.bin")).digest()
    real_seal_record = session._seal_record
    mutated = False

    def mutate_after_rehash(record) -> None:
        nonlocal mutated
        real_seal_record(record)
        if not mutated:
            mutated = True
            unbound.write_bytes(b"closing")

    monkeypatch.setattr(session, "_seal_record", mutate_after_rehash)

    with pytest.raises(
        ArtifactVerificationError,
        match="inventory changed during verification",
    ):
        session.seal()


def test_descriptor_tree_inventory_rejects_symlinked_ancestor(
    tmp_path: Path,
) -> None:
    real_tree = tmp_path / "real"
    real_tree.mkdir()
    (tmp_path / "linked").symlink_to(real_tree.name, target_is_directory=True)

    with pytest.raises(ArtifactVerificationError, match="symlink"):
        with ArtifactVerificationSession(tmp_path) as session:
            session.tree_inventory(Path("linked"))


def test_descriptor_tree_inventory_budget_is_enforced(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "one").write_bytes(b"1")
    (tree / "two").write_bytes(b"2")
    session = ArtifactVerificationSession(
        tmp_path,
        limits=_limits(max_inventory_entries=1),
    )
    with pytest.raises(ArtifactVerificationError, match="1-entry inventory limit"):
        session.tree_inventory(Path("tree"))
    with pytest.raises(ArtifactVerificationError, match="1-entry inventory limit"):
        session.seal()


def test_character_device_is_rejected_before_a_read_open() -> None:
    with pytest.raises(ArtifactVerificationError, match="not a regular file"):
        with ArtifactVerificationSession(Path("/")) as session:
            session.file_path(Path("/dev/null"), allow_empty=True)


def test_invalid_utf8_is_converted_to_a_verification_error(tmp_path: Path) -> None:
    (tmp_path / "invalid.json").write_bytes(b'{"value":"\xff"}')

    with pytest.raises(ArtifactVerificationError, match="not strict UTF-8"):
        with ArtifactVerificationSession(tmp_path) as session:
            session.file(Path("invalid.json")).read_text()


def test_json_object_rejects_a_non_object_document(tmp_path: Path) -> None:
    (tmp_path / "array.json").write_text("[1, 2]", encoding="utf-8")

    with pytest.raises(ArtifactVerificationError, match="one JSON object"):
        with ArtifactVerificationSession(tmp_path) as session:
            session.file(Path("array.json")).json_object()


def test_json_rejects_duplicate_object_keys(tmp_path: Path) -> None:
    (tmp_path / "duplicate.json").write_text('{"key": 1, "key": 2}', encoding="utf-8")

    with pytest.raises(ArtifactVerificationError, match="duplicate JSON key"):
        with ArtifactVerificationSession(tmp_path) as session:
            session.file(Path("duplicate.json")).json()


@pytest.mark.parametrize(
    ("payload", "limits", "message"),
    [
        ("[[[0]]]", _limits(max_json_depth=3), "exceeds depth 3"),
        ("[0, 1, 2]", _limits(max_json_nodes=3), "exceeds 3 nodes"),
        ('{"value": NaN}', _limits(), "non-finite JSON number"),
        ('{"value": 1e9999}', _limits(), "non-finite number"),
        ('{"value": "\\ud800"}', _limits(), "invalid Unicode scalar"),
    ],
)
def test_json_shape_and_constants_are_bounded(
    tmp_path: Path,
    payload: str,
    limits: ArtifactLimits,
    message: str,
) -> None:
    (tmp_path / "bounded.json").write_text(payload, encoding="utf-8")

    with pytest.raises(ArtifactVerificationError, match=message):
        with ArtifactVerificationSession(tmp_path, limits=limits) as session:
            session.file(Path("bounded.json")).json()


def test_json_size_is_bounded_before_parsing(tmp_path: Path) -> None:
    (tmp_path / "large.json").write_text('{"payload": "large"}', encoding="utf-8")

    session = ArtifactVerificationSession(tmp_path)
    with pytest.raises(ArtifactVerificationError, match="8-byte limit"):
        session.file(Path("large.json"), max_bytes=8).json()
    assert session.metrics.json_parses == 0
    with pytest.raises(ArtifactVerificationError, match="8-byte limit"):
        session.seal()


def test_json_is_parsed_once_per_session(tmp_path: Path) -> None:
    (tmp_path / "artifact.json").write_text('{"value": 1}', encoding="utf-8")

    with ArtifactVerificationSession(tmp_path) as session:
        handle = session.file(Path("artifact.json"))
        first = handle.json_object()
        second = handle.json_object()
        assert first == second
        first["value"] = "poisoned"
        assert handle.json_object() == {"value": 1}
        assert session.metrics.json_parses == 1
        assert session.metrics.json_reuse == 2


def test_json_depth_is_rejected_before_any_defensive_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "deep.json").write_text("[[[0]]]", encoding="utf-8")

    def forbidden_copy(value: object) -> object:
        raise AssertionError(f"deepcopy reached for rejected value: {value!r}")

    monkeypatch.setattr(
        artifact_verification.copy,
        "deepcopy",
        forbidden_copy,
    )
    with pytest.raises(ArtifactVerificationError, match="exceeds depth 2"):
        with ArtifactVerificationSession(
            tmp_path,
            limits=_limits(max_json_depth=2),
        ) as session:
            session.file(Path("deep.json")).json()


def test_json_defensive_copy_never_leaks_a_recursion_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "artifact.json").write_text('{"value": 1}', encoding="utf-8")
    session = ArtifactVerificationSession(tmp_path)
    handle = session.file(Path("artifact.json"))
    assert handle.json() == {"value": 1}

    def recursive_copy(value: object) -> object:
        raise RecursionError(f"injected for {value!r}")

    monkeypatch.setattr(
        artifact_verification.copy,
        "deepcopy",
        recursive_copy,
    )
    try:
        with pytest.raises(
            ArtifactVerificationError,
            match="safe JSON copy depth",
        ):
            handle.json()
    finally:
        session.close()


def test_cached_content_is_inaccessible_and_released_after_seal(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.json"
    artifact.write_text('{"value": 1}', encoding="utf-8")
    session = ArtifactVerificationSession(tmp_path)
    handle = session.file(Path("artifact.json"))
    assert handle.json_object() == {"value": 1}
    session.seal()

    for operation in (
        handle.read_bytes,
        handle.read_text,
        handle.json,
        handle.digest,
        lambda: handle.fileno,
    ):
        with pytest.raises(ArtifactVerificationError, match="already closed"):
            operation()
    assert session._buffered_bytes == 0
    assert session._memo == {}
    assert session._replays == {}


def test_external_fd_access_forces_measurement_before_exposure(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"payload")
    session = ArtifactVerificationSession(tmp_path)
    handle = session.file(Path("artifact.bin"))

    assert session.metrics.bytes_hashed == 0
    assert handle.pass_fds == (handle.fileno,)
    assert session.metrics.bytes_hashed == len(b"payload")
    session.seal()
    assert session.metrics.bytes_hashed == 2 * len(b"payload")


def test_capture_after_a_standalone_digest_is_blocked_before_a_third_pass(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"payload")
    session = ArtifactVerificationSession(tmp_path)
    handle = session.file(Path("artifact.bin"))
    handle.digest()

    with pytest.raises(ArtifactVerificationError, match="captured before"):
        handle.read_bytes()
    assert session.metrics.bytes_hashed == len(b"payload")
    with pytest.raises(ArtifactVerificationError, match="captured before"):
        session.seal()
    assert session.metrics.bytes_hashed == 2 * len(b"payload")


def test_a_failed_seal_can_never_be_replayed_as_success(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"AAAA")
    session = ArtifactVerificationSession(tmp_path)
    session.file(Path("artifact.bin")).digest()
    replacement = tmp_path / "replacement.bin"
    replacement.write_bytes(b"BBBB")
    replacement.replace(artifact)

    with pytest.raises(ArtifactVerificationError) as first:
        session.seal()
    with pytest.raises(ArtifactVerificationError) as second:
        session.seal()

    assert str(second.value) == str(first.value)


def test_hardlink_alias_reuses_the_held_inode_digest(tmp_path: Path) -> None:
    first_path = tmp_path / "first.bin"
    second_path = tmp_path / "second.bin"
    first_path.write_bytes(b"payload")
    os.link(first_path, second_path)

    with ArtifactVerificationSession(tmp_path) as session:
        first = session.file(Path("first.bin"))
        second = session.file(Path("second.bin"))
        assert first.fileno == second.fileno
        assert first.digest() == second.digest()
        assert session.metrics.files_opened == 2
        assert session.metrics.bytes_hashed == len(b"payload")
        assert session.metrics.digest_reuse == 3


@pytest.mark.parametrize("alias_name", ["first.bin", "second.bin"])
def test_every_hardlink_alias_path_is_revalidated_at_seal(
    tmp_path: Path,
    alias_name: str,
) -> None:
    first_path = tmp_path / "first.bin"
    second_path = tmp_path / "second.bin"
    first_path.write_bytes(b"payload")
    os.link(first_path, second_path)
    session = ArtifactVerificationSession(tmp_path)
    session.file(Path("first.bin")).digest()
    session.file(Path("second.bin")).digest()

    replacement = tmp_path / "replacement.bin"
    replacement.write_bytes(b"payload")
    replacement.replace(tmp_path / alias_name)

    with pytest.raises(
        ArtifactVerificationError,
        match="path resolves to another inode before closure",
    ):
        session.seal()


def test_open_file_budget_counts_logical_paths(tmp_path: Path) -> None:
    (tmp_path / "first.bin").write_bytes(b"first")
    (tmp_path / "second.bin").write_bytes(b"second")

    session = ArtifactVerificationSession(
        tmp_path,
        limits=_limits(max_open_files=1),
    )
    session.file(Path("first.bin"))
    with pytest.raises(ArtifactVerificationError, match="open-file budget"):
        session.file(Path("second.bin"))
    with pytest.raises(ArtifactVerificationError, match="open-file budget"):
        session.seal()


def test_path_and_closing_descriptor_budgets_are_enforced(tmp_path: Path) -> None:
    nested = tmp_path / "one" / "two"
    nested.mkdir(parents=True)
    (nested / "artifact.bin").write_bytes(b"payload")
    path_session = ArtifactVerificationSession(
        tmp_path,
        limits=_limits(max_path_components=2),
    )
    with pytest.raises(ArtifactVerificationError, match="exceeds 2 components"):
        path_session.file(Path("one/two/artifact.bin"))
    path_session.close()

    (tmp_path / "plain.bin").write_bytes(b"payload")
    closing_session = ArtifactVerificationSession(
        tmp_path,
        limits=_limits(max_closing_fds=1),
    )
    closing_session.file(Path("plain.bin")).digest()
    with pytest.raises(ArtifactVerificationError, match="closing-FD budget"):
        closing_session.seal()


def test_noncanonical_anchor_and_absolute_adapter_fail_typed(tmp_path: Path) -> None:
    with pytest.raises(ArtifactVerificationError, match="anchor is not canonical"):
        ArtifactVerificationSession(Path("/tmp/\x00artifact"))

    with pytest.raises(ArtifactVerificationError, match="not canonical"):
        with ArtifactVerificationSession(tmp_path) as session:
            session.file_path(Path("relative.bin"))


def test_hashed_byte_budget_is_enforced_during_measurement(tmp_path: Path) -> None:
    (tmp_path / "artifact.bin").write_bytes(b"12345")
    session = ArtifactVerificationSession(
        tmp_path,
        limits=_limits(max_hashed_bytes=4),
    )
    try:
        with pytest.raises(ArtifactVerificationError, match="hashed-byte budget"):
            session.file(Path("artifact.bin")).digest()
        assert session.metrics.bytes_hashed == 0
        with pytest.raises(ArtifactVerificationError, match="hashed-byte budget"):
            session.seal()
    finally:
        session.close()


def test_buffered_byte_budget_is_enforced_before_publication(tmp_path: Path) -> None:
    (tmp_path / "artifact.bin").write_bytes(b"12345")
    session = ArtifactVerificationSession(
        tmp_path,
        limits=_limits(max_buffered_bytes=4),
    )
    try:
        with pytest.raises(ArtifactVerificationError, match="buffered-byte budget"):
            session.file(Path("artifact.bin")).read_bytes()
        assert session.metrics.bytes_hashed == 0
        with pytest.raises(ArtifactVerificationError, match="buffered-byte budget"):
            session.seal()
    finally:
        session.close()


def test_memo_and_replay_are_scoped_and_run_factories_once(tmp_path: Path) -> None:
    memo_calls = 0
    replay_calls = 0

    def build_memo() -> object:
        nonlocal memo_calls
        memo_calls += 1
        return object()

    def build_replay() -> object:
        nonlocal replay_calls
        replay_calls += 1
        return object()

    with ArtifactVerificationSession(tmp_path) as session:
        memo_value = session.memo(("validation", 1), build_memo)
        replay_value = session.replay_once(("xorriso", 1), build_replay)
        assert session.memo(("validation", 1), build_memo) is memo_value
        assert session.replay_once(("xorriso", 1), build_replay) is replay_value
        assert memo_calls == 1
        assert replay_calls == 1
        assert session.metrics.replays == 1

    with ArtifactVerificationSession(tmp_path) as session:
        assert session.memo(("validation", 1), build_memo) is not memo_value
        assert session.replay_once(("xorriso", 1), build_replay) is not replay_value
        assert memo_calls == 2
        assert replay_calls == 2
        assert session.metrics.replays == 1


def test_memo_factory_failure_is_guarded_and_blocks_seal(tmp_path: Path) -> None:
    session = ArtifactVerificationSession(tmp_path)

    def blocked_validation() -> object:
        raise ArtifactVerificationError("memo validation failed closed")

    with pytest.raises(
        ArtifactVerificationError,
        match="memo validation failed closed",
    ):
        session.memo(("validation", 1), blocked_validation)
    with pytest.raises(
        ArtifactVerificationError,
        match="memo validation failed closed",
    ):
        session.seal()


def test_replay_counter_advances_only_after_a_successful_guarded_replay(
    tmp_path: Path,
) -> None:
    session = ArtifactVerificationSession(tmp_path)
    calls = 0

    def flaky_replay() -> object:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise ArtifactVerificationError("replay failed closed")
        return object()

    try:
        with pytest.raises(
            ArtifactVerificationError,
            match="replay failed closed",
        ):
            session.replay_once(("xorriso", 1), flaky_replay)
        assert session.metrics.replays == 0
        result = session.replay_once(("xorriso", 1), flaky_replay)
        assert session.metrics.replays == 1
        assert session.replay_once(("xorriso", 1), flaky_replay) is result
        assert session.metrics.replays == 1
        assert calls == 2
        with pytest.raises(
            ArtifactVerificationError,
            match="replay failed closed",
        ):
            session.seal()
    finally:
        session.close()


def test_close_aggregates_every_descriptor_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "first.bin").write_bytes(b"first")
    (tmp_path / "second.bin").write_bytes(b"second")
    session = ArtifactVerificationSession(tmp_path)
    session.file(Path("first.bin"))
    session.file(Path("second.bin"))
    injected = {
        session._records[0].descriptor: "first-close",
        session._records[1].descriptor: "second-close",
        session._anchor_descriptor: "anchor-close",
    }
    real_close = os.close

    def failing_close(descriptor: int) -> None:
        real_close(descriptor)
        failure = injected.get(descriptor)
        if failure is not None:
            raise OSError(errno.EIO, failure)

    monkeypatch.setattr(os, "close", failing_close)

    with pytest.raises(ArtifactVerificationError) as caught:
        session.close()
    detail = str(caught.value)
    assert "first-close" in detail
    assert "second-close" in detail
    assert "anchor-close" in detail
    assert session._closed


def test_close_failure_blocks_an_otherwise_successful_seal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "artifact.bin").write_bytes(b"artifact")
    session = ArtifactVerificationSession(tmp_path)
    session.file(Path("artifact.bin")).digest()
    failing_descriptor = session._records[0].descriptor
    real_close = os.close

    def failing_close(descriptor: int) -> None:
        real_close(descriptor)
        if descriptor == failing_descriptor:
            raise OSError(errno.EIO, "held-artifact-close")

    monkeypatch.setattr(os, "close", failing_close)

    with pytest.raises(
        ArtifactVerificationError,
        match="held-artifact-close",
    ):
        session.seal()
    assert session.receipt is None


@pytest.mark.parametrize(
    "case",
    [
        pytest.param("success", id="success"),
        pytest.param("decode-error", id="decode-error"),
    ],
)
def test_session_does_not_leak_descriptors(
    tmp_path: Path,
    case: str,
) -> None:
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"payload" if case == "success" else b"\xff")
    before = _fd_count()

    if case == "decode-error":
        with pytest.raises(ArtifactVerificationError, match="not strict UTF-8"):
            with ArtifactVerificationSession(tmp_path) as session:
                session.file(Path("artifact.bin")).read_text()
    else:
        with ArtifactVerificationSession(tmp_path) as session:
            session.file(Path("artifact.bin")).digest()

    assert _fd_count() == before
