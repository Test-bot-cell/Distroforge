from __future__ import annotations

import hashlib
import os
import socket
from pathlib import Path

import pytest

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
    with pytest.raises(ArtifactVerificationError, match="changed before closure"):
        session.seal()


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
