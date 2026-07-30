from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest
from conftest import (
    package_fixture_options,
    write_valid_boot_proof,
    write_valid_build_evidence,
)

from distroforge.core import command as command_module
from distroforge.core.command import (
    CommandError,
    CommandRunner,
    CommandSpec,
    ExecutionIdentityError,
)
from distroforge.core.evidence_run import canonical_sha256
from distroforge.core.project import Project
from distroforge.core.release_gate import (
    ReleaseGateService,
    _dispatch_binding_closes,
)


def _executable(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)
    return path


def test_successful_command_closes_and_logs_its_identity_interval(
    tmp_path: Path,
) -> None:
    tool = _executable(tmp_path / "fixture-tool", "#!/bin/sh\nprintf 'proved\\n'\n")
    log = tmp_path / "commands.jsonl"
    runner = CommandRunner(dry_run=False, log_path=log)

    result = runner.run(CommandSpec((str(tool),), description="Run stable tool"))

    assert result.stdout == "proved\n"
    identity = runner.execution_identities[0]
    assert identity["dispatch_bound"] is True
    bindings = identity["dispatch_bindings"]
    assert isinstance(bindings, list)
    assert len(bindings) == 2
    script_binding, interpreter_binding = bindings
    assert script_binding["execution_role"] == "script-body"
    assert script_binding["mode"] == "script-argument"
    assert interpreter_binding["execution_role"] == "shebang-interpreter"
    assert interpreter_binding["mode"] == "outer-shebang-interpreter"
    assert identity["dispatch_argv"] == [
        interpreter_binding["descriptor_path"],
        script_binding["descriptor_path"],
    ]
    descriptor = identity["dispatch_executable"]
    assert descriptor == interpreter_binding["descriptor_path"]
    assert script_binding["command"] == str(tool)
    assert script_binding["argv_index"] == 0
    assert script_binding["device"] == tool.stat().st_dev
    assert script_binding["inode"] == tool.stat().st_ino
    assert script_binding["size"] == tool.stat().st_size
    assert script_binding["sha256"] == hashlib.sha256(
        tool.read_bytes()
    ).hexdigest()
    assert identity["post_dispatch_verified"] is True
    assert identity["stable_across_dispatch"] is True
    assert identity["post_dispatch_process_returncode"] == 0
    post_chain = identity["post_execution_chain"]
    assert isinstance(post_chain, list)
    assert len(post_chain) == 2
    for post in post_chain:
        assert isinstance(post, dict)
        assert post["held_fd_sha256_unchanged"] is True
        assert post["held_fd_metadata_unchanged"] is True
        assert post["resolved_path_matches_held_fd"] is True
        assert post["stable_across_dispatch"] is True
    chain = identity["execution_chain"]
    assert isinstance(chain, list)
    assert _dispatch_binding_closes(identity, chain)

    events = [
        json.loads(line)["event"]
        for line in log.read_text(encoding="utf-8").splitlines()
    ]
    assert events == [
        "start",
        "execution-identity",
        "execution-identity-post-dispatch",
        "finish",
    ]


def test_atomic_replacement_is_a_failure_even_with_identical_bytes_and_no_check(
    tmp_path: Path,
) -> None:
    tool = _executable(
        tmp_path / "self-replacing-tool",
        "#!/bin/sh\ncp \"$1\" \"$1.next\"\nmv \"$1.next\" \"$1\"\nprintf 'child-ok\\n'\n",
    )
    runner = CommandRunner(dry_run=False)

    with pytest.raises(ExecutionIdentityError) as caught:
        runner.run(CommandSpec((str(tool), str(tool))), check=False)

    assert caught.value.process_result.returncode == 0
    assert caught.value.result.returncode == 125
    identity = runner.execution_identities[0]
    assert identity["post_dispatch_verified"] is False
    post_chain = identity["post_execution_chain"]
    assert isinstance(post_chain, list)
    post = post_chain[0]
    assert isinstance(post, dict)
    assert post["held_fd_sha256_unchanged"] is True
    assert post["resolved_sha256_unchanged"] is True
    assert post["resolved_path_matches_held_fd"] is False
    assert "resolved path no longer names the open file" in post["divergences"]


def test_target_root_mutation_breaks_the_whole_wrapper_chain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "rootfs"
    env = _executable(root / "usr" / "bin" / "env", "target env")
    target = _executable(root / "usr" / "bin" / "apt-get", "target apt v1")
    assert env.is_file()

    def mutate_target(
        argv: tuple[str, ...],
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        target.write_text("target apt v2", encoding="utf-8")
        target.chmod(0o755)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(command_module.subprocess, "run", mutate_target)
    runner = CommandRunner(dry_run=False)
    spec = CommandSpec(
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

    with pytest.raises(ExecutionIdentityError):
        runner.run(spec)

    identity = runner.execution_identities[0]
    post_chain = identity["post_execution_chain"]
    assert isinstance(post_chain, list)
    assert all(isinstance(entry, dict) for entry in post_chain)
    by_command = {entry["command"]: entry for entry in post_chain}
    assert by_command["chroot"]["stable_across_dispatch"] is True
    assert by_command["env"]["stable_across_dispatch"] is True
    assert by_command["apt-get"]["stable_across_dispatch"] is False
    assert by_command["apt-get"]["held_fd_sha256_unchanged"] is False
    assert by_command["apt-get"]["resolved_sha256_unchanged"] is False


def test_modify_then_restore_bytes_is_detected_by_the_open_inode_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = _executable(tmp_path / "restored-tool", "original bytes")
    original = tool.stat()

    def modify_and_restore(
        argv: tuple[str, ...],
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        tool.write_text("tampered bytes", encoding="utf-8")
        tool.write_text("original bytes", encoding="utf-8")
        tool.chmod(original.st_mode)
        tool.touch()
        command_module.os.utime(
            tool,
            ns=(original.st_atime_ns, original.st_mtime_ns),
        )
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(command_module.subprocess, "run", modify_and_restore)
    runner = CommandRunner(dry_run=False)

    with pytest.raises(ExecutionIdentityError):
        runner.run(CommandSpec((str(tool),)))

    identity = runner.execution_identities[0]
    post_chain = identity["post_execution_chain"]
    assert isinstance(post_chain, list)
    post = post_chain[0]
    assert isinstance(post, dict)
    assert post["held_fd_sha256_unchanged"] is True
    assert post["resolved_sha256_unchanged"] is True
    assert post["held_fd_metadata_unchanged"] is False
    assert "open file metadata changed across dispatch" in post["divergences"]


def test_streaming_command_keeps_the_same_post_dispatch_proof(
    tmp_path: Path,
) -> None:
    tool = _executable(
        tmp_path / "streaming-tool",
        "#!/bin/sh\nprintf 'one\\ntwo\\n'\n",
    )
    lines: list[str] = []
    runner = CommandRunner(dry_run=False)

    result = runner.run_streaming(CommandSpec((str(tool),)), lines.append)

    assert result.stdout == "one\ntwo\n"
    assert lines == ["one", "two"]
    identity = runner.execution_identities[0]
    assert identity["post_dispatch_verified"] is True
    post_chain = identity["post_execution_chain"]
    assert isinstance(post_chain, list)
    post = post_chain[0]
    assert isinstance(post, dict)
    assert post["stable_across_dispatch"] is True


def test_binary_command_captures_exact_bytes_under_the_dispatch_proof(
    tmp_path: Path,
) -> None:
    tool = _executable(
        tmp_path / "binary-tool",
        "#!/bin/sh\nprintf '\\000\\377'\n",
    )
    runner = CommandRunner(dry_run=False)
    output = tmp_path / "payload.tar"

    with output.open("w+b") as handle:
        result = runner.run_binary_to_file(
            CommandSpec((str(tool),)),
            handle,
            max_output_bytes=16,
        )

    assert output.read_bytes() == b"\x00\xff"
    assert result.stdout == "<2 binary bytes captured>\n"
    identity = runner.execution_identities[0]
    assert identity["post_dispatch_verified"] is True
    assert identity["stable_across_dispatch"] is True


def test_binary_command_refuses_output_beyond_the_explicit_bound(
    tmp_path: Path,
) -> None:
    tool = _executable(
        tmp_path / "oversized-binary-tool",
        "#!/bin/sh\nprintf '12345'\n",
    )
    runner = CommandRunner(dry_run=False)

    with (tmp_path / "bounded-output").open("w+b") as handle:
        with pytest.raises(CommandError, match="exceeded the 4-byte capture limit"):
            runner.run_binary_to_file(
                CommandSpec((str(tool),)),
                handle,
                max_output_bytes=4,
            )


def test_binary_command_refuses_unbounded_stderr_without_spooling_it(
    tmp_path: Path,
) -> None:
    runner = CommandRunner(dry_run=False)

    with (tmp_path / "bounded-stderr-output").open("w+b") as handle:
        with pytest.raises(
            CommandError,
            match="binary stderr exceeded the 1048576-byte capture limit",
        ) as failure:
            runner.run_binary_to_file(
                CommandSpec(
                    (
                        sys.executable,
                        "-c",
                        (
                            "import sys; "
                            "sys.stderr.buffer.write(b'x' * (1024 * 1024 + 1))"
                        ),
                    )
                ),
                handle,
                max_output_bytes=16,
            )

    assert len(failure.value.result.stderr) < 5000


def test_atomic_swap_cannot_select_different_dispatched_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = _executable(
        tmp_path / "dispatch-tool",
        "#!/bin/sh\nprintf 'trusted\\n'\n",
    )
    attacker = _executable(
        tmp_path / "attacker-tool",
        "#!/bin/sh\nprintf 'attacker\\n'\n",
    )
    parked = tmp_path / "trusted-parked"
    real_run = subprocess.run

    def swap_during_dispatch(
        argv: tuple[str, ...],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        tool.rename(parked)
        attacker.rename(tool)
        try:
            return real_run(argv, **kwargs)
        finally:
            tool.rename(attacker)
            parked.rename(tool)

    monkeypatch.setattr(command_module.subprocess, "run", swap_during_dispatch)
    runner = CommandRunner(dry_run=False)

    with pytest.raises(ExecutionIdentityError) as caught:
        runner.run(CommandSpec((str(tool),)))

    # The path was hostile at the instant Popen ran, but the kernel consumed the
    # already hashed descriptor.  The path attack is still refused after dispatch.
    assert caught.value.process_result.stdout == "trusted\n"
    assert "attacker" not in caught.value.process_result.stdout


def test_shebang_interpreter_swap_cannot_select_attacker_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    interpreter = tmp_path / "sealed-sh"
    attacker = tmp_path / "attacker-interpreter"
    shutil.copy2("/bin/sh", interpreter)
    shutil.copy2("/bin/false", attacker)
    interpreter.chmod(0o755)
    attacker.chmod(0o755)
    tool = _executable(
        tmp_path / "interpreter-bound-tool",
        f"#!{interpreter}\nprintf 'trusted-interpreter\\n'\n",
    )
    parked = tmp_path / "sealed-sh-parked"
    real_run = subprocess.run

    def swap_interpreter_during_dispatch(
        argv: tuple[str, ...],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        interpreter.rename(parked)
        attacker.rename(interpreter)
        try:
            return real_run(argv, **kwargs)
        finally:
            interpreter.rename(attacker)
            parked.rename(interpreter)

    monkeypatch.setattr(
        command_module.subprocess,
        "run",
        swap_interpreter_during_dispatch,
    )
    runner = CommandRunner(dry_run=False)

    with pytest.raises(ExecutionIdentityError) as caught:
        runner.run(CommandSpec((str(tool),)))

    assert caught.value.process_result.stdout == "trusted-interpreter\n"
    identity = runner.execution_identities[0]
    assert identity["stable_across_dispatch"] is False
    bindings = identity["dispatch_bindings"]
    assert isinstance(bindings, list)
    interpreter_binding = next(
        binding
        for binding in bindings
        if binding["execution_role"] == "shebang-interpreter"
    )
    assert interpreter_binding["command"] == str(interpreter)


def test_env_split_shebang_is_resolved_and_descriptor_bound(
    tmp_path: Path,
) -> None:
    tool = _executable(
        tmp_path / "env-split-tool",
        "#!/usr/bin/env -S sh -e\nprintf 'env-split-proved\\n'\n",
    )
    runner = CommandRunner(dry_run=False)

    result = runner.run(CommandSpec((str(tool),)))

    assert result.stdout == "env-split-proved\n"
    identity = runner.execution_identities[0]
    chain = identity["execution_chain"]
    assert isinstance(chain, list)
    script, interpreter = chain
    assert script["shebang_resolver"] == "/usr/bin/env"
    assert script["shebang_arguments"] == ["-e"]
    assert interpreter["command"] == "sh"
    assert _dispatch_binding_closes(identity, chain)


def test_env_shebang_with_implicit_argument_splitting_is_refused(
    tmp_path: Path,
) -> None:
    tool = _executable(
        tmp_path / "ambiguous-env-tool",
        "#!/usr/bin/env sh -e\nprintf 'must-not-run\\n'\n",
    )
    runner = CommandRunner(dry_run=False)

    with pytest.raises(ExecutionIdentityError) as caught:
        runner.run(CommandSpec((str(tool),)))

    assert caught.value.process_result.returncode == 125
    assert "must-not-run" not in caught.value.process_result.stdout
    identity = runner.execution_identities[0]
    chain = identity["execution_chain"]
    assert isinstance(chain, list)
    assert chain[0]["shebang_valid"] is False
    assert "explicit -S" in chain[0]["shebang_error"]


def test_nested_env_target_is_rewritten_to_its_hashed_descriptor(
    tmp_path: Path,
) -> None:
    tool = _executable(
        tmp_path / "nested-tool",
        "#!/bin/sh\nprintf 'nested-proved\\n'\n",
    )
    runner = CommandRunner(dry_run=False)
    original = ("env", "PROOF=1", str(tool))

    result = runner.run(CommandSpec(original))

    assert result.stdout == "nested-proved\n"
    identity = runner.execution_identities[0]
    dispatched = identity["dispatch_argv"]
    assert isinstance(dispatched, list)
    assert dispatched[:2] == ["env", "PROOF=1"]
    assert isinstance(dispatched[2], str)
    assert dispatched[2].startswith("/proc/")
    bindings = identity["dispatch_bindings"]
    assert isinstance(bindings, list)
    assert [binding["argv_index"] for binding in bindings] == [0, 2, 2]
    assert [binding["execution_role"] for binding in bindings] == [
        "argv-executable",
        "script-body",
        "shebang-interpreter",
    ]
    chain = identity["execution_chain"]
    assert isinstance(chain, list)
    assert _dispatch_binding_closes(identity, chain)


def _release_gate_with_mutated_provenance(
    tmp_path: Path,
    mutate: Callable[[dict[str, object]], None],
) -> str:
    project = Project.create("TOCTOU", tmp_path / "project", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "TOCTOU.iso"
    iso.write_bytes(b"iso")
    immutable = write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    provenance = json.loads(immutable.read_text(encoding="utf-8"))
    mutate(provenance)
    content = json.dumps(provenance, indent=2) + "\n"
    immutable.write_text(content, encoding="utf-8")
    (project.output_dir / "distroforge-provenance.json").write_text(
        content,
        encoding="utf-8",
    )
    manifest_path = immutable.parent / "RUN-MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    files = manifest["files"]
    assert isinstance(files, list)
    immutable_entry = next(
        item
        for item in files
        if isinstance(item, dict) and item.get("path") == str(immutable)
    )
    immutable_entry["size"] = immutable.stat().st_size
    immutable_entry["sha256"] = hashlib.sha256(
        immutable.read_bytes()
    ).hexdigest()
    manifest_path.write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )
    (immutable.parent / "RUN-MANIFEST.json.sha256").write_text(
        f"{hashlib.sha256(manifest_path.read_bytes()).hexdigest()}  "
        "RUN-MANIFEST.json\n",
        encoding="utf-8",
    )
    gate = ReleaseGateService().check(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
    )
    return next(item.detail for item in gate.items if item.code == "provenance")


def test_release_gate_rejects_the_old_pre_dispatch_only_format(
    tmp_path: Path,
) -> None:
    def remove_post_proof(provenance: dict[str, object]) -> None:
        entrypoints = provenance["executed_host_entrypoints"]
        assert isinstance(entrypoints, list)
        for entrypoint in entrypoints:
            assert isinstance(entrypoint, dict)
            for key in tuple(entrypoint):
                if key.startswith("post_") or key == "stable_across_dispatch":
                    entrypoint.pop(key)
        provenance["executed_host_entrypoints_sha256"] = canonical_sha256(
            entrypoints
        )

    detail = _release_gate_with_mutated_provenance(tmp_path, remove_post_proof)

    assert "post-dispatch" in detail


def test_release_gate_recomputes_post_dispatch_chain_invariants(
    tmp_path: Path,
) -> None:
    def forge_stable_flag(provenance: dict[str, object]) -> None:
        entrypoints = provenance["executed_host_entrypoints"]
        assert isinstance(entrypoints, list)
        entrypoint = entrypoints[0]
        assert isinstance(entrypoint, dict)
        post_chain = entrypoint["post_execution_chain"]
        assert isinstance(post_chain, list)
        post = post_chain[0]
        assert isinstance(post, dict)
        post["resolved_path_matches_held_fd"] = False
        entrypoint["post_execution_chain_sha256"] = canonical_sha256(post_chain)
        provenance["executed_host_entrypoints_sha256"] = canonical_sha256(
            entrypoints
        )

    detail = _release_gate_with_mutated_provenance(tmp_path, forge_stable_flag)

    assert "changed across dispatch" in detail


def test_release_gate_cross_checks_the_post_dispatch_log_and_provenance(
    tmp_path: Path,
) -> None:
    project = Project.create("LoggedTOCTOU", tmp_path / "logged-project", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "LoggedTOCTOU.iso"
    iso.write_bytes(b"iso")
    immutable = write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    run_dir = immutable.parent
    command_log = run_dir / "commands.jsonl"
    events = [
        json.loads(line)
        for line in command_log.read_text(encoding="utf-8").splitlines()
    ]
    post_event = next(
        event
        for event in events
        if event["event"] == "execution-identity-post-dispatch"
    )
    post_event["post_dispatch_process_returncode"] = 7
    command_log.write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )

    manifest_path = run_dir / "RUN-MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    command_item = next(
        item for item in manifest["files"] if item["path"] == str(command_log)
    )
    command_item["size"] = command_log.stat().st_size
    command_item["sha256"] = hashlib.sha256(command_log.read_bytes()).hexdigest()
    manifest_path.write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )
    manifest_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    (run_dir / "RUN-MANIFEST.json.sha256").write_text(
        f"{manifest_sha}  RUN-MANIFEST.json\n",
        encoding="utf-8",
    )

    gate = ReleaseGateService().check(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
    )
    detail = next(item.detail for item in gate.items if item.code == "provenance")

    assert "post-dispatch identity diverges" in detail
