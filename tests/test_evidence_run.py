from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.util
import json
import os
import py_compile
from pathlib import Path

import pytest
from conftest import (
    package_fixture_options,
    write_valid_boot_proof,
    write_valid_build_evidence,
)

import distroforge.core.release_gate as release_gate_module
from distroforge.core.beginner_iso import repair_beginner_iso_release_artifacts
from distroforge.core.build import BuildOptions
from distroforge.core.command import CommandRunner, CommandSpec, _execution_chain
from distroforge.core.evidence_run import (
    TOOLCHAIN_BINARIES,
    builder_source_identity,
    canonical_sha256,
    close_run_identity,
    first_symlink_in_confined_tree,
    make_run_context,
    observed_executable_counts,
    reserve_evidence_run,
    toolchain_identity,
)
from distroforge.core.iso_build import run_iso_build
from distroforge.core.project import Project
from distroforge.core.release_gate import (
    ReleaseGateService,
    _git_builder_publication_problem,
    _identity_closure_problem,
    _provenance_is_bootstrap,
)


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


def test_a_run_id_collision_is_refused_before_evidence_can_mix(tmp_path: Path) -> None:
    output = tmp_path / "dist"
    reserve_evidence_run(output, "same-run", executed=True)

    with pytest.raises(FileExistsError):
        reserve_evidence_run(output, "same-run", executed=True)


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
    check = next(
        item for item in closure["checks"] if item["name"] == "definition"
    )
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
    check = next(
        item for item in closure["checks"] if item["name"] == "source_iso"
    )
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
        item
        for item in context["identity_closure"]["checks"]
        if item["name"] == "builder_source"
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
        item
        for item in context["identity_closure"]["checks"]
        if item["name"] == "builder_source"
    )
    assert (
        check["final"]["filesystem_guard"]["content_sha256"]
        == context["builder_source"]["filesystem_guard"]["content_sha256"]
    )
    assert (
        check["final"]["filesystem_guard"]["directory_metadata_sha256"]
        != context["builder_source"]["filesystem_guard"][
            "directory_metadata_sha256"
        ]
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
        item
        for item in context["identity_closure"]["checks"]
        if item["name"] == "toolchain"
    )
    assert (
        check["final"]["fixture-tool"]["sha256"]
        == context["toolchain"]["fixture-tool"]["sha256"]
    )
    assert (
        check["final"]["fixture-tool"]["inode"]
        != context["toolchain"]["fixture-tool"]["inode"]
    )


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
    assert all(
        check["initial_sha256"] == check["final_sha256"]
        for check in closure["checks"]
    )
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
        "tracked_diff_sha256": (
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855"
        ),
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
            item["sha256"] = __import__("hashlib").sha256(
                artifact.read_bytes()
            ).hexdigest()
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


def test_release_gate_detects_provenance_alias_and_manifest_tampering(tmp_path: Path) -> None:
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
    assert item.status == "blocked"
    assert "differs from immutable" in item.detail


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
    validate_actions = (
        release_gate_module.validate_package_apt_actions_evidence
    )
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
    monkeypatch.setattr(
        release_gate_module,
        "MAX_REPORT_JSON_BYTES",
        action_path.stat().st_size - 1,
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
    assert "APT action report exceeds its byte bound" in item.detail


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
    provenance = project.output_dir / "distroforge-provenance.json"
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
        run["builder_source"]["ignored_runtime_paths"] = [
            "distroforge/__pycache__/injected.pyc"
        ]
        _reclose_fixture_identity(run)
    else:
        run["builder_source"]["commit_signature"] = "N"
        _reclose_fixture_identity(run)
    provenance.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

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
        name: run[name]
        for name in ("builder_source", "definition", "source_iso", "toolchain")
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


def test_release_gate_detects_a_command_log_changed_after_sealing(tmp_path: Path) -> None:
    project = Project.create("LogTamper", tmp_path / "log-tamper", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "LogTamper.iso"
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    command_log = (
        project.output_dir / "evidence" / "runs" / "build-run" / "commands.jsonl"
    )
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


def test_repair_preserves_real_build_provenance_and_labels_reconstruction(
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

    provenance.unlink()
    repair_beginner_iso_release_artifacts(project, BuildOptions(output_iso=iso))
    reconstructed = json.loads(provenance.read_text(encoding="utf-8"))
    assert reconstructed["attestation_kind"] == "reconstructed"
