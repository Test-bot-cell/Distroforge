from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import write_valid_boot_proof, write_valid_build_evidence

from distroforge.core.beginner_iso import repair_beginner_iso_release_artifacts
from distroforge.core.build import BuildOptions
from distroforge.core.command import CommandRunner, CommandSpec, _execution_chain
from distroforge.core.evidence_run import (
    builder_source_identity,
    canonical_sha256,
    first_symlink_in_confined_tree,
    make_run_context,
    observed_executable_counts,
    reserve_evidence_run,
    toolchain_identity,
)
from distroforge.core.iso_build import run_iso_build
from distroforge.core.project import Project
from distroforge.core.release_gate import ReleaseGateService


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
        BuildOptions(),
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
        BuildOptions(),
        iso=iso,
        output_dir=project.output_dir,
    )
    assert {item.code: item.status for item in clean.items}["provenance"] == "ready"

    provenance = project.output_dir / "distroforge-provenance.json"
    provenance.write_text(provenance.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    tampered = ReleaseGateService().check(
        project,
        BuildOptions(),
        iso=iso,
        output_dir=project.output_dir,
    )
    item = next(item for item in tampered.items if item.code == "provenance")
    assert item.status == "blocked"
    assert "differs from immutable" in item.detail


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
        BuildOptions(),
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
