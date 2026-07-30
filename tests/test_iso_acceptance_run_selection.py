from __future__ import annotations

import hashlib
import json
import os
import shlex
from pathlib import Path
from types import SimpleNamespace

from distroforge.cli import build_parser
from distroforge.commands.iso_accept import render_iso_accept
from distroforge.core.build import BuildOptions
from distroforge.core.demo_iso import run_demo_iso
from distroforge.core.iso_acceptance import accept_iso
from distroforge.core.project import Project
from distroforge.core.release_gate import ReleaseGateItem


def _identity(path: Path) -> dict[str, object]:
    return {
        "path": str(path),
        "size": path.stat().st_size,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _write_release_run(project: Project, iso: Path, run_id: str) -> Path:
    run_dir = project.output_dir / "evidence" / "runs" / run_id
    run_dir.mkdir(parents=True)
    iso_digest = hashlib.sha256(iso.read_bytes()).hexdigest()
    iso_build = run_dir / "ISO-BUILD.json"
    iso_build.write_text(
        json.dumps(
            {
                "schema": "distroforge.iso-build.v2",
                "run_id": run_id,
                "project": str(project.root),
                "status": "built",
                "execute": True,
                "output_iso": str(iso),
                "output_exists": True,
                "output_size": iso.stat().st_size,
                "output_sha256": iso_digest,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    provenance = run_dir / "distroforge-provenance.json"
    provenance.write_text(
        json.dumps(
            {
                "schema": "distroforge.provenance.v2",
                "attestation_kind": "build",
                "run_id": run_id,
                "output_iso": str(iso),
                "output_iso_sha256": iso_digest,
                "run": {"run_id": run_id, "mode": "execute"},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    manifest = run_dir / "RUN-MANIFEST.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": "distroforge.build-run-manifest.v1",
                "run_id": run_id,
                "mode": "execute",
                "status": "built",
                "files": [
                    _identity(iso_build),
                    _identity(provenance),
                    _identity(iso),
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    manifest_digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    (run_dir / "RUN-MANIFEST.json.sha256").write_text(
        f"{manifest_digest}  RUN-MANIFEST.json\n",
        encoding="utf-8",
    )
    return run_dir


def _gate(
    *,
    blocked: bool = False,
    boot_run_id: str | None = None,
) -> SimpleNamespace:
    items = (
        [ReleaseGateItem("remaining-evidence", "blocked", "fixture gate blocker")]
        if blocked
        else []
    )
    return SimpleNamespace(
        blocked=blocked,
        status="blocked" if blocked else "ready",
        items=items,
        boot_run_id=boot_run_id,
    )


def test_acceptance_ignores_stale_global_build_aliases(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = Project.create("AliasFree", tmp_path / "alias-free", "26.04")
    iso = project.output_dir / "AliasFree.iso"
    iso.write_bytes(b"current product")
    run_dir = _write_release_run(project, iso, "run-current")
    (project.output_dir / "ISO-BUILD.json").write_text(
        '{"run_id":"stale-alias","status":"blocked"}\n',
        encoding="utf-8",
    )
    (project.output_dir / "distroforge-provenance.json").write_text(
        '{"run_id":"stale-alias"}\n',
        encoding="utf-8",
    )
    seen: list[str | None] = []

    def check(_service, _project, _options, **kwargs):
        seen.append(kwargs.get("build_run_id"))
        return _gate()

    monkeypatch.setattr(
        "distroforge.core.iso_acceptance.ReleaseGateService.check",
        check,
    )

    report = accept_iso(project, BuildOptions(), iso=iso)
    payload = json.loads(
        (project.output_dir / "ISO-ACCEPTANCE.json").read_text(encoding="utf-8")
    )

    assert report.status == "accepted"
    assert report.build_run_id == "run-current"
    assert report.report == run_dir / "ISO-BUILD.json"
    assert seen == ["run-current"]
    assert payload["build_run_id"] == "run-current"
    assert payload["immutable_iso_build"] == str(run_dir / "ISO-BUILD.json")
    assert "--build-run-id run-current" in report.next_command
    assert str(run_dir / "ISO-BUILD.json") in report.render_text()


def test_acceptance_blocks_ambiguous_runs_and_requests_explicit_id(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = Project.create("Ambiguous", tmp_path / "ambiguous", "26.04")
    iso = project.output_dir / "Ambiguous.iso"
    iso.write_bytes(b"same product")
    _write_release_run(project, iso, "run-one")
    _write_release_run(project, iso, "run-two")

    def unexpected_gate(*_args, **_kwargs):
        raise AssertionError("release gate must not run after ambiguous selection")

    monkeypatch.setattr(
        "distroforge.core.iso_acceptance.ReleaseGateService.check",
        unexpected_gate,
    )

    report = accept_iso(project, BuildOptions(), iso=iso)

    assert report.blocked
    assert report.build_run_id is None
    assert report.report is None
    assert "--build-run-id RUN_ID" in report.next_command
    assert "multiple immutable executed build runs" in next(
        item.detail
        for item in report.items
        if item.code == "iso-build-report"
    )


def test_acceptance_explicit_run_reaches_remaining_release_gate(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = Project.create("Explicit", tmp_path / "explicit", "26.04")
    iso = project.output_dir / "Explicit.iso"
    iso.write_bytes(b"same product")
    _write_release_run(project, iso, "run-one")
    selected_dir = _write_release_run(project, iso, "run-two")
    seen: list[str | None] = []

    def check(_service, _project, _options, **kwargs):
        seen.append(kwargs.get("build_run_id"))
        return _gate(blocked=True)

    monkeypatch.setattr(
        "distroforge.core.iso_acceptance.ReleaseGateService.check",
        check,
    )

    report = accept_iso(
        project,
        BuildOptions(),
        iso=iso,
        build_run_id="run-two",
    )

    assert report.blocked
    assert report.build_run_id == "run-two"
    assert report.report == selected_dir / "ISO-BUILD.json"
    assert seen == ["run-two"]
    assert any(item.code == "gate-remaining-evidence" for item in report.items)
    assert "--build-run-id run-two" in report.next_command


def test_acceptance_boot_remediation_is_one_bound_pipeline(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = Project.create(
        "BootRemediation",
        tmp_path / "boot-remediation",
        "26.04",
    )
    iso = project.output_dir / "BootRemediation.iso"
    iso.write_bytes(b"same product")
    _write_release_run(project, iso, "build-selected")

    def check(_service, _project, _options, **_kwargs):
        return SimpleNamespace(
            blocked=True,
            status="blocked",
            items=[
                ReleaseGateItem(
                    "boot-proof",
                    "blocked",
                    "immutable boot evidence is missing",
                )
            ],
            boot_run_id=None,
        )

    monkeypatch.setattr(
        "distroforge.core.iso_acceptance.ReleaseGateService.check",
        check,
    )

    report = accept_iso(
        project,
        BuildOptions(),
        iso=iso,
        build_run_id="build-selected",
    )

    command = shlex.split(report.next_command)
    assert report.blocked
    assert command[:2] == ["distroforge", "release-pipeline"]
    assert command.count("distroforge") == 1
    assert command[command.index("--build-run-id") + 1] == "build-selected"
    assert "--run-boot-proof" in command
    assert "BOOT_RUN_ID" not in report.next_command


def test_acceptance_blocks_if_selected_immutable_report_is_swapped(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = Project.create("Swapped", tmp_path / "swapped", "26.04")
    iso = project.output_dir / "Swapped.iso"
    iso.write_bytes(b"same product")
    run_dir = _write_release_run(project, iso, "run-one")

    def swap_then_check(_service, _project, _options, **_kwargs):
        replacement = run_dir / "replacement.json"
        replacement.write_text('{"replacement":true}\n', encoding="utf-8")
        os.replace(replacement, run_dir / "ISO-BUILD.json")
        return _gate()

    monkeypatch.setattr(
        "distroforge.core.iso_acceptance.ReleaseGateService.check",
        swap_then_check,
    )

    report = accept_iso(project, BuildOptions(), iso=iso)

    assert report.blocked
    assert any(item.code == "artifact-session" for item in report.items)


def test_acceptance_propagates_explicit_standalone_boot_run(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = Project.create("StandaloneBoot", tmp_path / "standalone-boot", "26.04")
    iso = project.output_dir / "StandaloneBoot.iso"
    iso.write_bytes(b"same product")
    _write_release_run(project, iso, "build-selected")
    seen: list[tuple[str | None, str | None]] = []

    def check(_service, _project, _options, **kwargs):
        seen.append(
            (
                kwargs.get("build_run_id"),
                kwargs.get("boot_run_id"),
            )
        )
        return _gate(boot_run_id="boot-selected")

    monkeypatch.setattr(
        "distroforge.core.iso_acceptance.ReleaseGateService.check",
        check,
    )

    report = accept_iso(
        project,
        BuildOptions(),
        iso=iso,
        build_run_id="build-selected",
        boot_run_id="boot-selected",
    )

    assert seen == [("build-selected", "boot-selected")]
    assert report.status == "accepted"
    assert report.build_run_id == "build-selected"
    assert report.boot_run_id == "boot-selected"
    assert "--boot-run-id boot-selected" in report.next_command


def test_demo_iso_passes_exact_build_run_to_acceptance(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = Project.create("DemoRun", tmp_path / "demo-run", "26.04")
    doctor = SimpleNamespace(
        blocked=False,
        status="ready",
        next_command="none",
        to_dict=lambda: {"status": "ready"},
    )
    build = SimpleNamespace(
        blocked=False,
        status="built",
        run_id="demo-build-run",
        boot_proof=SimpleNamespace(run_id="demo-boot-run"),
        report=project.output_dir
        / "evidence"
        / "runs"
        / "demo-build-run"
        / "ISO-BUILD.json",
        to_dict=lambda: {"status": "built", "run_id": "demo-build-run"},
    )
    acceptance = SimpleNamespace(
        blocked=False,
        status="accepted",
        next_command=(
            "distroforge publish-bundle "
            f"{project.root} --build-run-id demo-build-run"
        ),
        to_dict=lambda: {
            "status": "accepted",
            "build_run_id": "demo-build-run",
        },
    )
    seen: list[tuple[str | None, str | None]] = []

    monkeypatch.setattr(
        "distroforge.core.demo_iso.diagnose_iso_build",
        lambda *_args, **_kwargs: doctor,
    )
    monkeypatch.setattr(
        "distroforge.core.demo_iso.run_iso_build",
        lambda *_args, **_kwargs: build,
    )

    def capture_accept(*_args, **kwargs):
        seen.append(
            (
                kwargs.get("build_run_id"),
                kwargs.get("boot_run_id"),
            )
        )
        return acceptance

    monkeypatch.setattr(
        "distroforge.core.demo_iso.accept_iso",
        capture_accept,
    )

    report = run_demo_iso(project.root, execute=True)

    assert report.status == "accepted"
    assert seen == [("demo-build-run", "demo-boot-run")]
    assert "--build-run-id demo-build-run" in report.next_command


def test_iso_accept_parser_and_renderer_propagate_run_ids(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = Project.create("CliRun", tmp_path / "cli-run", "26.04")
    args = build_parser().parse_args(
        [
            "iso-accept",
            str(project.root),
            "--build-run-id",
            "cli-build-run",
            "--boot-run-id",
            "cli-boot-run",
        ]
    )
    assert args.build_run_id == "cli-build-run"
    assert args.boot_run_id == "cli-boot-run"
    seen: list[tuple[str | None, str | None]] = []
    fake = SimpleNamespace(
        blocked=False,
        render_json=lambda: '{"build_run_id":"cli-build-run"}',
        render_text=lambda: "Build run: cli-build-run",
    )

    def capture_accept(*_args, **kwargs):
        seen.append(
            (
                kwargs.get("build_run_id"),
                kwargs.get("boot_run_id"),
            )
        )
        return fake

    monkeypatch.setattr(
        "distroforge.commands.iso_accept.accept_iso",
        capture_accept,
    )

    rendered, blocked = render_iso_accept(
        project.root,
        json_output=True,
        build_run_id=args.build_run_id,
        boot_run_id=args.boot_run_id,
    )

    assert blocked is False
    assert json.loads(rendered)["build_run_id"] == "cli-build-run"
    assert seen == [("cli-build-run", "cli-boot-run")]
