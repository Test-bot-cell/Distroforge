from __future__ import annotations

import errno
import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest
from conftest import write_valid_build_evidence

import distroforge.core.boot_proof as boot_proof_module
import distroforge.core.evidence_run as evidence_run_module
from distroforge.core.boot_proof import run_boot_proof
from distroforge.core.build import BuildOptions
from distroforge.core.evidence_run import evidence_run_path, write_immutable_text
from distroforge.core.prebuild_vm import QEMU_REPORT_SCHEMA, QemuReportValidation
from distroforge.core.project import Project


def _write_minimal_immutable_qemu_report(service: Any) -> None:
    report = evidence_run_path(
        service.output_dir,
        service.run_id,
        service.options.report_name,
        executed=True,
    )
    payload = {
        "schema": QEMU_REPORT_SCHEMA,
        "run_id": service.run_id,
        "status": "completed",
        "verdict": "passed",
        "boot": {"reached_milestone": "login_prompt"},
    }
    write_immutable_text(report, json.dumps(payload, indent=2) + "\n")


def _install_qemu_fixture(
    monkeypatch: pytest.MonkeyPatch,
) -> list[Path]:
    validated: list[Path] = []

    monkeypatch.setattr(
        boot_proof_module.CommandRunner,
        "has_binary",
        staticmethod(lambda name: name == "qemu-system-x86_64"),
    )
    monkeypatch.setattr(
        boot_proof_module.QemuLabService,
        "run",
        _write_minimal_immutable_qemu_report,
    )

    def validate(
        report_path: Path,
        iso_path: Path,
        *,
        session: object,
    ) -> QemuReportValidation:
        del iso_path, session
        validated.append(report_path)
        return QemuReportValidation(True, "fixture immutable QEMU report")

    monkeypatch.setattr(boot_proof_module, "validate_qemu_report", validate)
    return validated


def _prepare_alias(path: Path, kind: str, tmp_path: Path) -> bytes | None:
    if kind == "absent":
        return None
    if kind == "stale":
        body = b'{"schema":"stale","status":"blocked"}\n'
        path.write_bytes(body)
        return body
    if kind == "forged":
        body = b'{"status":"completed","verdict":"passed","forged":true}\n'
        path.write_bytes(body)
        return body
    if kind == "symlink":
        victim = tmp_path / f"{path.name}.victim"
        body = b'{"external":"victim"}\n'
        victim.write_bytes(body)
        path.symlink_to(victim)
        return body
    if kind == "fifo":
        os.mkfifo(path)
        return None
    raise AssertionError(f"unsupported test alias kind: {kind}")


def _alias_receipt(report: Any) -> dict[str, Any]:
    assert report.alias_publication_receipt is not None
    return json.loads(
        report.alias_publication_receipt.read_text(encoding="utf-8")
    )


@pytest.mark.parametrize(
    "alias_kind",
    ("absent", "stale", "forged", "symlink", "fifo"),
)
def test_qemu_global_alias_never_selects_or_changes_immutable_verdict(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    alias_kind: str,
) -> None:
    project = Project.create(
        f"QemuAlias{alias_kind}",
        tmp_path / f"qemu-alias-{alias_kind}",
        "26.04",
    )
    iso = project.output_dir / "boot.iso"
    iso.write_bytes(b"held ISO bytes")
    write_valid_build_evidence(
        project,
        iso,
        run_id="selected-build-run",
    )
    qemu_alias = project.output_dir / "qemu-lab-report.json"
    original_alias = _prepare_alias(qemu_alias, alias_kind, tmp_path)
    validated = _install_qemu_fixture(monkeypatch)

    report = run_boot_proof(
        project,
        iso=iso,
        backend="qemu",
        execute=True,
        build_run_id="selected-build-run",
    )

    assert report.status == "ready", report.notes
    assert report.run_id
    assert report.build_run_id == "selected-build-run"
    assert report.immutable_qemu_report == (
        project.output_dir
        / "evidence"
        / "runs"
        / report.run_id
        / "qemu-lab-report.json"
    )
    assert validated
    assert set(validated) == {report.immutable_qemu_report}
    assert qemu_alias not in validated
    immutable_bytes = report.immutable_qemu_report.read_bytes()
    assert report.qemu_report_sha256 == hashlib.sha256(
        immutable_bytes
    ).hexdigest()
    if alias_kind in {"stale", "forged"}:
        assert qemu_alias.read_bytes() == original_alias
    elif alias_kind == "symlink":
        assert qemu_alias.is_symlink()
        assert qemu_alias.read_bytes() == original_alias
    elif alias_kind == "fifo":
        assert qemu_alias.stat().st_mode
    else:
        assert not qemu_alias.exists()


@pytest.mark.parametrize(
    "alias_kind",
    ("absent", "stale", "forged", "symlink", "fifo"),
)
def test_boot_global_alias_is_optional_and_receipted_without_downgrade(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    alias_kind: str,
) -> None:
    project = Project.create(
        f"BootAlias{alias_kind}",
        tmp_path / f"boot-alias-{alias_kind}",
        "26.04",
    )
    iso = project.output_dir / "boot.iso"
    iso.write_bytes(b"held ISO bytes")
    write_valid_build_evidence(
        project,
        iso,
        run_id="selected-build-run",
    )
    boot_alias = project.output_dir / "boot-proof.json"
    original_alias = _prepare_alias(boot_alias, alias_kind, tmp_path)
    _install_qemu_fixture(monkeypatch)

    report = run_boot_proof(
        project,
        iso=iso,
        backend="qemu",
        execute=True,
        build_run_id="selected-build-run",
    )

    assert report.status == "ready", report.notes
    receipt = _alias_receipt(report)
    expected_status = "matched" if alias_kind == "absent" else "collision-preserved"
    assert receipt["status"] == expected_status
    assert receipt["run_id"] == report.run_id
    assert receipt["target"] == str(boot_alias)
    assert report.immutable_proof is not None
    assert receipt["authoritative_report"]["path"] == str(
        report.immutable_proof
    )
    immutable_bytes = report.immutable_proof.read_bytes()
    assert json.loads(immutable_bytes)["status"] == "ready"
    assert receipt["authoritative_report"]["size"] == len(immutable_bytes)
    assert receipt["authoritative_report"]["sha256"] == hashlib.sha256(
        immutable_bytes
    ).hexdigest()
    if alias_kind == "absent":
        assert boot_alias.read_bytes() == immutable_bytes
    elif alias_kind in {"stale", "forged"}:
        assert boot_alias.read_bytes() == original_alias
    elif alias_kind == "symlink":
        assert boot_alias.is_symlink()
        assert boot_alias.read_bytes() == original_alias
    else:
        assert boot_alias.stat().st_mode


def test_boot_manifest_binds_build_run_qemu_alias_receipt_and_sidecar(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    project = Project.create("BootManifest", tmp_path / "boot-manifest", "26.04")
    iso = project.output_dir / "boot.iso"
    iso.write_bytes(b"held ISO bytes")
    write_valid_build_evidence(
        project,
        iso,
        run_id="explicit-build-run",
    )
    options = BuildOptions()
    options._evidence_context = {"run_id": "context-build-run"}
    _install_qemu_fixture(monkeypatch)

    report = run_boot_proof(
        project,
        options,
        iso=iso,
        backend="qemu",
        execute=True,
        build_run_id="explicit-build-run",
    )

    assert report.status == "ready", report.notes
    assert report.build_run_id == "explicit-build-run"
    assert report.immutable_proof is not None
    assert report.immutable_qemu_report is not None
    assert report.run_manifest is not None
    assert report.alias_publication_receipt is not None
    proof_payload = json.loads(report.immutable_proof.read_text(encoding="utf-8"))
    assert proof_payload["run_id"] == report.run_id
    assert proof_payload["build_run_id"] == "explicit-build-run"
    assert proof_payload["immutable_qemu_report"] == str(
        report.immutable_qemu_report
    )
    assert proof_payload["qemu_report"] == "qemu-lab-report.json"
    assert proof_payload["alias_publication_receipt"] == str(
        report.alias_publication_receipt
    )

    manifest_bytes = report.run_manifest.read_bytes()
    manifest = json.loads(manifest_bytes)
    assert manifest["run_id"] == report.run_id
    assert manifest["build_run_id"] == "explicit-build-run"
    identities = {
        item["path"]: item
        for item in manifest["files"]
    }
    for expected in (
        report.immutable_proof,
        report.immutable_qemu_report,
        report.alias_publication_receipt,
        iso,
    ):
        assert str(expected) in identities
        body = expected.read_bytes()
        assert identities[str(expected)]["size"] == len(body)
        assert identities[str(expected)]["sha256"] == hashlib.sha256(
            body
        ).hexdigest()
    sidecar = report.run_manifest.with_name("RUN-MANIFEST.json.sha256")
    assert sidecar.read_text(encoding="utf-8") == (
        f"{hashlib.sha256(manifest_bytes).hexdigest()}  RUN-MANIFEST.json\n"
    )


def test_boot_build_run_binding_falls_back_to_exact_evidence_context(
    tmp_path: Path,
) -> None:
    project = Project.create(
        "BootContextBinding",
        tmp_path / "boot-context-binding",
        "26.04",
    )
    iso = project.output_dir / "boot.iso"
    iso.write_bytes(b"held ISO bytes")
    options = BuildOptions()
    options._evidence_context = {"run_id": "context-build-run"}

    report = run_boot_proof(
        project,
        options,
        iso=iso,
        backend="iso-scan",
        execute=False,
    )

    assert report.status == "planned", report.notes
    assert report.build_run_id == "context-build-run"
    assert report.immutable_proof is not None
    assert report.run_manifest is not None
    proof = json.loads(report.immutable_proof.read_text(encoding="utf-8"))
    manifest = json.loads(report.run_manifest.read_text(encoding="utf-8"))
    assert proof["build_run_id"] == "context-build-run"
    assert manifest["build_run_id"] == "context-build-run"


def test_boot_alias_post_link_error_is_unconfirmed_complete_and_fd_clean(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    project = Project.create("BootFsync", tmp_path / "boot-fsync", "26.04")
    iso = project.output_dir / "boot.iso"
    iso.write_bytes(b"held ISO bytes")
    target = project.output_dir / "boot-proof.plan.json"
    real_link = evidence_run_module.os.link
    injected = False

    def link_then_fail(
        source_name: str,
        target_name: str,
        **kwargs: Any,
    ) -> None:
        nonlocal injected
        real_link(source_name, target_name, **kwargs)
        destination_fd = kwargs.get("dst_dir_fd")
        destination_parent = (
            Path(os.readlink(f"/proc/self/fd/{destination_fd}"))
            if isinstance(destination_fd, int)
            else None
        )
        if (
            target_name == target.name
            and destination_parent == target.parent
            and not injected
        ):
            injected = True
            raise OSError(errno.EIO, "simulated post-link fsync failure")

    monkeypatch.setattr(evidence_run_module.os, "link", link_then_fail)
    before_fds = len(os.listdir("/proc/self/fd"))

    report = run_boot_proof(
        project,
        iso=iso,
        backend="iso-scan",
        execute=False,
        build_run_id="selected-build-run",
    )

    after_fds = len(os.listdir("/proc/self/fd"))
    assert injected
    assert report.status == "planned", report.notes
    assert _alias_receipt(report)["status"] == "unconfirmed"
    assert report.immutable_proof is not None
    assert json.loads(
        report.immutable_proof.read_text(encoding="utf-8")
    )["status"] == "planned"
    assert target.read_bytes() == report.immutable_proof.read_bytes()
    assert not tuple(project.output_dir.glob(".boot-proof*.staged-*"))
    assert after_fds == before_fds


@pytest.mark.parametrize(
    "explicit,context",
    (
        ("../escape", None),
        ("run/child", None),
        (None, {"run_id": "../context-escape"}),
        (None, {"run_id": 42}),
    ),
)
def test_boot_build_run_binding_rejects_unsafe_values_before_publication(
    tmp_path: Path,
    explicit: str | None,
    context: dict[str, object] | None,
) -> None:
    project = Project.create("BootBinding", tmp_path / "boot-binding", "26.04")
    iso = project.output_dir / "boot.iso"
    iso.write_bytes(b"held ISO bytes")
    options = BuildOptions()
    options._evidence_context = context

    with pytest.raises(ValueError, match="unsafe|safe"):
        run_boot_proof(
            project,
            options,
            iso=iso,
            backend="iso-scan",
            execute=False,
            build_run_id=explicit,
        )

    assert not (project.output_dir / "evidence").exists()
    assert not (project.output_dir / "boot-proof.plan.json").exists()
