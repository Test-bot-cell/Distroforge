from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Any

import pytest
from conftest import (
    package_fixture_options,
    write_valid_boot_proof,
    write_valid_build_evidence,
)

import distroforge.core.publish_bundle as publish_bundle_module
import distroforge.core.publish_drill as publish_drill_module
import distroforge.core.release_pipeline as release_pipeline_module
from distroforge.cli import main
from distroforge.core.artifact_paths import default_artifact_paths, default_output_iso
from distroforge.core.artifact_verification import ArtifactVerificationSession
from distroforge.core.boot_proof import run_boot_proof
from distroforge.core.build import BuildOptions
from distroforge.core.capture_diff import diff_capture_profile
from distroforge.core.evidence import EvidenceStatusService, validate_evidence_contract
from distroforge.core.evidence_run import stable_parent_identity
from distroforge.core.project import Project
from distroforge.core.publish_bundle import create_publish_bundle
from distroforge.core.publish_drill import run_publish_drill
from distroforge.core.publish_drill_baseline import promote_publish_drill_baseline
from distroforge.core.publish_drill_diff import diff_publish_drills
from distroforge.core.qemu_smoke import QemuSmokePlanner
from distroforge.core.release_explain import ReleaseExplainReport, explain_release
from distroforge.core.release_gate import ReleaseGateService
from distroforge.core.release_notes import write_release_notes
from distroforge.core.release_pipeline import (
    ReleasePipelineReport,
    ReleasePipelineStage,
    run_release_pipeline,
)
from distroforge.core.release_readiness import ReleaseReadinessService
from distroforge.core.release_signing import sign_release_bundle
from distroforge.core.release_verification import (
    ReleaseVerifyItem,
    ReleaseVerifyReport,
    verify_release_bundle,
)
from tests.publish_drill_contract import (
    publish_drill_text,
    stable_directory_identity,
)


def _write_bootable_iso(path) -> None:
    data = bytearray(80 * 2048)
    pvd = 16 * 2048
    data[pvd] = 1
    data[pvd + 1 : pvd + 6] = b"CD001"
    data[pvd + 6] = 1
    data[pvd + 40 : pvd + 72] = b"BOOTPROOF".ljust(32)
    boot = 17 * 2048
    data[boot] = 0
    data[boot + 1 : boot + 6] = b"CD001"
    data[boot + 6] = 1
    data[boot + 7 : boot + 30] = b"EL TORITO SPECIFICATION"
    data[boot + 71 : boot + 75] = (20).to_bytes(4, "little")
    terminator = 18 * 2048
    data[terminator] = 255
    data[terminator + 1 : terminator + 6] = b"CD001"
    data[terminator + 6] = 1
    data[24 * 2048 : 24 * 2048 + 48] = b"CASPER VMLINUZ INITRD BOOT.CAT FILESYSTEM.SQUASHFS"
    path.write_bytes(data)


def _write_drill(
    path, *, status="ready_to_publish", gate="ready", boot="runtime", blockers=(), sha="abc"
) -> None:
    fixture_options: dict[str, object] = {}
    if path.name == "PUBLISH-DRILL.json":
        bundle = path.parent
        project_root = bundle.parents[1]
        project_data = json.loads((project_root / "project.json").read_text(encoding="utf-8"))
        fixture_options = {
            "project": project_root,
            "project_name": project_data["name"],
            "bundle_dir": bundle,
            "bundle_identity": stable_directory_identity(bundle),
        }
    path.write_text(
        publish_drill_text(
            status=status,
            gate=gate,
            boot=boot,
            blockers=blockers,
            sha256=sha,
            **fixture_options,
        ),
        encoding="utf-8",
    )


def test_artifact_paths_are_host_paths_for_project(tmp_path) -> None:
    project = Project.create("ForgeLab", tmp_path / "forge-lab", "26.04")

    paths = default_artifact_paths(project)

    # The unversioned name was the defect: the builder writes ForgeLab-26.04.iso,
    # so boot-proof and the release stages used to look for an ISO that never
    # existed and reported it missing while it sat right next to them.
    assert paths.output_iso == project.output_dir / "ForgeLab-26.04.iso"
    assert paths.reports_dir == project.output_dir / "reports"
    assert "livefs_work_dir" in paths.to_dict()


def test_release_readiness_blocks_missing_iso_and_reports_qemu_plan(tmp_path) -> None:
    report = ReleaseReadinessService().check(tmp_path / "missing.iso", tmp_path)

    assert report.blocked
    assert any(item.name == "qemu-smoke" for item in report.items)
    assert "repo-trust" in report.render_text()


def test_release_gate_blocks_missing_iso_and_requires_policy_proof(tmp_path) -> None:
    project = Project.create("GateLab", tmp_path / "gate-lab", "26.04")
    project.source_mode = "bootstrap"

    report = ReleaseGateService().check(project, BuildOptions())

    assert report.blocked
    assert report.status == "blocked"
    assert any(item.code == "iso" and item.status == "blocked" for item in report.items)
    assert "Release gate" in report.render_text()


def test_release_gate_verifies_iso_sha_and_release_files(tmp_path) -> None:
    project = Project.create("GateReady", tmp_path / "gate-ready", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "GateReady.iso"
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    options = package_fixture_options()
    options.prebuild_vm.enabled = True

    report = ReleaseGateService().check(
        project,
        options,
        iso=iso,
        output_dir=project.output_dir,
        capture_artifact_receipt=True,
    )

    statuses = {item.code: item.status for item in report.items}
    assert statuses["iso"] == "ready"
    assert statuses["sha256"] == "ready"
    assert statuses["boot-proof"] == "ready"
    assert statuses["rootfs-identity"] == "ready"
    assert statuses["iso-assembly"] == "ready"
    assert statuses["package-inputs"] == "blocked"
    assert statuses["packaging-policy"] in {"ready", "review"}
    assert report.artifact_receipt is not None
    assert "artifact_receipt" not in report.to_dict()
    assert "artifact_receipt" not in report.render_json()


def test_release_gate_status_mode_does_not_hash_iso_for_artifact_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = Project.create("GatePreview", tmp_path / "gate-preview", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "GatePreview.iso"
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    options = package_fixture_options()
    options.prebuild_vm.enabled = True
    measured_paths: list[Path] = []
    real_measure = ArtifactVerificationSession._measure

    def record_measure(self, record, binding, **kwargs):
        measured_paths.append(self.anchor_path / binding.relative)
        return real_measure(self, record, binding, **kwargs)

    monkeypatch.setattr(ArtifactVerificationSession, "_measure", record_measure)

    report = ReleaseGateService().check(
        project,
        options,
        iso=iso,
        output_dir=project.output_dir,
        verify_checksums=False,
    )

    assert report.artifact_receipt is None
    assert iso not in measured_paths


def test_publish_bundle_collects_maintainer_release_evidence(tmp_path) -> None:
    project = Project.create("BundleReady", tmp_path / "bundle-ready", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "BundleReady.iso"
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    options = package_fixture_options()
    options.prebuild_vm.enabled = True

    report = create_publish_bundle(project, options, iso=iso, output_dir=project.output_dir)

    assert report.status == "blocked"
    assert report.published, report.missing
    assert report.publication_identity == stable_parent_identity(report.bundle_dir)
    package_inputs = next(item for item in report.gate.items if item.code == "package-inputs")
    assert "installed-file causality" in package_inputs.detail
    assert {
        "BundleReady.iso",
        "SHA256SUMS",
        "BUILDINFO",
        "distroforge-provenance.json",
        "report.html",
        "qemu-lab-report.json",
        "RELEASE-GATE.json",
        "README-PUBLISH.txt",
    } <= set(report.copied)
    assert (
        (report.bundle_dir / "README-PUBLISH.txt")
        .read_text(encoding="utf-8")
        .startswith("DistroForge maintainer publish bundle")
    )


@pytest.mark.parametrize(
    ("relative", "opening", "replacement"),
    (
        (
            "evidence/runs/build-run/distroforge-provenance.json",
            b'"attestation_kind": "build"',
            b'"attestation_kind": "builf"',
        ),
        ("BUILDINFO", b"fixture", b"fixturf"),
        (
            "evidence/runs/build-run/RUN-MANIFEST.json",
            b'"status": "built"',
            b'"status": "builf"',
        ),
    ),
)
def test_publish_bundle_blocks_product_changed_after_gate_before_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative: str,
    opening: bytes,
    replacement: bytes,
) -> None:
    project = Project.create("GateBound", tmp_path / "gate-bound", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "GateBound.iso"
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    options = package_fixture_options()
    options.prebuild_vm.enabled = True
    bundle = tmp_path / f"bundle-{Path(relative).name}"
    real_check = ReleaseGateService.check
    attacked = False

    def check_then_replace(self, *args: Any, **kwargs: Any):
        nonlocal attacked
        report = real_check(self, *args, **kwargs)
        artifact = project.output_dir / relative
        original_stat = artifact.stat()
        original = artifact.read_bytes()
        assert opening in original
        forged = original.replace(opening, replacement, 1)
        assert len(forged) == len(original)
        artifact.write_bytes(forged)
        os.utime(
            artifact,
            ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns),
        )
        attacked = True
        return report

    monkeypatch.setattr(ReleaseGateService, "check", check_then_replace)

    report = create_publish_bundle(
        project,
        options,
        iso=iso,
        output_dir=project.output_dir,
        bundle_dir=bundle,
    )

    assert attacked
    assert report.blocked
    assert report.published is False
    if relative.startswith("evidence/runs/"):
        assert any(
            "gate-bound evidence tree evidence/runs/build-run differs" in problem
            and "RUN-MANIFEST.json" in problem
            for problem in report.missing
        )
    else:
        assert any(
            f"gate-bound artifact {relative} changed after the release verdict" in problem
            for problem in report.missing
        )
    assert not bundle.exists()


def test_publish_bundle_blocks_same_bytes_new_inode_and_mode_after_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = Project.create("GateIdentity", tmp_path / "gate-identity", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "GateIdentity.iso"
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    options = package_fixture_options()
    options.prebuild_vm.enabled = True
    bundle = tmp_path / "gate-identity-bundle"
    buildinfo = project.output_dir / "BUILDINFO"
    real_check = ReleaseGateService.check
    identities: list[tuple[int, int]] = []

    def check_then_replace_inode(self, *args: Any, **kwargs: Any):
        report = real_check(self, *args, **kwargs)
        original = buildinfo.stat()
        replacement = buildinfo.with_name("BUILDINFO.replacement")
        replacement.write_bytes(buildinfo.read_bytes())
        replacement.chmod(0o777)
        os.utime(
            replacement,
            ns=(original.st_atime_ns, original.st_mtime_ns),
        )
        os.replace(replacement, buildinfo)
        identities.append((original.st_ino, buildinfo.stat().st_ino))
        return report

    monkeypatch.setattr(ReleaseGateService, "check", check_then_replace_inode)

    report = create_publish_bundle(
        project,
        options,
        iso=iso,
        output_dir=project.output_dir,
        bundle_dir=bundle,
    )

    assert identities and identities[0][0] != identities[0][1]
    assert report.blocked
    assert report.published is False
    assert any(
        "gate-bound artifact BUILDINFO changed after the release verdict" in problem
        for problem in report.missing
    )
    assert not bundle.exists()


def test_post_gate_boot_alias_appearance_does_not_change_sealed_selection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = Project.create("GateBootChoice", tmp_path / "gate-boot-choice", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "GateBootChoice.iso"
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    options = package_fixture_options()
    options.prebuild_vm.enabled = True
    proof = project.output_dir / "boot-proof.json"
    proof.unlink()
    assert not proof.exists()
    real_check = ReleaseGateService.check

    def check_then_add_unconsumed_alias(self, *args: Any, **kwargs: Any):
        report = real_check(self, *args, **kwargs)
        proof.write_text('{"post_gate":true}\n', encoding="utf-8")
        return report

    monkeypatch.setattr(
        ReleaseGateService,
        "check",
        check_then_add_unconsumed_alias,
    )

    report = create_publish_bundle(
        project,
        options,
        iso=iso,
        output_dir=project.output_dir,
        bundle_dir=tmp_path / "gate-boot-choice-bundle",
    )

    assert proof.is_file()
    assert report.published, report.missing
    assert "qemu-lab-report.json" in report.copied
    assert "boot-proof.json" in report.copied
    bundled_proof = report.bundle_dir / "boot-proof.json"
    assert (
        bundled_proof.read_bytes()
        == (project.output_dir / "evidence" / "runs" / "proof-run" / "boot-proof.json").read_bytes()
    )
    assert bundled_proof.read_bytes() != proof.read_bytes()


def test_publish_bundle_blocks_gate_consumed_file_omitted_from_copy_receipts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = Project.create("GateReceipt", tmp_path / "gate-receipt", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "GateReceipt.iso"
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    options = package_fixture_options()
    options.prebuild_vm.enabled = True
    bundle = tmp_path / "gate-receipt-bundle"
    real_sources = publish_bundle_module._bundle_sources

    def omit_buildinfo(
        product_iso: Path,
        output_dir: Path,
        build_options: BuildOptions,
    ) -> tuple[Path, ...]:
        return tuple(
            source
            for source in real_sources(product_iso, output_dir, build_options)
            if source.name != "BUILDINFO"
        )

    monkeypatch.setattr(publish_bundle_module, "_bundle_sources", omit_buildinfo)

    report = create_publish_bundle(
        project,
        options,
        iso=iso,
        output_dir=project.output_dir,
        bundle_dir=bundle,
    )

    assert report.blocked
    assert report.published is False
    assert any(
        "gate-bound artifact BUILDINFO" in problem and "was not copied into the bundle" in problem
        for problem in report.missing
    )
    assert not bundle.exists()


def test_publish_bundle_blocks_file_added_to_run_tree_after_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = Project.create("GateTree", tmp_path / "gate-tree", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "GateTree.iso"
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    options = package_fixture_options()
    options.prebuild_vm.enabled = True
    bundle = tmp_path / "gate-tree-bundle"
    real_check = ReleaseGateService.check
    added = project.output_dir / "evidence" / "runs" / "build-run" / "late.txt"

    def check_then_add(self, *args: Any, **kwargs: Any):
        report = real_check(self, *args, **kwargs)
        added.write_text("not in the sealed gate inventory\n", encoding="utf-8")
        return report

    monkeypatch.setattr(ReleaseGateService, "check", check_then_add)

    report = create_publish_bundle(
        project,
        options,
        iso=iso,
        output_dir=project.output_dir,
        bundle_dir=bundle,
    )

    assert report.blocked
    assert report.published is False
    assert any(
        "gate-bound evidence tree evidence/runs/build-run differs" in problem
        and "source identity differs from the expected verdict" in problem
        for problem in report.missing
    )
    assert not bundle.exists()


def test_publish_bundle_blocks_post_gate_unreceipted_run_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = Project.create("GateRunUnion", tmp_path / "gate-run-union", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "GateRunUnion.iso"
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    options = package_fixture_options()
    options.prebuild_vm.enabled = True
    bundle = tmp_path / "gate-run-union-bundle"
    qemu_alias = project.output_dir / options.prebuild_vm.report_name
    original_qemu = qemu_alias.read_bytes()
    evil_run = project.output_dir / "evidence" / "runs" / "evil--run"
    real_check = ReleaseGateService.check
    real_copy_tree = publish_bundle_module.copy_immutable_tree
    tree_copy_attempted = False

    def check_then_redirect_run(self, *args: Any, **kwargs: Any):
        report = real_check(self, *args, **kwargs)
        payload = json.loads(original_qemu)
        payload["run_id"] = "evil--run"
        forged = (json.dumps(payload, indent=2) + "\n").encode()
        assert len(forged) == len(original_qemu)
        qemu_alias.write_bytes(forged)
        evil_run.mkdir()
        (evil_run / "POST-GATE.txt").write_text(
            "not present in any sealed tree receipt\n",
            encoding="utf-8",
        )
        return report

    def forbid_unreceipted_tree_copy(
        source: Path,
        target: Path,
        **kwargs: Any,
    ):
        nonlocal tree_copy_attempted
        tree_copy_attempted = True
        return real_copy_tree(source, target, **kwargs)

    monkeypatch.setattr(ReleaseGateService, "check", check_then_redirect_run)
    monkeypatch.setattr(
        publish_bundle_module,
        "copy_immutable_tree",
        forbid_unreceipted_tree_copy,
    )

    report = create_publish_bundle(
        project,
        options,
        iso=iso,
        output_dir=project.output_dir,
        bundle_dir=bundle,
    )

    assert tree_copy_attempted
    assert report.blocked
    assert report.published, report.missing
    assert not (bundle / "evidence" / "runs" / "evil--run").exists()
    assert (bundle / "qemu-lab-report.json").read_bytes() != qemu_alias.read_bytes()
    assert report.gate.artifact_receipt is not None
    assert qemu_alias not in {item.absolute_path for item in report.gate.artifact_receipt.files}


def test_publish_bundle_marks_missing_boot_proof_as_blocked(tmp_path) -> None:
    project = Project.create("BundleBlocked", tmp_path / "bundle-blocked", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "BundleBlocked.iso"
    iso.write_bytes(b"iso")
    digest = __import__("hashlib").sha256(b"iso").hexdigest()
    (project.output_dir / "SHA256SUMS").write_text(f"{digest}  {iso.name}\n", encoding="utf-8")
    (project.output_dir / "BUILDINFO").write_text("Build-Date: now\n", encoding="utf-8")
    (project.output_dir / "distroforge-provenance.json").write_text("{}\n", encoding="utf-8")
    (project.output_dir / "report.html").write_text("<html></html>\n", encoding="utf-8")
    options = BuildOptions()
    options.prebuild_vm.enabled = True

    report = create_publish_bundle(project, options, iso=iso, output_dir=project.output_dir)

    assert report.blocked
    assert "qemu-lab-report.json" in report.missing
    assert not report.bundle_dir.exists()


def test_publish_bundle_copies_every_referenced_run_and_refuses_reuse(tmp_path) -> None:
    project = Project.create("ClosedBundle", tmp_path / "closed-source", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "ClosedBundle.iso"
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    bundle = tmp_path / "closed-bundle"

    first = create_publish_bundle(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
        bundle_dir=bundle,
    )
    second = create_publish_bundle(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
        bundle_dir=bundle,
    )

    assert first.blocked
    assert any(
        item.code == "package-inputs" and item.status == "blocked" for item in first.gate.items
    )
    assert (bundle / "evidence" / "runs" / "build-run" / "RUN-MANIFEST.json").is_file()
    assert (bundle / "evidence" / "runs" / "proof-run" / "qemu" / "serial.log").is_file()
    assert second.blocked
    assert any("not empty" in item for item in second.missing)


@pytest.mark.parametrize(
    "relative",
    (
        "BUILDINFO",
        "evidence/runs/build-run/RUN-MANIFEST.json",
    ),
)
def test_publish_bundle_rejects_same_size_staging_rewrite_before_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative: str,
) -> None:
    project = Project.create("DigestBound", tmp_path / "digest-bound", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "DigestBound.iso"
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    bundle = tmp_path / "digest-bound-bundle"
    real_publish = publish_bundle_module.publish_immutable_tree
    attacked = False

    def rewrite_before_publication(
        staging: Path,
        target: Path,
        **kwargs: Any,
    ):
        nonlocal attacked
        expected = kwargs.get("expected_digests")
        assert isinstance(expected, dict)
        staged_files = {
            path.relative_to(staging).as_posix() for path in staging.rglob("*") if path.is_file()
        }
        assert set(expected) == staged_files
        assert all(
            hashlib.sha256((staging / name).read_bytes()).hexdigest() == digest
            for name, digest in expected.items()
        )
        artifact = staging / relative
        opening = artifact.stat()
        opening_bytes = artifact.read_bytes()
        assert opening_bytes
        forged = bytes((opening_bytes[0] ^ 1,)) + opening_bytes[1:]
        artifact.write_bytes(forged)
        os.utime(
            artifact,
            ns=(opening.st_atime_ns, opening.st_mtime_ns),
        )
        attacked = True
        return real_publish(staging, target, **kwargs)

    monkeypatch.setattr(
        publish_bundle_module,
        "publish_immutable_tree",
        rewrite_before_publication,
    )

    report = create_publish_bundle(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
        bundle_dir=bundle,
    )

    assert attacked
    assert report.blocked
    assert report.published is False
    assert any("digest contract" in item for item in report.missing)
    assert not bundle.exists()


def test_publish_bundle_root_swap_before_file_copy_never_writes_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = Project.create("RootAnchor", tmp_path / "root-anchor", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "RootAnchor.iso"
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    bundle = tmp_path / "root-anchor-bundle"
    moved = tmp_path / "moved-owned-root-staging"
    real_copy = publish_bundle_module.copy_immutable_file
    replacement: Path | None = None
    victim_bytes = b"foreign staging root\n"

    def swap_before_file_copy(
        source: Path,
        target: Path,
        **kwargs: Any,
    ):
        nonlocal replacement
        if replacement is None:
            replacement = target.parent
            replacement.rename(moved)
            replacement.mkdir()
            (replacement / "victim.txt").write_bytes(victim_bytes)
        return real_copy(source, target, **kwargs)

    monkeypatch.setattr(
        publish_bundle_module,
        "copy_immutable_file",
        swap_before_file_copy,
    )

    report = create_publish_bundle(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
        bundle_dir=bundle,
    )

    assert replacement is not None
    assert report.blocked
    assert report.published is False
    assert {entry.name for entry in replacement.iterdir()} == {"victim.txt"}
    assert (replacement / "victim.txt").read_bytes() == victim_bytes
    assert (moved / "evidence" / "runs").is_dir()
    assert not bundle.exists()


def test_publish_bundle_root_swap_before_generated_text_never_writes_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = Project.create("TextAnchor", tmp_path / "text-anchor", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "TextAnchor.iso"
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    bundle = tmp_path / "text-anchor-bundle"
    moved = tmp_path / "moved-owned-text-staging"
    real_write = publish_bundle_module.write_immutable_text
    replacement: Path | None = None
    victim_bytes = b"foreign text staging root\n"

    def swap_before_text_write(
        target: Path,
        content: str,
        **kwargs: Any,
    ):
        nonlocal replacement
        if replacement is None:
            replacement = target.parent
            replacement.rename(moved)
            replacement.mkdir()
            (replacement / "victim.txt").write_bytes(victim_bytes)
        return real_write(target, content, **kwargs)

    monkeypatch.setattr(
        publish_bundle_module,
        "write_immutable_text",
        swap_before_text_write,
    )

    report = create_publish_bundle(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
        bundle_dir=bundle,
    )

    assert replacement is not None
    assert report.blocked
    assert report.published is False
    assert {entry.name for entry in replacement.iterdir()} == {"victim.txt"}
    assert (replacement / "victim.txt").read_bytes() == victim_bytes
    assert not (replacement / "RELEASE-GATE.json").exists()
    assert (moved / "BUILDINFO").is_file()
    assert not bundle.exists()


def test_publish_bundle_nested_parent_creation_stays_on_held_root_after_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = Project.create("ParentAnchor", tmp_path / "parent-anchor", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "ParentAnchor.iso"
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    bundle = tmp_path / "parent-anchor-bundle"
    moved = tmp_path / "moved-owned-parent-staging"
    real_mkdir = os.mkdir
    replacement: Path | None = None
    victim_bytes = b"foreign nested-parent staging root\n"

    def swap_before_nested_parent(
        path: str | bytes,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> None:
        nonlocal replacement
        if path == "evidence" and dir_fd is not None and replacement is None:
            replacement = Path(os.readlink(f"/proc/self/fd/{dir_fd}"))
            replacement.rename(moved)
            replacement.mkdir()
            (replacement / "victim.txt").write_bytes(victim_bytes)
        real_mkdir(path, mode, dir_fd=dir_fd)

    monkeypatch.setattr(
        publish_bundle_module.os,
        "mkdir",
        swap_before_nested_parent,
    )

    report = create_publish_bundle(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
        bundle_dir=bundle,
    )

    assert replacement is not None
    assert report.blocked
    assert report.published is False
    assert {entry.name for entry in replacement.iterdir()} == {"victim.txt"}
    assert (replacement / "victim.txt").read_bytes() == victim_bytes
    assert not (replacement / "evidence").exists()
    assert (moved / "evidence" / "runs").is_dir()
    assert not bundle.exists()


def test_publish_bundle_root_swap_before_run_copy_never_creates_victim_parents(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = Project.create("RunAnchor", tmp_path / "run-anchor", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "RunAnchor.iso"
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    bundle = tmp_path / "run-anchor-bundle"
    moved = tmp_path / "moved-owned-run-staging"
    real_copy_tree = publish_bundle_module.copy_immutable_tree
    replacement: Path | None = None
    victim_bytes = b"foreign run staging root\n"

    def swap_before_run_copy(
        source: Path,
        target: Path,
        **kwargs: Any,
    ):
        nonlocal replacement
        if replacement is None:
            replacement = target.parents[2]
            replacement.rename(moved)
            replacement.mkdir()
            (replacement / "victim.txt").write_bytes(victim_bytes)
        return real_copy_tree(source, target, **kwargs)

    monkeypatch.setattr(
        publish_bundle_module,
        "copy_immutable_tree",
        swap_before_run_copy,
    )

    report = create_publish_bundle(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
        bundle_dir=bundle,
    )

    assert replacement is not None
    assert report.blocked
    assert report.published is False
    assert {entry.name for entry in replacement.iterdir()} == {"victim.txt"}
    assert (replacement / "victim.txt").read_bytes() == victim_bytes
    assert not (replacement / "evidence").exists()
    assert (moved / "evidence" / "runs").is_dir()
    assert not bundle.exists()


@pytest.mark.parametrize(
    ("run_id", "gate_code"),
    (("build-run", "provenance"), ("proof-run", "boot-proof")),
)
def test_publish_bundle_never_follows_an_evidence_directory_symlink(
    tmp_path,
    run_id: str,
    gate_code: str,
) -> None:
    project = Project.create(f"Linked{run_id}", tmp_path / f"linked-{run_id}", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / f"Linked{run_id}.iso"
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    outside = tmp_path / f"outside-{run_id}"
    outside.mkdir()
    (outside / "must-not-be-bundled.txt").write_text(
        "external evidence bytes\n",
        encoding="utf-8",
    )
    linked = project.output_dir / "evidence" / "runs" / run_id / "external"
    linked.symlink_to(outside, target_is_directory=True)
    bundle = tmp_path / f"bundle-{run_id}"

    gate = ReleaseGateService().check(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
    )
    report = create_publish_bundle(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
        bundle_dir=bundle,
    )

    matching_gate = next(item for item in gate.items if item.code == gate_code)
    assert matching_gate.status == "blocked"
    assert "unsafe symlink" in matching_gate.detail
    assert report.blocked
    assert any("unsafe symlink" in item for item in report.missing)
    assert not list(bundle.rglob("must-not-be-bundled.txt"))


def test_publish_bundle_rejects_a_symlinked_runs_ancestor(tmp_path) -> None:
    project = Project.create("LinkedRuns", tmp_path / "linked-runs", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "LinkedRuns.iso"
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    runs = project.output_dir / "evidence" / "runs"
    external_runs = tmp_path / "external-runs"
    runs.rename(external_runs)
    runs.symlink_to(external_runs, target_is_directory=True)
    bundle = tmp_path / "linked-runs-bundle"

    gate = ReleaseGateService().check(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
    )
    report = create_publish_bundle(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
        bundle_dir=bundle,
    )

    provenance = next(item for item in gate.items if item.code == "provenance")
    assert provenance.status == "blocked"
    assert "unsafe symlink" in provenance.detail
    assert report.blocked
    assert "evidence/runs/<run_id>" in report.missing
    assert not (bundle / "evidence" / "runs" / "build-run").exists()


def test_publish_bundle_refuses_a_symlinked_destination_root(tmp_path) -> None:
    project = Project.create("LinkedBundle", tmp_path / "linked-bundle", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "LinkedBundle.iso"
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    external = tmp_path / "external-bundle-target"
    external.mkdir()
    bundle = tmp_path / "publish-link"
    bundle.symlink_to(external, target_is_directory=True)

    report = create_publish_bundle(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
        bundle_dir=bundle,
    )

    assert report.blocked
    assert any("already reserved" in item for item in report.missing)
    assert not list(external.iterdir())


def test_publish_bundle_refuses_a_symlinked_destination_parent(
    tmp_path: Path,
) -> None:
    project = Project.create(
        "LinkedBundleParent",
        tmp_path / "linked-bundle-parent",
        "26.04",
    )
    iso = project.output_dir / "LinkedBundleParent.iso"
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    external = tmp_path / "external-parent"
    external.mkdir()
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(external, target_is_directory=True)
    bundle = linked_parent / "nested" / "publish"

    report = create_publish_bundle(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
        bundle_dir=bundle,
    )

    assert report.blocked
    assert any("could not be anchored safely" in item for item in report.missing)
    assert list(external.iterdir()) == []


def test_publish_bundle_staging_reservation_error_is_a_blocked_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    project = Project.create("StageFail", tmp_path / "stage-fail", "26.04")
    iso = project.output_dir / "StageFail.iso"
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    bundle = tmp_path / "stage-fail-publish"
    monkeypatch.setattr(
        publish_bundle_module,
        "owned_temporary_directory",
        lambda **_kwargs: (_ for _ in ()).throw(
            PermissionError("simulated staging reservation denial")
        ),
    )

    report = create_publish_bundle(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
        bundle_dir=bundle,
    )

    assert report.blocked
    assert any("staging reservation failed closed" in item for item in report.missing)
    assert not bundle.exists()
    assert list(tmp_path.glob(f".{bundle.name}.staging-*")) == []


def test_publish_bundle_cleanup_error_is_a_blocked_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    project = Project.create("CleanupFail", tmp_path / "cleanup-fail", "26.04")
    iso = project.output_dir / "CleanupFail.iso"
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    bundle = tmp_path / "cleanup-fail-publish"
    monkeypatch.setattr(
        publish_bundle_module,
        "publish_immutable_tree",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("simulated publication failure")),
    )
    monkeypatch.setattr(
        publish_bundle_module,
        "cleanup_owned_tree",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("simulated cleanup failure")),
    )

    report = create_publish_bundle(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
        bundle_dir=bundle,
    )

    assert report.blocked
    assert any("atomic bundle publication failed" in item for item in report.missing)
    assert any("staging cleanup failed closed" in item for item in report.missing)
    assert not bundle.exists()


def test_publish_bundle_publication_failure_leaves_no_final_or_staging_tree(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    project = Project.create("AtomicBundle", tmp_path / "atomic-source", "26.04")
    iso = project.output_dir / "AtomicBundle.iso"
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    bundle = tmp_path / "atomic-publish"

    def fail_publication(*args: object, **kwargs: object) -> None:
        raise OSError("simulated atomic directory publication failure")

    monkeypatch.setattr(
        publish_bundle_module,
        "publish_immutable_tree",
        fail_publication,
    )

    report = create_publish_bundle(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
        bundle_dir=bundle,
    )

    assert report.blocked
    assert not report.published
    assert any("atomic bundle publication failed" in item for item in report.missing)
    assert not bundle.exists()
    assert list(tmp_path.glob(f".{bundle.name}.staging-*")) == []


def test_publish_bundle_never_cleans_a_recreated_staging_victim(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    project = Project.create(
        "OwnedStaging",
        tmp_path / "owned-staging-source",
        "26.04",
    )
    iso = project.output_dir / "OwnedStaging.iso"
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    bundle = tmp_path / "owned-staging-publish"
    real_publish = publish_bundle_module.publish_immutable_tree
    observed: dict[str, Path] = {}

    def recreate_consumed_name(
        staging: Path,
        target: Path,
        **kwargs: object,
    ):
        receipt = real_publish(staging, target, **kwargs)
        staging.mkdir()
        (staging / "foreign-victim.txt").write_text(
            "must survive\n",
            encoding="utf-8",
        )
        observed["staging"] = staging
        return receipt

    monkeypatch.setattr(
        publish_bundle_module,
        "publish_immutable_tree",
        recreate_consumed_name,
    )

    report = create_publish_bundle(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
        bundle_dir=bundle,
    )

    assert report.published, report.missing
    assert (observed["staging"] / "foreign-victim.txt").read_text(
        encoding="utf-8"
    ) == "must survive\n"


def test_release_pipeline_stops_when_publish_has_no_complete_final_tree(
    tmp_path,
) -> None:
    project = Project.create("NoPartialPipeline", tmp_path / "no-partial", "26.04")
    iso = project.output_dir / "NoPartialPipeline.iso"
    iso.write_bytes(b"iso")

    report = run_release_pipeline(
        project,
        BuildOptions(),
        iso=iso,
        output_dir=project.output_dir,
    )

    assert report.status == "blocked"
    assert not report.bundle_dir.exists()
    assert [stage.name for stage in report.stages][-1] == "publish-bundle"


def test_release_pipeline_never_writes_into_a_concurrent_bundle_collision(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    project = Project.create(
        "ConcurrentBundle",
        tmp_path / "concurrent-source",
        "26.04",
    )
    iso = project.output_dir / "ConcurrentBundle.iso"
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    bundle = tmp_path / "concurrent-publish"

    def collide_with_foreign_tree(
        staging,
        target,
        **kwargs: object,
    ) -> None:
        del staging, kwargs
        target.mkdir()
        (target / "foreign-victim.txt").write_text(
            "must survive untouched\n",
            encoding="utf-8",
        )
        raise FileExistsError("simulated concurrent no-replace collision")

    monkeypatch.setattr(
        publish_bundle_module,
        "publish_immutable_tree",
        collide_with_foreign_tree,
    )

    report = run_release_pipeline(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
        bundle_dir=bundle,
    )

    assert report.status == "blocked"
    assert [stage.name for stage in report.stages][-1] == "publish-bundle"
    assert {path.name for path in bundle.iterdir()} == {"foreign-victim.txt"}
    assert (bundle / "foreign-victim.txt").read_text(encoding="utf-8") == "must survive untouched\n"


def test_release_pipeline_never_writes_into_a_post_publication_clone(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    project = Project.create(
        "SwappedPipeline",
        tmp_path / "swapped-pipeline-source",
        "26.04",
    )
    iso = project.output_dir / "SwappedPipeline.iso"
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    bundle = tmp_path / "swapped-pipeline-publish"
    moved = tmp_path / "swapped-pipeline-original"
    real_sign = release_pipeline_module.sign_release_bundle
    swapped = False

    def swap_before_first_sign(*args: object, **kwargs: object):
        nonlocal swapped
        if not swapped:
            swapped = True
            bundle.rename(moved)
            bundle.mkdir()
            (bundle / "foreign-victim.txt").write_text(
                "must survive untouched\n",
                encoding="utf-8",
            )
        return real_sign(*args, **kwargs)

    monkeypatch.setattr(
        release_pipeline_module,
        "sign_release_bundle",
        swap_before_first_sign,
    )

    report = run_release_pipeline(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
        bundle_dir=bundle,
    )

    assert report.status == "blocked"
    assert {path.name for path in bundle.iterdir()} == {"foreign-victim.txt"}
    assert (bundle / "foreign-victim.txt").read_text(encoding="utf-8") == "must survive untouched\n"
    assert not (moved / "RELEASE-MANIFEST.json").exists()
    assert not (moved / "SIGNING-REPORT.json").exists()


def test_publish_drill_never_writes_into_an_unpublished_bundle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    project = Project.create(
        "ForeignDrillBundle",
        tmp_path / "foreign-drill-source",
        "26.04",
    )
    bundle = tmp_path / "foreign-drill-bundle"

    def collided_pipeline(*args: object, **kwargs: object) -> ReleasePipelineReport:
        del args, kwargs
        bundle.mkdir()
        (bundle / "foreign-victim.txt").write_text(
            "must survive untouched\n",
            encoding="utf-8",
        )
        return ReleasePipelineReport(
            project.root,
            bundle,
            "blocked",
            (
                ReleasePipelineStage(
                    "publish-bundle",
                    "blocked",
                    "atomic no-replace collision",
                ),
            ),
        )

    monkeypatch.setattr(
        publish_drill_module,
        "run_release_pipeline",
        collided_pipeline,
    )

    report = run_publish_drill(project, bundle_dir=bundle)

    assert report.status == "blocked"
    assert {path.name for path in bundle.iterdir()} == {"foreign-victim.txt"}
    assert not report.drill.exists()
    assert not report.explanation.markdown.exists()


def test_publish_drill_blocks_if_terminal_read_only_verification_changes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    project = Project.create(
        "TerminalDrift",
        tmp_path / "terminal-drift-source",
        "26.04",
    )
    bundle = tmp_path / "terminal-drift-bundle"
    bundle.mkdir()
    bundle_identity = stable_parent_identity(bundle)
    pipeline = ReleasePipelineReport(
        project.root,
        bundle,
        "ready",
        (
            ReleasePipelineStage(
                "verify-release",
                "ready",
                "initial verification completed",
            ),
        ),
        bundle_identity,
    )
    preliminary = ReleaseVerifyReport(
        project.root,
        bundle,
        "ready",
        (ReleaseVerifyItem("artifact-session", "ready", "opening"),),
        bundle_identity,
    )
    terminal = ReleaseVerifyReport(
        project.root,
        bundle,
        "blocked",
        (ReleaseVerifyItem("artifact-session", "blocked", "drift"),),
        bundle_identity,
    )
    explanation = ReleaseExplainReport(
        project.root,
        project.output_dir / "TerminalDrift.iso",
        bundle,
        "ready",
        bundle / "RELEASE-EXPLAIN.md",
        (),
        (),
        (),
        {
            "status": "ready",
            "selected_backend": "qemu",
            "proof_level": "runtime",
            "attempted_backends": "qemu",
        },
        (),
    )
    verification_calls = 0

    def sequential_verification(*args: object, **kwargs: object) -> ReleaseVerifyReport:
        nonlocal verification_calls
        del args
        assert kwargs["publish_report"] is False
        verification_calls += 1
        return preliminary if verification_calls == 1 else terminal

    monkeypatch.setattr(
        publish_drill_module,
        "run_release_pipeline",
        lambda *args, **kwargs: pipeline,
    )
    monkeypatch.setattr(
        publish_drill_module,
        "verify_release_bundle",
        sequential_verification,
    )
    monkeypatch.setattr(
        publish_drill_module,
        "_read_drill_evidence",
        lambda *args, **kwargs: ({"verify": preliminary.to_dict()}, None),
    )
    monkeypatch.setattr(
        publish_drill_module,
        "explain_release",
        lambda *args, **kwargs: explanation,
    )

    report = run_publish_drill(project, bundle_dir=bundle)

    assert verification_calls == 2
    assert report.status == "blocked"
    assert not report.drill.exists()
    assert "terminal verification changed" in str(report.evidence)


def test_publish_drill_validates_its_full_contract_before_publication(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    project = Project.create(
        "StrictDrillPublication",
        tmp_path / "strict-drill-publication",
        "26.04",
    )
    bundle = project.output_dir / "publish"
    bundle.mkdir()
    bundle_identity = stable_parent_identity(bundle)
    pipeline = ReleasePipelineReport(
        project.root,
        bundle,
        "ready",
        (
            ReleasePipelineStage(
                "verify-release",
                "ready",
                "synthetic incomplete pipeline",
            ),
        ),
        bundle_identity,
    )
    verification = ReleaseVerifyReport(
        project.root,
        bundle,
        "ready",
        (ReleaseVerifyItem("artifact-session", "ready", "sealed"),),
        bundle_identity,
    )
    explanation = ReleaseExplainReport(
        project.root,
        project.output_dir / "StrictDrillPublication.iso",
        bundle,
        "ready",
        bundle / "RELEASE-EXPLAIN.md",
        (),
        (),
        (),
        {
            "status": "ready",
            "selected_backend": "qemu",
            "proof_level": "runtime",
            "attempted_backends": "qemu",
        },
        (),
    )
    monkeypatch.setattr(
        publish_drill_module,
        "run_release_pipeline",
        lambda *args, **kwargs: pipeline,
    )
    monkeypatch.setattr(
        publish_drill_module,
        "verify_release_bundle",
        lambda *args, **kwargs: verification,
    )
    monkeypatch.setattr(
        publish_drill_module,
        "_read_drill_evidence",
        lambda *args, **kwargs: ({"verify": verification.to_dict()}, None),
    )
    monkeypatch.setattr(
        publish_drill_module,
        "explain_release",
        lambda *args, **kwargs: explanation,
    )

    report = run_publish_drill(project, bundle_dir=bundle)

    assert report.status == "blocked"
    assert "drill_schema_error" in report.evidence
    assert not report.drill.exists()


def test_notes_and_read_only_explanation_do_not_recreate_a_missing_bundle(
    tmp_path,
) -> None:
    project = Project.create("MissingBundleReports", tmp_path / "reports", "26.04")
    bundle = project.output_dir / "publish"

    notes = write_release_notes(project, bundle_dir=bundle)
    explanation = explain_release(
        project,
        bundle_dir=bundle,
        write=False,
    )

    assert notes.status == "blocked"
    assert explanation.status == "blocked"
    assert not bundle.exists()


def test_release_explain_never_infers_ready_from_boot_proof_alone(
    tmp_path,
) -> None:
    project = Project.create("ExplainStrict", tmp_path / "explain-strict", "26.04")
    bundle = project.output_dir / "publish"
    bundle.mkdir(parents=True)
    (bundle / "boot-proof.json").write_text(
        json.dumps(
            {
                "status": "ready",
                "blocked": False,
                "selected_backend": "qemu",
                "proof_level": "runtime",
                "attempted_backends": ["qemu"],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    report = explain_release(project, bundle_dir=bundle)

    assert report.status == "blocked"
    assert any("release-gate" in blocker for blocker in report.blocked)
    assert any("manifest" in blocker for blocker in report.blocked)
    assert any("verify" in blocker for blocker in report.blocked)
    assert not report.markdown.exists()


def test_release_explain_rejects_a_fifo_without_waiting_or_writing(
    tmp_path,
) -> None:
    project = Project.create("ExplainFifo", tmp_path / "explain-fifo", "26.04")
    bundle = project.output_dir / "publish"
    bundle.mkdir(parents=True)
    os.mkfifo(bundle / "RELEASE-GATE.json")

    report = explain_release(project, bundle_dir=bundle)

    assert report.status == "blocked"
    assert any("RELEASE-GATE.json" in blocker for blocker in report.blocked)
    assert not report.markdown.exists()


def test_release_notes_reject_invalid_unicode_without_partial_outputs(
    tmp_path,
) -> None:
    project = Project.create("NotesUnicode", tmp_path / "notes-unicode", "26.04")
    bundle = project.output_dir / "publish"
    bundle.mkdir(parents=True)
    (bundle / "RELEASE-MANIFEST.json").write_bytes(b'{"gate_status":"ready"}\xff')

    report = write_release_notes(project, bundle_dir=bundle)

    assert report.status == "blocked"
    assert any("manifest" in blocker for blocker in report.blockers)
    assert not report.notes.exists()
    assert not report.changelog.exists()


@pytest.mark.parametrize("mutation", ("symlink", "fifo", "oversized"))
def test_publish_bundle_run_identity_json_is_bounded_and_nofollow(
    mutation: str,
    tmp_path,
) -> None:
    project = Project.create("BoundedBundle", tmp_path / mutation, "26.04")
    iso = project.output_dir / "BoundedBundle.iso"
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    provenance = (
        project.output_dir / "evidence" / "runs" / "build-run" / "distroforge-provenance.json"
    )
    provenance.unlink()
    if mutation == "symlink":
        external = tmp_path / f"{mutation}-external.json"
        external.write_text('{"run_id":"build-run"}\n', encoding="utf-8")
        provenance.symlink_to(external)
    elif mutation == "fifo":
        os.mkfifo(provenance)
    else:
        with provenance.open("wb") as handle:
            handle.truncate(publish_bundle_module._PUBLISH_JSON_BYTES + 1)
    bundle = tmp_path / f"{mutation}-bundle"

    report = create_publish_bundle(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
        bundle_dir=bundle,
    )

    assert report.blocked
    provenance_item = next(item for item in report.gate.items if item.code == "provenance")
    assert provenance_item.status == "blocked"
    assert "No immutable executed build provenance was selected" in provenance_item.detail


def test_release_gate_and_bundle_select_new_immutable_run_despite_stale_aliases(
    tmp_path: Path,
) -> None:
    project = Project.create("RunAuthority", tmp_path / "run-authority", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "RunAuthority.iso"
    iso.write_bytes(b"initial")
    run_one_provenance = write_valid_build_evidence(
        project,
        iso,
        run_id="run-one",
    )
    stale_build = (run_one_provenance.parent / "ISO-BUILD.json").read_bytes()
    stale_provenance = run_one_provenance.read_bytes()
    (project.iso_root / "run-two-marker").write_text("run two\n", encoding="utf-8")
    write_valid_build_evidence(project, iso, run_id="run-two")
    write_valid_boot_proof(project, iso)
    (project.output_dir / "ISO-BUILD.json").write_bytes(stale_build)
    (project.output_dir / "distroforge-provenance.json").write_bytes(stale_provenance)
    options = package_fixture_options()
    options.prebuild_vm.enabled = True
    bundle = tmp_path / "run-two-bundle"

    report = create_publish_bundle(
        project,
        options,
        iso=iso,
        output_dir=project.output_dir,
        bundle_dir=bundle,
    )

    assert report.gate.build_run_id == "run-two"
    assert report.gate.immutable_provenance == (
        project.output_dir / "evidence" / "runs" / "run-two" / "distroforge-provenance.json"
    )
    assert report.published, report.missing
    assert (bundle / "ISO-BUILD.json").read_bytes() == (
        project.output_dir / "evidence" / "runs" / "run-two" / "ISO-BUILD.json"
    ).read_bytes()
    assert (bundle / "distroforge-provenance.json").read_bytes() == (
        project.output_dir / "evidence" / "runs" / "run-two" / "distroforge-provenance.json"
    ).read_bytes()
    assert report.gate.artifact_receipt is not None
    receipt_paths = {item.absolute_path for item in report.gate.artifact_receipt.files}
    assert project.output_dir / "ISO-BUILD.json" not in receipt_paths
    assert project.output_dir / "distroforge-provenance.json" not in receipt_paths


def test_sign_release_plan_is_nonmutating_and_plans_signatures(tmp_path) -> None:
    project = Project.create("SignBundle", tmp_path / "sign-bundle", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "SignBundle.iso"
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    options = package_fixture_options()
    options.prebuild_vm.enabled = True
    publication = create_publish_bundle(
        project,
        options,
        iso=iso,
        output_dir=project.output_dir,
    )
    assert publication.published, publication.missing
    bundle = publication.bundle_dir
    opening = {
        path.relative_to(bundle).as_posix(): path.read_bytes()
        for path in bundle.rglob("*")
        if path.is_file()
    }

    report = sign_release_bundle(project)

    assert report.status == "planned"
    assert opening == {
        path.relative_to(bundle).as_posix(): path.read_bytes()
        for path in bundle.rglob("*")
        if path.is_file()
    }
    assert not (bundle / "RELEASE-MANIFEST.json").exists()
    assert not (bundle / "SIGNING-REPORT.json").exists()
    assert {"SHA256SUMS.asc", "RELEASE-GATE.json.asc", "RELEASE-MANIFEST.json.asc"} <= set(
        report.planned
    )
    assert any(entry.name == "SHA256SUMS" for entry in report.manifest_entries)


def test_executing_signing_refuses_a_blocked_gate(tmp_path) -> None:
    project = Project.create("BlockedSign", tmp_path / "blocked-sign", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "BlockedSign.iso"
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    options = package_fixture_options()
    options.prebuild_vm.enabled = True
    publication = create_publish_bundle(
        project,
        options,
        iso=iso,
        output_dir=project.output_dir,
    )
    assert publication.published, publication.missing
    assert publication.gate.blocked
    bundle = publication.bundle_dir

    report = sign_release_bundle(project, bundle_dir=bundle, execute=True)

    assert report.status == "blocked"
    assert any("signing was refused" in item for item in report.skipped)
    assert not list(bundle.glob("*.asc"))


def test_release_notes_use_bundle_manifest_gate_and_signing_report(tmp_path) -> None:
    project = Project.create("NotesBundle", tmp_path / "notes-bundle", "26.04")
    bundle = project.output_dir / "publish"
    bundle.mkdir(parents=True)
    (bundle / "RELEASE-MANIFEST.json").write_text(
        json.dumps(
            {
                "gate_status": "blocked",
                "files": [
                    {"name": "NotesBundle.iso", "size": 3, "sha256": "a" * 64},
                    {
                        "name": "qemu-lab-report.json",
                        "size": 2,
                        "sha256": "b" * 64,
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    (bundle / "RELEASE-GATE.json").write_text(
        json.dumps(
            {
                "status": "blocked",
                "blocked": True,
                "items": [
                    {
                        "code": "boot-proof",
                        "status": "blocked",
                        "detail": "missing",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (bundle / "SIGNING-REPORT.json").write_text(
        json.dumps(
            {
                "status": "planned",
                "execute": False,
                "signed": [],
                "planned": [
                    "SHA256SUMS.asc",
                    "RELEASE-GATE.json.asc",
                    "RELEASE-MANIFEST.json.asc",
                ],
                "skipped": [],
            }
        ),
        encoding="utf-8",
    )
    (bundle / "BUILDINFO").write_text("Build-Date: now\n", encoding="utf-8")
    (bundle / "distroforge-provenance.json").write_text(
        '{"builder": "distroforge"}\n', encoding="utf-8"
    )

    report = write_release_notes(project)

    assert report.status == "blocked"
    assert "boot-proof: missing" in report.blockers
    notes = (bundle / "RELEASE-NOTES.md").read_text(encoding="utf-8")
    changelog = (bundle / "CHANGELOG.txt").read_text(encoding="utf-8")
    assert "NotesBundle Release Notes" in notes
    assert "sha256sum -c SHA256SUMS" in notes
    assert "planned at snapshot: `SHA256SUMS.asc`" in notes
    assert "distroforge verify-release" in notes
    assert "--gpg-fingerprint EXPECTED_FULL_FINGERPRINT" in notes
    assert "gpg --verify" not in notes
    assert "Status: BLOCKED" in changelog


def test_verify_release_bundle_checks_manifest_and_sha256sums(tmp_path) -> None:
    project = Project.create("VerifyBundle", tmp_path / "verify-bundle", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "VerifyBundle.iso"
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    options = package_fixture_options()
    options.prebuild_vm.enabled = True
    create_publish_bundle(project, options, iso=iso, output_dir=project.output_dir)
    sign_release_bundle(project, publish_artifacts=True)

    report = verify_release_bundle(project)

    assert report.status == "blocked"
    assert (project.output_dir / "publish" / "VERIFY-REPORT.json").exists()
    statuses = {item.code: item.status for item in report.items}
    assert statuses["manifest"] == "ready"
    assert statuses["sha256sums"] == "ready"
    assert statuses["gate-status"] == "blocked"
    assert any(item.code == "signature" and item.status == "review" for item in report.items)
    persisted = (project.output_dir / "publish" / "VERIFY-REPORT.json").read_bytes()

    repeated = verify_release_bundle(project)

    assert repeated.to_dict() == report.to_dict()
    assert (project.output_dir / "publish" / "VERIFY-REPORT.json").read_bytes() == persisted


def test_verify_release_bundle_blocks_manifest_mismatch(tmp_path) -> None:
    project = Project.create("VerifyMismatch", tmp_path / "verify-mismatch", "26.04")
    bundle = project.output_dir / "publish"
    bundle.mkdir(parents=True)
    (bundle / "demo.iso").write_bytes(b"changed")
    (bundle / "SHA256SUMS").write_text(
        f"{__import__('hashlib').sha256(b'changed').hexdigest()}  demo.iso\n", encoding="utf-8"
    )
    (bundle / "RELEASE-GATE.json").write_text(
        '{"status": "ready", "items": []}\n', encoding="utf-8"
    )
    (bundle / "SIGNING-REPORT.json").write_text(
        '{"status": "planned", "planned": []}\n', encoding="utf-8"
    )
    (bundle / "RELEASE-MANIFEST.json").write_text(
        json.dumps(
            {"gate_status": "ready", "files": [{"name": "demo.iso", "size": 3, "sha256": "bad"}]}
        ),
        encoding="utf-8",
    )

    report = verify_release_bundle(project)

    assert report.blocked
    assert any(item.code == "manifest-size" and item.status == "blocked" for item in report.items)


def test_verify_release_rejects_manifest_escape_and_unmanifested_files(tmp_path) -> None:
    project = Project.create("ManifestEscape", tmp_path / "manifest-escape", "26.04")
    bundle = project.output_dir / "publish"
    bundle.mkdir(parents=True)
    outside = project.output_dir / "outside.txt"
    outside.write_text("outside\n", encoding="utf-8")
    digest = __import__("hashlib").sha256(outside.read_bytes()).hexdigest()
    (bundle / "RELEASE-MANIFEST.json").write_text(
        json.dumps(
            {
                "gate_status": "ready",
                "files": [
                    {
                        "name": "../outside.txt",
                        "size": outside.stat().st_size,
                        "sha256": digest,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (bundle / "RELEASE-GATE.json").write_text(
        '{"status":"ready","items":[]}\n',
        encoding="utf-8",
    )
    (bundle / "SIGNING-REPORT.json").write_text(
        '{"status":"planned","planned":[]}\n',
        encoding="utf-8",
    )
    (bundle / "extra.txt").write_text("not manifested\n", encoding="utf-8")

    report = verify_release_bundle(project, bundle_dir=bundle)

    assert report.blocked
    assert any(item.code == "manifest-path" for item in report.items)
    assert any(item.code == "manifest-extra" for item in report.items)


def test_relocated_bundle_verifies_runtime_evidence_without_source_tree(tmp_path) -> None:
    project = Project.create("Portable", tmp_path / "portable-source", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "Portable.iso"
    iso.write_bytes(b"iso")
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    bundle = tmp_path / "portable-bundle"
    publish = create_publish_bundle(
        project,
        package_fixture_options(),
        iso=iso,
        output_dir=project.output_dir,
        bundle_dir=bundle,
    )
    assert publish.blocked
    assert publish.published, publish.missing
    assert any(
        item.code == "package-inputs" and item.status == "blocked" for item in publish.gate.items
    )
    signing = sign_release_bundle(
        project,
        bundle_dir=bundle,
        publish_artifacts=True,
    )
    assert (bundle / "RELEASE-MANIFEST.json").exists(), signing
    manifest = json.loads((bundle / "RELEASE-MANIFEST.json").read_text(encoding="utf-8"))
    sealed_before = {
        entry["name"]: __import__("hashlib")
        .sha256((bundle / entry["name"]).read_bytes())
        .hexdigest()
        for entry in manifest["files"]
    }
    shutil.move(
        str(project.output_dir / "evidence"),
        str(tmp_path / "detached-source-evidence"),
    )

    report = verify_release_bundle(project, bundle_dir=bundle)

    runtime = next(item for item in report.items if item.code == "runtime-evidence")
    assert runtime.status == "ready"
    assert report.blocked
    assert sealed_before == {
        name: __import__("hashlib").sha256((bundle / name).read_bytes()).hexdigest()
        for name in sealed_before
    }


def test_release_pipeline_runs_publish_sign_notes_and_verify(tmp_path) -> None:
    project = Project.create("PipelineBundle", tmp_path / "pipeline-bundle", "26.04")
    project.source_mode = "bootstrap"
    iso = default_output_iso(project)
    iso.write_bytes(b"iso")
    options = package_fixture_options()
    options.prebuild_vm.enabled = True
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)

    report = run_release_pipeline(project, options, iso=iso, output_dir=project.output_dir)

    assert report.status == "blocked"
    bundle = project.output_dir / "publish"
    assert (bundle / "RELEASE-PIPELINE.json").exists()
    assert (bundle / "RELEASE-MANIFEST.json").exists()
    assert (bundle / "RELEASE-NOTES.md").exists()
    assert (bundle / "VERIFY-REPORT.json").exists()
    assert {"repair-artifacts", "publish-bundle", "sign-release-final", "verify-release"} <= {
        stage.name for stage in report.stages
    }
    publish_stage = next(stage for stage in report.stages if stage.name == "publish-bundle")
    assert publish_stage.status == "blocked"


def test_release_pipeline_can_run_iso_scan_boot_proof(tmp_path) -> None:
    project = Project.create("PipelineIsoScan", tmp_path / "pipeline-iso-scan", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "PipelineIsoScan.iso"
    _write_bootable_iso(iso)
    write_valid_build_evidence(project, iso)

    report = run_release_pipeline(
        project,
        BuildOptions(),
        iso=iso,
        output_dir=project.output_dir,
        run_boot_proof=True,
        boot_proof_backend="iso-scan",
    )

    stages = {stage.name: stage.status for stage in report.stages}
    proof = json.loads((project.output_dir / "boot-proof.json").read_text(encoding="utf-8"))
    assert stages["boot-proof"] == "review"
    assert proof["backend"] == "iso-scan"


def test_release_pipeline_auto_boot_proof_falls_back_to_iso_scan(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("distroforge.core.boot_proof.CommandRunner.has_binary", lambda name: False)
    project = Project.create("PipelineAutoScan", tmp_path / "pipeline-auto-scan", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "PipelineAutoScan.iso"
    _write_bootable_iso(iso)
    write_valid_build_evidence(project, iso)

    report = run_release_pipeline(
        project, BuildOptions(), iso=iso, output_dir=project.output_dir, run_boot_proof=True
    )

    stages = {stage.name: stage.status for stage in report.stages}
    proof = json.loads((project.output_dir / "boot-proof.json").read_text(encoding="utf-8"))
    assert stages["boot-proof"] == "review"
    assert proof["backend"] == "auto"
    assert proof["attempted_backends"] == ["qemu", "iso-scan"]
    assert proof["selected_backend"] == "iso-scan"
    assert proof["proof_level"] == "none"


def test_release_explain_summarizes_boot_proof_and_next_commands(tmp_path) -> None:
    project = Project.create("ExplainMe", tmp_path / "explain-me", "26.04")
    iso = project.output_dir / "ExplainMe.iso"
    _write_bootable_iso(iso)
    digest = __import__("hashlib").sha256(iso.read_bytes()).hexdigest()
    bundle = project.output_dir / "publish"
    bundle.mkdir()
    (bundle / "RELEASE-GATE.json").write_text(
        json.dumps(
            {
                "iso": str(iso),
                "status": "ready",
                "blocked": False,
                "items": [
                    {
                        "code": "iso",
                        "status": "ready",
                        "detail": f"{iso.stat().st_size} bytes",
                    },
                    {
                        "code": "sha256",
                        "status": "ready",
                        "detail": digest,
                    },
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (bundle / "RELEASE-MANIFEST.json").write_text(
        json.dumps(
            {
                "gate_status": "ready",
                "files": [
                    {
                        "name": iso.name,
                        "size": iso.stat().st_size,
                        "sha256": digest,
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (bundle / "VERIFY-REPORT.json").write_text(
        json.dumps(
            {
                "status": "ready",
                "blocked": False,
                "items": [
                    {
                        "code": "artifact-session",
                        "status": "ready",
                        "detail": "descriptor session sealed",
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (bundle / "boot-proof.json").write_text(
        json.dumps(
            {
                "status": "ready",
                "blocked": False,
                "selected_backend": "iso-scan",
                "proof_level": "structural",
                "attempted_backends": ["qemu", "iso-scan"],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    report = explain_release(project, iso=iso)

    assert report.boot_proof["proof_level"] == "structural"
    assert any("boot-proof" in item for item in report.blocked)
    assert any("--backend qemu" in command for command in report.next_commands)
    assert not (project.output_dir / "publish" / "RELEASE-EXPLAIN.md").exists()


def test_publish_drill_runs_safe_rehearsal_without_signing(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("distroforge.core.boot_proof.CommandRunner.has_binary", lambda name: False)
    project = Project.create("DrillMe", tmp_path / "drill-me", "26.04")
    project.source_mode = "bootstrap"
    iso = default_output_iso(project)
    _write_bootable_iso(iso)
    write_valid_build_evidence(project, iso)
    digest = __import__("hashlib").sha256(iso.read_bytes()).hexdigest()
    (project.output_dir / "SHA256SUMS").write_text(f"{digest}  {iso.name}\n", encoding="utf-8")

    report = run_publish_drill(project, BuildOptions(), iso=iso)

    payload = report.to_dict()
    assert report.status == "blocked"
    assert payload["execute_signing"] is False
    assert payload["pipeline"]["stages"][0]["name"] == "boot-proof"
    assert not (project.output_dir / "publish").exists()


def test_publish_drill_diff_flags_regression(tmp_path) -> None:
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    _write_drill(old)
    _write_drill(
        new,
        status="blocked",
        gate="blocked",
        boot="structural",
        blockers=("boot-proof: downgraded",),
        sha="def",
    )

    report = diff_publish_drills(old, new)

    assert report.verdict == "regressed"
    assert "DistroForge.iso" in report.manifest_changed
    assert any("boot proof regressed" in reason for reason in report.reasons)
    assert any("new blocker" in reason for reason in report.reasons)


def test_publish_drill_baseline_promotes_only_non_blocked_by_default(tmp_path) -> None:
    project = Project.create("BaselineMe", tmp_path / "baseline-me", "26.04")
    bundle = project.output_dir / "publish"
    bundle.mkdir(parents=True)
    _write_drill(bundle / "PUBLISH-DRILL.json", status="blocked")

    refused = promote_publish_drill_baseline(project)

    assert refused.status == "blocked"
    assert refused.promoted is False
    assert not (bundle / "PUBLISH-DRILL.previous.json").exists()

    _write_drill(bundle / "PUBLISH-DRILL.json", status="review_required")
    promoted = promote_publish_drill_baseline(project)

    assert promoted.status == "ready"
    assert promoted.promoted is True
    assert (bundle / "PUBLISH-DRILL.previous.json").exists()
    assert (bundle / "PUBLISH-DRILL-BASELINE.json").exists()


def test_boot_proof_writes_planned_normalized_report(tmp_path) -> None:
    project = Project.create("BootProof", tmp_path / "boot-proof", "26.04")
    iso = project.output_dir / "BootProof.iso"
    iso.write_bytes(b"iso")

    report = run_boot_proof(project, iso=iso, backend="qemu", execute=False, timeout=120)

    assert report.status == "planned"
    proof = json.loads(report.proof.read_text(encoding="utf-8"))
    assert proof["status"] == "planned"
    assert proof["backend"] == "qemu"


def test_boot_proof_auto_falls_back_to_iso_scan_when_qemu_is_missing(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("distroforge.core.boot_proof.CommandRunner.has_binary", lambda name: False)
    project = Project.create("AutoScan", tmp_path / "auto-scan", "26.04")
    iso = project.output_dir / "AutoScan.iso"
    _write_bootable_iso(iso)

    report = run_boot_proof(project, iso=iso, backend="auto", execute=True)

    proof = json.loads((project.output_dir / "boot-proof.json").read_text(encoding="utf-8"))
    assert report.status == "ready"
    assert proof["backend"] == "auto"
    assert proof["attempted_backends"] == ["qemu", "iso-scan"]
    assert proof["selected_backend"] == "iso-scan"
    assert proof["proof_level"] == "structural"
    assert proof["evidence"]["iso_scan"]["el_torito"] is True


def test_boot_proof_iso_scan_writes_ready_structural_report(tmp_path) -> None:
    project = Project.create("IsoScan", tmp_path / "iso-scan", "26.04")
    iso = project.output_dir / "IsoScan.iso"
    _write_bootable_iso(iso)

    report = run_boot_proof(project, iso=iso, backend="iso-scan", execute=True)

    proof = json.loads((project.output_dir / "boot-proof.json").read_text(encoding="utf-8"))
    assert report.status == "ready"
    assert proof["backend"] == "iso-scan"
    assert proof["evidence"]["iso9660"] is True
    assert proof["evidence"]["el_torito"] is True
    assert proof["evidence"]["boot_payload"] is True
    assert proof["evidence"]["volume_id"] == "BOOTPROOF"


def test_release_gate_rejects_planned_boot_proof(tmp_path) -> None:
    project = Project.create("BootGate", tmp_path / "boot-gate", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "BootGate.iso"
    iso.write_bytes(b"iso")
    digest = __import__("hashlib").sha256(b"iso").hexdigest()
    (project.output_dir / "SHA256SUMS").write_text(f"{digest}  {iso.name}\n", encoding="utf-8")
    (project.output_dir / "BUILDINFO").write_text("Build-Date: now\n", encoding="utf-8")
    (project.output_dir / "distroforge-provenance.json").write_text("{}\n", encoding="utf-8")
    (project.output_dir / "report.html").write_text("<html></html>\n", encoding="utf-8")
    run_boot_proof(project, iso=iso, backend="qemu", execute=False)
    options = BuildOptions()
    options.prebuild_vm.enabled = True

    gate = ReleaseGateService().check(project, options, iso=iso, output_dir=project.output_dir)

    assert {item.code: item.status for item in gate.items}["boot-proof"] == "blocked"


def test_release_gate_rejects_structural_iso_scan_as_runtime_proof(tmp_path) -> None:
    project = Project.create("IsoScanGate", tmp_path / "iso-scan-gate", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "IsoScanGate.iso"
    _write_bootable_iso(iso)
    digest = __import__("hashlib").sha256(iso.read_bytes()).hexdigest()
    (project.output_dir / "SHA256SUMS").write_text(f"{digest}  {iso.name}\n", encoding="utf-8")
    (project.output_dir / "BUILDINFO").write_text("Build-Date: now\n", encoding="utf-8")
    (project.output_dir / "distroforge-provenance.json").write_text("{}\n", encoding="utf-8")
    (project.output_dir / "report.html").write_text("<html></html>\n", encoding="utf-8")
    run_boot_proof(project, iso=iso, backend="iso-scan", execute=True)

    gate = ReleaseGateService().check(
        project, BuildOptions(), iso=iso, output_dir=project.output_dir
    )

    assert {item.code: item.status for item in gate.items}["boot-proof"] == "blocked"


def test_release_gate_marks_required_publish_signing_as_review(tmp_path) -> None:
    project = Project.create("SignGate", tmp_path / "sign-gate", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "SignGate.iso"
    iso.write_bytes(b"iso")
    digest = __import__("hashlib").sha256(b"iso").hexdigest()
    (project.output_dir / "SHA256SUMS").write_text(f"{digest}  {iso.name}\n", encoding="utf-8")
    (project.output_dir / "BUILDINFO").write_text("Build-Date: now\n", encoding="utf-8")
    (project.output_dir / "distroforge-provenance.json").write_text("{}\n", encoding="utf-8")
    (project.output_dir / "report.html").write_text("<html></html>\n", encoding="utf-8")
    (project.output_dir / "qemu-lab-report.json").write_text("{}\n", encoding="utf-8")
    options = BuildOptions()
    options.prebuild_vm.enabled = True
    options.release_artifacts.sign = True

    report = ReleaseGateService().check(project, options, iso=iso, output_dir=project.output_dir)

    statuses = {item.code: item.status for item in report.items}
    assert statuses["publish-signing"] == "review"


def test_qemu_smoke_plan_includes_online_offline_install_matrix(tmp_path) -> None:
    plan = QemuSmokePlanner().plan(tmp_path / "demo.iso")
    scenarios = {scenario.name for scenario in plan.scenarios}
    modes = {
        (scenario.firmware, scenario.network, scenario.install_mode) for scenario in plan.scenarios
    }
    secure_boot_states = {scenario.secure_boot for scenario in plan.scenarios}

    assert "live-bios-offline" in scenarios
    assert "install-bios-offline" in scenarios
    assert "install-uefi-online" in scenarios
    assert any(scenario.network for scenario in plan.scenarios)
    assert ("bios", False, "install") in modes
    assert ("uefi", True, "install") in modes
    assert {"planned", "unsupported"} <= secure_boot_states
    assert all(scenario.status == "planned" for scenario in plan.scenarios)
    assert all("qemu-system-x86_64" in scenario.command[0] for scenario in plan.scenarios)
    assert "Plan only" in plan.render_text()


def test_evidence_status_summarizes_project_without_executing_builds(tmp_path) -> None:
    project = Project.create("EvidenceLab", tmp_path / "evidence-lab", "26.04")
    project.source_mode = "bootstrap"
    project.save()

    report = EvidenceStatusService().check(project)
    payload = report.to_dict()

    assert payload["schema"] == "distroforge.evidence-status.v1"
    assert report.status in {"blocked", "review", "ready"}
    assert any(item.code == "qemu-smoke-plan" for item in report.items)
    assert any(item.code.startswith("host:") for item in report.items)
    assert any(item.code.startswith("chroot:") for item in report.items)
    assert report.counts()["review"] >= 1
    assert report.next_actions()
    assert "Evidence status" in report.render_text()
    assert "Next actions" in report.render_text()
    assert "ready items hidden" in report.render_text()
    assert "[ready]" in report.render_text(verbose=True)


def test_evidence_profiles_stage_maintainer_noise(tmp_path) -> None:
    project = Project.create("EvidenceProfiles", tmp_path / "evidence-profiles", "26.04")

    dev = EvidenceStatusService().check(project, profile="dev")
    package = EvidenceStatusService().check(project, profile="package")
    iso = EvidenceStatusService().check(project, profile="iso")
    publish = EvidenceStatusService().check(project, profile="publish")

    assert dev.profile == "dev"
    assert not any(item.code == "qemu-smoke-plan" for item in dev.items)
    assert any(item.code.startswith("package:") for item in package.items)
    assert any(item.code == "qemu-smoke-plan" for item in iso.items)
    assert any(item.code.startswith("release-gate:") for item in iso.items)
    assert any(item.code.startswith("publish:") for item in publish.items)


def test_evidence_status_deduplicates_actions_and_renders_fix_plan(tmp_path) -> None:
    project = Project.create("EvidenceFixPlan", tmp_path / "evidence-fix-plan", "26.04")

    report = EvidenceStatusService().check(project, profile="publish")

    assert len(report.next_actions(20)) == len(set(report.next_actions(20)))
    assert "Evidence fix plan" in report.render_fix_plan_text()
    assert any(command.startswith("distroforge iso-build") for command in report.fix_plan())
    assert any(command.startswith("distroforge release-readiness") for command in report.fix_plan())


def test_evidence_status_summarizes_source_tree_without_project_json(tmp_path) -> None:
    root = tmp_path / "source-tree"
    (root / "distroforge").mkdir(parents=True)
    (root / "debian").mkdir()
    (root / "pyproject.toml").write_text("[project]\nname = 'distroforge'\n", encoding="utf-8")
    (root / "debian/control").write_text("Source: distroforge\n", encoding="utf-8")

    report = EvidenceStatusService().check_source_tree(root)

    assert any(item.code == "source-tree" and item.status == "ready" for item in report.items)
    assert any(item.code.startswith("chroot:") for item in report.items)
    assert any(item.code == "qemu-smoke-plan" for item in report.items)


def test_evidence_package_profile_includes_maintainer_doctor_and_parent_artifacts(tmp_path) -> None:
    root = tmp_path / "source-package"
    output_dir = root / "dist"
    (root / "distroforge").mkdir(parents=True)
    (root / "debian").mkdir()
    output_dir.mkdir()
    (root / "pyproject.toml").write_text("[project]\nname = 'distroforge'\n", encoding="utf-8")
    (root / "debian/control").write_text("Source: distroforge\n", encoding="utf-8")
    (tmp_path / "distroforge_1.0-1_all.deb").write_bytes(b"package")
    (tmp_path / "distroforge_1.0-1_amd64.buildinfo").write_text(
        "Format: 1.0\nSource: distroforge\nBuild-Tainted-By:\n usr-local-has-programs\n",
        encoding="utf-8",
    )
    (output_dir / "AUTOPKGTEST-DOCTOR.json").write_text(
        json.dumps(
            {
                "schema": "distroforge.autopkgtest-doctor.v1",
                "status": "testbed-broken",
                "classification": "testbed-readonly",
                "detail": "testbed cannot write apt preferences",
            }
        ),
        encoding="utf-8",
    )

    report = EvidenceStatusService().check_source_tree(
        root,
        output_dir=output_dir,
        profile="package",
    )
    items = {item.code: item for item in report.items}

    assert items["debian-dev-doctor"].status in {"ready", "review"}
    assert items["package:deb"].status == "ready"
    assert items["package:buildinfo"].status == "ready"
    assert items["buildinfo-taint"].status == "review"
    assert items["autopkgtest-run"].status == "review"
    assert "testbed-readonly" in items["autopkgtest-run"].detail
    assert "hermetic-build-plan" in " ".join(report.fix_plan())
    assert any("autopkgtest-doctor" in command for command in report.fix_plan())
    assert any(
        "autopkgtest-doctor" in command and "--backend schroot" in command
        for command in report.fix_plan()
    )
    assert any(
        "hermetic-release-bundle" in command and " --output " in command
        for command in report.fix_plan()
    )
    assert not any(
        "hermetic-release-bundle" in command and "--output-dir" in command
        for command in report.fix_plan()
    )


def test_evidence_package_profile_marks_passed_autopkgtest_run_ready(tmp_path) -> None:
    root = tmp_path / "source-package"
    output_dir = root / "dist"
    (root / "distroforge").mkdir(parents=True)
    (root / "debian").mkdir()
    output_dir.mkdir()
    (root / "pyproject.toml").write_text("[project]\nname = 'distroforge'\n", encoding="utf-8")
    (root / "debian/control").write_text("Source: distroforge\n", encoding="utf-8")
    (tmp_path / "distroforge_1.0-1_all.deb").write_bytes(b"package")
    (output_dir / "AUTOPKGTEST-DOCTOR.json").write_text(
        json.dumps(
            {
                "schema": "distroforge.autopkgtest-doctor.v1",
                "status": "passed",
                "classification": "passed",
                "detail": "Autopkgtest passed.",
            }
        ),
        encoding="utf-8",
    )

    report = EvidenceStatusService().check_source_tree(
        root,
        output_dir=output_dir,
        profile="package",
    )
    items = {item.code: item for item in report.items}

    assert items["autopkgtest-run"].status == "ready"
    assert "passed: passed" in items["autopkgtest-run"].detail
    assert not any("autopkgtest-doctor" in command for command in report.fix_plan())


def test_cli_evidence_status_accepts_source_tree_without_project_json(tmp_path, capsys) -> None:
    root = tmp_path / "source-cli"
    (root / "distroforge").mkdir(parents=True)
    (root / "debian").mkdir()
    (root / "pyproject.toml").write_text("[project]\nname = 'distroforge'\n", encoding="utf-8")
    (root / "debian/control").write_text("Source: distroforge\n", encoding="utf-8")

    with pytest.raises(SystemExit) as exc:
        main(["evidence-status", str(root), "--json"])
    assert exc.value.code == 2
    payload = json.loads(capsys.readouterr().out)

    assert payload["schema"] == "distroforge.evidence-status.v1"
    assert payload["blocked"] is True
    assert any(item["code"] == "source-tree" for item in payload["items"])

    with pytest.raises(SystemExit) as exc:
        main(["evidence-status", str(root), "--profile", "dev", "--json"])
    assert exc.value.code == 2
    dev_payload = json.loads(capsys.readouterr().out)
    assert dev_payload["profile"] == "dev"
    assert not any(item["code"] == "qemu-smoke-plan" for item in dev_payload["items"])

    with pytest.raises(SystemExit) as exc:
        main(["evidence-status", str(root), "--profile", "dev", "--fix-plan"])
    assert exc.value.code == 2
    assert "Evidence fix plan" in capsys.readouterr().out


def test_evidence_contract_validation_reports_missing_files(tmp_path) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "artifact.deb").write_text("package\n", encoding="utf-8")
    (bundle / "BUNDLE-CONTRACT.json").write_text(
        json.dumps(
            {
                "schema": "distroforge.hermetic-release-bundle.contract.v1",
                "required_artifacts": ["artifact.deb", "missing.dsc"],
                "required_evidence": ["VERIFY-REPORT.txt"],
            }
        ),
        encoding="utf-8",
    )

    report = validate_evidence_contract(bundle)

    assert report.status == "blocked"
    assert report.missing_artifacts == ("missing.dsc",)
    assert report.missing_evidence == ("VERIFY-REPORT.txt",)
    assert "Evidence contract validation" in report.render_text()


def test_evidence_contract_validation_reports_malformed_contract(tmp_path) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "BUNDLE-CONTRACT.json").write_text(
        json.dumps(
            {
                "schema": "wrong",
                "required_artifacts": ["../escape"],
                "required_evidence": "VERIFY-REPORT.txt",
            }
        ),
        encoding="utf-8",
    )

    report = validate_evidence_contract(bundle)

    assert report.status == "invalid"
    assert report.blocked is True
    assert "schema must be" in report.errors[0]
    assert "required_evidence must be a list" in report.render_text()


def test_cli_evidence_verify_reports_invalid_json_cleanly(tmp_path, capsys) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "BUNDLE-CONTRACT.json").write_text("{ nope", encoding="utf-8")

    with pytest.raises(SystemExit) as exc:
        main(["evidence-verify", str(bundle), "--json"])

    assert exc.value.code == 2
    assert "is not valid JSON" in capsys.readouterr().err


def test_capture_diff_summarizes_profile_findings(tmp_path) -> None:
    profile = tmp_path / "captured.yaml"
    profile.write_text(
        """
packages: [vim, curl]
capture_config_files:
  - path: /etc/default/locale
capture:
  report:
    counts:
      captured: 3
      ignored: 2
      dangerous: 1
""",
        encoding="utf-8",
    )

    diff = diff_capture_profile(profile)

    assert diff.packages == 2
    assert diff.config_files == ["/etc/default/locale"]
    assert diff.dangerous == 1


def test_cli_release_readiness_and_qemu_smoke_plan(monkeypatch, tmp_path, capsys) -> None:
    iso = tmp_path / "demo.iso"

    with pytest.raises(SystemExit) as exc:
        main(["release-readiness", "--iso", str(iso), "--output-dir", str(tmp_path)])
    assert exc.value.code == 2
    assert "Release readiness" in capsys.readouterr().out

    project_for_doctor = Project.create("DoctorCli", tmp_path / "doctor-cli", "26.04")
    main(["iso-doctor", str(project_for_doctor.root), "--json"])
    doctor = json.loads(capsys.readouterr().out)
    assert doctor["next_command"].startswith("distroforge build")

    project_for_build = Project.create("IsoBuildCli", tmp_path / "iso-build-cli", "26.04")
    project_for_build.source_mode = "bootstrap"
    project_for_build.save()
    main(["iso-build", str(project_for_build.root), "--json"])
    assert json.loads(capsys.readouterr().out)["status"] in {"planned", "blocked"}

    main(["qemu-smoke-plan", "--iso", str(iso)])
    assert "QEMU install smoke plan" in capsys.readouterr().out

    project = Project.create("GateCli", tmp_path / "gate-cli", "26.04")
    with pytest.raises(SystemExit) as exc:
        main(["evidence-status", str(project.root), "--json"])
    assert exc.value.code == 2
    evidence = json.loads(capsys.readouterr().out)
    assert evidence["schema"] == "distroforge.evidence-status.v1"
    assert any(item["code"] == "qemu-smoke-plan" for item in evidence["items"])

    with pytest.raises(SystemExit) as exc:
        main(["evidence-status", str(project.root), "--verbose"])
    assert exc.value.code == 2
    assert "[ready]" in capsys.readouterr().out

    with pytest.raises(SystemExit) as exc:
        main(["release-gate", str(project.root), "--json"])
    assert exc.value.code == 2
    assert '"status": "blocked"' in capsys.readouterr().out

    with pytest.raises(SystemExit) as exc:
        main(["publish-bundle", str(project.root), "--json"])
    assert exc.value.code == 2
    assert json.loads(capsys.readouterr().out)["status"] == "blocked"

    main(["sign-release", str(project.root), "--json"])
    assert json.loads(capsys.readouterr().out)["status"] in {"planned", "blocked"}

    with pytest.raises(SystemExit) as exc:
        main(["release-notes", str(project.root), "--json"])
    assert exc.value.code == 2
    assert json.loads(capsys.readouterr().out)["status"] == "blocked"

    with pytest.raises(SystemExit) as exc:
        main(["verify-release", str(project.root), "--json"])
    assert exc.value.code == 2
    assert json.loads(capsys.readouterr().out)["status"] in {"blocked", "review"}

    main(["explain-release", str(project.root), "--json"])
    assert "next_commands" in json.loads(capsys.readouterr().out)

    with pytest.raises(SystemExit) as exc:
        main(["publish-drill", str(project.root), "--json"])
    assert exc.value.code == 2
    assert "execute_signing" in json.loads(capsys.readouterr().out)

    with pytest.raises(SystemExit) as exc:
        main(["publish-drill-baseline", str(project.root), "--json"])
    assert exc.value.code == 2
    assert "promoted" in json.loads(capsys.readouterr().out)

    old = tmp_path / "old-drill.json"
    new = tmp_path / "new-drill.json"
    _write_drill(old)
    _write_drill(
        new,
        status="blocked",
        gate="blocked",
        boot="structural",
        blockers=("boot-proof: downgraded",),
    )
    main(["publish-drill-diff", str(old), str(new), "--json"])
    assert json.loads(capsys.readouterr().out)["verdict"] == "regressed"

    with pytest.raises(SystemExit) as exc:
        main(["release-pipeline", str(project.root), "--json"])
    assert exc.value.code == 2
    assert json.loads(capsys.readouterr().out)["status"] == "blocked"

    main(["boot-proof", str(project.root), "--dry-run", "--json"])
    assert json.loads(capsys.readouterr().out)["status"] == "blocked"

    iso = project.output_dir / "GateCli.iso"
    _write_bootable_iso(iso)
    main(["boot-proof", str(project.root), "--iso", str(iso), "--backend", "iso-scan", "--json"])
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "ready"
    assert output["backend"] == "iso-scan"

    monkeypatch.setattr("distroforge.core.boot_proof.CommandRunner.has_binary", lambda name: False)
    auto_project = Project.create("AutoGateCli", tmp_path / "auto-gate-cli", "26.04")
    auto_iso = auto_project.output_dir / "AutoGateCli.iso"
    _write_bootable_iso(auto_iso)
    main(
        [
            "boot-proof",
            str(auto_project.root),
            "--iso",
            str(auto_iso),
            "--backend",
            "auto",
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "ready"
    assert output["selected_backend"] == "iso-scan"
    assert output["proof_level"] == "structural"


def test_cli_evidence_verify_validates_bundle_contract(tmp_path, capsys) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "one.txt").write_text("one\n", encoding="utf-8")
    (bundle / "BUNDLE-CONTRACT.json").write_text(
        json.dumps(
            {
                "schema": "distroforge.hermetic-release-bundle.contract.v1",
                "required_artifacts": ["one.txt"],
                "required_evidence": ["two.txt"],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as exc:
        main(["evidence-verify", str(bundle), "--json"])
    assert exc.value.code == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema"] == "distroforge.evidence-contract-validation.v1"
    assert payload["missing_evidence"] == ["two.txt"]


def test_cli_artifact_paths_and_capture_diff(tmp_path, capsys) -> None:
    project = Project.create("ForgeLab", tmp_path / "forge-lab", "26.04")
    profile = tmp_path / "captured.yaml"
    profile.write_text("packages: [vim]\n", encoding="utf-8")

    main(["artifact-paths", str(project.root)])
    assert "Host artifact paths" in capsys.readouterr().out

    main(["capture-diff", str(profile)])
    assert "Captured profile diff" in capsys.readouterr().out
