from __future__ import annotations

import json

import pytest

from distroforge.cli import main
from distroforge.core.artifact_paths import default_artifact_paths
from distroforge.core.boot_proof import run_boot_proof
from distroforge.core.build import BuildOptions
from distroforge.core.capture_diff import diff_capture_profile
from distroforge.core.evidence import EvidenceStatusService, validate_evidence_contract
from distroforge.core.project import Project
from distroforge.core.publish_bundle import create_publish_bundle
from distroforge.core.publish_drill import run_publish_drill
from distroforge.core.publish_drill_baseline import promote_publish_drill_baseline
from distroforge.core.publish_drill_diff import diff_publish_drills
from distroforge.core.qemu_smoke import QemuSmokePlanner
from distroforge.core.release_explain import explain_release
from distroforge.core.release_gate import ReleaseGateService
from distroforge.core.release_notes import write_release_notes
from distroforge.core.release_pipeline import run_release_pipeline
from distroforge.core.release_readiness import ReleaseReadinessService
from distroforge.core.release_signing import sign_release_bundle
from distroforge.core.release_verification import verify_release_bundle


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


def _write_drill(path, *, status="ready_to_publish", gate="ready", boot="runtime", blockers=(), sha="abc") -> None:
    path.write_text(
        json.dumps(
            {
                "status": status,
                "explanation": {
                    "boot_proof": {"proof_level": boot},
                    "blocked_items": list(blockers),
                    "review": [],
                    "next_commands": ["distroforge verify-release project --bundle-dir dist/publish"],
                },
                "evidence": {
                    "release_gate": {"status": gate},
                    "manifest": {"files": [{"name": "Demo.iso", "size": 3, "sha256": sha}]},
                    "signing": {"planned": ["SHA256SUMS.asc"], "signed": [], "skipped": []},
                },
            }
        ),
        encoding="utf-8",
    )


def test_artifact_paths_are_host_paths_for_project(tmp_path) -> None:
    project = Project.create("ForgeLab", tmp_path / "forge-lab", "26.04")

    paths = default_artifact_paths(project)

    assert paths.output_iso == project.output_dir / "ForgeLab.iso"
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
    digest = __import__("hashlib").sha256(b"iso").hexdigest()
    (project.output_dir / "SHA256SUMS").write_text(f"{digest}  {iso.name}\n", encoding="utf-8")
    (project.output_dir / "BUILDINFO").write_text("Build-Date: now\n", encoding="utf-8")
    (project.output_dir / "distroforge-provenance.json").write_text("{}", encoding="utf-8")
    (project.output_dir / "report.html").write_text("<html></html>\n", encoding="utf-8")
    (project.output_dir / "qemu-lab-report.json").write_text("{}", encoding="utf-8")
    options = BuildOptions()
    options.prebuild_vm.enabled = True

    report = ReleaseGateService().check(project, options, iso=iso, output_dir=project.output_dir)

    statuses = {item.code: item.status for item in report.items}
    assert statuses["iso"] == "ready"
    assert statuses["sha256"] == "ready"
    assert statuses["boot-proof"] == "ready"
    assert statuses["packaging-policy"] in {"ready", "review"}


def test_publish_bundle_collects_maintainer_release_evidence(tmp_path) -> None:
    project = Project.create("BundleReady", tmp_path / "bundle-ready", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "BundleReady.iso"
    iso.write_bytes(b"iso")
    digest = __import__("hashlib").sha256(b"iso").hexdigest()
    for name, body in {
        "SHA256SUMS": f"{digest}  {iso.name}\n",
        "BUILDINFO": "Build-Date: now\n",
        "distroforge-provenance.json": "{}\n",
        "report.html": "<html></html>\n",
        "qemu-lab-report.json": "{}\n",
    }.items():
        (project.output_dir / name).write_text(body, encoding="utf-8")
    options = BuildOptions()
    options.prebuild_vm.enabled = True

    report = create_publish_bundle(project, options, iso=iso, output_dir=project.output_dir)

    assert report.status in {"review", "ready"}
    assert {"BundleReady.iso", "SHA256SUMS", "BUILDINFO", "distroforge-provenance.json", "report.html", "qemu-lab-report.json", "RELEASE-GATE.json", "README-PUBLISH.txt"} <= set(report.copied)
    assert (report.bundle_dir / "README-PUBLISH.txt").read_text(encoding="utf-8").startswith("DistroForge maintainer publish bundle")


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
    assert "boot-proof" in (report.bundle_dir / "README-PUBLISH.txt").read_text(encoding="utf-8")


def test_sign_release_writes_manifest_and_plans_signatures(tmp_path) -> None:
    project = Project.create("SignBundle", tmp_path / "sign-bundle", "26.04")
    bundle = project.output_dir / "publish"
    bundle.mkdir(parents=True)
    for name, body in {
        "SHA256SUMS": "abc  SignBundle.iso\n",
        "RELEASE-GATE.json": '{"status": "review"}\n',
        "README-PUBLISH.txt": "Status: REVIEW\n",
    }.items():
        (bundle / name).write_text(body, encoding="utf-8")

    report = sign_release_bundle(project)

    assert report.status == "planned"
    assert (bundle / "RELEASE-MANIFEST.json").exists()
    assert (bundle / "SIGNING-REPORT.json").exists()
    assert {"SHA256SUMS.asc", "RELEASE-GATE.json.asc", "RELEASE-MANIFEST.json.asc"} <= set(report.planned)
    manifest = json.loads((bundle / "RELEASE-MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["gate_status"] == "review"
    assert any(entry["name"] == "SHA256SUMS" for entry in manifest["files"])


def test_release_notes_use_bundle_manifest_gate_and_signing_report(tmp_path) -> None:
    project = Project.create("NotesBundle", tmp_path / "notes-bundle", "26.04")
    bundle = project.output_dir / "publish"
    bundle.mkdir(parents=True)
    (bundle / "RELEASE-MANIFEST.json").write_text(
        json.dumps(
            {
                "gate_status": "blocked",
                "files": [
                    {"name": "NotesBundle.iso", "size": 3, "sha256": "abc"},
                    {"name": "qemu-lab-report.json", "size": 2, "sha256": "def"},
                ],
            }
        ),
        encoding="utf-8",
    )
    (bundle / "RELEASE-GATE.json").write_text(
        json.dumps({"status": "blocked", "items": [{"code": "boot-proof", "status": "blocked", "detail": "missing"}]}),
        encoding="utf-8",
    )
    (bundle / "SIGNING-REPORT.json").write_text(json.dumps({"status": "planned", "planned": ["SHA256SUMS.asc"]}), encoding="utf-8")
    (bundle / "BUILDINFO").write_text("Build-Date: now\n", encoding="utf-8")
    (bundle / "distroforge-provenance.json").write_text('{"builder": "distroforge"}\n', encoding="utf-8")

    report = write_release_notes(project)

    assert report.status == "blocked"
    assert "boot-proof: missing" in report.blockers
    notes = (bundle / "RELEASE-NOTES.md").read_text(encoding="utf-8")
    changelog = (bundle / "CHANGELOG.txt").read_text(encoding="utf-8")
    assert "NotesBundle Release Notes" in notes
    assert "sha256sum -c SHA256SUMS" in notes
    assert "planned: `SHA256SUMS.asc`" in notes
    assert "Status: BLOCKED" in changelog


def test_verify_release_bundle_checks_manifest_and_sha256sums(tmp_path) -> None:
    project = Project.create("VerifyBundle", tmp_path / "verify-bundle", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "VerifyBundle.iso"
    iso.write_bytes(b"iso")
    digest = __import__("hashlib").sha256(b"iso").hexdigest()
    for name, body in {
        "SHA256SUMS": f"{digest}  {iso.name}\n",
        "BUILDINFO": "Build-Date: now\n",
        "distroforge-provenance.json": "{}\n",
        "report.html": "<html></html>\n",
        "qemu-lab-report.json": "{}\n",
    }.items():
        (project.output_dir / name).write_text(body, encoding="utf-8")
    options = BuildOptions()
    options.prebuild_vm.enabled = True
    create_publish_bundle(project, options, iso=iso, output_dir=project.output_dir)
    sign_release_bundle(project)

    report = verify_release_bundle(project)

    assert report.status == "review"
    assert (project.output_dir / "publish" / "VERIFY-REPORT.json").exists()
    statuses = {item.code: item.status for item in report.items}
    assert statuses["manifest"] == "ready"
    assert statuses["sha256sums"] == "ready"
    assert any(item.code == "signature" and item.status == "review" for item in report.items)


def test_verify_release_bundle_blocks_manifest_mismatch(tmp_path) -> None:
    project = Project.create("VerifyMismatch", tmp_path / "verify-mismatch", "26.04")
    bundle = project.output_dir / "publish"
    bundle.mkdir(parents=True)
    (bundle / "demo.iso").write_bytes(b"changed")
    (bundle / "SHA256SUMS").write_text(f"{__import__('hashlib').sha256(b'changed').hexdigest()}  demo.iso\n", encoding="utf-8")
    (bundle / "RELEASE-GATE.json").write_text('{"status": "ready", "items": []}\n', encoding="utf-8")
    (bundle / "SIGNING-REPORT.json").write_text('{"status": "planned", "planned": []}\n', encoding="utf-8")
    (bundle / "RELEASE-MANIFEST.json").write_text(
        json.dumps({"gate_status": "ready", "files": [{"name": "demo.iso", "size": 3, "sha256": "bad"}]}),
        encoding="utf-8",
    )

    report = verify_release_bundle(project)

    assert report.blocked
    assert any(item.code == "manifest-size" and item.status == "blocked" for item in report.items)


def test_release_pipeline_runs_publish_sign_notes_and_verify(tmp_path) -> None:
    project = Project.create("PipelineBundle", tmp_path / "pipeline-bundle", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "PipelineBundle.iso"
    iso.write_bytes(b"iso")
    options = BuildOptions()
    options.prebuild_vm.enabled = True
    (project.output_dir / "qemu-lab-report.json").write_text("{}\n", encoding="utf-8")

    report = run_release_pipeline(project, options, iso=iso, output_dir=project.output_dir)

    assert report.status == "review"
    bundle = project.output_dir / "publish"
    assert (bundle / "RELEASE-PIPELINE.json").exists()
    assert (bundle / "RELEASE-MANIFEST.json").exists()
    assert (bundle / "RELEASE-NOTES.md").exists()
    assert (bundle / "VERIFY-REPORT.json").exists()
    assert {"repair-artifacts", "publish-bundle", "sign-release-final", "verify-release"} <= {stage.name for stage in report.stages}


def test_release_pipeline_can_run_iso_scan_boot_proof(tmp_path) -> None:
    project = Project.create("PipelineIsoScan", tmp_path / "pipeline-iso-scan", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "PipelineIsoScan.iso"
    _write_bootable_iso(iso)

    report = run_release_pipeline(project, BuildOptions(), iso=iso, output_dir=project.output_dir, run_boot_proof=True, boot_proof_backend="iso-scan")

    stages = {stage.name: stage.status for stage in report.stages}
    proof = json.loads((project.output_dir / "boot-proof.json").read_text(encoding="utf-8"))
    assert stages["boot-proof"] == "ready"
    assert proof["backend"] == "iso-scan"


def test_release_pipeline_auto_boot_proof_falls_back_to_iso_scan(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("distroforge.core.boot_proof.CommandRunner.has_binary", lambda name: False)
    project = Project.create("PipelineAutoScan", tmp_path / "pipeline-auto-scan", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "PipelineAutoScan.iso"
    _write_bootable_iso(iso)

    report = run_release_pipeline(project, BuildOptions(), iso=iso, output_dir=project.output_dir, run_boot_proof=True)

    stages = {stage.name: stage.status for stage in report.stages}
    proof = json.loads((project.output_dir / "boot-proof.json").read_text(encoding="utf-8"))
    assert stages["boot-proof"] == "ready"
    assert proof["backend"] == "auto"
    assert proof["attempted_backends"] == ["qemu", "iso-scan"]
    assert proof["selected_backend"] == "iso-scan"
    assert proof["proof_level"] == "structural"


def test_release_explain_summarizes_boot_proof_and_next_commands(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("distroforge.core.boot_proof.CommandRunner.has_binary", lambda name: False)
    project = Project.create("ExplainMe", tmp_path / "explain-me", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "ExplainMe.iso"
    _write_bootable_iso(iso)
    digest = __import__("hashlib").sha256(iso.read_bytes()).hexdigest()
    (project.output_dir / "SHA256SUMS").write_text(f"{digest}  {iso.name}\n", encoding="utf-8")
    (project.output_dir / "BUILDINFO").write_text("Build-Date: now\n", encoding="utf-8")
    (project.output_dir / "distroforge-provenance.json").write_text("{}\n", encoding="utf-8")
    (project.output_dir / "report.html").write_text("<html></html>\n", encoding="utf-8")
    run_boot_proof(project, iso=iso, backend="auto", execute=True)
    create_publish_bundle(project, BuildOptions(), iso=iso, output_dir=project.output_dir)

    report = explain_release(project, iso=iso)

    assert report.boot_proof["proof_level"] == "structural"
    assert any("boot-proof" in item for item in report.ready)
    assert any("--backend qemu" in command for command in report.next_commands)
    assert (project.output_dir / "publish" / "RELEASE-EXPLAIN.md").exists()
    assert "Release Evidence" in (project.output_dir / "publish" / "RELEASE-EXPLAIN.md").read_text(encoding="utf-8")


def test_publish_drill_runs_safe_rehearsal_without_signing(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("distroforge.core.boot_proof.CommandRunner.has_binary", lambda name: False)
    project = Project.create("DrillMe", tmp_path / "drill-me", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "DrillMe.iso"
    _write_bootable_iso(iso)
    digest = __import__("hashlib").sha256(iso.read_bytes()).hexdigest()
    (project.output_dir / "SHA256SUMS").write_text(f"{digest}  {iso.name}\n", encoding="utf-8")

    report = run_publish_drill(project, BuildOptions(), iso=iso)

    payload = json.loads((project.output_dir / "publish" / "PUBLISH-DRILL.json").read_text(encoding="utf-8"))
    signing = json.loads((project.output_dir / "publish" / "SIGNING-REPORT.json").read_text(encoding="utf-8"))
    assert report.status in {"review_required", "ready_to_publish"}
    assert payload["execute_signing"] is False
    assert signing["execute"] is False
    assert (project.output_dir / "publish" / "RELEASE-EXPLAIN.md").exists()
    assert payload["pipeline"]["stages"][0]["name"] == "boot-proof"


def test_publish_drill_diff_flags_regression(tmp_path) -> None:
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    _write_drill(old)
    _write_drill(new, status="blocked", gate="blocked", boot="structural", blockers=("boot-proof: downgraded",), sha="def")

    report = diff_publish_drills(old, new)

    assert report.verdict == "regressed"
    assert "Demo.iso" in report.manifest_changed
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
    proof = json.loads((project.output_dir / "boot-proof.json").read_text(encoding="utf-8"))
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


def test_release_gate_accepts_ready_iso_scan_boot_proof(tmp_path) -> None:
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

    gate = ReleaseGateService().check(project, BuildOptions(), iso=iso, output_dir=project.output_dir)

    assert {item.code: item.status for item in gate.items}["boot-proof"] == "ready"


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
    modes = {(scenario.firmware, scenario.network, scenario.install_mode) for scenario in plan.scenarios}
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
    assert any("autopkgtest-doctor" in command and "--backend schroot" in command for command in report.fix_plan())
    assert any("hermetic-release-bundle" in command and " --output " in command for command in report.fix_plan())
    assert not any("hermetic-release-bundle" in command and "--output-dir" in command for command in report.fix_plan())


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

    main(["publish-bundle", str(project.root), "--json"])
    assert json.loads(capsys.readouterr().out)["status"] == "blocked"

    main(["sign-release", str(project.root), "--json"])
    assert json.loads(capsys.readouterr().out)["status"] in {"planned", "blocked"}

    main(["release-notes", str(project.root), "--json"])
    assert json.loads(capsys.readouterr().out)["status"] == "blocked"

    main(["verify-release", str(project.root), "--json"])
    assert json.loads(capsys.readouterr().out)["status"] in {"blocked", "review"}

    main(["explain-release", str(project.root), "--json"])
    assert "next_commands" in json.loads(capsys.readouterr().out)

    main(["publish-drill", str(project.root), "--json"])
    assert "execute_signing" in json.loads(capsys.readouterr().out)

    main(["publish-drill-baseline", str(project.root), "--json"])
    assert "promoted" in json.loads(capsys.readouterr().out)

    old = tmp_path / "old-drill.json"
    new = tmp_path / "new-drill.json"
    _write_drill(old)
    _write_drill(new, status="blocked", gate="blocked", boot="structural", blockers=("boot-proof: downgraded",))
    main(["publish-drill-diff", str(old), str(new), "--json"])
    assert json.loads(capsys.readouterr().out)["verdict"] == "regressed"

    main(["release-pipeline", str(project.root), "--json"])
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
    main(["boot-proof", str(project.root), "--iso", str(iso), "--backend", "auto", "--json"])
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
