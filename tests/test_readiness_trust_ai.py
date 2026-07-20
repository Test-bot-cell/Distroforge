from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from distroforge.ai.forgeadvisor import ForgeAdvisor
from distroforge.ai.review import ConstrainedRecipeAssistant, PlanReviewer
from distroforge.cli import build_parser, main
from distroforge.core.apt import PackagePlan
from distroforge.core.beginner_iso import (
    explain_beginner_iso_failure,
    prepare_beginner_iso_path,
    repair_beginner_iso_release_artifacts,
    run_beginner_iso_boot_proof,
)
from distroforge.core.branding import BrandingOptions
from distroforge.core.build import BuildOptions, BuildOrchestrator
from distroforge.core.build_journey import apply_journey_step, build_journey, check_journey_step
from distroforge.core.command import CommandRunner
from distroforge.core.command_registry import gui_option_parity_report
from distroforge.core.customize import selected_desktop
from distroforge.core.definition import definition_from_project, load_definition, write_definition
from distroforge.core.diff_preview import DiffPreviewService
from distroforge.core.dry_run_report import generate_dry_run_report
from distroforge.core.education import explain_risks, render_glossary
from distroforge.core.policy import PolicyService
from distroforge.core.poweruser_iso import prepare_poweruser_iso_path
from distroforge.core.preflight import _validate_package_intent
from distroforge.core.project import Project
from distroforge.core.readiness import ReadinessService
from distroforge.core.release_artifacts import ReleaseArtifactOptions
from distroforge.core.trust import TrustOptions, TrustService
from distroforge.core.validate import (
    has_errors,
    validate_branding_options,
    validate_release_artifacts_options,
)
from distroforge.core.workflows import evaluate_workflow_fit, recommend_workflow_actions


def test_trust_service_verifies_source_sha256(tmp_path: Path) -> None:
    iso = tmp_path / "source.iso"
    iso.write_bytes(b"distroforge")
    digest = hashlib.sha256(b"distroforge").hexdigest()

    report = TrustService().check_source_iso(iso, TrustOptions(source_sha256=digest))

    assert report.ok
    assert any(check.code == "source-sha256-ok" for check in report.checks)


def test_build_dry_run_records_source_signature_verification(tmp_path: Path) -> None:
    iso = tmp_path / "source.iso"
    sig = tmp_path / "source.iso.gpg"
    iso.write_bytes(b"distroforge")
    sig.write_text("signature", encoding="utf-8")
    digest = hashlib.sha256(b"distroforge").hexdigest()
    project = Project.create("TrustBuild", tmp_path / "trust-build", "26.04")
    project.source_iso = iso
    options = BuildOptions(
        trust=TrustOptions(
            source_sha256=digest,
            source_signature=sig,
            source_gpg_fingerprint="ABCDEF1234567890",
        )
    )
    runner = CommandRunner(dry_run=True)

    BuildOrchestrator(project, runner, options).run()

    commands = [spec.argv for spec in runner.history]
    assert ("trust-report", "ok", "2") in commands
    assert ("gpg", "--verify", str(sig), str(iso)) in commands
    assert ("gpg-fingerprint-check", "ABCDEF1234567890") in commands


def test_readiness_blocks_required_missing_source_checksum(tmp_path: Path) -> None:
    project = Project.create("TrustMe", tmp_path / "trust-me", "26.04")
    project.source_iso = tmp_path / "missing.iso"
    options = BuildOptions(trust=TrustOptions(require_source_checksum=True))

    report = ReadinessService().check(project, options)

    assert report.status == "blocked"
    assert any(check.code == "trust-source-sha256-required" for check in report.checks)


def test_trust_strict_mode_requires_checksum_and_signature(tmp_path: Path) -> None:
    iso = tmp_path / "source.iso"
    iso.write_bytes(b"distroforge")

    lenient = TrustService().check_source_iso(iso, TrustOptions())
    strict = TrustService().check_source_iso(iso, TrustOptions(), strict=True)

    assert lenient.ok  # missing checksum/signature is advisory by default
    assert not strict.ok
    strict_codes = {check.code for check in strict.checks}
    assert "source-sha256-required" in strict_codes
    assert "source-signature-required" in strict_codes


def test_readiness_strict_blocks_unverified_source(tmp_path: Path) -> None:
    project = Project.create("StrictReady", tmp_path / "strict-ready", "26.04")
    project.source_iso = tmp_path / "source.iso"
    options = BuildOptions()
    options.policy.strict = True

    report = ReadinessService().check(project, options)

    assert report.status == "blocked"
    assert any(check.code == "trust-source-sha256-required" for check in report.checks)


def test_release_artifacts_must_be_signed_in_strict_mode() -> None:
    unsigned = ReleaseArtifactOptions(sign=False)
    signed = ReleaseArtifactOptions(sign=True, gpg_key="ABCD1234")

    assert validate_release_artifacts_options(unsigned) == []  # advisory by default
    assert has_errors(validate_release_artifacts_options(unsigned, strict=True))
    assert validate_release_artifacts_options(signed, strict=True) == []


def test_branding_relative_assets_escalate_in_strict_mode() -> None:
    options = BrandingOptions(logo="assets/logo.png", home_url="not-a-url")

    lenient = validate_branding_options(options)
    strict = validate_branding_options(options, strict=True)

    assert not has_errors(lenient)
    assert any(issue.level == "warning" for issue in lenient)
    assert has_errors(strict)


def test_dry_run_report_has_transaction_timeline_and_commands(tmp_path: Path) -> None:
    project = Project.create("DryReport", tmp_path / "dry-report", "26.04")
    project.source_mode = "bootstrap"
    project.packages = ["git"]
    options = BuildOptions()

    report = generate_dry_run_report(project, options)

    assert report.transaction.build_id
    assert report.steps
    assert "git" in report.install
    assert report.commands
    assert report.command_summary["total"] > 0
    assert any(finding.code.startswith("bootstrap-rootfs") for finding in report.findings)
    assert "Timeline:" in report.render_text()
    assert "Findings:" in report.render_text()


def test_dry_run_report_detects_dirty_output_and_incomplete_rootfs(tmp_path: Path) -> None:
    project = Project.create("DirtyDryRun", tmp_path / "dirty-dry-run", "26.04")
    project.source_mode = "bootstrap"
    project.output_dir.mkdir(exist_ok=True)
    (project.output_dir / "old.iso").write_text("old", encoding="utf-8")
    project.squashfs_root.mkdir(parents=True, exist_ok=True)
    (project.squashfs_root / "partial").write_text("", encoding="utf-8")

    report = generate_dry_run_report(project, BuildOptions(), run_orchestrator=False)
    codes = {finding.code for finding in report.findings}

    assert "output-dir-not-empty" in codes
    assert "bootstrap-rootfs-incomplete" in codes


def test_dry_run_report_detects_locked_boot_artifacts_without_privilege(tmp_path: Path) -> None:
    project = Project.create("LockedBoot", tmp_path / "locked-boot", "26.04")
    project.source_mode = "bootstrap"
    boot = project.squashfs_root / "boot"
    boot.mkdir(parents=True)
    (project.squashfs_root / "var/lib/dpkg").mkdir(parents=True)
    (project.squashfs_root / "var/lib/dpkg/status").write_text("", encoding="utf-8")
    (project.squashfs_root / "etc").mkdir()
    (project.squashfs_root / "etc/os-release").write_text("ID=ubuntu\n", encoding="utf-8")
    kernel = boot / "vmlinuz-test"
    kernel.write_text("kernel", encoding="utf-8")
    kernel.chmod(0)

    try:
        report = generate_dry_run_report(project, BuildOptions(use_sudo=False), run_orchestrator=False)
    finally:
        kernel.chmod(0o644)

    assert any(finding.code == "bootstrap-locked-boot-artifacts" for finding in report.findings)


def test_dry_run_report_warns_when_pkexec_backend_is_selected(monkeypatch, tmp_path: Path) -> None:
    project = Project.create("PkexecWarning", tmp_path / "pkexec-warning", "26.04")
    project.source_mode = "bootstrap"
    monkeypatch.setenv("DISTROFORGE_PRIVILEGE", "pkexec")

    report = generate_dry_run_report(project, BuildOptions(), run_orchestrator=False)

    assert any(finding.code == "privilege-pkexec-fragile" for finding in report.findings)


def test_dry_run_report_notes_sudo_askpass(monkeypatch, tmp_path: Path) -> None:
    project = Project.create("AskpassWarning", tmp_path / "askpass-warning", "26.04")
    project.source_mode = "bootstrap"
    monkeypatch.setenv("DISTROFORGE_PRIVILEGE", "sudo")
    monkeypatch.setattr("distroforge.core.dry_run_report.sudo_askpass_program", lambda: "/usr/bin/ssh-askpass")

    report = generate_dry_run_report(project, BuildOptions(), run_orchestrator=False)

    assert any(finding.code == "privilege-sudo-askpass" for finding in report.findings)


def test_policy_findings_explain_and_remediate(tmp_path: Path) -> None:
    project = Project.create("Policy", tmp_path / "policy", "26.04")
    project.customization.autologin_user = "root"
    options = BuildOptions()

    findings = PolicyService().check(project, options, options.policy)

    assert findings[0].code == "root-autologin"
    assert findings[0].explanation
    assert findings[0].remediation
    assert findings[0].to_dict()["severity"] == "error"


def test_education_and_ai_review_are_local_and_schema_bound(tmp_path: Path) -> None:
    project = Project.create("Teach", tmp_path / "teach", "26.04")
    project.source_mode = "bootstrap"
    options = BuildOptions()
    readiness = ReadinessService().check(project, options)
    dry_run = generate_dry_run_report(project, options, run_orchestrator=False)

    assert "sha256:" in render_glossary("sha256")
    assert "Risk explanation" in explain_risks(project, options)
    assert PlanReviewer().review(readiness, dry_run).verdict
    assert ConstrainedRecipeAssistant().suggest_definition("dev python")["packages"]


def test_workflow_fit_flags_features_without_supporting_proof(tmp_path: Path) -> None:
    project = Project.create("WorkflowFit", tmp_path / "workflow-fit", "26.04")
    project.source_mode = "bootstrap"
    options = BuildOptions()
    options.autoinstall.enabled = True
    options.system_sync.enabled = True

    findings = evaluate_workflow_fit(project, options)
    codes = {finding.code for finding in findings}

    assert "workflow-autoinstall-untested" in codes
    assert "workflow-risky-module-without-snapshot" in codes
    assert "workflow-release-evidence-without-boot-proof" in codes


def test_readiness_recommends_next_best_actions(tmp_path: Path) -> None:
    project = Project.create("NextAction", tmp_path / "next-action", "26.04")
    project.source_mode = "bootstrap"
    options = BuildOptions()
    options.autoinstall.enabled = True
    options.system_sync.enabled = True

    report = ReadinessService().check(project, options, include_dry_run=False)
    actions = {recommendation.code for recommendation in report.recommendations}
    action_ids = {recommendation.action_id for recommendation in report.recommendations}
    rendered = report.render_text()
    data = report.to_dict()

    assert {"shape-empty-bootstrap", "prove-autoinstall", "enable-risk-snapshots"} <= actions
    assert {"open-packages", "open-virtualization-lab", "open-build-release"} <= action_ids
    assert "Next recommended actions:" in rendered
    assert "Virtualization Lab" in rendered
    assert data["recommendations"][0]["action_id"]


def test_workflow_recommendations_have_default_review_action(tmp_path: Path) -> None:
    project = Project.create("ReviewNext", tmp_path / "review-next", "26.04")
    project.source_mode = "bootstrap"
    project.customization.desktop = "gnome"
    options = BuildOptions()
    options.prebuild_vm.enabled = True

    recommendations = recommend_workflow_actions(project, options, ())

    assert recommendations[0].code == "review-dry-run"
    assert recommendations[0].gui_surface == "Build & Release page"


def test_build_journey_guides_beginner_and_maintainer_paths(tmp_path: Path) -> None:
    project = Project.create("Journey", tmp_path / "journey", "26.04")
    options = BuildOptions()

    beginner = build_journey(project, options, "beginner")
    maintainer = build_journey(project, options, "maintainer")

    assert beginner.current is not None
    assert beginner.current.step.step_id == "source"
    assert "Source page" in beginner.render_text()
    assert [item.step.step_id for item in maintainer.items][-2:] == [
        "release-evidence",
        "publish-gate",
    ]

    project.source_mode = "bootstrap"
    project.customization.desktop = "ubuntu"
    iso = project.output_dir / "Journey.iso"
    iso.write_bytes(b"iso")
    digest = hashlib.sha256(b"iso").hexdigest()
    (project.output_dir / "SHA256SUMS").write_text(f"{digest}  {iso.name}\n", encoding="utf-8")
    (project.output_dir / "BUILDINFO").write_text("Build-Date: now\n", encoding="utf-8")
    (project.output_dir / "distroforge-provenance.json").write_text("{}", encoding="utf-8")
    (project.output_dir / "report.html").write_text("<html></html>\n", encoding="utf-8")
    (project.output_dir / "qemu-lab-report.json").write_text("{}", encoding="utf-8")
    options.output_iso = iso
    options.prebuild_vm.enabled = True
    options.release_artifacts.enabled = True
    options.provenance.enabled = True
    options.html_report.enabled = True
    report = build_journey(project, options, "maintainer")

    assert report.complete
    assert report.to_dict()["current_step"] is None


def test_journey_apply_turns_steps_into_project_and_definition_state(tmp_path: Path) -> None:
    project = Project.create("ApplyJourney", tmp_path / "apply-journey", "26.04")
    options = BuildOptions()

    source = apply_journey_step(project, options, "source")
    identity = apply_journey_step(project, options, "identity")
    boot = apply_journey_step(project, options, "boot-proof")
    release = apply_journey_step(project, options, "release-evidence")
    publish = apply_journey_step(project, options, "publish-gate")

    assert source.changed_project
    assert identity.changed_project
    assert boot.changed_options
    assert release.changed_options
    assert publish.changed_options
    assert project.source_starter
    assert project.customization.desktop == "ubuntu"
    assert project.packages == []
    assert options.prebuild_vm.enabled
    assert options.bootcheck.enabled
    assert options.qa.scenarios == ["live-bios", "live-uefi"]
    assert options.reproducible.enabled


def test_build_plan_filters_conflicting_desktop_packages(tmp_path: Path) -> None:
    project = Project.create("DesktopConflict", tmp_path / "desktop-conflict", "26.04")
    project.customization.desktop = "ubuntu_minimal"
    project.packages = [
        "ubuntu-desktop",
        "xubuntu-desktop",
        "ubuntu-desktop-minimal",
    ]

    options = BuildOptions(package_plan=PackagePlan(install=["curl", "kubuntu-desktop", "ubuntu-desktop"]))
    merged = BuildOrchestrator(project, CommandRunner(dry_run=True), options)._merged_package_plan()

    assert "ubuntu-desktop-minimal" in merged.install
    assert "curl" in merged.install
    assert "gdm3" in merged.install
    assert "ubuntu-desktop" not in merged.install
    assert "xubuntu-desktop" not in merged.install
    assert "kubuntu-desktop" not in merged.install


def test_validate_warns_when_stale_desktop_packages_exist(tmp_path: Path) -> None:
    project = Project.create("DesktopConflictWarn", tmp_path / "desktop-conflict-warn", "26.04")
    project.source_mode = "bootstrap"
    project.customization.desktop = "ubuntu_minimal"
    project.packages = [
        "kubuntu-desktop",
        "xubuntu-desktop",
        "vim",
    ]

    issues = _validate_package_intent(project, BuildOptions())

    warning = next(issue for issue in issues if issue.level == "warning")
    assert warning.code == "desktop-conflict"
    assert "kubuntu-desktop" in warning.message
    assert "xubuntu-desktop" in warning.message


def test_project_load_sanitizes_legacy_desktop_packages_in_place(tmp_path: Path) -> None:
    project = Project.create("SanitizeDesktop", tmp_path / "sanitize-desktop", "26.04")
    project.customization.desktop = "ubuntu"
    project.packages = ["ubuntu-desktop", "kubuntu-desktop", "vim"]
    project.save()

    reloaded = Project.load(project.root)

    assert "kubuntu-desktop" not in reloaded.packages
    assert reloaded.packages == ["ubuntu-desktop", "vim"]

    persisted = json.loads((project.root / "project.json").read_text(encoding="utf-8"))
    assert "kubuntu-desktop" not in persisted["packages"]


def test_unknown_desktop_choice_does_not_crash_and_keeps_user_intent(tmp_path: Path) -> None:
    project = Project.create("UnknownDesktop", tmp_path / "unknown-desktop", "26.04")
    project.customization.desktop = "not-a-real-desktop"
    project.packages = ["kubuntu-desktop", "vim"]

    assert selected_desktop(project.customization) is None

    merged = BuildOrchestrator(project, CommandRunner(dry_run=True))._merged_package_plan()
    assert "kubuntu-desktop" in merged.install
    assert "vim" in merged.install
    assert "kubuntu-desktop" not in merged.remove


def test_build_plan_keeps_explicit_display_manager_on_debian_family(tmp_path: Path) -> None:
    project = Project.create("DesktopConflictDebian", tmp_path / "desktop-conflict-debian", "debian-13.5")
    project.customization.desktop = "ubuntu_minimal"
    options = BuildOptions(package_plan=PackagePlan(install=["lightdm", "task-kde-desktop"]))

    merged = BuildOrchestrator(project, CommandRunner(dry_run=True), options)._merged_package_plan()

    assert "gnome-core" in merged.install
    assert "gdm3" in merged.install
    assert "lightdm" in merged.install
    assert "task-kde-desktop" not in merged.install


def test_end_to_end_desktop_switch_reflects_warning_plan_and_diff(tmp_path: Path) -> None:
    project = Project.create("DesktopSwitch", tmp_path / "desktop-switch", "26.04")
    project.source_mode = "bootstrap"
    project.customization.desktop = "ubuntu"
    project.packages = ["xubuntu-desktop", "vim"]

    project.customization.desktop = "kubuntu"
    merged = BuildOrchestrator(project, CommandRunner(dry_run=True))._merged_package_plan()
    preview = DiffPreviewService().preview(project, BuildOptions())
    issues = _validate_package_intent(project, BuildOptions())

    assert "kubuntu-desktop" in merged.install
    assert "xubuntu-desktop" not in merged.install
    assert "xubuntu-desktop" not in preview.install
    assert "sddm" in merged.install
    assert "gdm3" not in merged.install
    assert any(item.code == "desktop-conflict" and item.level == "warning" for item in issues)


def test_dry_run_report_keeps_desktop_conflict_warning(tmp_path: Path) -> None:
    project = Project.create("DryRunDesktopConflict", tmp_path / "dry-run-desktop-conflict", "26.04")
    project.source_mode = "bootstrap"
    project.customization.desktop = "ubuntu"
    project.packages = ["kubuntu-desktop", "vim"]

    report = generate_dry_run_report(project, BuildOptions(), run_orchestrator=False)

    assert any(
        finding["code"] == "validation-desktop-conflict" and finding["level"] == "warning"
        for finding in report.to_dict()["findings"]
    )


def test_skeleton_desktop_source_keeps_selected_desktop_packages(tmp_path: Path) -> None:
    project = Project.create("SkeletonDesktop", tmp_path / "skeleton-desktop", "26.04")
    project.source_mode = "bootstrap"
    project.customization.desktop = "ubuntu"

    options = BuildOptions()
    options.desktop_source.enabled = True
    options.desktop_source.desktop = "ubuntu"

    merged = BuildOrchestrator(project, CommandRunner(dry_run=True), options)._merged_package_plan()

    assert "ubuntu-desktop" in merged.install
    assert "gdm3" in merged.install


def test_journey_check_reports_step_status_for_cli_and_cards(tmp_path: Path) -> None:
    project = Project.create("CheckJourney", tmp_path / "check-journey", "26.04")
    project.source_mode = "bootstrap"
    options = BuildOptions()
    options.autoinstall.enabled = True

    identity = check_journey_step(project, options, "identity")
    deployment = check_journey_step(project, options, "deployment")

    assert identity.status == "warning"
    assert deployment.status == "warning"
    assert "No desktop" in identity.render_text()
    assert "without QEMU" in deployment.to_dict()["findings"][0]


def test_journey_dry_run_step_reflects_real_plan_validation(tmp_path: Path) -> None:
    # The dry-run/readiness step must mirror real configuration validation, never a no-op
    # that claims a brand-new project was already reviewed.
    fresh = Project.create("DryRunFresh", tmp_path / "dry-run-fresh", "26.04")
    fresh_items = {item.step.step_id: item.status for item in build_journey(fresh, BuildOptions(), "beginner").items}
    assert fresh_items["dry-run"] != "done"

    ready = Project.create("DryRunReady", tmp_path / "dry-run-ready", "26.04")
    ready.source_mode = "bootstrap"
    ready_items = {item.step.step_id: item.status for item in build_journey(ready, BuildOptions(), "beginner").items}
    assert ready_items["dry-run"] == "done"


def test_journey_check_dry_run_blocks_until_plan_validates(tmp_path: Path) -> None:
    fresh = Project.create("CheckDryFresh", tmp_path / "check-dry-fresh", "26.04")
    blocked = check_journey_step(fresh, BuildOptions(), "dry-run")
    assert blocked.status == "error"
    assert any("source" in finding for finding in blocked.to_dict()["findings"])

    ready = Project.create("CheckDryReady", tmp_path / "check-dry-ready", "26.04")
    ready.source_mode = "bootstrap"
    clear = check_journey_step(ready, BuildOptions(), "dry-run")
    assert clear.status == "ok"


def test_publish_gate_journey_surfaces_release_confidence_ritual(tmp_path: Path) -> None:
    # The maintainer publish-gate step must teach the release-confidence ritual
    # (sign -> verify -> compare baseline -> CVE) as advisory guidance, even before any
    # signing, verification or baseline report exists in the publish bundle.
    project = Project.create("RitualFiring", tmp_path / "ritual-firing", "26.04")
    project.source_mode = "bootstrap"
    options = BuildOptions()

    check = check_journey_step(project, options, "publish-gate")
    blob = " ".join(check.findings)
    assert check.status in {"error", "warning", "ok"}
    assert "sign-release" in blob
    assert "verify-release" in blob
    assert "publish-drill-baseline" in blob or "publish-drill-diff" in blob
    assert "CVE scan: disabled" in blob

    # The same ritual is carried by the step's next action (shown on the GUI card) and the
    # apply note, so the CLI journey and the Start-page card teach an identical discipline.
    item = next(i for i in build_journey(project, options, "maintainer").items if i.step.step_id == "publish-gate")
    assert "sign-release" in item.next_action and "publish-drill-diff" in item.next_action
    apply_note = " ".join(apply_journey_step(project, options, "publish-gate").notes)
    assert "sign-release" in apply_note and "verify-release" in apply_note


def test_publish_gate_journey_reflects_existing_release_reports(tmp_path: Path) -> None:
    # When the bundle already holds signing/verification/baseline reports, the journey check
    # reports their real status instead of generic guidance, and mirrors the CVE policy.
    project = Project.create("RitualReports", tmp_path / "ritual-reports", "26.04")
    project.source_mode = "bootstrap"
    bundle = project.output_dir / "publish"
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "SIGNING-REPORT.json").write_text(json.dumps({"status": "signed"}), encoding="utf-8")
    (bundle / "VERIFY-REPORT.json").write_text(json.dumps({"status": "ready"}), encoding="utf-8")
    (bundle / "PUBLISH-DRILL.previous.json").write_text(json.dumps({"status": "ready"}), encoding="utf-8")

    options = BuildOptions()
    options.vuln_scan.enabled = True
    options.vuln_scan.policy = "block-high"

    blob = " ".join(check_journey_step(project, options, "publish-gate").findings)
    assert "Signing: signed" in blob
    assert "Verification: ready" in blob
    assert "Baseline present" in blob
    assert "CVE scan: enabled (policy=block-high)" in blob


def test_release_confidence_ritual_is_advisory_not_gating(tmp_path: Path) -> None:
    # Signing/verification/baseline are publishing discipline, not gate requirements: a
    # maintainer journey completes on gate evidence alone even when those reports are absent,
    # while the advisory check still flags that they were never run.
    project = Project.create("RitualAdvisory", tmp_path / "ritual-advisory", "26.04")
    project.source_mode = "bootstrap"
    project.customization.desktop = "ubuntu"
    iso = project.output_dir / "RitualAdvisory.iso"
    iso.write_bytes(b"iso")
    digest = hashlib.sha256(b"iso").hexdigest()
    (project.output_dir / "SHA256SUMS").write_text(f"{digest}  {iso.name}\n", encoding="utf-8")
    (project.output_dir / "BUILDINFO").write_text("Build-Date: now\n", encoding="utf-8")
    (project.output_dir / "distroforge-provenance.json").write_text("{}", encoding="utf-8")
    (project.output_dir / "report.html").write_text("<html></html>\n", encoding="utf-8")
    (project.output_dir / "qemu-lab-report.json").write_text("{}", encoding="utf-8")
    options = BuildOptions()
    options.output_iso = iso
    options.prebuild_vm.enabled = True
    options.release_artifacts.enabled = True
    options.provenance.enabled = True
    options.html_report.enabled = True

    report = build_journey(project, options, "maintainer")
    publish = next(i for i in report.items if i.step.step_id == "publish-gate")
    assert publish.status == "done"
    assert report.complete
    blob = " ".join(check_journey_step(project, options, "publish-gate").findings)
    assert "Signing not run" in blob
    assert "Verification not run" in blob


def test_beginner_iso_path_prepares_definition_dry_run_and_gate(tmp_path: Path, monkeypatch) -> None:
    project = Project.create("BeginnerIso", tmp_path / "beginner-iso", "26.04")

    report = prepare_beginner_iso_path(project, apply_safe_defaults=True, dry_run=True)

    assert (project.root / "beginner-iso.yaml").exists()
    assert (project.root / "beginner-iso-dry-run.json").exists()
    assert project.source_starter
    assert project.customization.desktop == "ubuntu"
    assert report.gate_status == "blocked"
    assert "--execute" in report.next_command

    class FakeOrchestrator:
        def __init__(self, project, runner, options, progress=None) -> None:
            self.project = project
            self.runner = runner
            self.options = options
            self.progress = progress

        def run(self) -> None:
            iso = self.options.output_iso
            assert iso is not None
            iso.parent.mkdir(parents=True, exist_ok=True)
            iso.write_bytes(b"iso")
            digest = hashlib.sha256(b"iso").hexdigest()
            (iso.parent / "SHA256SUMS").write_text(f"{digest}  {iso.name}\n", encoding="utf-8")
            (iso.parent / "BUILDINFO").write_text("Build-Date: now\n", encoding="utf-8")
            (iso.parent / "distroforge-provenance.json").write_text("{}", encoding="utf-8")
            (iso.parent / "report.html").write_text("<html></html>\n", encoding="utf-8")
            (iso.parent / "qemu-lab-report.json").write_text("{}", encoding="utf-8")
            self.runner.run(__import__("distroforge.core.command", fromlist=["CommandSpec"]).CommandSpec(("write-file", str(iso))))

    monkeypatch.setattr("distroforge.core.beginner_iso.BuildOrchestrator", FakeOrchestrator)

    executed = prepare_beginner_iso_path(project, apply_safe_defaults=True, dry_run=True, execute=True)

    assert executed.executed
    assert executed.build_status == "completed"
    assert executed.command_log is not None
    assert executed.gate_status == "review"
    assert "release-gate" in executed.next_command


def test_cli_readiness_dry_run_glossary_and_ai_review(capsys, tmp_path: Path) -> None:
    project = Project.create("CliUX", tmp_path / "cli-ux", "26.04")
    project.source_mode = "bootstrap"
    project.save()

    main(["readiness", str(project.root)])
    readiness_output = capsys.readouterr().out
    assert "Readiness:" in readiness_output
    assert "Next recommended actions:" in readiness_output

    main(["journey", str(project.root), "--level", "maintainer"])
    journey_output = capsys.readouterr().out
    assert "DistroForge build journey [maintainer]" in journey_output
    assert "Quality Lab / Virtualization Lab" in journey_output

    main(["journey", str(project.root), "--apply", "identity"])
    apply_output = capsys.readouterr().out
    assert "Applied journey step: Shape identity and desktop" in apply_output
    assert "Updated project:" in apply_output

    main(["journey", str(project.root), "--check", "boot-proof", "--json"])
    check_output = json.loads(capsys.readouterr().out)
    assert check_output["step_id"] == "boot-proof"
    assert check_output["status"] in {"ok", "warning"}

    main(["journey", str(project.root), "--check", "publish-gate", "--json"])
    gate_output = json.loads(capsys.readouterr().out)
    assert gate_output["step_id"] == "publish-gate"
    assert gate_output["status"] in {"error", "warning", "ok"}

    main(["beginner-iso", str(project.root), "--apply-safe-defaults", "--dry-run", "--json"])
    beginner_output = json.loads(capsys.readouterr().out)
    assert beginner_output["gate_status"] == "blocked"
    assert beginner_output["build_status"] == "not-run"
    assert beginner_output["definition"].endswith("beginner-iso.yaml")

    main(["beginner-iso", str(project.root), "--doctor", "--json"])
    doctor_output = json.loads(capsys.readouterr().out)
    assert "install_command" in doctor_output
    assert "missing" in doctor_output

    main(["dry-run-report", str(project.root), "--json", "--no-command-simulation"])
    report = json.loads(capsys.readouterr().out)
    assert report["transaction"]["build_id"]


def test_cli_explain_risk_renders_plain_language(capsys, tmp_path: Path) -> None:
    project = Project.create("ExplainRiskCli", tmp_path / "explain-risk-cli", "26.04")
    project.source_mode = "bootstrap"
    project.save()

    main(["explain-risk", str(project.root)])

    output = capsys.readouterr().out
    assert "Risk explanation" in output


def test_beginner_iso_install_missing_tools_is_explicit(monkeypatch, capsys, tmp_path: Path) -> None:
    project = Project.create("CliDoctor", tmp_path / "cli-doctor", "26.04")
    called = []

    monkeypatch.setattr("distroforge.core.command.CommandRunner.has_binary", lambda self, name: False)
    monkeypatch.setattr("distroforge.commands.beginner_iso.install_missing", lambda runner, items: called.append([item.binary for item in items]))

    main(["beginner-iso", str(project.root), "--install-missing-tools", "--json"])
    output = json.loads(capsys.readouterr().out)

    assert output["installed"] is True
    assert output["install_packages"]
    assert called and "xorriso" in called[0]


def test_beginner_iso_explains_last_failure_from_command_log(capsys, tmp_path: Path) -> None:
    project = Project.create("CliFailure", tmp_path / "cli-failure", "26.04")
    log = project.root / "beginner-iso-build-commands.jsonl"
    log.write_text('{"event":"finish","command":"mksquashfs root filesystem.squashfs","returncode":1}\n', encoding="utf-8")

    report = explain_beginner_iso_failure(project)

    assert report.category == "squashfs"
    assert "squashfs-tools" in report.next_action

    main(["beginner-iso", str(project.root), "--explain-last-failure", "--json"])
    output = json.loads(capsys.readouterr().out)
    assert output["category"] == "squashfs"


def test_beginner_iso_repairs_derivable_release_artifacts(capsys, tmp_path: Path) -> None:
    project = Project.create("RepairIso", tmp_path / "repair-iso", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "RepairIso.iso"
    iso.parent.mkdir(parents=True, exist_ok=True)
    iso.write_bytes(b"iso")
    options = BuildOptions()
    options.output_iso = iso
    options.prebuild_vm.enabled = True
    options.bootcheck.enabled = True

    report = repair_beginner_iso_release_artifacts(project, options)

    assert report.gate_status == "blocked"
    assert {"SHA256SUMS", "BUILDINFO", "distroforge-provenance.json", "report.html"} <= set(report.repaired)
    assert (project.output_dir / "SHA256SUMS").read_text(encoding="utf-8").strip().endswith("RepairIso.iso")
    assert any("Boot proof was not repaired" in item for item in report.skipped)

    definition = project.root / "repair.yaml"
    write_definition(definition_from_project(project, options), definition)
    main(["beginner-iso", str(project.root), "--repair-release-artifacts", "--definition", str(definition), "--json"])
    output = json.loads(capsys.readouterr().out)
    assert "SHA256SUMS" in output["repaired"]


def test_beginner_iso_boot_proof_plans_and_gate_uses_proof_report(capsys, tmp_path: Path) -> None:
    project = Project.create("BootProofIso", tmp_path / "boot-proof-iso", "26.04")
    project.source_mode = "bootstrap"
    iso = project.output_dir / "BootProofIso.iso"
    iso.write_bytes(b"iso")
    options = BuildOptions()
    options.output_iso = iso
    options.prebuild_vm.enabled = True

    planned = run_beginner_iso_boot_proof(project, options, execute=False)
    assert planned.status == "planned"
    assert planned.gate_status == "blocked"

    (project.output_dir / options.prebuild_vm.report_name).write_text("{}", encoding="utf-8")
    repair_beginner_iso_release_artifacts(project, options)
    gate = __import__("distroforge.core.release_gate", fromlist=["ReleaseGateService"]).ReleaseGateService().check(project, options, iso=iso, output_dir=project.output_dir)
    statuses = {item.code: item.status for item in gate.items}
    assert statuses["boot-proof"] == "ready"

    definition = project.root / "boot-proof.yaml"
    write_definition(definition_from_project(project, options), definition)
    main(["beginner-iso", str(project.root), "--run-boot-proof", "--dry-run", "--definition", str(definition), "--json"])
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "planned"


def test_beginner_iso_repair_stays_blocked_without_iso(capsys, tmp_path: Path) -> None:
    project = Project.create("NoIsoRepair", tmp_path / "no-iso-repair", "26.04")

    report = repair_beginner_iso_release_artifacts(project)

    assert report.gate_status == "blocked"
    assert not report.repaired
    assert "ISO is missing" in report.skipped[0]

    main(["glossary", "squashfs"])
    assert "squashfs:" in capsys.readouterr().out

    main(["ai-review", str(project.root)])
    assert "AI-assisted review:" in capsys.readouterr().out


def test_poweruser_iso_path_enables_guarded_advanced_modules(capsys, tmp_path: Path) -> None:
    project = Project.create("PowerPath", tmp_path / "power-path", "26.04")

    report = prepare_poweruser_iso_path(project, apply_safe_defaults=True, dry_run=True)

    assert (project.root / "poweruser-iso.yaml").exists()
    assert (project.root / "poweruser-iso-dry-run.json").exists()
    assert {"deb822-mirrors", "autoinstall", "auto-drivers", "systemd-services", "rollback-snapshots"} <= set(report.modules)
    data = load_definition(project.root / "poweruser-iso.yaml")
    assert data["mirrors"]["enabled"] is True
    assert data["autoinstall"]["enabled"] is True
    assert data["snapshots"]["enabled"] is True
    assert data["snapshots"]["auto_restore_on_failure"] is True
    assert report.gate_status == "blocked"

    main(["poweruser-iso", str(project.root), "--apply-safe-defaults", "--dry-run", "--json"])
    output = json.loads(capsys.readouterr().out)
    assert "rollback-snapshots" in output["modules"]


def test_forgeadvisor_explains_logs_and_reviews_builds(capsys, tmp_path: Path) -> None:
    log = tmp_path / "build.log"
    log.write_text(
        "Command failed with exit code 126: pkexec /usr/bin/install file target\n"
        "mksquashfs failed near filesystem.squashfs\n",
        encoding="utf-8",
    )
    project = Project.create("Advisor", tmp_path / "advisor", "26.04")
    project.source_mode = "bootstrap"
    project.output_dir.mkdir(exist_ok=True)
    (project.output_dir / "old.iso").write_text("old", encoding="utf-8")
    project.save()

    report = ForgeAdvisor().explain_log(log)
    assert {finding.code for finding in report.findings} >= {"pkexec-authorization", "squashfs"}
    assert report.findings[0].citations

    main(["forgeadvisor", "explain-log", str(log)])
    assert "ForgeAdvisor:" in capsys.readouterr().out

    main(["forgeadvisor", "review-build", str(project.root)])
    output = capsys.readouterr().out
    assert "ForgeAdvisor:" in output
    assert "output-dir-not-empty" in output
    # Default options keep the privilege helper on, so privilege-disabled stays silent...
    assert "privilege-disabled" not in output
    # ...but --no-sudo (parity with the GUI sudo toggle) surfaces it on the same findings path.
    main(["forgeadvisor", "review-build", str(project.root), "--no-sudo"])
    assert "privilege-disabled" in capsys.readouterr().out

    main(["forgeadvisor", "doctor-ai", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["backend"] == "offline"


def test_gui_option_parity_reports_missing_options() -> None:
    parser = build_parser()
    sub = next(action for action in parser._actions if isinstance(action, argparse._SubParsersAction))
    build = sub.choices["build"]
    options = {
        option: action.dest
        for action in build._actions
        for option in action.option_strings
        if option.startswith("--")
    }
    gui_source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in Path("distroforge/ui").glob("*.py")
    )

    report = gui_option_parity_report(options, gui_source)

    assert "--source-iso-sha256" in report
    assert "Build option -> GUI coverage" in report
    assert "MISSING" not in report
