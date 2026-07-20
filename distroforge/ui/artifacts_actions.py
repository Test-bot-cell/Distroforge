from __future__ import annotations

from pathlib import Path

from distroforge.core.artifact_paths import default_artifact_paths
from distroforge.core.evidence import EvidenceStatusService, validate_evidence_contract
from distroforge.core.packaging import (
    HermeticBuildPlan,
    create_hermetic_release_bundle,
    debian_changelog_version,
    diagnose_autopkgtest,
    packaging_policy_report,
)
from distroforge.core.qemu_smoke import QemuSmokePlanner
from distroforge.core.release_readiness import ReleaseReadinessService
from distroforge.core.source_starter import apply_source_starter
from distroforge.ui.qt import QFileDialog


def browse_buildinfo_action(window) -> None:
    path, _ = QFileDialog.getOpenFileName(
        window,
        "Select Debian buildinfo",
        filter="Buildinfo files (*.buildinfo);;All files (*)",
    )
    if path:
        window.artifacts_buildinfo_edit.setText(path)
        if window.project:
            apply_source_starter(window.project, "local-iso", source_iso=Path(path))
            window._refresh()


def browse_changes_action(window) -> None:
    path, _ = QFileDialog.getOpenFileName(
        window,
        "Select Debian changes file",
        filter="Changes files (*.changes);;All files (*)",
    )
    if path:
        window.artifacts_changes_edit.setText(path)


def load_artifact_defaults_action(window) -> None:
    if not window._require_project():
        return
    assert window.project
    paths = default_artifact_paths(window.project)
    window.artifacts_output_iso_edit.setText(str(paths.output_iso))
    window.artifacts_reports_dir_edit.setText(str(paths.reports_dir))
    window.artifacts_livefs_work_dir_edit.setText(str(paths.livefs_work_dir))
    window.artifacts_live_build_dir_edit.setText(str(paths.live_build_dir))
    window.artifacts_screenshot_edit.setText(str(paths.screenshot))
    window.artifacts_serial_log_edit.setText(str(paths.serial_log))
    window.artifacts_view.setPlainText(paths.render_text())
    window._open_surface("artifacts")


def run_release_readiness_action(window) -> None:
    iso = Path(window.artifacts_output_iso_edit.text().strip() or window.output_iso_edit.text().strip() or "/tmp/distroforge.iso")
    output_dir = Path(window.artifacts_reports_dir_edit.text().strip() or iso.parent)
    report = ReleaseReadinessService().check(iso, output_dir)
    window.artifacts_view.setPlainText(report.render_text())
    window._log("Rendered release readiness report.")
    window._open_surface("artifacts")


def run_release_gate_action(window) -> None:
    if not window._require_project():
        return
    from distroforge.core.release_gate import ReleaseGateService
    iso = Path(window.artifacts_output_iso_edit.text().strip() or window.output_iso_edit.text().strip() or "/tmp/distroforge.iso")
    output_dir = Path(window.artifacts_reports_dir_edit.text().strip() or iso.parent)
    window.artifacts_view.setPlainText(ReleaseGateService().check(window.project, window._build_options(), iso=iso, output_dir=output_dir).render_text())
    window._log("Rendered release gate report.")
    window._open_surface("artifacts")


def run_evidence_status_action(window, *, verbose: bool = False, fix_plan: bool = False) -> None:
    if not window._require_project():
        return
    assert window.project
    iso = Path(window.artifacts_output_iso_edit.text().strip() or window.output_iso_edit.text().strip() or window.project.output_dir / f"{window.project.name}.iso")
    output_dir = Path(window.artifacts_reports_dir_edit.text().strip() or iso.parent)
    report = EvidenceStatusService().check(window.project, window._build_options(), iso=iso, output_dir=output_dir)
    counts = report.counts()
    summary = f"Evidence {report.status.upper()} | ready {counts['ready']} | review {counts['review']} | blocked {counts['blocked']} | invalid {counts['invalid']}"
    if hasattr(window, "evidence_summary_label"):
        window.evidence_summary_label.setText(summary)
    window.ai_view.setPlainText(report.render_fix_plan_text() if fix_plan else report.render_text(verbose=verbose))
    window._log(f"Rendered evidence status with status {report.status}.")
    window._open_surface("maintainer")


def verify_evidence_contract_action(window) -> None:
    if not window._require_project():
        return
    assert window.project
    reports_dir = Path(window.artifacts_reports_dir_edit.text().strip() or window.project.output_dir)
    contract_root = reports_dir if (reports_dir / "BUNDLE-CONTRACT.json").exists() else reports_dir.parent
    try:
        report = validate_evidence_contract(contract_root)
    except FileNotFoundError as exc:
        window.artifacts_view.setPlainText(str(exc))
        window._log("Evidence contract is missing.")
        window._open_surface("artifacts")
        return
    window.artifacts_view.setPlainText(report.render_text())
    window._log(f"Verified evidence contract with status {report.status}.")
    window._open_surface("artifacts")


def create_publish_bundle_action(window) -> None:
    if not window._require_project():
        return
    from distroforge.core.publish_bundle import create_publish_bundle
    iso = Path(window.artifacts_output_iso_edit.text().strip() or window.output_iso_edit.text().strip() or "/tmp/distroforge.iso")
    output_dir = Path(window.artifacts_reports_dir_edit.text().strip() or iso.parent)
    report = create_publish_bundle(window.project, window._build_options(), iso=iso, output_dir=output_dir)
    window.artifacts_view.setPlainText(report.render_text())
    window._log(f"Created publish bundle with gate {report.status}.")
    window._open_surface("artifacts")


def run_qemu_smoke_plan_action(window) -> None:
    iso = Path(window.artifacts_output_iso_edit.text().strip() or window.output_iso_edit.text().strip() or "/tmp/distroforge.iso")
    plan = QemuSmokePlanner().plan(iso)
    window.artifacts_view.setPlainText(plan.render_text())
    window._log("Rendered QEMU install smoke plan.")
    window._open_surface("artifacts")


def run_packaging_policy_action(window) -> None:
    if not window._require_project():
        return
    assert window.project
    buildinfo_text = window.artifacts_buildinfo_edit.text().strip()
    changes_text = window.artifacts_changes_edit.text().strip()
    report = packaging_policy_report(
        window.project.root,
        Path(buildinfo_text) if buildinfo_text else None,
        Path(changes_text) if changes_text else None,
    )
    window.artifacts_view.setPlainText(report.render_text())
    window._log("Rendered packaging policy report.")
    window._open_surface("artifacts")


def run_autopkgtest_doctor_action(window) -> None:
    if not window._require_project():
        return
    assert window.project
    report = diagnose_autopkgtest(window.project.root)
    window.artifacts_view.setPlainText(report.render_text())
    window._log(f"Rendered autopkgtest doctor with status {report.status}.")
    window._open_surface("artifacts")


def run_hermetic_build_plan_action(window) -> None:
    if not window._require_project():
        return
    assert window.project
    plan = HermeticBuildPlan(
        root=window.project.root,
        backend=str(window.hermetic_backend_combo.currentData() or "sbuild"),
        suite=window.hermetic_suite_edit.text().strip() or "unstable",
    )
    window.artifacts_view.setPlainText(plan.render_text())
    window._log("Rendered hermetic build plan.")
    window._open_surface("artifacts")


def create_hermetic_release_bundle_action(window) -> None:
    if not window._require_project():
        return
    assert window.project
    suite = window.hermetic_suite_edit.text().strip() or "resolute"
    artifact_dir = window.project.root.parent
    version = debian_changelog_version(window.project.root)
    output_dir = artifact_dir / f"distroforge-{version}-hermetic-release"
    autopkgtest_dir = output_dir / "AUTOPKGTEST"
    report = create_hermetic_release_bundle(
        window.project.root,
        output_dir=output_dir,
        artifact_dir=artifact_dir,
        version=version,
        suite=suite,
        autopkgtest_dir=autopkgtest_dir if autopkgtest_dir.exists() else None,
        replace=True,
    )
    window.artifacts_view.setPlainText(report.render_text())
    window._log(f"Created hermetic release bundle with status {report.status}.")
    window._open_surface("artifacts")
