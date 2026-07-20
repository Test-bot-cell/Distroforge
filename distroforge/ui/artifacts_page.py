from __future__ import annotations

from pathlib import Path

from distroforge.ui.path_actions import picker
from distroforge.ui.qt import QVBoxLayout, QWidget
from distroforge.ui.step_focus import StepFocusHeader
from distroforge.ui.widgets import button as _button
from distroforge.ui.widgets import button_group as _button_group
from distroforge.ui.widgets import responsive_form as _responsive_form
from distroforge.ui.widgets import responsive_row as _responsive_row
from distroforge.ui.widgets import section as _section


def build_artifacts_page(window) -> QWidget:
    page = QWidget()
    layout = QVBoxLayout(page)
    layout.setContentsMargins(18, 18, 18, 18)
    layout.addWidget(StepFocusHeader(window, "release-evidence"))
    form = _responsive_form()
    form.addRow(
        "Output ISO",
        _responsive_row(
            window.artifacts_output_iso_edit,
            picker(
                window,
                window.artifacts_output_iso_edit,
                title="Select output ISO",
                file_filter="ISO images (*.iso);;All files (*)",
            ),
            breakpoint=680,
        ),
    )
    form.addRow(
        "Reports dir",
        _responsive_row(
            window.artifacts_reports_dir_edit,
            picker(window, window.artifacts_reports_dir_edit, title="Select reports dir", mode="dir"),
            breakpoint=680,
        ),
    )
    form.addRow(
        "livefs work dir",
        _responsive_row(
            window.artifacts_livefs_work_dir_edit,
            picker(window, window.artifacts_livefs_work_dir_edit, title="Select livefs work dir", mode="dir"),
            breakpoint=680,
        ),
    )
    form.addRow(
        "live-build dir",
        _responsive_row(
            window.artifacts_live_build_dir_edit,
            picker(window, window.artifacts_live_build_dir_edit, title="Select live-build dir", mode="dir"),
            breakpoint=680,
        ),
    )
    form.addRow(
        "Screenshot",
        _responsive_row(
            window.artifacts_screenshot_edit,
            picker(
                window,
                window.artifacts_screenshot_edit,
                title="Select screenshot",
                file_filter="Images (*.ppm *.png *.jpg);;All files (*)",
            ),
            breakpoint=680,
        ),
    )
    form.addRow(
        "Serial log",
        _responsive_row(
            window.artifacts_serial_log_edit,
            picker(
                window,
                window.artifacts_serial_log_edit,
                title="Select serial log",
                file_filter="Logs (*.log *.txt);;All files (*)",
            ),
            breakpoint=680,
        ),
    )
    form.addRow("Boot proof backend", window.boot_proof_backend_combo)
    form.addRow(
        "Buildinfo",
        _responsive_row(window.artifacts_buildinfo_edit, _button("Select", window._browse_buildinfo, "open"), breakpoint=680),
    )
    form.addRow(
        "Changes",
        _responsive_row(window.artifacts_changes_edit, _button("Select", window._browse_changes, "open"), breakpoint=680),
    )
    form.addRow("Hermetic backend", window.hermetic_backend_combo)
    form.addRow("Hermetic suite", window.hermetic_suite_edit)
    readiness = _button_group(
        "Readiness",
        _button("Load Defaults", window._load_artifact_defaults, "plan"),
        _button("Release Readiness", window._run_release_readiness, "audit"),
        _button("Release Gate", window._run_release_gate, "audit"),
        _button("Packaging Policy", window._run_packaging_policy, "audit"),
        _button("Autopkgtest Doctor", window._run_autopkgtest_doctor, "audit"),
    )
    proof = _button_group(
        "Boot and build proof",
        _button("Hermetic Build", window._run_hermetic_build_plan, "plan"),
        _button("Hermetic Bundle", window._create_hermetic_release_bundle, "save"),
        _button("Verify Evidence", window._verify_evidence_contract, "audit"),
        _button("QEMU Smoke Plan", window._run_qemu_smoke_plan, "plan"),
        _button("Boot Proof", lambda: boot_proof_from_artifacts(window), "audit"),
    )
    sign = _button_group(
        "Sign, notes and verify",
        _button("Publish Bundle", window._create_publish_bundle, "save"),
        _button("Plan Sign Release", lambda: sign_release_from_artifacts(window), "save"),
        _button("Release Notes", lambda: release_notes_from_artifacts(window), "save"),
        _button("Verify Release", lambda: verify_release_from_artifacts(window), "audit"),
        _button("Explain Release", lambda: explain_release_from_artifacts(window), "audit"),
    )
    drills = _button_group(
        "Drills and pipeline",
        _button("Publish Drill", lambda: publish_drill_from_artifacts(window), "start"),
        _button("Promote Drill", lambda: promote_drill_from_artifacts(window), "save"),
        _button("Compare Drill", lambda: compare_drill_from_artifacts(window), "audit"),
        _button("Release Pipeline", lambda: release_pipeline_from_artifacts(window), "start"),
    )
    layout.addWidget(_section("Host Artifact Paths", form, readiness, proof, sign, drills))
    layout.addWidget(_section("Artifact Report", window.artifacts_view), 1)
    return page


def sign_release_from_artifacts(window) -> None:
    if not window._require_project():
        return
    from distroforge.core.release_signing import sign_release_bundle

    reports_dir = Path(window.artifacts_reports_dir_edit.text().strip() or window.project.output_dir)
    bundle_dir = reports_dir if reports_dir.name == "publish" else reports_dir.parent / "publish"
    report = sign_release_bundle(window.project, bundle_dir=bundle_dir, execute=False, gpg_key=window.artifact_gpg_key_edit.text().strip() or None)
    window.artifacts_view.setPlainText(report.render_text())
    window._log(f"Planned release signing with status {report.status}.")
    window._open_surface("artifacts")


def release_notes_from_artifacts(window) -> None:
    if not window._require_project():
        return
    from distroforge.core.release_notes import write_release_notes

    reports_dir = Path(window.artifacts_reports_dir_edit.text().strip() or window.project.output_dir)
    bundle_dir = reports_dir if reports_dir.name == "publish" else reports_dir.parent / "publish"
    report = write_release_notes(window.project, bundle_dir=bundle_dir)
    window.artifacts_view.setPlainText(report.render_text())
    window._log(f"Wrote release notes with status {report.status}.")
    window._open_surface("artifacts")


def verify_release_from_artifacts(window) -> None:
    if not window._require_project():
        return
    from distroforge.core.release_verification import verify_release_bundle

    reports_dir = Path(window.artifacts_reports_dir_edit.text().strip() or window.project.output_dir)
    bundle_dir = reports_dir if reports_dir.name == "publish" else reports_dir.parent / "publish"
    report = verify_release_bundle(window.project, bundle_dir=bundle_dir)
    window.artifacts_view.setPlainText(report.render_text())
    window._log(f"Verified release bundle with status {report.status}.")
    window._open_surface("artifacts")


def explain_release_from_artifacts(window) -> None:
    if not window._require_project():
        return
    from distroforge.core.release_explain import explain_release

    reports_dir = Path(window.artifacts_reports_dir_edit.text().strip() or window.project.output_dir)
    bundle_dir = reports_dir if reports_dir.name == "publish" else reports_dir.parent / "publish"
    iso = Path(window.artifacts_output_iso_edit.text().strip() or window.output_iso_edit.text().strip() or window.project.output_dir / f"{window.project.name}.iso")
    report = explain_release(window.project, iso=iso, bundle_dir=bundle_dir)
    window.artifacts_view.setPlainText(report.render_text())
    window._log(f"Explained release evidence with status {report.status}.")
    window._open_surface("artifacts")


def publish_drill_from_artifacts(window) -> None:
    if not window._require_project():
        return
    from distroforge.core.publish_drill import run_publish_drill

    reports_dir = Path(window.artifacts_reports_dir_edit.text().strip() or window.project.output_dir)
    bundle_dir = reports_dir if reports_dir.name == "publish" else reports_dir.parent / "publish"
    iso = Path(window.artifacts_output_iso_edit.text().strip() or window.output_iso_edit.text().strip() or window.project.output_dir / f"{window.project.name}.iso")
    backend = str(window.boot_proof_backend_combo.currentData() or "auto")
    report = run_publish_drill(window.project, window._build_options(), iso=iso, bundle_dir=bundle_dir, gpg_key=window.artifact_gpg_key_edit.text().strip() or None, boot_backend=backend)
    window.artifacts_view.setPlainText(report.render_text())
    window._log(f"Ran publish drill with status {report.status}.")
    window._open_surface("artifacts")


def compare_drill_from_artifacts(window) -> None:
    if not window._require_project():
        return
    from distroforge.core.publish_drill_diff import diff_publish_drills

    reports_dir = Path(window.artifacts_reports_dir_edit.text().strip() or window.project.output_dir)
    bundle_dir = reports_dir if reports_dir.name == "publish" else reports_dir.parent / "publish"
    report = diff_publish_drills(bundle_dir / "PUBLISH-DRILL.previous.json", bundle_dir / "PUBLISH-DRILL.json")
    window.artifacts_view.setPlainText(report.render_text())
    window._log(f"Compared publish drills with verdict {report.verdict}.")
    window._open_surface("artifacts")


def promote_drill_from_artifacts(window) -> None:
    if not window._require_project():
        return
    from distroforge.core.publish_drill_baseline import promote_publish_drill_baseline

    reports_dir = Path(window.artifacts_reports_dir_edit.text().strip() or window.project.output_dir)
    bundle_dir = reports_dir if reports_dir.name == "publish" else reports_dir.parent / "publish"
    report = promote_publish_drill_baseline(window.project, bundle_dir=bundle_dir)
    window.artifacts_view.setPlainText(report.render_text())
    window._log(f"Promoted publish drill baseline with status {report.status}.")
    window._open_surface("artifacts")


def release_pipeline_from_artifacts(window) -> None:
    if not window._require_project():
        return
    from distroforge.core.release_pipeline import run_release_pipeline

    reports_dir = Path(window.artifacts_reports_dir_edit.text().strip() or window.project.output_dir)
    bundle_dir = reports_dir if reports_dir.name == "publish" else reports_dir.parent / "publish"
    iso = Path(window.artifacts_output_iso_edit.text().strip() or window.output_iso_edit.text().strip() or window.project.output_dir / f"{window.project.name}.iso")
    report = run_release_pipeline(window.project, window._build_options(), iso=iso, output_dir=iso.parent, bundle_dir=bundle_dir, gpg_key=window.artifact_gpg_key_edit.text().strip() or None)
    window.artifacts_view.setPlainText(report.render_text())
    window._log(f"Ran release pipeline with status {report.status}.")
    window._open_surface("artifacts")


def boot_proof_from_artifacts(window) -> None:
    if not window._require_project():
        return
    from distroforge.core.boot_proof import run_boot_proof

    iso = Path(window.artifacts_output_iso_edit.text().strip() or window.output_iso_edit.text().strip() or window.project.output_dir / f"{window.project.name}.iso")
    backend = str(window.boot_proof_backend_combo.currentData() or "auto")
    report = run_boot_proof(window.project, window._build_options(), iso=iso, backend=backend, execute=True)
    window.artifacts_view.setPlainText(report.render_text())
    window._log(f"Ran {backend} boot proof with status {report.status}.")
    window._open_surface("artifacts")
