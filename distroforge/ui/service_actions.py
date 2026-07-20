from __future__ import annotations

from distroforge.core.command import CommandRunner
from distroforge.core.doctor import (
    install_packages_for_debian_dev,
    manual_install_packages_for_debian_dev,
    run_debian_dev_doctor,
    run_doctor,
)
from distroforge.core.ux_audit import audit_experience, gui_source_root


def run_doctor_action(window) -> None:
    def _work():
        lines = []
        for item in run_doctor(CommandRunner(dry_run=True)):
            mark = "ok" if item.available else "missing"
            lines.append(f"{mark:8} {item.binary:18} {item.reason}")
        return "\n".join(lines)

    def _done(text):
        window._log(text)
        window._open_surface("logs")

    window._run_in_worker(_work, _done, "Running doctor checks…")


def run_debian_dev_doctor_action(window) -> None:
    def _work():
        report = run_debian_dev_doctor(CommandRunner(dry_run=True))
        lines = ["Debian/Ubuntu maintainer tooling"]
        for item in report:
            mark = "ok" if item.available else "missing"
            lines.append(
                f"{mark:8} {item.group:10} {item.binary:22} {item.apt_package:22} {item.reason}"
            )
        packages = install_packages_for_debian_dev(report)
        manual = manual_install_packages_for_debian_dev(report)
        if packages:
            lines.extend(["", "Missing apt packages:", "  " + " ".join(packages)])
            lines.extend(["", "Install preview:", "  distroforge doctor --debian-dev --install"])
        if manual:
            lines.extend(
                [
                    "",
                    "Manual review packages:",
                    "  " + " ".join(manual),
                    "  Install manually only if you accept possible live/initramfs package changes.",
                ]
            )
        return "\n".join(lines)

    def _done(text):
        window.ai_view.setPlainText(text)
        window._log("Debian/Ubuntu maintainer doctor rendered.")
        window._open_surface("maintainer")

    window._run_in_worker(_work, _done, "Running Debian/Ubuntu maintainer doctor…")


def run_ux_audit_action(window) -> None:
    if not window._require_project():
        return
    window._sync_project_from_ui()
    assert window.project
    project, options, gui_source = window.project, window._build_options(), gui_source_root()

    def _work():
        return audit_experience(project, options, gui_source)

    def _done(report):
        window.ux_audit_view.setPlainText(report.render_text())
        window._log(f"UX audit score: {report.score}/100")
        window._open_surface("quality")

    window._run_in_worker(_work, _done, "Running UX audit…")


def run_readiness_action(window) -> None:
    from distroforge.core.readiness import ReadinessService

    if not window._require_project():
        return
    window._sync_project_from_ui()
    assert window.project
    project, options = window.project, window._build_options()

    def _work():
        return ReadinessService().check(project, options)

    def _done(report):
        window.readiness_view.setPlainText(report.render_text())
        window._log(f"Readiness: {report.status} ({report.score}/100)")
        window._open_surface("quality")

    window._run_in_worker(_work, _done, "Checking build readiness…")


def run_preview_action(window) -> None:
    from distroforge.core.qemu_preview import QemuPreviewOptions, QemuPreviewService

    if not window._require_project():
        return
    window._sync_project_from_ui()
    assert window.project
    project, options = window.project, window._build_options()
    display = window.preview_display_combo.currentData() or "gtk"
    target_iso = options.output_iso or project.output_dir / f"{project.name}.iso"

    def _work():
        runner = CommandRunner(dry_run=True)
        return QemuPreviewService(runner, target_iso, project.workdir, project.output_dir, QemuPreviewOptions(display=display)).run()

    def _done(report):
        window.readiness_view.setPlainText(report.render_text())
        window._log(f"Preview planned ({report.display}) for {report.iso.name}")
        window._open_surface("quality")

    window._run_in_worker(_work, _done, "Planning interactive preview…")


def run_interaction_action(window) -> None:
    from distroforge.core.interaction_plan import resolve_interaction_plan
    from distroforge.core.qemu_interaction import QemuInteractionOptions, QemuInteractionService

    if not window._require_project():
        return
    window._sync_project_from_ui()
    assert window.project
    project, options = window.project, window._build_options()
    plan_name = window.interaction_plan_combo.currentData() or "boot-capture"
    target_iso = options.output_iso or project.output_dir / f"{project.name}.iso"

    def _work():
        runner = CommandRunner(dry_run=True)
        plan = resolve_interaction_plan(plan_name, target_iso)
        return QemuInteractionService(runner, target_iso, project.workdir, project.output_dir, plan, QemuInteractionOptions()).run()

    def _done(report):
        window.readiness_view.setPlainText(report.render_text())
        window._log(f"Interaction planned ({report.plan.name}) for {report.iso.name}")
        window._open_surface("quality")

    window._run_in_worker(_work, _done, "Planning QEMU interaction…")


def run_mirrors_doctor_action(window) -> None:
    from distroforge.core.mirrors import MirrorService

    if not window._require_project():
        return
    window._sync_project_from_ui()
    assert window.project
    project, options = window.project, window._build_options()

    def _work():
        return MirrorService(CommandRunner(dry_run=True), project, options.mirrors, use_sudo=options.use_sudo).doctor()

    def _done(report):
        window.mirrors_view.setPlainText(report.render_text())
        window._log(f"Mirror doctor: {report.status}")
        window._open_surface("source")

    window._run_in_worker(_work, _done, "Running mirror doctor…")


def run_branding_compliance_action(window) -> None:
    from distroforge.core.branding_compliance import BrandingComplianceService

    if not window._require_project():
        return
    window._sync_project_from_ui()
    assert window.project
    project, options = window.project, window._build_options()
    mode = "redistributable" if options.policy.strict else options.policy.branding_mode

    def _work():
        return BrandingComplianceService().audit(project, options.branding, mode)

    def _done(report):
        window.compliance_view.setPlainText(report.render_text())
        window._log(f"Branding compliance: {report.status}")
        window._open_surface("quality")

    window._run_in_worker(_work, _done, "Auditing branding compliance…")


def run_debrand_scan_action(window) -> None:
    from distroforge.core.debrand import DebrandService

    if not window._require_project():
        return
    window._sync_project_from_ui()
    assert window.project
    project, options = window.project, window._build_options()

    def _work():
        return DebrandService(CommandRunner(dry_run=True)).scan(project, options.branding)

    def _done(report):
        window.compliance_view.setPlainText(report.render_text())
        window._log(f"Debrand scan: {report.status}")
        window._open_surface("quality")

    window._run_in_worker(_work, _done, "Scanning for branding remnants…")


def run_ai_review_action(window) -> None:
    from distroforge.ai.review import PlanReviewer
    from distroforge.core.dry_run_report import generate_dry_run_report
    from distroforge.core.readiness import ReadinessService

    if not window._require_project():
        return
    window._sync_project_from_ui()
    assert window.project
    project, options = window.project, window._build_options()

    def _work():
        readiness = ReadinessService().check(project, options)
        dry_run = generate_dry_run_report(project, options, run_orchestrator=False)
        return PlanReviewer().review(readiness, dry_run)

    def _done(review):
        window.ai_view.setPlainText(review.render_text())
        window._log(f"AI-assisted review: {review.verdict}")
        window._open_surface("maintainer")

    window._run_in_worker(_work, _done, "Running AI build review…")


def run_forgeadvisor_action(window) -> None:
    from distroforge.ai.backend import select_backend
    from distroforge.ai.forgeadvisor import ForgeAdvisor
    from distroforge.core.build_memory import BuildMemory, default_corpus_path

    if not window._require_project():
        return
    window._sync_project_from_ui()
    assert window.project
    project, options = window.project, window._build_options()
    backend = select_backend(window.advisor_backend_combo.currentData())
    level = window.advisor_register_combo.currentData()

    def _work():
        return ForgeAdvisor(backend, BuildMemory(default_corpus_path()), level).review_build(project, options)

    def _done(report):
        window.ai_view.setPlainText(report.render_text())
        window._log(f"ForgeAdvisor review: {report.verdict}")
        window._open_surface("maintainer")

    window._run_in_worker(_work, _done, "ForgeAdvisor reviewing build…")


def run_forgeadvisor_propose_action(window) -> None:
    from distroforge.ai.backend import select_backend
    from distroforge.ai.forgeadvisor import ForgeAdvisor
    from distroforge.core.build_memory import BuildMemory, default_corpus_path

    if not window._require_project():
        return
    window._sync_project_from_ui()
    assert window.project
    project, options = window.project, window._build_options()
    backend = select_backend(window.advisor_backend_combo.currentData())
    level = window.advisor_register_combo.currentData()

    def _work():
        return ForgeAdvisor(backend, BuildMemory(default_corpus_path()), level).propose_fixes(project, options)

    def _done(report):
        window.ai_view.setPlainText(report.render_text())
        window._log(f"ForgeAdvisor proposals: {report.verdict} (preview only)")
        window._open_surface("maintainer")

    window._run_in_worker(_work, _done, "ForgeAdvisor drafting fix proposals…")
