from __future__ import annotations

from pathlib import Path


def explain_risk_action(window) -> None:
    from distroforge.core.education import explain_risks

    if not window._require_project():
        return
    window._sync_project_from_ui()
    assert window.project
    project, options = window.project, window._build_options()

    def _work():
        return explain_risks(project, options)

    def _done(text):
        window.ai_view.setPlainText(text)
        window._log("Risk explanation rendered.")
        window._open_surface("maintainer")

    window._run_in_worker(_work, _done, "Explaining build risks…")


def forgeadvisor_explain_log_action(window) -> None:
    from distroforge.ai.backend import select_backend
    from distroforge.ai.forgeadvisor import ForgeAdvisor
    from distroforge.core.build_memory import BuildMemory, default_corpus_path
    from distroforge.ui.qt import QFileDialog

    path, _ = QFileDialog.getOpenFileName(
        window, "Select build log", filter="Log files (*.log *.txt);;All files (*)"
    )
    if not path:
        return
    backend = select_backend(window.advisor_backend_combo.currentData())
    level = window.advisor_register_combo.currentData()

    def _work():
        return ForgeAdvisor(backend, BuildMemory(default_corpus_path()), level).explain_log(Path(path))

    def _done(report):
        window.ai_view.setPlainText(report.render_text())
        window._log(f"ForgeAdvisor log explanation: {report.verdict}")
        window._open_surface("maintainer")

    window._run_in_worker(_work, _done, "ForgeAdvisor explaining log…")


def forgeadvisor_triage_log_action(window) -> None:
    from distroforge.ai.backend import select_backend
    from distroforge.ai.forgeadvisor import ForgeAdvisor
    from distroforge.core.build_memory import BuildMemory, default_corpus_path
    from distroforge.ui.qt import QFileDialog

    path, _ = QFileDialog.getOpenFileName(
        window, "Select build log", filter="Log files (*.log *.txt);;All files (*)"
    )
    if not path:
        return
    backend = select_backend(window.advisor_backend_combo.currentData())
    level = window.advisor_register_combo.currentData()

    def _work():
        return ForgeAdvisor(backend, BuildMemory(default_corpus_path()), level).triage_log(Path(path))

    def _done(report):
        window.ai_view.setPlainText(report.render_text())
        window._log(f"ForgeAdvisor log triage: {report.verdict}")
        window._open_surface("maintainer")

    window._run_in_worker(_work, _done, "ForgeAdvisor triaging log…")


def forgeadvisor_doctor_ai_action(window) -> None:
    from distroforge.ai.backend import select_backend
    from distroforge.ai.forgeadvisor import ForgeAdvisor
    from distroforge.core.build_memory import BuildMemory, default_corpus_path

    backend = select_backend(window.advisor_backend_combo.currentData())
    level = window.advisor_register_combo.currentData()

    def _work():
        return ForgeAdvisor(backend, BuildMemory(default_corpus_path()), level).doctor()

    def _done(report):
        window.ai_view.setPlainText(report.render_text())
        window._log(f"ForgeAdvisor AI doctor: {report.verdict}")
        window._open_surface("maintainer")

    window._run_in_worker(_work, _done, "Checking local AI backend…")


def forgeadvisor_explain_evidence_action(window) -> None:
    from distroforge.ai.backend import select_backend
    from distroforge.ai.forgeadvisor import ForgeAdvisor
    from distroforge.core.build_memory import BuildMemory, default_corpus_path

    if not window._require_project():
        return
    assert window.project
    backend = select_backend(window.advisor_backend_combo.currentData())
    level = window.advisor_register_combo.currentData()
    iso = Path(window.artifacts_output_iso_edit.text().strip() or window.output_iso_edit.text().strip() or window.project.output_dir / f"{window.project.name}.iso")
    output_dir = Path(window.artifacts_reports_dir_edit.text().strip() or iso.parent)

    def _work():
        return ForgeAdvisor(backend, BuildMemory(default_corpus_path()), level).explain_evidence(
            window.project.root,
            options=window._build_options(),
            iso=iso,
            output_dir=output_dir,
            profile="publish",
        )

    def _done(report):
        window.ai_view.setPlainText(report.render_text())
        window._log(f"ForgeAdvisor evidence explanation: {report.verdict}")
        window._open_surface("maintainer")

    window._run_in_worker(_work, _done, "ForgeAdvisor explaining evidence…")


def forgeadvisor_fix_plan_action(window) -> None:
    from distroforge.ai.backend import select_backend
    from distroforge.ai.forgeadvisor import ForgeAdvisor
    from distroforge.core.build_memory import BuildMemory, default_corpus_path

    if not window._require_project():
        return
    assert window.project
    backend = select_backend(window.advisor_backend_combo.currentData())
    level = window.advisor_register_combo.currentData()
    iso = Path(window.artifacts_output_iso_edit.text().strip() or window.output_iso_edit.text().strip() or window.project.output_dir / f"{window.project.name}.iso")
    output_dir = Path(window.artifacts_reports_dir_edit.text().strip() or iso.parent)

    def _work():
        return ForgeAdvisor(backend, BuildMemory(default_corpus_path()), level).narrate_fix_plan(
            window.project.root,
            options=window._build_options(),
            iso=iso,
            output_dir=output_dir,
            profile="publish",
        )

    def _done(report):
        window.ai_view.setPlainText(report.render_text())
        window._log(f"ForgeAdvisor fix plan: {report.verdict} (preview only)")
        window._open_surface("maintainer")

    window._run_in_worker(_work, _done, "ForgeAdvisor narrating fix plan…")


def forgeadvisor_review_definition_action(window) -> None:
    from distroforge.ai.backend import select_backend
    from distroforge.ai.forgeadvisor import ForgeAdvisor
    from distroforge.core.build_memory import BuildMemory, default_corpus_path
    from distroforge.ui.qt import QFileDialog

    path, _ = QFileDialog.getOpenFileName(
        window, "Select build definition", filter="Definitions (*.yaml *.yml *.json);;All files (*)"
    )
    if not path:
        return
    backend = select_backend(window.advisor_backend_combo.currentData())
    level = window.advisor_register_combo.currentData()

    def _work():
        return ForgeAdvisor(backend, BuildMemory(default_corpus_path()), level).review_definition(Path(path))

    def _done(report):
        window.ai_view.setPlainText(report.render_text())
        window._log(f"ForgeAdvisor definition review: {report.verdict}")
        window._open_surface("maintainer")

    window._run_in_worker(_work, _done, "ForgeAdvisor reviewing definition…")


def forgeadvisor_search_local_action(window) -> None:
    from distroforge.ai.backend import select_backend
    from distroforge.ai.forgeadvisor import ForgeAdvisor
    from distroforge.core.build_memory import BuildMemory, default_corpus_path

    if not window._require_project():
        return
    assert window.project
    backend = select_backend(window.advisor_backend_combo.currentData())
    level = window.advisor_register_combo.currentData()
    query = window.terminal_input.text().strip() or "evidence"

    def _work():
        return ForgeAdvisor(backend, BuildMemory(default_corpus_path()), level).search_local(
            window.project.root, query, limit=8
        )

    def _done(report):
        window.ai_view.setPlainText(report.render_text())
        window._log(f"ForgeAdvisor local search: {report.verdict}")
        window._open_surface("maintainer")

    window._run_in_worker(_work, _done, "ForgeAdvisor searching local knowledge…")


def forgeadvisor_copilot_action(window) -> None:
    from distroforge.ai.backend import select_backend
    from distroforge.ai.forgeadvisor import ForgeAdvisor
    from distroforge.core.build_memory import BuildMemory, default_corpus_path

    if not window._require_project():
        return
    assert window.project
    backend = select_backend(window.advisor_backend_combo.currentData())
    level = window.advisor_register_combo.currentData()
    iso = Path(window.artifacts_output_iso_edit.text().strip() or window.output_iso_edit.text().strip() or window.project.output_dir / f"{window.project.name}.iso")
    output_dir = Path(window.artifacts_reports_dir_edit.text().strip() or iso.parent)
    query = window.terminal_input.text().strip() or "evidence release readiness"

    def _work():
        return ForgeAdvisor(backend, BuildMemory(default_corpus_path()), level).maintainer_copilot(
            window.project.root,
            options=window._build_options(),
            iso=iso,
            output_dir=output_dir,
            profile="publish",
            query=query,
            limit=5,
        )

    def _done(report):
        window.ai_view.setPlainText(report.render_text())
        window._log(f"Maintainer Copilot: {report.verdict} (preview only)")
        window._open_surface("maintainer")

    window._run_in_worker(_work, _done, "Running Maintainer Copilot…")


def review_current_plan_action(window) -> None:
    from distroforge.core.manifest import PackageEntry

    plan = window._package_plan()
    manifest = {
        name: PackageEntry(name=name, version="planned")
        for name in [*plan.install, *plan.remove]
    }
    _render_advice(window, manifest)


def review_manifest_file_action(window) -> None:
    from distroforge.core.manifest import read_manifest
    from distroforge.ui.qt import QFileDialog

    path, _ = QFileDialog.getOpenFileName(window, "Select filesystem.manifest")
    if not path:
        return
    try:
        manifest = read_manifest(Path(path))
    except Exception as exc:
        window._error(str(exc))
        return
    _render_advice(window, manifest)


def _render_advice(window, manifest) -> None:
    from distroforge.ai.advisor import ManifestAdvisor

    advice = ManifestAdvisor().advise(manifest)
    if not advice:
        window.ai_view.setPlainText("No advisory findings.")
        return
    window.ai_view.setPlainText(
        "\n\n".join(
            f"[{item.level}] {item.title}\n{item.detail}\n{', '.join(item.packages)}"
            for item in advice
        )
    )
    window._open_surface("maintainer")
