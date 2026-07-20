from __future__ import annotations

from pathlib import Path

from distroforge.core.apt import PackagePlan
from distroforge.core.build import BuildOptions
from distroforge.core.build_journey import JOURNEY_STEPS
from distroforge.core.customize import load_desktops
from distroforge.core.derivative_profile import DerivativeProfileService
from distroforge.core.desktop_source import load_desktop_source_profiles
from distroforge.core.explain import explain_build
from distroforge.core.persona import load_personas
from distroforge.core.plugin_catalog import render_catalog
from distroforge.core.profiles import get_profile, load_profiles
from distroforge.core.project import Project
from distroforge.core.releases import load_releases
from distroforge.core.source_starter import (
    default_starter_for_release,
)
from distroforge.core.terminal import PtySession
from distroforge.ui import preferences
from distroforge.ui.advanced_page import build_advanced_page
from distroforge.ui.advisor_actions import (
    explain_risk_action,
    forgeadvisor_copilot_action,
    forgeadvisor_doctor_ai_action,
    forgeadvisor_explain_evidence_action,
    forgeadvisor_explain_log_action,
    forgeadvisor_fix_plan_action,
    forgeadvisor_review_definition_action,
    forgeadvisor_search_local_action,
    forgeadvisor_triage_log_action,
    review_current_plan_action,
    review_manifest_file_action,
)
from distroforge.ui.artifacts_actions import (
    browse_buildinfo_action,
    browse_changes_action,
    create_hermetic_release_bundle_action,
    create_publish_bundle_action,
    load_artifact_defaults_action,
    run_autopkgtest_doctor_action,
    run_evidence_status_action,
    run_hermetic_build_plan_action,
    run_packaging_policy_action,
    run_qemu_smoke_plan_action,
    run_release_gate_action,
    run_release_readiness_action,
    verify_evidence_contract_action,
)
from distroforge.ui.artifacts_page import build_artifacts_page
from distroforge.ui.branding_actions import (
    export_brand_identity_action,
    run_brand_preview_action,
)
from distroforge.ui.build_controller import BuildController
from distroforge.ui.build_guidance import (
    privilege_status_text,
)
from distroforge.ui.build_options_mapper import build_options_from_window
from distroforge.ui.build_page import build_build_page
from distroforge.ui.capture_actions import (
    browse_capture_output_action,
    browse_live_build_output_action,
    browse_livefs_dest_iso_action,
    browse_livefs_work_dir_action,
    browse_partition_layout_action,
    export_capture_profile_action,
    plan_live_build_action,
    plan_livefs_iso_action,
    plan_systemd_image_action,
    rebuild_from_capture_action,
    run_capture_scan_action,
    run_upgrade_preflight_action,
    write_live_build_plan_action,
    write_livefs_iso_plan_action,
)
from distroforge.ui.capture_page import build_capture_page
from distroforge.ui.cli_equivalent import build_cli_equivalent
from distroforge.ui.command_center_page import (
    JOURNEY_TARGETS,
    apply_current_journey_step,
    build_command_center_page,
    command_center_text,
    open_current_journey_step,
)
from distroforge.ui.customization_page import build_customization_page
from distroforge.ui.first_run import FirstRunDialog
from distroforge.ui.icons import phase_icon
from distroforge.ui.iso_page import build_iso_page
from distroforge.ui.jobs import GuiJob
from distroforge.ui.journey_cards import refresh_start_journey_cards
from distroforge.ui.journey_shell import build_journey_spine
from distroforge.ui.logs_page import build_logs_page
from distroforge.ui.maintainer_page import build_maintainer_page
from distroforge.ui.mirror_actions import (
    apply_mirrors_action,
    render_mirrors_action,
    restore_mirrors_action,
)
from distroforge.ui.packages_page import build_packages_page
from distroforge.ui.plugins_page import build_plugins_page
from distroforge.ui.profile_actions import (
    create_derivative_project_action,
    export_derivative_profile_definition_action,
    export_profile_definition_action,
    run_derivative_profile_plan_action,
    run_profile_diff_action,
)
from distroforge.ui.project_actions import (
    apply_source_starter_action,
    new_project_action,
    open_project_action,
    save_project_action,
    use_previous_project_source_action,
)
from distroforge.ui.project_page import build_project_page
from distroforge.ui.qt import (
    QComboBox,
    QCompleter,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QKeySequence,
    QLabel,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QShortcut,
    QSplitter,
    QStackedWidget,
    Qt,
    QTimer,
    QToolBar,
    QVBoxLayout,
    QWidget,
)
from distroforge.ui.quality_page import build_quality_page
from distroforge.ui.recipe_actions import (
    clear_build_preset_action,
    export_build_preset_action,
    export_recipe_action,
    import_build_preset_action,
    import_recipe_action,
    show_guided_recipes_action,
)
from distroforge.ui.recipes_page import build_recipes_page
from distroforge.ui.service_actions import (
    run_ai_review_action,
    run_branding_compliance_action,
    run_debian_dev_doctor_action,
    run_debrand_scan_action,
    run_doctor_action,
    run_forgeadvisor_action,
    run_forgeadvisor_propose_action,
    run_interaction_action,
    run_mirrors_doctor_action,
    run_preview_action,
    run_readiness_action,
    run_ux_audit_action,
)
from distroforge.ui.service_runner import ServiceRunnerMixin
from distroforge.ui.step_focus import StepFocusHeader
from distroforge.ui.terminal_actions import (
    mount_terminal_runtime_action,
    poll_terminal_action,
    send_terminal_input_action,
    show_chroot_backend_status_action,
    start_terminal_action,
    stop_terminal_action,
    unmount_terminal_runtime_action,
)
from distroforge.ui.virtualization_page import build_virtualization_page
from distroforge.ui.widgets import (
    button as _button,
)
from distroforge.ui.widgets import (
    scroll_page as _scroll_page,
)
from distroforge.ui.widgets import (
    set_combo_data as _set_combo_data,
)
from distroforge.ui.widgets import (
    tame_combo as _tame_combo,
)
from distroforge.ui.widgets import (
    toolbar_action as _toolbar_action,
)
from distroforge.ui.window_widgets import build_window_widgets


class MainWindow(ServiceRunnerMixin, QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("DistroForge")
        self.project: Project | None = None
        self.terminal_session: PtySession | None = None
        self.build_job: GuiJob | None = None
        self.loaded_preset_options: BuildOptions | None = None
        self.loaded_preset_path: Path | None = None
        self._job_step_total = 0
        self._job_step_done = 0
        self._first_run_shown = False
        self.profiles = load_profiles()
        self.derivative_profiles = DerivativeProfileService().list_profiles()
        self.personas = load_personas()
        self.releases = load_releases()
        self.desktops = load_desktops()
        self.desktop_source_profiles = load_desktop_source_profiles()

        self._pages = QStackedWidget()
        # Stable surface keys in build order; the journey spine and every
        # routing call address a surface by key, never by list index.
        self._surface_labels = {
            "start": "Start",
            "source": "Source",
            "packages": "Packages",
            "identity": "Desktop & Identity",
            "capture": "Capture & Images",
            "presets": "Presets",
            "quality": "Quality Lab",
            "virtualization": "Virtualization Lab",
            "artifacts": "Artifacts",
            "maintainer": "Maintainer",
            "command-center": "Command Center",
            "extensions": "Extensions",
            "advanced": "Advanced Modules",
            "build": "Build & Release",
            "logs": "Logs",
        }
        self._surfaces: dict[str, int] = {}
        self._compact_shell: bool | None = None
        self._rail_width_compact = 150
        self._rail_width_expanded = 250
        self._progress_width_compact = 112
        self._progress_width_expanded = 190
        self._step_focus_headers: list = []

        self._make_widgets()
        self._build_pages()
        self._build_toolbar()

        self._rail = _scroll_page(build_journey_spine(self))
        self._rail.setObjectName("JourneyRail")
        self._rail.setFixedWidth(self._rail_width_expanded)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._rail)
        splitter.addWidget(self._pages)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        root = QWidget()
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)
        root_layout.addWidget(self._header())
        root_layout.addWidget(splitter, 1)
        self.setCentralWidget(root)
        self.statusBar().showMessage("Ready")
        self._restore_workflow_level()
        self._open_surface("start")
        self._refresh()
        self._apply_mode_visibility()
        self._sync_desktop_source_hint()
        QTimer.singleShot(250, self._show_first_run_once)
        self._apply_responsive_shell()

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self._apply_responsive_shell()

    def _apply_responsive_shell(self) -> None:
        if not hasattr(self, "_rail") or not hasattr(self, "progress"):
            return
        compact = self.width() < 980
        if compact == self._compact_shell:
            return
        self._compact_shell = compact
        self._rail.setFixedWidth(self._rail_width_compact if compact else self._rail_width_expanded)
        self.header_project_label.setVisible(not compact)
        self.progress.setFixedWidth(self._progress_width_compact if compact else self._progress_width_expanded)
        toolbar = getattr(self, "_toolbar", None)
        if toolbar is not None:
            style = (
                Qt.ToolButtonStyle.ToolButtonIconOnly
                if compact
                else Qt.ToolButtonStyle.ToolButtonTextBesideIcon
            )
            toolbar.setToolButtonStyle(style)

    def _make_widgets(self) -> None:
        build_window_widgets(self)

    def _sync_desktop_source_hint(self) -> None:
        key = self.desktop_combo.currentData()
        profile = self.desktop_source_profiles.get(key)
        if not profile:
            self.desktop_source_version_edit.setPlaceholderText("")
            return
        self.desktop_source_version_edit.setPlaceholderText(profile.current_version)
        self.desktop_source_components_edit.setPlaceholderText(
            f"{profile.key}-session|{profile.current_version}|https://...tar.xz"
        )

    def _build_toolbar(self) -> None:
        toolbar = QToolBar("Main")
        toolbar.setMovable(False)
        toolbar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self._toolbar = toolbar
        self.addToolBar(toolbar)
        _toolbar_action(toolbar, "New", self._new_project, "new")
        _toolbar_action(toolbar, "Open", self._open_project, "open")
        _toolbar_action(toolbar, "Save", self._save_project, "save")
        toolbar.addSeparator()
        _toolbar_action(toolbar, "Doctor", self._doctor, "doctor")
        _toolbar_action(toolbar, "First Run", self._show_first_run, "help")
        _toolbar_action(toolbar, "Plan", self._show_plan, "plan")
        _toolbar_action(toolbar, "Explain", self._explain_build, "explain")
        _toolbar_action(toolbar, "UX Audit", self._run_ux_audit, "audit")
        _toolbar_action(toolbar, "Readiness", self._run_readiness, "audit")
        _toolbar_action(toolbar, "Branding Compliance", self._run_branding_compliance, "audit")
        _toolbar_action(toolbar, "AI Review", self._run_ai_review, "explain")
        _toolbar_action(toolbar, "Dry-run", lambda: self._run_build(execute=False), "dry")
        _toolbar_action(toolbar, "Cancel Job", self._cancel_job, "cancel")

    def _header(self) -> QWidget:
        header = QFrame()
        header.setObjectName("AppHeader")
        layout = QHBoxLayout(header)
        layout.setContentsMargins(18, 12, 18, 12)
        layout.setSpacing(12)
        self._home_button = _button("Start", lambda: self._open_surface("start"), "home")
        self._home_button.setObjectName("HomeButton")
        self._home_button.setToolTip("Return to the project Start surface")
        layout.addWidget(self._home_button)
        title = QLabel("DistroForge")
        title.setObjectName("AppTitle")
        layout.addWidget(title)
        layout.addWidget(self.header_project_label, 1)
        level_label = QLabel("Level")
        level_label.setObjectName("HeaderFieldLabel")
        _tame_combo(self.mode_combo, visible_chars=14)
        self.mode_combo.setMaximumWidth(240)
        palette = self._build_palette_combo()
        palette.setMaximumWidth(200)
        layout.addWidget(level_label)
        layout.addWidget(self.mode_combo)
        layout.addWidget(palette)
        layout.addWidget(self.progress)
        self.progress.setFixedWidth(self._progress_width_expanded)
        return header

    def _palette_entries(self) -> list[tuple[str, tuple]]:
        """Single source for the command palette: every surface plus every guided
        journey step, each carrying a typed routing payload. Surfaces preserve the
        level-independent escape hatch (every surface stays reachable); the journey
        steps make the palette a complete keyboard-first action index.
        """
        entries: list[tuple[str, tuple]] = []
        for key, label in self._surface_labels.items():
            entries.append((label, ("surface", key)))
        for step in JOURNEY_STEPS:
            target = JOURNEY_TARGETS[step.action_id]
            entries.append((f"{step.title} ({step.level})", ("journey", target, step.step_id)))
        # Search aliases: the chroot terminal lives on the Maintainer surface, but a
        # user looking for it types "terminal" or "shell", not "maintainer". Route
        # those words to the surface that hosts it so the feature is discoverable by
        # the name people reach for. Each reuses the existing "surface" payload, so
        # the level-independent reachability set is unchanged.
        for alias in ("Chroot terminal", "Terminal", "Shell"):
            entries.append((alias, ("surface", "maintainer")))
        return entries

    def _build_palette_combo(self) -> QComboBox:
        combo = QComboBox()
        combo.setObjectName("SurfacePalette")
        combo.setEditable(True)
        combo.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        combo.addItem("Open tool…", None)
        for label, payload in self._palette_entries():
            combo.addItem(label, payload)
        combo.lineEdit().setPlaceholderText("Open tool…")
        completer = combo.completer()
        completer.setCompletionMode(QCompleter.CompletionMode.PopupCompletion)
        completer.setFilterMode(Qt.MatchFlag.MatchContains)
        completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        _tame_combo(combo, visible_chars=16)
        combo.activated.connect(lambda _index: self._palette_navigate(combo))
        self._palette_combo = combo
        shortcut = QShortcut(QKeySequence("Ctrl+K"), self)
        shortcut.activated.connect(self._focus_palette)
        return combo

    def _focus_palette(self) -> None:
        self._palette_combo.setFocus()
        line = self._palette_combo.lineEdit()
        if line is not None:
            line.selectAll()

    def _palette_navigate(self, combo: QComboBox) -> None:
        payload = combo.currentData()
        combo.setCurrentIndex(0)
        if not payload:
            return
        if payload[0] == "surface":
            self._open_surface(payload[1])
        elif payload[0] == "journey":
            self._focus_journey_step(payload[1], payload[2])

    def _open_surface(self, key: str) -> None:
        index = self._surfaces.get(key)
        if index is None:
            self._error(f"Unknown surface: {key}")
            return
        self._pages.setCurrentIndex(index)
        self._home_button.setVisible(key != "start")
        header = self._current_step_focus()
        if header is not None:
            header.reset_step()

    def _current_step_focus(self) -> StepFocusHeader | None:
        page = self._pages.currentWidget()
        return page.findChild(StepFocusHeader) if page is not None else None

    def _focus_journey_step(self, key: str, step_id: str) -> None:
        """Open a surface for a journey step and focus its banner on that step.

        Surfaces that back several steps keep one retargetable StepFocusHeader, so
        a journey click always lands on the right what/why/status without stacking
        banners. ``_open_surface`` resets the banner to the surface's canonical
        step first; this then retargets it to the routed step.
        """
        self._open_surface(key)
        if step_id:
            header = self._current_step_focus()
            if header is not None:
                header.set_step(step_id)

    def _restore_workflow_level(self) -> None:
        saved = preferences.load_workflow_level()
        index = self.mode_combo.findData(saved)
        if index >= 0:
            self.mode_combo.blockSignals(True)
            self.mode_combo.setCurrentIndex(index)
            self.mode_combo.blockSignals(False)

    def _on_level_changed(self) -> None:
        self._apply_mode_visibility()
        level = self.mode_combo.currentData()
        if level:
            preferences.save_workflow_level(str(level))
        if hasattr(self, "journey_spine"):
            self.journey_spine.refresh()
        if self.project:
            journey, parity = command_center_text(self)
            self.journey_view.setPlainText(journey)
            self.command_center_view.setPlainText(parity)

    def _on_chroot_backend_changed(self) -> None:
        backend = self.terminal_backend_combo.currentData()
        if backend:
            preferences.save_chroot_backend(str(backend))

    def _build_pages(self) -> None:
        pages = [
            build_project_page(self),
            self._iso_page(),
            self._packages_page(),
            self._customization_page(),
            self._capture_page(),
            self._recipes_page(),
            self._quality_page(),
            self._virtualization_page(),
            self._artifacts_page(),
            self._maintainer_page(),
            self._command_center_page(),
            self._plugins_page(),
            self._advanced_page(),
            self._build_page(),
            self._logs_page(),
        ]
        for key, page in zip(self._surface_labels, pages, strict=True):
            self._surfaces[key] = self._pages.count()
            self._pages.addWidget(_scroll_page(page))

    def _iso_page(self) -> QWidget:
        return build_iso_page(self)

    def _packages_page(self) -> QWidget:
        return build_packages_page(self)

    def _capture_page(self) -> QWidget:
        return build_capture_page(self)

    def _advanced_page(self) -> QWidget:
        return build_advanced_page(self)

    def _build_page(self) -> QWidget:
        return build_build_page(self)

    def _refresh_privilege_status(self) -> None:
        if not hasattr(self, "privilege_status_label"):
            return
        self.privilege_status_label.setText(
            privilege_status_text(self.sudo_check.isChecked(), self.pkexec_check.isChecked())
        )

    def _customization_page(self) -> QWidget:
        return build_customization_page(self)

    def _recipes_page(self) -> QWidget:
        return build_recipes_page(self)

    def _quality_page(self) -> QWidget:
        return build_quality_page(self)

    def _virtualization_page(self) -> QWidget:
        return build_virtualization_page(self)

    def _artifacts_page(self) -> QWidget:
        return build_artifacts_page(self)

    def _maintainer_page(self) -> QWidget:
        return build_maintainer_page(self)

    def _plugins_page(self) -> QWidget:
        return build_plugins_page(self)

    def _command_center_page(self) -> QWidget:
        return build_command_center_page(self)

    def _logs_page(self) -> QWidget:
        return build_logs_page(self)

    def _refresh_command_center(self) -> None:
        journey, parity = command_center_text(self)
        self.journey_view.setPlainText(journey)
        self.command_center_view.setPlainText(parity)
        self._log("Refreshed CLI / GUI command map.")

    def _open_current_journey_step(self) -> None:
        open_current_journey_step(self)

    def _apply_current_journey_step(self) -> None:
        apply_current_journey_step(self)

    def _new_project(self) -> None:
        new_project_action(self)

    def _open_project(self) -> None:
        open_project_action(self)

    def _save_project(self) -> None:
        save_project_action(self)

    def _browse_iso(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select source ISO", filter="ISO images (*.iso)")
        if path:
            self.source_iso_edit.setText(path)

    def _browse_output_iso(self) -> None:
        default = self.output_iso_edit.text().strip()
        if not default and self.project:
            default = str(self.project.output_dir / f"{self.project.name}.iso")
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Select output ISO on host",
            default,
            filter="ISO images (*.iso)",
        )
        if path:
            self.output_iso_edit.setText(path)

    def _browse_capture_output(self) -> None:
        browse_capture_output_action(self)

    def _browse_live_build_output(self) -> None:
        browse_live_build_output_action(self)

    def _browse_livefs_work_dir(self) -> None:
        browse_livefs_work_dir_action(self)

    def _browse_livefs_dest_iso(self) -> None:
        browse_livefs_dest_iso_action(self)

    def _browse_partition_layout(self) -> None:
        browse_partition_layout_action(self)

    def _browse_derivative_dockerfile(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select derivative Dockerfile",
            filter="Dockerfiles (Dockerfile* *.Dockerfile);;All files (*)",
        )
        if path:
            self.derivative_dockerfile_edit.setText(path)

    def _browse_buildinfo(self) -> None:
        browse_buildinfo_action(self)

    def _browse_changes(self) -> None:
        browse_changes_action(self)

    def _apply_source_starter(self) -> None:
        apply_source_starter_action(self)

    def _use_previous_project_source(self) -> None:
        use_previous_project_source_action(self)

    def _browse_wallpaper(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select wallpaper", filter="Images (*.png *.jpg *.jpeg *.webp)"
        )
        if path:
            self.wallpaper_edit.setText(path)

    def _run_capture_scan(self) -> None:
        run_capture_scan_action(self)

    def _export_capture_profile(self) -> None:
        export_capture_profile_action(self)

    def _rebuild_from_capture(self) -> None:
        rebuild_from_capture_action(self)

    def _plan_live_build(self) -> None:
        plan_live_build_action(self)

    def _write_live_build_plan(self) -> None:
        write_live_build_plan_action(self)

    def _plan_livefs_iso(self) -> None:
        plan_livefs_iso_action(self)

    def _write_livefs_iso_plan(self) -> None:
        write_livefs_iso_plan_action(self)

    def _run_upgrade_preflight(self) -> None:
        run_upgrade_preflight_action(self)

    def _plan_systemd_image(self) -> None:
        plan_systemd_image_action(self)

    def _load_artifact_defaults(self) -> None:
        load_artifact_defaults_action(self)

    def _run_release_readiness(self) -> None:
        run_release_readiness_action(self)

    def _run_release_gate(self) -> None:
        run_release_gate_action(self)

    def _run_evidence_status(self) -> None:
        run_evidence_status_action(self)

    def _run_evidence_status_verbose(self) -> None:
        run_evidence_status_action(self, verbose=True)

    def _run_evidence_fix_plan(self) -> None:
        run_evidence_status_action(self, fix_plan=True)

    def _verify_evidence_contract(self) -> None:
        verify_evidence_contract_action(self)

    def _create_publish_bundle(self) -> None:
        create_publish_bundle_action(self)

    def _run_qemu_smoke_plan(self) -> None:
        run_qemu_smoke_plan_action(self)

    def _run_packaging_policy(self) -> None:
        run_packaging_policy_action(self)

    def _run_autopkgtest_doctor(self) -> None:
        run_autopkgtest_doctor_action(self)

    def _run_hermetic_build_plan(self) -> None:
        run_hermetic_build_plan_action(self)

    def _create_hermetic_release_bundle(self) -> None:
        create_hermetic_release_bundle_action(self)

    def _doctor(self) -> None:
        run_doctor_action(self)

    def _show_plan(self) -> None:
        BuildController(self).show_plan()

    def _populate_plan_steps(self, steps) -> None:
        self.plan_steps_list.clear()
        for index, step in enumerate(steps, start=1):
            item = QListWidgetItem(
                phase_icon(step.phase),
                f"{index:02d}  {step.title}\n{step.detail}",
            )
            item.setData(Qt.ItemDataRole.UserRole, step.phase.value)
            self.plan_steps_list.addItem(item)

    def _run_build(self, execute: bool) -> None:
        BuildController(self).run_build(execute)

    def _start_terminal(self) -> None:
        start_terminal_action(self)

    def _show_chroot_backend_status(self) -> None:
        show_chroot_backend_status_action(self)

    def _send_terminal_input(self) -> None:
        send_terminal_input_action(self)

    def _poll_terminal(self) -> None:
        poll_terminal_action(self)

    def _stop_terminal(self) -> None:
        stop_terminal_action(self)

    def _mount_terminal_runtime(self) -> None:
        mount_terminal_runtime_action(self)

    def _unmount_terminal_runtime(self) -> None:
        unmount_terminal_runtime_action(self)

    def _review_current_plan(self) -> None:
        review_current_plan_action(self)

    def _review_manifest_file(self) -> None:
        review_manifest_file_action(self)

    def _show_first_run(self) -> None:
        self._first_run_shown = True
        FirstRunDialog(self).exec()

    def _show_first_run_once(self) -> None:
        if self._first_run_shown or self.project is not None:
            return
        self._show_first_run()

    def _export_recipe(self) -> None:
        export_recipe_action(self)

    def _export_build_preset(self) -> None:
        export_build_preset_action(self)

    def _import_recipe(self) -> None:
        import_recipe_action(self)

    def _import_build_preset(self) -> None:
        import_build_preset_action(self)

    def _clear_build_preset(self) -> None:
        clear_build_preset_action(self)

    def _show_guided_recipes(self) -> None:
        show_guided_recipes_action(self)

    def _run_ux_audit(self) -> None:
        run_ux_audit_action(self)

    def _run_readiness(self) -> None:
        run_readiness_action(self)

    def _run_preview(self) -> None:
        run_preview_action(self)

    def _run_interaction(self) -> None:
        run_interaction_action(self)

    def _run_mirrors_doctor(self) -> None:
        run_mirrors_doctor_action(self)

    def _render_mirrors(self) -> None:
        render_mirrors_action(self)

    def _apply_mirrors(self) -> None:
        apply_mirrors_action(self)

    def _restore_mirrors(self) -> None:
        restore_mirrors_action(self)

    def _run_branding_compliance(self) -> None:
        run_branding_compliance_action(self)

    def _run_debrand_scan(self) -> None:
        run_debrand_scan_action(self)

    def _run_brand_preview(self) -> None:
        run_brand_preview_action(self)

    def _export_brand_identity(self) -> None:
        export_brand_identity_action(self)

    def _run_profile_diff(self) -> None:
        run_profile_diff_action(self)

    def _export_profile_definition(self) -> None:
        export_profile_definition_action(self)

    def _run_derivative_profile_plan(self) -> None:
        run_derivative_profile_plan_action(self)

    def _export_derivative_profile_definition(self) -> None:
        export_derivative_profile_definition_action(self)

    def _create_derivative_project(self) -> None:
        create_derivative_project_action(self)

    def _run_ai_review(self) -> None:
        run_ai_review_action(self)

    def _run_forgeadvisor(self) -> None:
        run_forgeadvisor_action(self)

    def _run_debian_dev_doctor(self) -> None:
        run_debian_dev_doctor_action(self)

    def _forgeadvisor_propose_fixes(self) -> None:
        run_forgeadvisor_propose_action(self)

    def _explain_build(self) -> None:
        if not self._require_project():
            return
        self._sync_project_from_ui()
        assert self.project
        self.plan_view.setPlainText(explain_build(self.project, self._build_options()).render_text())
        self._open_surface("build")

    def _explain_risk(self) -> None:
        explain_risk_action(self)

    def _forgeadvisor_explain_log(self) -> None:
        forgeadvisor_explain_log_action(self)

    def _forgeadvisor_triage_log(self) -> None:
        forgeadvisor_triage_log_action(self)

    def _forgeadvisor_explain_evidence(self) -> None:
        forgeadvisor_explain_evidence_action(self)

    def _forgeadvisor_fix_plan(self) -> None:
        forgeadvisor_fix_plan_action(self)

    def _forgeadvisor_review_definition(self) -> None:
        forgeadvisor_review_definition_action(self)

    def _forgeadvisor_search_local(self) -> None:
        forgeadvisor_search_local_action(self)

    def _forgeadvisor_copilot(self) -> None:
        forgeadvisor_copilot_action(self)

    def _forgeadvisor_doctor_ai(self) -> None:
        forgeadvisor_doctor_ai_action(self)

    def _filter_logs(self) -> None:
        needle = self.log_filter_edit.text().strip().lower()
        if not needle:
            return
        lines = [
            line
            for line in self.logs.toPlainText().splitlines()
            if needle in line.lower()
        ]
        self.logs.setPlainText("\n".join(lines))

    def _clear_log_filter(self) -> None:
        self.log_filter_edit.clear()

    def _open_logs_page(self) -> None:
        self._open_surface("logs")
        self._log("Log filter cleared; new log entries will continue below.")

    def _refresh_plugins(self) -> None:
        if not self._require_project():
            return
        assert self.project
        self.plugins_view.setPlainText(render_catalog(self.project.root))
        self._open_surface("extensions")

    def _poll_job(self) -> None:
        if not self.build_job:
            self.job_timer.stop()
            self.progress.setVisible(False)
            return
        for event in self.build_job.poll():
            if event.kind == "progress":
                new_step = event.current is not None and event.current != self._job_step_done
                if event.current is not None:
                    self._job_step_done = event.current
                phase = event.phase or "step"
                total = event.total or self._job_step_total
                if event.fraction is not None:
                    self.progress.setRange(0, 1000)
                    self.progress.setValue(round(event.fraction * 1000))
                    self.progress.setFormat(
                        f"{self._job_step_done}/{total} {phase} {round(event.fraction * 100)}%"
                    )
                else:
                    bar_total = max(total, self._job_step_done)
                    if bar_total > 0:
                        self.progress.setRange(0, bar_total)
                    self.progress.setValue(self._job_step_done)
                    self.progress.setFormat(f"{self._job_step_done}/{bar_total} {phase}")
                if new_step:
                    if self._job_step_done > 0:
                        self.plan_steps_list.setCurrentRow(self._job_step_done - 1)
                    title = event.title or phase
                    self._log(f"[{phase}] {title}: {event.message}")
                continue
            if event.kind == "error":
                self._log(f"ERROR: {event.message}")
                QMessageBox.critical(self, "DistroForge", event.message)
            elif event.kind == "journey":
                self.journey_view.setPlainText(event.message)
            else:
                self._log(event.message)
            if event.kind in {"done", "error"}:
                if event.kind == "done":
                    self.progress.setValue(self.progress.maximum())
                self.progress.setVisible(False)
                self.job_timer.stop()
        if not self.build_job.running and not self.job_timer.isActive():
            self.build_job = None

    def _cancel_job(self) -> None:
        if not self.build_job or not self.build_job.running:
            self._log("No running job.")
            return
        self.build_job.cancel()

    def _apply_mode_visibility(self) -> None:
        mode = self.mode_combo.currentData()
        advanced = mode in {"power-user", "maintainer", "developer"}
        pro = mode in {"maintainer", "developer"}
        for widget in (
            self.proposed_check,
            self.proposed_pin_edit,
            self.rolling_full_upgrade_check,
            self.apt_proxy_edit,
            self.auto_recovery_check,
        ):
            widget.setVisible(advanced)
        for widget in (self.devel_suite_edit, self.backports_check, self.apt_cache_dir_edit):
            widget.setVisible(pro)
        if mode == "beginner":
            self.sanitize_check.setChecked(True)
            self.prune_packages_check.setChecked(True)
            self.snapshots_check.setChecked(True)
        if mode in {"maintainer", "developer"}:
            self.sanitize_check.setChecked(True)
            self.sanitize_apt_lists_check.setChecked(True)
            self.sanitize_ssh_keys_check.setChecked(True)
            self.snapshots_check.setChecked(True)
            self.auto_recovery_check.setChecked(True)
            self.release_artifacts_check.setChecked(True)
            self.html_report_check.setChecked(True)
            self.reproducible_check.setChecked(True)
            self.prebuild_vm_check.setChecked(True)

    def _build_options(self) -> BuildOptions:
        return build_options_from_window(self)

    def _cli_equivalent(self) -> str:
        return build_cli_equivalent(self)

    def _package_plan(self) -> PackagePlan:
        profile_key = self.profile_combo.currentData()
        installs = _split_packages(self.install_edit.toPlainText())
        removes = _split_packages(self.remove_edit.toPlainText())
        if profile_key:
            profile = get_profile(profile_key)
            installs = [*profile.install, *installs]
            removes = [*profile.remove, *removes]
        return PackagePlan(
            install=installs,
            remove=removes,
            purge=self.purge_remove_check.isChecked(),
        ).normalized()

    def _sync_project_from_ui(self) -> None:
        if not self.project:
            return
        iso_text = self.source_iso_edit.text().strip()
        self.project.source_mode = "bootstrap" if self.from_scratch_check.isChecked() else "iso"
        self.project.source_iso = Path(iso_text) if iso_text else None
        if self.project.source_iso:
            self.project.source_starter = {
                "key": "local-iso",
                "kind": "local-iso",
                "release": self.project.release.version,
                "label": f"Local ISO for {self.project.release.label}",
                "description": "Existing local ISO selected by the user.",
                "source_mode": "iso",
                "url": str(self.project.source_iso),
            }
        elif self.project.source_mode == "bootstrap" and not self.project.source_starter:
            self.project.source_starter = {
                "key": default_starter_for_release(self.project.release.version),
                "kind": "skeleton",
                "release": self.project.release.version,
                "label": f"{self.project.release.label} skeleton",
                "description": "Minimal skeleton source starter.",
                "source_mode": "bootstrap",
            }
        self.project.repositories = [
            line.strip()
            for line in self.repositories_edit.toPlainText().splitlines()
            if line.strip()
        ]
        plan = self._package_plan()
        self.project.packages = plan.install
        self.project.remove_packages = plan.remove
        custom = self.project.customization
        custom.desktop = self.desktop_combo.currentData() or None
        custom.display_manager = self.display_manager_combo.currentData() or None
        custom.autologin_user = self.autologin_edit.text().strip() or None
        custom.wallpaper = self.wallpaper_edit.text().strip() or None
        custom.hostname = self.hostname_edit.text().strip() or None
        custom.locale = _combo_value(self.locale_combo) or None
        custom.timezone = _combo_value(self.timezone_combo) or None
        custom.keyboard_layout = _combo_value(self.keyboard_combo) or None

    def _refresh(self) -> None:
        if hasattr(self, "journey_spine"):
            self.journey_spine.refresh()
        for header in getattr(self, "_step_focus_headers", ()):
            header.refresh()
        if not self.project:
            self.project_label.setText(f"No project loaded\nKnown releases: {', '.join(self.releases)}")
            self.header_project_label.setText("No project loaded")
            self.journey_view.setPlainText("Create or open a project to start the guided build journey.")
            refresh_start_journey_cards(self)
            self.summary_release.setText("-")
            self.summary_source.setText("-")
            self.summary_packages.setText("0")
            self.summary_desktop.setText("-")
            return
        self.project_label.setText(
            f"{self.project.name}\n{self.project.root}\n{self.project.release.label}"
        )
        self.header_project_label.setText(f"{self.project.name} - {self.project.release.label}")
        self.summary_release.setText(self.project.release.version)
        self.summary_source.setText(_source_summary(self.project))
        self.summary_packages.setText(str(len(self.project.packages) + len(self.project.remove_packages)))
        self.summary_desktop.setText(self.project.customization.desktop or "source")
        self.source_iso_edit.setText(str(self.project.source_iso or ""))
        self.from_scratch_check.setChecked(self.project.source_mode == "bootstrap")
        self.source_starter_summary.setText(_source_summary(self.project, long=True))
        if self.project.source_starter:
            _set_combo_data(self.source_starter_combo, str(self.project.source_starter.get("key", "")))
        self.repositories_edit.setPlainText("\n".join(self.project.repositories))
        self.install_edit.setPlainText("\n".join(self.project.packages))
        self.remove_edit.setPlainText("\n".join(self.project.remove_packages))
        custom = self.project.customization
        _set_combo_data(self.desktop_combo, custom.desktop or "")
        _set_combo_data(self.display_manager_combo, custom.display_manager or "")
        self.autologin_edit.setText(custom.autologin_user or "")
        self.wallpaper_edit.setText(custom.wallpaper or "")
        self.hostname_edit.setText(custom.hostname or "")
        _set_editable_combo_value(self.locale_combo, custom.locale or "")
        _set_editable_combo_value(self.timezone_combo, custom.timezone or "")
        _set_editable_combo_value(self.keyboard_combo, custom.keyboard_layout or "")
        journey, parity = command_center_text(self)
        self.journey_view.setPlainText(journey)
        self.command_center_view.setPlainText(parity)
        refresh_start_journey_cards(self)

    def _require_project(self) -> bool:
        if self.project:
            return True
        self._error("Create or open a project first.")
        return False

    def _log(self, text: str) -> None:
        self.logs.appendPlainText(text)
        first_line = text.splitlines()[0] if text else "Ready"
        self.statusBar().showMessage(first_line[:160])

    def _error(self, text: str) -> None:
        self._log(f"ERROR: {text}")
        QMessageBox.critical(self, "DistroForge", text)


def _split_packages(text: str) -> list[str]:
    packages: list[str] = []
    for raw_line in text.replace(",", "\n").splitlines():
        item = raw_line.strip()
        if item and not item.startswith("#"):
            packages.append(item)
    return packages


def _source_summary(project: Project, long: bool = False) -> str:
    starter = project.source_starter or {}
    label = str(starter.get("label") or "")
    kind = str(starter.get("kind") or project.source_mode)
    if project.source_iso:
        base = f"Local ISO: {project.source_iso}"
    elif label:
        base = label
    elif project.source_mode == "bootstrap":
        base = "Skeleton"
    else:
        base = "ISO missing"
    if not long:
        return base
    url = starter.get("url")
    checksum = starter.get("checksum_url")
    pieces = [f"{base} ({kind})"]
    if url and not project.source_iso:
        pieces.append(f"source: {url}")
    if checksum:
        pieces.append(f"checksums: {checksum}")
    return "\n".join(pieces)


def _combo_value(combo: QComboBox) -> str:
    text = combo.currentText().strip()
    index = combo.currentIndex()
    if index >= 0 and text == combo.itemText(index):
        data = combo.itemData(index)
        return str(data or "").strip()
    return text


def _set_editable_combo_value(combo: QComboBox, value: str) -> None:
    index = combo.findData(value)
    if index >= 0:
        combo.setCurrentIndex(index)
        return
    combo.setCurrentText(value)


def _int_or_default(value: str, default: int) -> int:
    try:
        return int(value)
    except ValueError:
        return default


def _optional_int(value: str) -> int | None:
    text = value.strip()
    if not text:
        return None
    return _int_or_default(text, 0)
