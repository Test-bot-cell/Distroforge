from __future__ import annotations

from distroforge.core.build import BuildOptions
from distroforge.core.project import Project
from distroforge.core.ux_audit import (
    _LEVEL_AUDIT_PATHS,
    audit_experience,
    gui_source_root,
)
from distroforge.core.workflows import LEVEL_KEYS


def _developer_areas(report) -> set[str]:
    return {finding.area for finding in report.findings if finding.persona == "developer"}


def test_gui_source_root_is_the_ui_directory() -> None:
    root = gui_source_root()
    assert root.is_dir()
    assert root.name == "ui"


def test_canonical_gui_source_satisfies_parity_audit(tmp_path) -> None:
    project = Project.create("ParityAudit", tmp_path / "parity-audit", "26.04")
    report = audit_experience(project, BuildOptions(), gui_source_root())
    parity_errors = [finding for finding in report.findings if finding.level == "error"]
    assert parity_errors == [], report.render_text()


def test_audit_paths_cover_exactly_the_canonical_levels() -> None:
    # ux_audit must audit every canonical workflow level, in order, with no extra path.
    assert tuple(_LEVEL_AUDIT_PATHS) == LEVEL_KEYS


def test_developer_path_is_silent_without_extensions(tmp_path) -> None:
    project = Project.create("DevSilent", tmp_path / "dev-silent", "26.04")
    report = audit_experience(project, BuildOptions())
    assert _developer_areas(report) == set()


def test_developer_path_flags_plugins_without_snapshots(tmp_path) -> None:
    project = Project.create("DevPlugins", tmp_path / "dev-plugins", "26.04")
    options = BuildOptions()
    options.plugins.plugins_dir = tmp_path / "plugins"
    options.snapshots.enabled = False
    report = audit_experience(project, options)
    assert "plugins" in _developer_areas(report)


def test_developer_path_flags_imported_scripts_without_snapshots(tmp_path) -> None:
    project = Project.create("DevImport", tmp_path / "dev-import", "26.04")
    options = BuildOptions()
    options.import_scripts.scripts = [tmp_path / "legacy.sh"]
    options.snapshots.enabled = False
    report = audit_experience(project, options)
    assert "imported hooks" in _developer_areas(report)


def test_developer_path_flags_unpinned_desktop_source(tmp_path) -> None:
    project = Project.create("DevDesktop", tmp_path / "dev-desktop", "26.04")
    options = BuildOptions()
    options.desktop_source.enabled = True
    options.desktop_source.require_sha256 = False
    report = audit_experience(project, options)
    assert "desktop source" in _developer_areas(report)


def test_developer_path_flags_extension_without_reproducible(tmp_path) -> None:
    project = Project.create("DevRepro", tmp_path / "dev-repro", "26.04")
    options = BuildOptions()
    options.plugins.plugins_dir = tmp_path / "plugins"
    options.reproducible.enabled = False
    report = audit_experience(project, options)
    assert "reproducibility" in _developer_areas(report)


def test_developer_path_is_clean_when_extensions_are_safe(tmp_path) -> None:
    project = Project.create("DevClean", tmp_path / "dev-clean", "26.04")
    options = BuildOptions()
    options.plugins.plugins_dir = tmp_path / "plugins"
    options.import_scripts.scripts = [tmp_path / "legacy.sh"]
    options.desktop_source.enabled = True
    options.desktop_source.require_sha256 = True
    options.snapshots.enabled = True
    options.reproducible.enabled = True
    report = audit_experience(project, options)
    assert _developer_areas(report) == set()
