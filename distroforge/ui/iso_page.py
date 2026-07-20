from __future__ import annotations

from distroforge.ui.path_actions import picker
from distroforge.ui.qt import QVBoxLayout, QWidget
from distroforge.ui.step_focus import StepFocusHeader
from distroforge.ui.widgets import button as _button
from distroforge.ui.widgets import responsive_form as _responsive_form
from distroforge.ui.widgets import responsive_row as _responsive_row
from distroforge.ui.widgets import section as _section


def build_iso_page(window) -> QWidget:
    page = QWidget()
    layout = QVBoxLayout(page)
    layout.setContentsMargins(18, 18, 18, 18)
    layout.addWidget(StepFocusHeader(window, "source"))
    starter_form = _responsive_form()
    starter_form.addRow("Starter", window.source_starter_combo)
    starter_form.addRow("Current source", window.source_starter_summary)
    starter_actions = _responsive_row(
        _button("Apply starter", window._apply_source_starter, "start"),
        _button("Use previous project", window._use_previous_project_source, "open"),
        breakpoint=720,
    )
    layout.addWidget(_section("Source Starter", starter_form, starter_actions))
    row = _responsive_row(
        window.source_iso_edit,
        _button("Select", window._browse_iso, "open"),
        breakpoint=720,
    )
    layout.addWidget(_section("Local ISO", row))
    trust_form = _responsive_form()
    trust_form.addRow("SHA256", window.source_iso_sha256_edit)
    trust_form.addRow(
        "Detached signature",
        _responsive_row(
            window.source_iso_signature_edit,
            picker(
                window,
                window.source_iso_signature_edit,
                title="Select detached signature",
                file_filter="Signatures (*.asc *.sig *.gpg);;All files (*)",
            ),
            breakpoint=680,
        ),
    )
    trust_form.addRow("Signer fingerprint", window.source_iso_gpg_fingerprint_edit)
    trust_form.addRow(window.require_source_checksum_check)
    trust_form.addRow(window.require_source_signature_check)
    layout.addWidget(_section("Source Trust", trust_form))
    mirror_form = _responsive_form()
    mirror_form.addRow(window.mirrors_check)
    mirror_form.addRow("Archive mirror", window.mirror_archive_edit)
    mirror_form.addRow("Security mirror", window.mirror_security_edit)
    mirror_form.addRow("Country", window.mirror_country_edit)
    mirror_form.addRow(window.mirror_allow_http_check)
    mirror_form.addRow(window.mirror_override_security_check)
    mirror_actions = _responsive_row(
        _button("Doctor", window._run_mirrors_doctor, "audit"),
        _button("Render", window._render_mirrors, "plan"),
        _button("Apply", window._apply_mirrors, "start"),
        _button("Restore", window._restore_mirrors, "clear"),
        breakpoint=860,
    )
    layout.addWidget(_section("APT Mirrors", mirror_form, mirror_actions, window.mirrors_view), 1)
    layout.addWidget(_section("Repositories", window.repositories_edit), 1)
    return page
