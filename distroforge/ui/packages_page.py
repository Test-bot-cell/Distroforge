from __future__ import annotations

from distroforge.ui.qt import QVBoxLayout, QWidget
from distroforge.ui.step_focus import StepFocusHeader
from distroforge.ui.widgets import button as _button
from distroforge.ui.widgets import responsive_form as _responsive_form
from distroforge.ui.widgets import responsive_row as _responsive_row
from distroforge.ui.widgets import section as _section


def build_packages_page(window) -> QWidget:
    page = QWidget()
    layout = QVBoxLayout(page)
    layout.setContentsMargins(18, 18, 18, 18)
    layout.addWidget(StepFocusHeader(window, "identity"))
    form = _responsive_form()
    form.addRow("Persona", window.persona_combo)
    form.addRow("Profile", window.profile_combo)
    form.addRow("Derivative", window.derivative_profile_combo)
    form.addRow(
        "Dockerfile",
        _responsive_row(
            window.derivative_dockerfile_edit,
            _button("Select", window._browse_derivative_dockerfile, "open"),
            breakpoint=680,
        ),
    )
    profile_actions = _responsive_row(
        _button("Profile Diff", window._run_profile_diff, "audit"),
        _button("Export Profile", window._export_profile_definition, "save"),
        _button("Derivative Plan", window._run_derivative_profile_plan, "plan"),
        _button("Export Derivative", window._export_derivative_profile_definition, "save"),
        _button("Create Derivative Project", window._create_derivative_project, "new"),
        breakpoint=720,
    )
    layout.addWidget(_section("Package Strategy", form, profile_actions))
    package_rows = _responsive_row(
        _section("Install", window.install_edit),
        _section("Remove", window.remove_edit),
        breakpoint=900,
    )
    layout.addWidget(package_rows, 1)
    layout.addWidget(_section("Profile", window.profile_view), 1)
    return page
