from __future__ import annotations

from distroforge.core.command import CommandRunner
from distroforge.core.doctor import apt_install_command, install_packages_for, run_doctor
from distroforge.core.education import render_glossary
from distroforge.core.gnome_favorites import pin_launcher, read_favorites, unpin_launcher
from distroforge.ui.preferences import load_dock_pin_choice, save_dock_pin_choice
from distroforge.ui.qt import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
)


class FirstRunDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("DistroForge first run")
        self.resize(760, 520)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("DistroForge can check the host before you create or build an ISO."))
        self.report = QPlainTextEdit()
        self.report.setReadOnly(True)
        layout.addWidget(self.report, 1)
        self.refresh_button = QPushButton("Check dependencies")
        self.refresh_button.clicked.connect(self.refresh)
        layout.addWidget(self.refresh_button)
        # The dock pin used to be attempted by a root postinst, behind the user's
        # back. It is now one question, asked once, inside the user's own session --
        # and the box starts cleared so silence is never taken for a yes.
        self.dock_checkbox = QCheckBox("Keep DistroForge in the GNOME dock (favorites)")
        layout.addWidget(self.dock_checkbox)
        self.dock_status = QLabel("")
        layout.addWidget(self.dock_status)
        layout.addWidget(QLabel("ISO build glossary"))
        self.glossary_view = QPlainTextEdit()
        self.glossary_view.setReadOnly(True)
        self.glossary_view.setPlainText(render_glossary())
        layout.addWidget(self.glossary_view, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)
        self.refresh()
        self.refresh_dock_state()

    def refresh(self) -> None:
        report = run_doctor(CommandRunner(dry_run=True))
        lines = []
        for item in report:
            state = "ok" if item.available else "missing"
            lines.append(f"{state:8} {item.binary:20} {item.reason}")
        packages = install_packages_for(report, include_optional=True)
        if packages:
            lines.extend(["", "Install missing Ubuntu packages with:", apt_install_command(packages)])
        else:
            lines.extend(["", "All required and optional host dependencies were detected."])
        self.report.setPlainText("\n".join(lines))

    def refresh_dock_state(self) -> None:
        # `gsettings get` changes nothing, so the reader executes: a dry-run read
        # would report an empty dock and the checkbox would lie about the state.
        state = read_favorites(CommandRunner(dry_run=False))
        self.dock_checkbox.setEnabled(state.available)
        self.dock_status.setText(state.summary())
        saved = load_dock_pin_choice()
        self.dock_checkbox.setChecked(state.pinned if saved is None else saved)

    def accept(self) -> None:
        self.apply_dock_choice()
        super().accept()

    def apply_dock_choice(self) -> None:
        """Act on the checkbox both ways: what the user grants, the user can revoke."""
        wanted = self.dock_checkbox.isChecked()
        save_dock_pin_choice(wanted)
        if not self.dock_checkbox.isEnabled():
            return
        runner = CommandRunner(dry_run=False)
        state = pin_launcher(runner) if wanted else unpin_launcher(runner)
        self.dock_status.setText(state.summary())
