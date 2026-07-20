from __future__ import annotations

from distroforge.core.command import CommandRunner
from distroforge.core.doctor import apt_install_command, install_packages_for, run_doctor
from distroforge.core.education import render_glossary
from distroforge.ui.qt import (
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
        layout.addWidget(QLabel("ISO build glossary"))
        self.glossary_view = QPlainTextEdit()
        self.glossary_view.setReadOnly(True)
        self.glossary_view.setPlainText(render_glossary())
        layout.addWidget(self.glossary_view, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)
        self.refresh()

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
