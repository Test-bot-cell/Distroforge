from __future__ import annotations

from distroforge.ui.path_actions import picker
from distroforge.ui.qt import QVBoxLayout, QWidget
from distroforge.ui.step_focus import StepFocusHeader
from distroforge.ui.widgets import button as _button
from distroforge.ui.widgets import responsive_form as _responsive_form
from distroforge.ui.widgets import responsive_row as _responsive_row
from distroforge.ui.widgets import section as _section


def build_virtualization_page(window) -> QWidget:
    page = QWidget()
    layout = QVBoxLayout(page)
    layout.setContentsMargins(18, 18, 18, 18)
    layout.addWidget(StepFocusHeader(window, "boot-proof"))

    vm_form = _responsive_form()
    vm_form.addRow(window.preview_check)
    vm_form.addRow("Preview display", window.preview_display_combo)
    vm_form.addRow("Interaction plan", window.interaction_plan_combo)
    vm_form.addRow(window.prebuild_vm_check)
    vm_form.addRow("VM profile", window.prebuild_vm_profile_combo)
    vm_form.addRow("VM firmware", window.prebuild_vm_firmware_combo)
    vm_form.addRow(window.prebuild_vm_secure_boot_check)
    vm_form.addRow(window.prebuild_vm_tpm_check)
    vm_form.addRow("VM memory MB", window.prebuild_vm_memory_edit)
    vm_form.addRow("VM CPUs", window.prebuild_vm_cpus_edit)
    vm_form.addRow("VM disk size", window.prebuild_vm_disk_size_edit)
    vm_form.addRow(window.prebuild_vm_network_check)
    vm_form.addRow("VM timeout", window.prebuild_vm_timeout_edit)
    vm_form.addRow("Serial log", window.prebuild_vm_serial_log_edit)
    vm_form.addRow(window.prebuild_vm_screenshot_check)
    vm_form.addRow("Screenshot name", window.prebuild_vm_screenshot_name_edit)
    vm_form.addRow("QMP socket", window.prebuild_vm_qmp_socket_edit)
    vm_form.addRow("PID file", window.prebuild_vm_pid_file_edit)
    vm_form.addRow(
        "OVMF code",
        _responsive_row(
            window.prebuild_vm_ovmf_code_edit,
            picker(
                window,
                window.prebuild_vm_ovmf_code_edit,
                title="Select OVMF code firmware",
                file_filter="Firmware (*.fd *.bin);;All files (*)",
            ),
            breakpoint=680,
        ),
    )
    vm_form.addRow(
        "OVMF vars",
        _responsive_row(
            window.prebuild_vm_ovmf_vars_edit,
            picker(
                window,
                window.prebuild_vm_ovmf_vars_edit,
                title="Select OVMF vars template",
                file_filter="Firmware (*.fd *.bin);;All files (*)",
            ),
            breakpoint=680,
        ),
    )
    vm_form.addRow("Report JSON", window.prebuild_vm_report_name_edit)
    vm_form.addRow("Success markers", window.prebuild_vm_success_patterns_edit)
    vm_form.addRow(window.qemu_screenshot_check)

    actions = _responsive_row(
        _button("Plan QEMU", window._show_plan, "plan"),
        _button("Preview ISO", window._run_preview, "plan"),
        _button("Run interaction", window._run_interaction, "plan"),
        _button("Readiness", window._run_readiness, "audit"),
        _button("Open logs", window._open_logs_page, "open"),
        breakpoint=780,
    )
    layout.addWidget(_section("QEMU Virtualization", vm_form, actions))
    layout.addWidget(_section("Readiness", window.readiness_view), 1)
    return page
