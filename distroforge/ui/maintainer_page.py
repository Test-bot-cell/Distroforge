from __future__ import annotations

from distroforge.ui.qt import QLabel, QVBoxLayout, QWidget
from distroforge.ui.widgets import button as _button
from distroforge.ui.widgets import button_group as _button_group
from distroforge.ui.widgets import responsive_row as _responsive_row
from distroforge.ui.widgets import section as _section


def build_maintainer_page(window) -> QWidget:
    page = QWidget()
    layout = QVBoxLayout(page)
    layout.setContentsMargins(18, 18, 18, 18)
    review_group = _button_group(
        "Review and explain",
        _button("Review package plan", window._review_current_plan, "explain"),
        _button("Review manifest file", window._review_manifest_file, "open"),
        _button("Debian Dev Doctor", window._run_debian_dev_doctor, "audit"),
        _button("Evidence Status", window._run_evidence_status, "audit"),
        _button("Verbose Evidence", window._run_evidence_status_verbose, "audit"),
        _button("Evidence Fix Plan", window._run_evidence_fix_plan, "dry"),
        _button("Verify Evidence", window._verify_evidence_contract, "audit"),
        _button("Explain build", window._explain_build, "explain"),
        _button("Explain risks", window._explain_risk, "explain"),
    )
    advisor_group = _button_group(
        "AI advisor",
        _button("AI review plan", window._run_ai_review, "audit"),
        _button("ForgeAdvisor", window._run_forgeadvisor, "audit"),
        _button("Maintainer Copilot", window._forgeadvisor_copilot, "audit"),
        _button("FA: propose fixes", window._forgeadvisor_propose_fixes, "audit"),
        _button("FA: evidence", window._forgeadvisor_explain_evidence, "audit"),
        _button("FA: fix plan", window._forgeadvisor_fix_plan, "dry"),
        _button("FA: explain log", window._forgeadvisor_explain_log, "open"),
        _button("FA: triage log", window._forgeadvisor_triage_log, "open"),
        _button("FA: review def", window._forgeadvisor_review_definition, "open"),
        _button("FA: search local", window._forgeadvisor_search_local, "search"),
        _button("FA: AI doctor", window._forgeadvisor_doctor_ai, "audit"),
    )
    backend_row = _responsive_row(
        QLabel("AI narration backend"),
        window.advisor_backend_combo,
        QLabel("Advisory register"),
        window.advisor_register_combo,
        breakpoint=720,
    )
    terminal_actions = _responsive_row(
        _button("Mount runtime", window._mount_terminal_runtime, "start"),
        _button("Unmount runtime", window._unmount_terminal_runtime, "stop"),
        window.terminal_backend_combo,
        _button("Backend Status", window._show_chroot_backend_status, "audit"),
        _button("Start", window._start_terminal, "start", primary=True),
        window.terminal_input,
        _button("Send", window._send_terminal_input, "dry"),
        _button("Stop", window._stop_terminal, "stop"),
        breakpoint=1180,
    )
    top = _responsive_row(
        _section("Review", review_group, advisor_group, backend_row, window.evidence_summary_label, window.ai_view),
        _section("Chroot Terminal", window.terminal_status, window.terminal_view, terminal_actions),
        breakpoint=1080,
    )
    layout.addWidget(top, 1)
    return page
